import socket
import struct
from argparse import Namespace
from typing import Any

from impacket.dcerpc.v5.dtypes import (
    DWORD,
    NULL,
    STR,
    ULONG,
    WSTR,
)
from impacket.dcerpc.v5.ndr import (
    NDRCALL,
    NDRPOINTER,
    NDRSMALL,
    NDRSTRUCT,
    NDRUNION,
    NDRUniConformantArray,
    NDRUniFixedArray,
)
from impacket.dcerpc.v5.rpcrt import DCERPCException

from aorta.transport import dns_connect

# impacket 0.13 ships no dnsserver module, so the stubs below are hand-rolled
# per Samba's librpc/idl/{dnsserver,dnsp}.idl (== MS-DNSP wire format). We use
# the DOTNET client version so the create-info carries aipMasters (IP4_ARRAY)
# and the forwarder timeout/recursion fields -- letting us create a conditional
# forwarder zone with its master IPs in a single ZoneCreate call.

DNS_CLIENT_VERSION_DOTNET = 0x00060000
(
    DNS_ZONE_TYPE_CACHE,
    DNS_ZONE_TYPE_PRIMARY,
    DNS_ZONE_TYPE_SECONDARY,
    DNS_ZONE_TYPE_STUB,
    DNS_ZONE_TYPE_FORWARDER,
    DNS_ZONE_TYPE_SECONDARY_CACHE,
) = range(0, 6)
ZONE_TYPE_NAMES = {
    DNS_ZONE_TYPE_CACHE: "cache",
    DNS_ZONE_TYPE_PRIMARY: "primary",
    DNS_ZONE_TYPE_SECONDARY: "secondary",
    DNS_ZONE_TYPE_STUB: "stub",
    DNS_ZONE_TYPE_FORWARDER: "forwarder",
    DNS_ZONE_TYPE_SECONDARY_CACHE: "secondary-cache",
}

DNSSRV_TYPEID_NULL = 0
DNSSRV_TYPEID_DWORD = 1
DNSSRV_TYPEID_IPARRAY = 4
DNSSRV_TYPEID_ZONE_INFO_DOTNET = 22
DNSSRV_TYPEID_ZONE_CREATE_DOTNET = 26
DNSSRV_TYPEID_ZONE_LIST = 27
DNSSRV_TYPEID_ENUM_ZONES_FILTER = 33

# DNS winerror codes of interest (DNS_ERROR_* are 9600+)
DNS_ERROR_ZONE_ALREADY_EXISTS = 9619  # 0x2593
DNS_ERROR_ZONE_DOES_NOT_EXIST = 9601  # 0x2501
W_E_ACCESS_DENIED = 5  # ERROR_ACCESS_DENIED


def ip_to_dw(ip: str) -> int:
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def dw_to_ip(dw: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", dw & 0xFFFFFFFF))


def ip4_array_to_strs(a: Any) -> list[str]:
    if not a:
        return []
    return [dw_to_ip(x) for x in a["AddrArray"]]


# impacket's conformant STR/WSTR omit the NUL terminator (max/actual count =
# char count, no trailing \0), which Windows MS-DNSP rejects as
# rpc_x_bad_stub_data, and assigning dtypes.NULL to an LPSTR yields a
# pointer-to-empty rather than a null pointer. These subclasses fix both: they
# NUL-terminate on assignment and produce a real null pointer (ReferentID 0)
# when assigned NULL.
class _NZ_STR(STR):
    def __setitem__(self, key: str, value: Any) -> None:
        if key == "Data" and isinstance(value, str):
            value = value + "\x00"
        return STR.__setitem__(self, key, value)


class _NZ_WSTR(WSTR):
    def __setitem__(self, key: str, value: Any) -> None:
        if key == "Data" and isinstance(value, str):
            value = value + "\x00"
        return WSTR.__setitem__(self, key, value)


class DNS_LPSTR(NDRPOINTER):
    referent = (("Data", _NZ_STR),)


class DNS_LPWSTR(NDRPOINTER):
    referent = (("Data", _NZ_WSTR),)


# --- shared NDR building blocks --------------------------------------------


class DWORD_ARRAY(NDRUniConformantArray):
    item = "<L"


class IP4_ARRAY(NDRSTRUCT):
    structure = (
        ("AddrCount", ULONG),
        ("AddrArray", DWORD_ARRAY),
    )


class PIP4_ARRAY(NDRPOINTER):
    referent = (("Data", IP4_ARRAY),)


class RESERVED32(NDRUniFixedArray):
    def getDataLen(self, data: bytes, offset: int = 0) -> int:
        return 32 * 4


# --- DNS_RPC_ZONE_CREATE_INFO_DOTNET (typeid 26) ---------------------------


class DNS_RPC_ZONE_CREATE_INFO_DOTNET(NDRSTRUCT):
    structure = (
        ("dwRpcStructureVersion", ULONG),
        ("dwReserved0", ULONG),
        ("pszZoneName", DNS_LPSTR),
        ("dwZoneType", ULONG),
        ("fAllowUpdate", NDRSMALL),  # dns_zone_update is [enum8bit] -> 1 byte + 3 pad
        ("fAging", ULONG),  # BOOL (boolean32)
        ("dwFlags", ULONG),
        ("pszDataFile", DNS_LPSTR),
        ("fDsIntegrated", ULONG),
        ("fLoadExisting", ULONG),
        ("pszAdmin", DNS_LPSTR),
        ("aipMasters", PIP4_ARRAY),
        ("aipSecondaries", PIP4_ARRAY),
        ("fSecureSecondaries", ULONG),
        ("fNotifyLevel", ULONG),
        ("dwTimeout", ULONG),  # forwarder timeout
        ("fRecurseAfterForwarding", ULONG),
        ("dwDpFlags", ULONG),
        ("pszDpFqdn", DNS_LPSTR),
        ("dwReserved", RESERVED32),
    )


class PDNS_RPC_ZONE_CREATE_INFO_DOTNET(NDRPOINTER):
    referent = (("Data", DNS_RPC_ZONE_CREATE_INFO_DOTNET),)


# --- DNS_RPC_ZONE_INFO_DOTNET (typeid 22) -- used to verify masters ---------


class DNS_RPC_ZONE_INFO_DOTNET(NDRSTRUCT):
    structure = (
        ("dwRpcStructureVersion", ULONG),
        ("dwReserved0", ULONG),
        ("pszZoneName", DNS_LPSTR),
        ("dwZoneType", ULONG),
        ("fReverse", ULONG),
        ("fAllowUpdate", NDRSMALL),
        ("fPaused", ULONG),
        ("fShutdown", ULONG),
        ("fAutoCreated", ULONG),
        ("fUseDatabase", ULONG),
        ("pszDataFile", DNS_LPSTR),
        ("aipMasters", PIP4_ARRAY),
        ("fSecureSecondaries", ULONG),
        ("fNotifyLevel", ULONG),
        ("aipSecondaries", PIP4_ARRAY),
        ("aipNotify", PIP4_ARRAY),
        ("fUseWins", ULONG),
        ("fUseNbstat", ULONG),
        ("fAging", ULONG),
        ("dwNoRefreshInterval", ULONG),
        ("dwRefreshInterval", ULONG),
        ("dwAvailForScavengeTime", ULONG),
        ("aipScavengeServers", PIP4_ARRAY),
        ("dwForwarderTimeout", ULONG),
        ("fForwarderSlave", ULONG),
        ("aipLocalMasters", PIP4_ARRAY),
        ("dwDpFlags", ULONG),
        ("pszDpFqdn", DNS_LPSTR),
        ("pwszZoneDn", DNS_LPWSTR),
        ("dwLastSuccessfulSoaCheck", ULONG),
        ("dwLastSuccessfulXfr", ULONG),
        ("dwReserved1", ULONG),
        ("dwReserved2", ULONG),
        ("dwReserved3", ULONG),
        ("dwReserved4", ULONG),
        ("dwReserved5", ULONG),
        ("pReserved1", DNS_LPSTR),
        ("pReserved2", DNS_LPSTR),
        ("pReserved3", DNS_LPSTR),
        ("pReserved4", DNS_LPSTR),
    )


class PDNS_RPC_ZONE_INFO_DOTNET(NDRPOINTER):
    referent = (("Data", DNS_RPC_ZONE_INFO_DOTNET),)


# --- DNS_RPC_ZONE_DOTNET (list entry) + DNS_RPC_ZONE_LIST_DOTNET (typeid 27) -


class DNS_RPC_ZONE_DOTNET(NDRSTRUCT):
    structure = (
        ("dwRpcStructureVersion", ULONG),
        ("dwReserved0", ULONG),
        ("pszZoneName", DNS_LPWSTR),  # UTF-16
        ("Flags", ULONG),
        ("ZoneType", NDRSMALL),  # UCHAR
        ("Version", NDRSMALL),  # UCHAR
        ("dwDpFlags", ULONG),
        ("pszDpFqdn", DNS_LPSTR),  # UTF-8
    )


class PDNS_RPC_ZONE_DOTNET(NDRPOINTER):
    referent = (("Data", DNS_RPC_ZONE_DOTNET),)


class PZONE_ARRAY(NDRUniConformantArray):
    item = PDNS_RPC_ZONE_DOTNET


class DNS_RPC_ZONE_LIST_DOTNET(NDRSTRUCT):
    structure = (
        ("dwRpcStructureVersion", ULONG),
        ("dwReserved0", ULONG),
        ("dwZoneCount", ULONG),
        ("ZoneArray", PZONE_ARRAY),
    )


class PDNS_RPC_ZONE_LIST_DOTNET(NDRPOINTER):
    referent = (("Data", DNS_RPC_ZONE_LIST_DOTNET),)


# --- the discriminated union (switch_is(dwTypeId), pointer arms) -----------


class DNSSRV_RPC_UNION(NDRUNION):
    commonHdr = (("tag", ULONG),)
    union = {
        DNSSRV_TYPEID_NULL: ("Null", NDRPOINTER),
        DNSSRV_TYPEID_DWORD: ("Dword", ULONG),
        DNSSRV_TYPEID_IPARRAY: ("IpArray", PIP4_ARRAY),
        DNSSRV_TYPEID_ZONE_INFO_DOTNET: ("ZoneInfo", PDNS_RPC_ZONE_INFO_DOTNET),
        DNSSRV_TYPEID_ZONE_CREATE_DOTNET: ("ZoneCreate", PDNS_RPC_ZONE_CREATE_INFO_DOTNET),
        DNSSRV_TYPEID_ZONE_LIST: ("ZoneList", PDNS_RPC_ZONE_LIST_DOTNET),
    }


class PDNSSRV_RPC_UNION(NDRPOINTER):
    referent = (("Data", DNSSRV_RPC_UNION),)


# --- RPC stubs: opnum 5 Operation2 / opnum 6 Query2 / opnum 7 ComplexOp2 ---


class DnssrvOperation2(NDRCALL):
    opnum = 5
    structure = (
        ("dwClientVersion", ULONG),
        ("dwSettingFlags", ULONG),
        ("pwszServerName", DNS_LPWSTR),  # UTF-16, unique
        ("pszZone", DNS_LPSTR),  # UTF-8, unique (nullable)
        ("dwContext", ULONG),
        ("pszOperation", DNS_LPSTR),  # UTF-8
        ("dwTypeId", ULONG),
        ("pData", DNSSRV_RPC_UNION),
    )


class DnssrvOperation2Response(NDRCALL):
    structure = (("ErrorCode", DWORD),)


class DnssrvQuery2(NDRCALL):
    opnum = 6
    structure = (
        ("dwClientVersion", ULONG),
        ("dwSettingFlags", ULONG),
        ("pwszServerName", DNS_LPWSTR),
        ("pszZone", DNS_LPSTR),  # unique, nullable
        ("pszOperation", DNS_LPSTR),
    )


class DnssrvQuery2Response(NDRCALL):
    structure = (
        ("pdwTypeId", DWORD),
        ("ppData", DNSSRV_RPC_UNION),
        ("ErrorCode", DWORD),
    )


class DnssrvComplexOperation2(NDRCALL):
    opnum = 7
    structure = (
        ("dwClientVersion", ULONG),
        ("dwSettingFlags", ULONG),
        ("pwszServerName", DNS_LPWSTR),
        ("pszZone", DNS_LPSTR),
        ("pszOperation", DNS_LPSTR),
        ("dwTypeIn", ULONG),
        ("pDataIn", DNSSRV_RPC_UNION),
    )


class DnssrvComplexOperation2Response(NDRCALL):
    structure = (
        ("pdwTypeOut", DWORD),
        ("ppDataOut", DNSSRV_RPC_UNION),
        ("ErrorCode", DWORD),
    )


def dns_union(arm_name: str, typeid: int, value: Any) -> DNSSRV_RPC_UNION:
    u = DNSSRV_RPC_UNION()
    u["tag"] = typeid
    u[arm_name] = value
    return u


def build_ip4_array(ips: list[str]) -> IP4_ARRAY:
    a = IP4_ARRAY()
    a["AddrCount"] = len(ips)
    a["AddrArray"] = [ip_to_dw(ip) for ip in ips]
    return a


def _dns_decode_error(exc: Exception) -> str:
    code = getattr(exc, "error_code", None)
    if code is not None:
        hint = ""
        if code == W_E_ACCESS_DENIED:
            hint = " (ACCESS_DENIED -- is the user in DnsAdmins?)"
        elif code == DNS_ERROR_ZONE_ALREADY_EXISTS:
            hint = " (zone already exists -- use --force)"
        elif code == DNS_ERROR_ZONE_DOES_NOT_EXIST:
            hint = " (zone does not exist)"
        return f"0x{code & 0xFFFFFFFF:08x}{hint}"
    return str(exc)


def _op2(
    dce: Any,
    args: Namespace,
    zone: str | None,
    operation: str,
    typeid: int,
    arm_name: str,
    value: Any,
) -> Any:
    req = DnssrvOperation2()
    req["dwClientVersion"] = DNS_CLIENT_VERSION_DOTNET
    req["dwSettingFlags"] = 0
    req["pwszServerName"] = args.dc
    req["pszZone"] = zone if zone is not None else NULL
    req["dwContext"] = 0
    req["pszOperation"] = operation
    req["dwTypeId"] = typeid
    req["pData"] = dns_union(arm_name, typeid, value)
    return dce.request(req)


def build_zone_create_info(args: Namespace) -> DNS_RPC_ZONE_CREATE_INFO_DOTNET:
    info = DNS_RPC_ZONE_CREATE_INFO_DOTNET()
    info["dwRpcStructureVersion"] = 1
    info["pszZoneName"] = args.zone
    info["dwZoneType"] = DNS_ZONE_TYPE_FORWARDER
    info["fAllowUpdate"] = 0
    info["fAging"] = 0
    info["pszDataFile"] = NULL
    info["fDsIntegrated"] = 0
    info["fLoadExisting"] = 1
    info["pszAdmin"] = NULL
    info["aipMasters"] = build_ip4_array(args.master)
    info["aipSecondaries"] = NULL
    info["fSecureSecondaries"] = 0
    info["fNotifyLevel"] = 0
    info["dwTimeout"] = args.forwarder_timeout
    info["fRecurseAfterForwarding"] = 1 if args.use_recursion else 0
    info["dwDpFlags"] = 0
    info["pszDpFqdn"] = NULL
    info["dwReserved"] = b"\x00" * (32 * 4)
    return info


def query_zone_info(dce: Any, args: Namespace, zone: str) -> Any:
    req = DnssrvQuery2()
    req["dwClientVersion"] = DNS_CLIENT_VERSION_DOTNET
    req["dwSettingFlags"] = 0
    req["pwszServerName"] = args.dc
    req["pszZone"] = zone
    req["pszOperation"] = "ZoneInfo"
    resp = dce.request(req)
    return resp["ppData"]["ZoneInfo"]


def print_forwarder(idx: int, name: Any, masters: list[str], timeout: int = 5, extra: str = "") -> None:
    name = (name or "").rstrip("\x00") if isinstance(name, str) else name
    print(f"    [{idx}] {name}  (type: forwarder){extra}")
    print(f"        MasterServers: {', '.join(masters) if masters else '(none)'}")
    print(f"        ForwarderTimeout: {timeout}")
    print()


def enum_zones(dce: Any, args: Namespace) -> list[Any]:
    req = DnssrvComplexOperation2()
    req["dwClientVersion"] = DNS_CLIENT_VERSION_DOTNET
    req["dwSettingFlags"] = 0
    req["pwszServerName"] = args.dc
    req["pszZone"] = NULL
    req["pszOperation"] = "EnumZones"
    req["dwTypeIn"] = DNSSRV_TYPEID_DWORD
    req["pDataIn"] = dns_union("Dword", DNSSRV_TYPEID_DWORD, 0xFFFFFFFF)  # all zone types
    resp = dce.request(req)
    return resp["ppDataOut"]["ZoneList"]["ZoneArray"] or []


def show_forwarders(dce: Any, args: Namespace) -> None:
    zones = enum_zones(dce, args)
    forwarders = [z for z in zones if z["ZoneType"] == DNS_ZONE_TYPE_FORWARDER]
    print(f"[+] Total zones: {len(zones)}; forwarder zones: {len(forwarders)}\n")
    for i, z in enumerate(forwarders, 1):
        masters: list[str] = []
        timeout = 5
        try:
            info = query_zone_info(dce, args, z["pszZoneName"])
            masters = ip4_array_to_strs(info["aipMasters"])
            timeout = info["dwForwarderTimeout"]
        except Exception as e:
            print(f"    [!] could not read masters for {z['pszZoneName']}: {_dns_decode_error(e)}")
        print_forwarder(i, z["pszZoneName"], masters, timeout)


def _zone_create(dce: Any, args: Namespace) -> None:
    _op2(dce, args, None, "ZoneCreate", DNSSRV_TYPEID_ZONE_CREATE_DOTNET, "ZoneCreate", build_zone_create_info(args))


def cmd_forwarder_add(args: Namespace) -> None:
    print(f"[*] Adding conditional forwarder: {args.zone} -> {', '.join(args.master)} on {args.dc}")
    dce = dns_connect(args)
    try:
        _forwarder_do_add(dce, args)
    finally:
        dce.disconnect()


def _forwarder_do_add(dce: Any, args: Namespace) -> None:
    print("[*] Sending ZoneCreate (R_DnssrvOperation2 opnum 5, type FORWARDER)...")
    try:
        _zone_create(dce, args)
    except DCERPCException as e:
        code = getattr(e, "error_code", None)
        code = code & 0xFFFFFFFF if code else None
        print(f"[-] ZoneCreate failed: {_dns_decode_error(e)}")
        if code == DNS_ERROR_ZONE_ALREADY_EXISTS and args.force:
            print(f"[*] --force: deleting existing zone {args.zone} and recreating")
            try:
                _op2(dce, args, args.zone, "DeleteZone", DNSSRV_TYPEID_NULL, "Null", NULL)
                print("[+] Existing zone deleted")
            except DCERPCException as e2:
                print(f"[-] Force-delete failed: {_dns_decode_error(e2)}")
                return
            print("[*] Recreating zone...")
            try:
                _zone_create(dce, args)
            except DCERPCException as e2:
                print(f"[-] Recreate failed: {_dns_decode_error(e2)}")
                return
        else:
            return

    print("[+] FORWARDER CREATED")
    print(f"[+] Conditional forwarder: {args.zone} -> {', '.join(args.master)}")
    print("\n[*] Current forwarder state:")
    try:
        show_forwarders(dce, args)
    except Exception as e:
        print(f"[!] post-create listing failed: {_dns_decode_error(e)}")


def cmd_forwarder_list(args: Namespace) -> None:
    dce = dns_connect(args)
    try:
        print(f"[*] Enumerating DNS zones on {args.dc} ...")
        show_forwarders(dce, args)
    finally:
        dce.disconnect()


def cmd_forwarder_delete(args: Namespace) -> None:
    dce = dns_connect(args)
    try:
        if args.all:
            names = [z["pszZoneName"] for z in enum_zones(dce, args) if z["ZoneType"] == DNS_ZONE_TYPE_FORWARDER]
            if not names:
                print("[*] No forwarder zones to delete")
                return
            for name in names:
                print(f"[*] Deleting forwarder zone {name}")
                _op2(dce, args, name, "DeleteZone", DNSSRV_TYPEID_NULL, "Null", NULL)
                print("[+] Deleted")
        else:
            print(f"[*] Deleting forwarder zone {args.zone}")
            _op2(dce, args, args.zone, "DeleteZone", DNSSRV_TYPEID_NULL, "Null", NULL)
            print("[+] Deleted")
    finally:
        dce.disconnect()
