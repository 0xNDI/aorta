import os
from argparse import Namespace
from typing import Any

from impacket.dcerpc.v5 import epm, lsad, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.uuid import uuidtup_to_bin

# NOTE: this is the BINARY (uuid, version) form. impacket's DCERPC.bind() writes
# iface_uuid straight into the bind PDU's AbstractSyntax, so a string tuple would
# be zeroed out and every bind would fail with abstract_syntax_not_supported.
MSRPC_UUID_DNSSERVER = uuidtup_to_bin(("50abc2a4-574d-40b3-9d66-ee4fd5fba076", "5.0"))

POLICY_ACCESS = 0x02000000


def _set_creds(rpctransport: Any, args: Namespace) -> Any:
    do_kerberos = args.aes is not None or args.ccache is not None or args.kerberos
    if args.aes is not None:
        rpctransport.set_credentials(args.user, "", args.domain, aesKey=args.aes)
    elif args.ccache is not None:
        os.environ["KRB5CCNAME"] = args.ccache
        rpctransport.set_credentials(args.user, "", args.domain)
    elif args.password is not None:
        rpctransport.set_credentials(args.user, args.password, args.domain)
    elif args.hashes is not None:
        lm, nt = args.hashes.split(":", 1) if ":" in args.hashes else ("", args.hashes)
        rpctransport.set_credentials(args.user, "", args.domain, lmhash=lm, nthash=nt)
    else:  # pragma: no cover
        raise ValueError("no auth method selected")
    if do_kerberos:
        rpctransport.set_kerberos(True, args.kdc)
    return rpctransport


def build_transport(args: Namespace, pipe: str = r"\PIPE\lsarpc") -> Any:
    rpctransport = transport.DCERPCTransportFactory(f"ncacn_np:{args.dc}[{pipe}]")
    return _set_creds(rpctransport, args)


def connect(args: Namespace) -> tuple[Any, Any]:
    # Connect to LSARPC over SMB and open the LSA policy handle.
    dce = build_transport(args, r"\PIPE\lsarpc").get_dce_rpc()
    dce.connect()
    dce.bind(lsad.MSRPC_UUID_LSAD)
    policy_handle = lsad.hLsarOpenPolicy2(dce, POLICY_ACCESS)["PolicyHandle"]
    return dce, policy_handle


def dns_connect(args: Namespace) -> Any:
    # MS-DNSP lives on ncacn_ip_tcp at a dynamic port; resolve it via the endpoint
    # mapper (TCP:135) and bind with packet privacy (MS-DNSP needs >= integrity).
    # For Kerberos modes the auth type MUST be GSS_NEGOTIATE: impacket's TCP
    # transport defaults to NTLM, whose bind_ack still arrives but whose context
    # then fails at AUTH3 and the first call dies with rpc_s_access_denied.
    sb = epm.hept_map(args.dc, MSRPC_UUID_DNSSERVER, protocol="ncacn_ip_tcp")
    rpctransport = transport.DCERPCTransportFactory(sb)
    _set_creds(rpctransport, args)
    dce = rpctransport.get_dce_rpc()
    if args.aes is not None or args.ccache is not None or args.kerberos:
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    dce.set_auth_level(6)  # RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    dce.connect()
    dce.bind(MSRPC_UUID_DNSSERVER)
    return dce
