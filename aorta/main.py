import argparse
from argparse import Namespace
from typing import Any

from aorta.forwarder import cmd_forwarder_add, cmd_forwarder_delete, cmd_forwarder_list
from aorta.trust import cmd_trust_add, cmd_trust_delete, cmd_trust_list


def add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-u", "--user", required=True, help="username")
    p.add_argument("-d", "--domain", required=True, help="domain (FQDN)")
    p.add_argument("--dc", required=True, help="DC target (IP for NTLM; FQDN recommended for Kerberos)")
    p.add_argument("--kdc", default=None, help="KDC host for Kerberos auth (default: --dc)")
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("-p", "--password", help="plaintext password")
    auth.add_argument("--hashes", help="NTLM hashes LM:NTH (e.g. :8ba3...)")
    auth.add_argument("--aes", help="AES key (128/256) - Kerberos")
    auth.add_argument("--ccache", help="Kerberos ccache file path")
    p.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="use Kerberos with -p/--hashes (implied by --aes/--ccache)",
    )


def _add_trust_subparsers(group: Any) -> None:
    p_list = group.add_parser("list", help="enumerate and display trusts")
    add_common_args(p_list)

    p_add = group.add_parser("add", help="create the AORTA inbound forest trust")
    add_common_args(p_add)
    p_add.add_argument("--attacker-domain", required=True, help="attacker forest FQDN")
    p_add.add_argument("--attacker-netbios", required=True, help="attacker NetBIOS name")
    p_add.add_argument("--attacker-sid", required=True, help="attacker domain SID")
    p_add.add_argument(
        "--trust-password", required=True, help="trust password (must match attacker-side outgoing trust)"
    )
    p_add.add_argument(
        "--force", action="store_true", help="if a trust with the same SID exists, delete and recreate it"
    )

    p_del = group.add_parser("delete", help="delete a trust")
    add_common_args(p_del)
    tgt = p_del.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--sid", help="SID of the trust to delete")
    tgt.add_argument("--all", action="store_true", help="delete every trust")


def _add_forwarder_subparsers(group: Any) -> None:
    p_list = group.add_parser("list", help="list DNS zones (highlighting forwarders)")
    add_common_args(p_list)

    p_add = group.add_parser("add", help="create a DNS conditional forwarder zone")
    add_common_args(p_add)
    p_add.add_argument("--zone", required=True, help="zone FQDN to forward (e.g. bytestorm.local)")
    p_add.add_argument(
        "--master", required=True, action="append", metavar="IP", help="master/forwarder IP (repeatable)"
    )
    p_add.add_argument("--forwarder-timeout", type=int, default=5, help="forwarder timeout in seconds (default 5)")
    p_add.add_argument(
        "--no-recursion",
        dest="use_recursion",
        action="store_false",
        default=True,
        help="do not recurse after forwarding (default: recurse)",
    )
    p_add.add_argument("--force", action="store_true", help="if the zone already exists, delete and recreate it")

    p_del = group.add_parser("delete", help="delete a forwarder zone")
    add_common_args(p_del)
    tgt = p_del.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--zone", help="zone to delete")
    tgt.add_argument("--all", action="store_true", help="delete every forwarder zone")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aorta",
        description="AORTA — Account Operators Replicating Trust Attack tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    top = parser.add_subparsers(dest="group", required=True, metavar="{trust,forwarder}")

    trust = top.add_parser("trust", help="forest trust (LSARPC) commands")
    trust_cmds = trust.add_subparsers(dest="cmd", required=True, metavar="{add,list,delete}")
    _add_trust_subparsers(trust_cmds)

    fwd = top.add_parser("forwarder", help="DNS conditional forwarder (MS-DNSP) commands")
    fwd_cmds = fwd.add_subparsers(dest="cmd", required=True, metavar="{add,list,delete}")
    _add_forwarder_subparsers(fwd_cmds)

    return parser


TRUST_DISPATCH: dict[str, Any] = {
    "list": cmd_trust_list,
    "add": cmd_trust_add,
    "delete": cmd_trust_delete,
}
FORWARDER_DISPATCH: dict[str, Any] = {
    "list": cmd_forwarder_list,
    "add": cmd_forwarder_add,
    "delete": cmd_forwarder_delete,
}


def main() -> None:
    args: Namespace = build_parser().parse_args()
    if args.kdc is None:
        args.kdc = args.dc
    if args.group == "trust":
        TRUST_DISPATCH[args.cmd](args)
    else:
        FORWARDER_DISPATCH[args.cmd](args)
