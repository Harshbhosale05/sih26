"""Email transport-security policy audit from the DNS in the same capture.

This is the differentiator that costs almost nothing and that nobody else will
build. A capture of real mail traffic contains the lookups that preceded the
SMTP connections, so we can answer questions no single session can:

  * Did the sender even *ask* for an MTA-STS policy (RFC 8461)?
  * Is one published, and in what mode?
  * Is DANE/TLSA deployed for the MX (RFC 7672)?
  * Is TLS-RPT configured (RFC 8460)?
  * Are SPF and DMARC published (NIST SP 800-177r1)?

And then the correlation that makes it a finding rather than a fact:
**did the observed TLS behaviour comply with the policy that was actually
fetched?** A sender that retrieved `mode=enforce` and then transmitted in
cleartext is a provable policy violation.

Honesty rule enforced throughout: no DNS in the capture means "cannot assess",
never "not published". Those are completely different claims.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.engines.tshark import DNSRecord

TYPE_A = 1
TYPE_MX = 15
TYPE_TXT = 16
TYPE_TLSA = 52

_MTA_STS_PREFIX = "_mta-sts."
_TLSRPT_PREFIX = "_smtp._tls."
_DMARC_PREFIX = "_dmarc."
_TLSA_RE = re.compile(r"^_(\d+)\._tcp\.(.+)$")

_STS_VERSION = re.compile(r"v\s*=\s*STSv1", re.IGNORECASE)
_STS_ID = re.compile(r"id\s*=\s*([^;\s]+)", re.IGNORECASE)
_DMARC_POLICY = re.compile(r"\bp\s*=\s*(none|quarantine|reject)", re.IGNORECASE)
_SPF_ALL = re.compile(r"([-~+?])all", re.IGNORECASE)


@dataclass
class DomainPolicy:
    """What DNS told us about one domain's email transport security."""

    domain: str
    mx_hosts: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)

    mta_sts_queried: bool = False
    mta_sts_published: bool | None = None
    mta_sts_id: str | None = None

    tlsrpt_queried: bool = False
    tlsrpt_published: bool | None = None

    dane_queried: bool = False
    dane_published: bool | None = None

    spf_published: bool | None = None
    spf_qualifier: str | None = None

    dmarc_queried: bool = False
    dmarc_published: bool | None = None
    dmarc_policy: str | None = None

    frames: list[int] = field(default_factory=list)

    def serialise(self) -> dict:
        return {
            "domain": self.domain,
            "mx_hosts": self.mx_hosts,
            "resolved_ips": self.resolved_ips,
            "mta_sts": {
                "queried": self.mta_sts_queried,
                "published": self.mta_sts_published,
                "id": self.mta_sts_id,
            },
            "tls_rpt": {"queried": self.tlsrpt_queried, "published": self.tlsrpt_published},
            "dane": {"queried": self.dane_queried, "published": self.dane_published},
            "spf": {"published": self.spf_published, "qualifier": self.spf_qualifier},
            "dmarc": {
                "queried": self.dmarc_queried,
                "published": self.dmarc_published,
                "policy": self.dmarc_policy,
            },
            "frames": sorted(set(self.frames)),
        }


@dataclass
class DNSAudit:
    observed: bool
    total_records: int = 0
    domains: dict[str, DomainPolicy] = field(default_factory=dict)
    # MX hostname / resolved IP -> the domain it serves, so a TLS session can be
    # traced back to the policy that governs it.
    ip_to_domain: dict[str, str] = field(default_factory=dict)

    def serialise(self) -> dict:
        return {
            "observed": self.observed,
            "total_records": self.total_records,
            "domains": [d.serialise() for d in self.domains.values()],
            "note": (
                "Derived from DNS in this same capture. Absence of DNS means the "
                "policy could not be assessed — not that no policy exists."
            ),
        }


def _base_domain(qname: str, prefix: str) -> str:
    return qname[len(prefix):] if qname.startswith(prefix) else qname


def audit(records: list[DNSRecord]) -> DNSAudit:
    result = DNSAudit(observed=bool(records), total_records=len(records))
    if not records:
        return result

    def domain(name: str) -> DomainPolicy:
        return result.domains.setdefault(name, DomainPolicy(domain=name))

    for rec in records:
        name = rec.qname

        # --- MTA-STS (RFC 8461) -----------------------------------------
        if name.startswith(_MTA_STS_PREFIX):
            base = _base_domain(name, _MTA_STS_PREFIX)
            d = domain(base)
            d.frames.append(rec.frame_number)
            if not rec.is_response:
                d.mta_sts_queried = True
                continue
            texts = " ".join(rec.txt)
            if rec.rcode == 0 and _STS_VERSION.search(texts):
                d.mta_sts_published = True
                match = _STS_ID.search(texts)
                d.mta_sts_id = match.group(1) if match else None
            else:
                d.mta_sts_published = False
            continue

        # --- TLS-RPT (RFC 8460) -----------------------------------------
        if name.startswith(_TLSRPT_PREFIX):
            base = _base_domain(name, _TLSRPT_PREFIX)
            d = domain(base)
            d.frames.append(rec.frame_number)
            if not rec.is_response:
                d.tlsrpt_queried = True
            else:
                d.tlsrpt_published = rec.rcode == 0 and any(
                    "v=TLSRPTv1" in t for t in rec.txt
                )
            continue

        # --- DMARC --------------------------------------------------------
        if name.startswith(_DMARC_PREFIX):
            base = _base_domain(name, _DMARC_PREFIX)
            d = domain(base)
            d.frames.append(rec.frame_number)
            if not rec.is_response:
                d.dmarc_queried = True
            else:
                texts = " ".join(rec.txt)
                d.dmarc_published = rec.rcode == 0 and "v=DMARC1" in texts
                match = _DMARC_POLICY.search(texts)
                d.dmarc_policy = match.group(1).lower() if match else None
            continue

        # --- DANE / TLSA (RFC 7672) ---------------------------------------
        tlsa = _TLSA_RE.match(name)
        if tlsa and rec.qtype == TYPE_TLSA:
            host = tlsa.group(2)
            # TLSA is published for the MX host; attribute it to every domain
            # whose MX we have seen pointing there.
            for d in result.domains.values():
                if host in d.mx_hosts:
                    d.frames.append(rec.frame_number)
                    if not rec.is_response:
                        d.dane_queried = True
                    else:
                        d.dane_published = rec.rcode == 0 and rec.answer_count > 0
            continue

        # --- MX -----------------------------------------------------------
        if rec.qtype == TYPE_MX:
            d = domain(name)
            d.frames.append(rec.frame_number)
            if rec.is_response:
                for host in rec.mx:
                    host = host.lower().rstrip(".")
                    if host and host not in d.mx_hosts:
                        d.mx_hosts.append(host)
            continue

        # --- TXT at the apex: SPF ------------------------------------------
        if rec.qtype == TYPE_TXT and rec.is_response:
            texts = " ".join(rec.txt)
            if "v=spf1" in texts.lower():
                d = domain(name)
                d.frames.append(rec.frame_number)
                d.spf_published = True
                match = _SPF_ALL.search(texts)
                d.spf_qualifier = match.group(1) if match else None
            continue

        # --- A records: map MX hostnames to the IPs sessions connect to -----
        if rec.qtype == TYPE_A and rec.is_response:
            for d in result.domains.values():
                if name in d.mx_hosts:
                    for ip in rec.addresses:
                        if ip not in d.resolved_ips:
                            d.resolved_ips.append(ip)
                        result.ip_to_domain[ip] = d.domain
                    d.frames.append(rec.frame_number)

    return result
