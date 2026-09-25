"""Findings from correlating DNS policy against what the sessions actually did.

Single-session analysis can say "this went in cleartext". Only correlation with
the DNS in the same capture can say "this went in cleartext *after the sender
fetched a policy that forbids it*" -- which is a provable violation rather than
an observation, and is what makes it actionable.
"""

from __future__ import annotations

from app.detection.engine import VERDICT_UNKNOWN, DraftFinding
from app.dnsx.policy import DNSAudit, DomainPolicy
from app.models.session import EmailSession
from app.protocols import CLEARTEXT_STATES

_CLEARTEXT = {s.value for s in CLEARTEXT_STATES}


def _sessions_for(policy: DomainPolicy, sessions: list[EmailSession]) -> list[EmailSession]:
    """Sessions whose server IP resolves to one of this domain's MX hosts."""
    return [s for s in sessions if s.server_ip in policy.resolved_ips]


def detect(audit: DNSAudit, sessions: list[EmailSession]) -> list[DraftFinding]:
    if not audit.observed:
        # Say nothing at all. A capture with no DNS supports no DNS conclusion,
        # and emitting "policy not published" here would be a fabrication.
        return []

    drafts: list[DraftFinding] = []

    for policy in audit.domains.values():
        related = _sessions_for(policy, sessions)
        cleartext = [
            s for s in related
            if s.encryption_state in _CLEARTEXT and not s.is_indeterminate
        ]
        frames = sorted(set(policy.frames))[:6]
        server_list = sorted({f"{s.server_ip}:{s.server_port}" for s in related})

        # --- The headline: policy fetched, policy ignored -------------------
        if policy.mta_sts_published and cleartext:
            drafts.append(
                DraftFinding(
                    category="mta_sts_policy_violation",
                    session_ref=cleartext[0].ref,
                    session_id=cleartext[0].id,
                    description=(
                        f"{policy.domain} publishes an MTA-STS policy and the sender "
                        f"retrieved it, yet {len(cleartext)} session(s) to its mail "
                        "servers carried data without TLS."
                    ),
                    rationale=(
                        "MTA-STS (RFC 8461) exists precisely to stop cleartext delivery "
                        "and downgrade attacks. A sender that fetched the policy and then "
                        "transmitted in the clear either ignored it or was prevented from "
                        "honouring it — the second case is what STARTTLS stripping looks "
                        "like from the DNS side."
                    ),
                    evidence={
                        "domain": policy.domain,
                        "mta_sts_id": policy.mta_sts_id,
                        "mx_hosts": policy.mx_hosts,
                        "cleartext_sessions": [s.ref for s in cleartext],
                        "servers": server_list,
                    },
                    evidence_frames=frames + [cleartext[0].first_frame],
                    wireshark_filter=cleartext[0].wireshark_filter,
                    affected_sessions=len(cleartext),
                )
            )

        # --- Policy absent entirely ----------------------------------------
        elif policy.mta_sts_queried and policy.mta_sts_published is False:
            drafts.append(
                DraftFinding(
                    category="mta_sts_not_published",
                    session_ref=related[0].ref if related else None,
                    session_id=related[0].id if related else None,
                    description=(
                        f"{policy.domain} does not publish an MTA-STS policy. A sender "
                        "queried for one and received no valid record."
                    ),
                    rationale=(
                        "Without MTA-STS (RFC 8461) or DANE (RFC 7672), a sending MTA has "
                        "no way to know that TLS is required, so an on-path attacker can "
                        "strip STARTTLS and the message is delivered in cleartext with no "
                        "error visible to either party."
                    ),
                    evidence={
                        "domain": policy.domain,
                        "mx_hosts": policy.mx_hosts,
                        "dane_published": policy.dane_published,
                        "servers": server_list,
                    },
                    evidence_frames=frames,
                    wireshark_filter=related[0].wireshark_filter if related else None,
                )
            )

        # --- DANE ------------------------------------------------------------
        if policy.mx_hosts and policy.dane_published is False:
            drafts.append(
                DraftFinding(
                    category="dane_not_deployed",
                    session_ref=None,
                    session_id=None,
                    description=(
                        f"No DANE/TLSA record is published for the mail servers of "
                        f"{policy.domain}."
                    ),
                    rationale=(
                        "DANE (RFC 7672) binds the server's certificate to DNSSEC, giving "
                        "a sender a cryptographic reason to refuse a downgrade. It "
                        "complements MTA-STS rather than replacing it."
                    ),
                    evidence={"domain": policy.domain, "mx_hosts": policy.mx_hosts},
                    evidence_frames=frames,
                )
            )

        # --- Reporting -------------------------------------------------------
        if policy.tlsrpt_queried and policy.tlsrpt_published is False:
            drafts.append(
                DraftFinding(
                    category="tlsrpt_not_configured",
                    session_ref=None,
                    session_id=None,
                    description=f"{policy.domain} has no TLS-RPT reporting address configured.",
                    rationale=(
                        "TLS-RPT (RFC 8460) is how an operator learns that senders are "
                        "failing to establish TLS. Without it, the stripping and downgrade "
                        "problems this report identifies would never have been noticed."
                    ),
                    evidence={"domain": policy.domain},
                    evidence_frames=frames,
                )
            )

        # --- Authentication --------------------------------------------------
        if policy.dmarc_queried and policy.dmarc_published is False:
            drafts.append(
                DraftFinding(
                    category="dmarc_not_published",
                    session_ref=None,
                    session_id=None,
                    description=f"{policy.domain} does not publish a DMARC policy.",
                    rationale=(
                        "DMARC is the enforcement layer over SPF and DKIM (NIST SP "
                        "800-177r1). Without it, a receiver has no instruction on what to "
                        "do when authentication fails."
                    ),
                    evidence={"domain": policy.domain, "spf_published": policy.spf_published},
                    evidence_frames=frames,
                )
            )
        elif policy.dmarc_published and policy.dmarc_policy == "none":
            drafts.append(
                DraftFinding(
                    category="dmarc_policy_none",
                    session_ref=None,
                    session_id=None,
                    description=f"{policy.domain} publishes DMARC with p=none (monitor only).",
                    rationale=(
                        "p=none collects reports but instructs receivers to take no action "
                        "on failures, so it provides no protection against spoofing."
                    ),
                    evidence={"domain": policy.domain, "dmarc_policy": policy.dmarc_policy},
                    evidence_frames=frames,
                )
            )

        # --- Sessions we could not attribute ---------------------------------
        if policy.mx_hosts and not policy.resolved_ips:
            drafts.append(
                DraftFinding(
                    category="dns_correlation_incomplete",
                    session_ref=None,
                    session_id=None,
                    description=(
                        f"MX records for {policy.domain} were observed but their addresses "
                        "were not, so sessions could not be attributed to this domain's policy."
                    ),
                    rationale=(
                        "The capture contains the MX lookup but not the subsequent A/AAAA "
                        "resolution, so policy compliance for this domain is undetermined."
                    ),
                    verdict=VERDICT_UNKNOWN,
                    evidence={"domain": policy.domain, "mx_hosts": policy.mx_hosts},
                    evidence_frames=frames,
                )
            )

    return drafts
