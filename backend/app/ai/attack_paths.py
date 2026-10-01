"""Attack-path analysis: from isolated findings to adversary scenarios.

A finding says "credentials crossed port 25 in cleartext". An incident
responder needs the scenario that finding belongs to: *who* could exploit it,
*how*, and *what they gain*. This module correlates findings into a small
library of email-interception scenarios, each mapped to MITRE ATT&CK, and
scores how strongly the capture supports each one.

Scoring is evidence-weighted and fully explainable:

    likelihood = 1 - prod(1 - w_i * c_i)      (noisy-OR over observed indicators)

where w_i is the indicator's diagnostic weight in the scenario and c_i the
confidence of the finding that evidences it. Indicators that are *required*
gate the scenario: without them it is not reported. Impact is fixed per
scenario (what the adversary obtains); exposure is the share of observed
sessions that carry the scenario's evidence. The ranking score combines the
three. Every number is shown with the indicators behind it.

This is correlation over deterministic findings. It states which scenarios
the evidence is *consistent with*; it never claims an attack took place.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from app.models.finding import Finding
from app.models.session import EmailSession

ATTACK = {
    "T1557": ("Adversary-in-the-Middle", "https://attack.mitre.org/techniques/T1557/"),
    "T1040": ("Network Sniffing", "https://attack.mitre.org/techniques/T1040/"),
    "T1552": ("Unsecured Credentials", "https://attack.mitre.org/techniques/T1552/"),
    "T1552.004": ("Unsecured Credentials: Private Keys", "https://attack.mitre.org/techniques/T1552/004/"),
    "T1078": ("Valid Accounts", "https://attack.mitre.org/techniques/T1078/"),
    "T1114.002": ("Email Collection: Remote Email Collection", "https://attack.mitre.org/techniques/T1114/002/"),
    "T1562.010": ("Impair Defenses: Downgrade Attack", "https://attack.mitre.org/techniques/T1562/010/"),
    "T1588.004": ("Obtain Capabilities: Digital Certificates", "https://attack.mitre.org/techniques/T1588/004/"),
    "T1573": ("Encrypted Channel", "https://attack.mitre.org/techniques/T1573/"),
}


@dataclass
class Indicator:
    categories: set[str]
    weight: float
    label: str
    required: bool = False


@dataclass
class Scenario:
    key: str
    title: str
    summary: str
    impact: float                      # 0..1, what the adversary gains
    impact_label: str
    indicators: list[Indicator]
    stages: list[tuple[str, str, list[str]]]   # (stage, description, ATT&CK ids)
    same_session: bool = False         # indicators must co-occur in one session
    mitigations: list[str] = field(default_factory=list)


SCENARIOS: list[Scenario] = [
    Scenario(
        key="strip_and_harvest",
        title="Credential interception via STARTTLS stripping",
        summary=(
            "An on-path adversary removes the STARTTLS capability from the server's reply, the "
            "client continues in cleartext, and authentication credentials are captured."
        ),
        impact=1.0,
        impact_label="Account takeover",
        indicators=[
            Indicator({"starttls_stripping"}, 0.9, "STARTTLS capability altered in transit", required=True),
            Indicator({"cleartext_credential_exposure"}, 0.8, "Credentials sent after the downgrade"),
            Indicator({"cleartext_mail_transaction"}, 0.4, "Message content sent in cleartext"),
            Indicator({"mta_sts_not_published", "dane_not_deployed"}, 0.3, "No MTA-STS/DANE policy to force TLS"),
        ],
        stages=[
            ("Position", "Gain an on-path position between client and mail server", ["T1557"]),
            ("Downgrade", "Rewrite the EHLO response so STARTTLS is not offered", ["T1562.010", "T1557"]),
            ("Collect", "Read AUTH exchange and message content from the cleartext session", ["T1040", "T1552"]),
            ("Exploit", "Reuse harvested credentials against mailboxes", ["T1078", "T1114.002"]),
        ],
        mitigations=["deploy_mta_sts_dane", "enforce_tls"],
    ),
    Scenario(
        key="passive_harvest",
        title="Passive credential harvesting",
        summary=(
            "Credentials are transmitted before TLS is established, so anyone able to observe the "
            "network path can collect them without interfering with the traffic."
        ),
        impact=0.95,
        impact_label="Account takeover",
        indicators=[
            Indicator({"cleartext_credential_exposure"}, 0.9, "AUTH / LOGIN / USER-PASS in cleartext", required=True),
            Indicator({"starttls_advertised_not_used"}, 0.4, "TLS was offered but not used"),
            Indicator({"starttls_not_advertised"}, 0.4, "Server does not offer TLS"),
            Indicator({"starttls_downgrade_fallback"}, 0.6, "Client fell back to cleartext after a failed upgrade"),
        ],
        stages=[
            ("Observe", "Capture traffic on any segment between client and server", ["T1040"]),
            ("Collect", "Decode AUTH LOGIN / PLAIN, IMAP LOGIN or POP3 USER/PASS", ["T1552"]),
            ("Exploit", "Log in with the recovered credentials", ["T1078", "T1114.002"]),
        ],
        mitigations=["enforce_tls"],
    ),
    Scenario(
        key="content_interception",
        title="Message content interception",
        summary="Message bodies and mailbox data traverse the network unencrypted and can be read or copied in transit.",
        impact=0.8,
        impact_label="Disclosure of message content",
        indicators=[
            Indicator({"cleartext_mail_transaction"}, 0.85, "Mail data transferred without TLS", required=True),
            Indicator({"starttls_advertised_not_used", "starttls_not_advertised"}, 0.4, "No TLS upgrade on the session"),
            Indicator({"mta_sts_policy_violation"}, 0.6, "Published MTA-STS policy was not honoured"),
        ],
        stages=[
            ("Observe", "Capture traffic on the path", ["T1040"]),
            ("Collect", "Reassemble DATA / FETCH / RETR payloads", ["T1114.002"]),
        ],
        mitigations=["enforce_tls", "deploy_mta_sts_dane"],
    ),
    Scenario(
        key="impersonation",
        title="Server impersonation through certificate weakness",
        summary=(
            "Clients that accept this server's invalid certificate will also accept an attacker's, "
            "allowing a man-in-the-middle to terminate TLS and read or alter mail."
        ),
        impact=0.85,
        impact_label="Interception of encrypted sessions",
        indicators=[
            Indicator({"certificate_expired", "certificate_not_yet_valid"}, 0.6, "Certificate outside its validity period", required=False),
            Indicator({"certificate_self_signed"}, 0.6, "Self-signed certificate in use"),
            Indicator({"certificate_hostname_mismatch"}, 0.7, "Certificate does not match the server name"),
            Indicator({"certificate_chain_invalid"}, 0.8, "Chain signatures do not verify"),
            Indicator({"certificate_weak_key", "certificate_weak_signature"}, 0.5, "Weak key or signature hash"),
        ],
        stages=[
            ("Position", "Intercept connections to the mail server", ["T1557"]),
            ("Impersonate", "Present a forged or self-issued certificate that clients accept", ["T1588.004"]),
            ("Collect", "Decrypt, read and relay the session", ["T1040", "T1114.002"]),
        ],
        mitigations=["renew_certificate", "fix_certificate_chain", "deploy_mta_sts_dane"],
    ),
    Scenario(
        key="protocol_downgrade",
        title="Downgrade to legacy TLS or weak ciphers",
        summary=(
            "The server accepts deprecated protocol versions or weak cipher suites, enabling "
            "version-rollback and cipher attacks against sessions that should be protected."
        ),
        impact=0.6,
        impact_label="Weakened confidentiality",
        indicators=[
            Indicator({"deprecated_tls_version"}, 0.8, "TLS 1.0 / 1.1 negotiated"),
            Indicator({"weak_cipher_suite"}, 0.6, "CBC, 3DES or RC4 cipher negotiated"),
        ],
        stages=[
            ("Position", "Intercept the handshake", ["T1557"]),
            ("Downgrade", "Force the weakest protocol or cipher both sides accept", ["T1562.010"]),
            ("Exploit", "Apply known attacks against the legacy construction", ["T1040"]),
        ],
        mitigations=["disable_legacy_tls", "modern_ciphers"],
    ),
    Scenario(
        key="retrospective_decryption",
        title="Retrospective decryption of recorded traffic",
        summary=(
            "Recorded sessions can be decrypted later: immediately after a server key compromise "
            "where forward secrecy is absent, or by a future quantum computer where key exchange is "
            "classical (harvest now, decrypt later)."
        ),
        impact=0.7,
        impact_label="Delayed disclosure of archived mail",
        indicators=[
            Indicator({"no_forward_secrecy"}, 0.85, "Static RSA key exchange (no forward secrecy)"),
            Indicator({"pqc_server_not_ready"}, 0.5, "Server declines hybrid post-quantum key exchange"),
            Indicator({"__classical_kex"}, 0.35, "All key exchange is classical (quantum-vulnerable)"),
        ],
        stages=[
            ("Record", "Store encrypted traffic today", ["T1040"]),
            ("Acquire", "Obtain the server private key, or wait for a quantum computer", ["T1552.004"]),
            ("Decrypt", "Recover session keys and read archived mail", ["T1114.002"]),
        ],
        mitigations=["modern_ciphers", "enable_hybrid_pqc"],
    ),
]


def _server_of(f: Finding, by_ref: dict[str, EmailSession]) -> str | None:
    ev = f.evidence or {}
    if isinstance(ev.get("server"), str):
        return ev["server"]
    prof = ev.get("server_profile")
    if isinstance(prof, dict) and prof.get("server"):
        return prof["server"]
    s = by_ref.get(f.session_ref or "")
    return f"{s.server_ip}:{s.server_port}" if s else None


def analyse(sessions: list[EmailSession], findings: list[Finding]) -> dict:
    email = [s for s in sessions if s.protocol]
    by_ref = {s.ref: s for s in email}
    fails = [f for f in findings if f.verdict == "FAIL"]
    by_cat: dict[str, list[Finding]] = defaultdict(list)
    for f in fails:
        by_cat[f.category].append(f)

    # Synthetic indicator: every observed TLS session uses classical key exchange.
    tls = [s for s in email if s.tls_version]
    classical = bool(tls) and not any(s.tls_pqc_selected for s in tls)

    results = []
    for sc in SCENARIOS:
        matched = []
        for ind in sc.indicators:
            if "__classical_kex" in ind.categories:
                if classical:
                    matched.append((ind, [], 1.0))
                continue
            hits = [f for c in ind.categories for f in by_cat.get(c, [])]
            if hits:
                matched.append((ind, hits, max(h.confidence for h in hits)))

        if any(ind.required for ind in sc.indicators) and not any(ind.required for ind, _, _ in matched):
            continue
        # A scenario resting only on the weakest background indicator is noise.
        if not matched or all(ind.weight < 0.4 for ind, _, _ in matched):
            continue

        p_none = 1.0
        for ind, _, conf in matched:
            p_none *= 1 - ind.weight * conf
        likelihood = 1 - p_none

        refs = sorted({f.ref for _, hits, _ in matched for f in hits})
        sess = sorted({f.session_ref for _, hits, _ in matched for f in hits if f.session_ref})
        if not sess and "__classical_kex" in {c for ind, _, _ in matched for c in ind.categories}:
            sess = sorted(s.ref for s in tls)
        servers = sorted({srv for _, hits, _ in matched for f in hits if (srv := _server_of(f, by_ref))})
        exposure = len(sess) / len(email) if email else 0.0
        score = round(100 * likelihood * (0.65 * sc.impact + 0.35 * min(1.0, exposure * 2)), 1)

        results.append({
            "key": sc.key,
            "title": sc.title,
            "summary": sc.summary,
            "likelihood": round(likelihood, 3),
            "impact": sc.impact,
            "impact_label": sc.impact_label,
            "exposure_pct": round(100 * exposure, 1),
            "score": score,
            "level": "High" if score >= 60 else "Elevated" if score >= 35 else "Low",
            "indicators": [
                {
                    "label": ind.label,
                    "weight": ind.weight,
                    "observed": any(ind is m[0] for m in matched),
                    "required": ind.required,
                    "findings": [f.ref for m in matched if m[0] is ind for f in m[1]],
                    "contribution": round(ind.weight * next((m[2] for m in matched if m[0] is ind), 0), 3),
                }
                for ind in sc.indicators
            ],
            "stages": [
                {
                    "stage": st,
                    "description": desc,
                    "techniques": [{"id": t, "name": ATTACK[t][0], "url": ATTACK[t][1]} for t in techs],
                }
                for st, desc, techs in sc.stages
            ],
            "finding_refs": refs,
            "sessions": sess[:25],
            "servers": servers,
            "mitigations": sc.mitigations,
        })

    results.sort(key=lambda r: -r["score"])
    techniques = sorted(
        {t["id"] for r in results for st in r["stages"] for t in st["techniques"]},
    )
    return {
        "scenarios": results,
        "techniques": [{"id": t, "name": ATTACK[t][0], "url": ATTACK[t][1]} for t in techniques],
        "method": (
            "Findings are correlated into scenarios by indicator matching. Likelihood is a noisy-OR "
            "over observed indicators weighted by diagnostic strength and finding confidence; score "
            "= 100 × likelihood × (0.65 × impact + 0.35 × exposure). Scenarios describe what the "
            "evidence is consistent with, not a confirmed attack."
        ),
    }
