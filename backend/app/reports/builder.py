"""Assemble the full report payload once, render it in several formats.

Both the JSON export and the HTML report read from this single structure, so
the machine-readable output and the human-readable one can never drift apart
and disagree about what was found.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.analytics import graph, starttls
from app.analytics.priority import prioritise
from app.ml import risk as ml_risk
from app.dnsx import audit as dns_audit
from app.pqc.readiness import assess as assess_pqc
from app.engines.tshark import extract_dns
from app.models import Capture, EmailSession, Finding
from app.posture import build_fingerprints, compute
from app.pqc import build as build_cbom
from app.remediation.planner import plan as remediation_plan

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Stated in every report. These are the boundaries of what passive analysis can
# establish, and a report that omits them overstates its own authority.
LIMITATIONS = [
    "The assessment is passive. It is based solely on the evidence item; no mail server was "
    "contacted, scanned or probed.",
    "TLS application data was not decrypted. Message content was not examined; the analysis "
    "covers handshakes, certificates, protocol dialogue and flow behaviour.",
    "TLS 1.3 encrypts the Certificate message (RFC 8446 §4.4.2). Certificates in TLS 1.3 "
    "sessions cannot be examined without session keys; certificate coverage is reduced accordingly.",
    "Certificate chain signatures are verified from the captured data. Trust anchoring uses the "
    "public (Mozilla) root store and any configured enterprise roots; a chain ending at a root "
    "outside these stores is reported as an untrusted anchor rather than as invalid.",
    "The evidence represents a partial view of the environment. Sessions that were not fully "
    "captured are reported as undetermined and excluded from scoring.",
    "Anomaly scores and risk classes are statistical indicators used for prioritisation. They are "
    "not evidence of an attack, and no finding in this report depends on them.",
    "Projected scores in the remediation plan are obtained by re-evaluating the captured sessions "
    "as though each change had been in place. They must be confirmed by verification and re-capture.",
    "The posture score is the method described in Appendix B, with weights defined in the "
    "assessment policy. It is not an industry certification.",
    "Where DNS traffic is absent from the evidence, email security policy (MTA-STS, DANE, DMARC) "
    "is reported as not assessed, which does not indicate that the policy is absent.",
]


def starttls_summary(session: EmailSession) -> str:
    """One-line account of how this session's upgrade attempt went.

    The encryption state alone says where a session ended up; this says how it
    got there, which is usually the actionable part. "advertised → not used" is
    a client problem; "not advertised" is a server problem; "mangled" is a
    network problem. Same cleartext outcome, three different fixes.
    """
    state = session.encryption_state

    if state == "IMPLICIT_TLS":
        return "implicit TLS — no plaintext phase"
    if state == "TRUNCATED":
        return "not observed — capture incomplete"
    if session.upgrade_advertised_mangled:
        return "capability mangled in transit → cleartext"
    if state == "STARTTLS_NOT_ADVERTISED":
        return "not advertised by server → cleartext"
    if state == "STARTTLS_REJECTED":
        return "requested → rejected by server"
    if state == "PLAINTEXT_AFTER_FAILURE":
        return "requested → rejected → cleartext anyway"
    if state == "STARTTLS_NEGOTIATION_FAILED":
        if session.upgrade_requested:
            return "advertised → requested → negotiation failed"
        return "negotiation began → never completed"
    if state == "STARTTLS_ADVERTISED_NOT_USED":
        return "advertised → client never requested it"
    if state == "TLS_ESTABLISHED":
        if session.upgrade_requested:
            return "advertised → requested → established"
        return "established"
    if state == "PLAINTEXT_THROUGHOUT":
        return "never attempted"
    return state.replace("_", " ").lower()


def timeline(session: EmailSession) -> list[dict]:
    """Compact state transitions with the frame that caused each one."""
    return [
        {
            "state": t.get("to", "").replace("_", " ").lower(),
            "frame": t.get("frame"),
            "trigger": t.get("trigger"),
        }
        for t in (session.state_transitions or [])
    ]


def _starttls_section(sessions: list[EmailSession]) -> dict:
    data = starttls.analyse(sessions)
    return {
        "summary": data["summary"],
        "funnel": data["funnel"],
        "failure_points": [
            {k: f[k] for k in ("key", "label", "owner", "severity", "count", "pct", "servers", "explanation")}
            for f in data["failure_points"]
        ],
    }


def build(
    capture: Capture,
    sessions: list[EmailSession],
    findings: list[Finding],
    *,
    include_dns: bool = True,
) -> dict:
    posture = compute(sessions, findings)
    fingerprints = build_fingerprints(sessions)

    dns = None
    if include_dns:
        try:
            dns = dns_audit(extract_dns(Path(capture.stored_path))).serialise()
        except Exception:  # noqa: BLE001 - a report must render without DNS
            dns = None

    tls_sessions = [s for s in sessions if s.tls_version]
    cert_observable = sum(1 for s in tls_sessions if s.cert_observable)

    dependency = graph.build(sessions, findings)
    ranked = prioritise(findings, sessions, dependency["blast_radius"])
    risk_results = {
        s.ref: ml_risk.RiskResult(session_ref=s.ref, risk_class=s.risk_class,
                                  confidence=s.risk_confidence or 0, score=s.risk_score or 0,
                                  probabilities={})
        for s in sessions if s.risk_class
    }
    try:
        plan = remediation_plan(capture, sessions, findings)
    except Exception:  # noqa: BLE001 - a report must render without the plan
        plan = None

    return {
        "report": {
            "title": "Email Cryptographic Security Posture Assessment",
            "report_id": f"SMS-{capture.ref}-{datetime.now(timezone.utc):%Y%m%d}",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "SecureMailScope 0.1.0",
            "problem_statement": "SIH26159 — NTRO",
            "classification": "CONFIDENTIAL — contains network evidence",
            "analysis_type": "Passive packet-capture analysis",
        },
        "evidence": {
            "capture_ref": capture.ref,
            "filename": capture.original_filename,
            "sha256": capture.sha256,
            "size_bytes": capture.size_bytes,
            "format": capture.container_format,
            "packet_count": capture.packet_count,
            "first_packet_at": capture.first_packet_at.isoformat() if capture.first_packet_at else None,
            "last_packet_at": capture.last_packet_at.isoformat() if capture.last_packet_at else None,
            "duration_seconds": capture.duration_seconds,
            "snaplen": capture.snaplen,
            "snaplen_truncated": capture.snaplen_truncated,
            "uploaded_at": capture.uploaded_at.isoformat() if capture.uploaded_at else None,
        },
        "posture": posture.serialise(),
        "summary": {
            "sessions": len(sessions),
            "by_protocol": dict(Counter(s.protocol for s in sessions if s.protocol)),
            "by_encryption_state": dict(Counter(s.encryption_state for s in sessions)),
            "indeterminate": sum(1 for s in sessions if s.is_indeterminate),
            "findings": len(findings),
            "by_severity": dict(Counter(f.severity for f in findings)),
            "unknown_verdicts": sum(1 for f in findings if f.verdict == "UNKNOWN"),
        },
        "coverage": {
            "tls_sessions": len(tls_sessions),
            "certificate_observable": cert_observable,
            "certificate_coverage_pct": (
                round(100 * cert_observable / len(tls_sessions), 1) if tls_sessions else None
            ),
            "sessions_fully_observed": sum(1 for s in sessions if s.session_complete),
        },
        "findings": [
            {
                "ref": f.ref,
                "severity": f.severity,
                "category": f.category,
                "verdict": f.verdict,
                "confidence": f.confidence,
                "detection_method": f.detection_method,
                "title": f.title,
                "description": f.description,
                "rationale": f.rationale,
                "recommendation": f.recommendation,
                "standards": f.standard_refs or [],
                "session_ref": f.session_ref,
                "evidence": f.evidence,
                "evidence_frames": f.evidence_frames or [],
                "wireshark_filter": f.wireshark_filter,
                "affected_sessions": f.affected_sessions,
            }
            for f in sorted(findings, key=lambda x: (x.severity_rank, x.first_frame or 0))
        ],
        "sessions": [
            {
                "ref": s.ref,
                "protocol": s.protocol,
                "client": f"{s.client_ip}:{s.client_port}",
                "server": f"{s.server_ip}:{s.server_port}",
                "encryption_state": s.encryption_state,
                "starttls": starttls_summary(s),
                "timeline": timeline(s),
                "tls_version": s.tls_version,
                "cipher_suite": s.tls_cipher_suite,
                "forward_secrecy": s.tls_forward_secrecy,
                "selected_group": s.tls_selected_group,
                "ja4": s.tls_ja4,
                "ja4s": s.tls_ja4s,
                "cert_observable": s.cert_observable,
                "indeterminate": s.is_indeterminate,
                "anomaly_score": s.anomaly_score,
                "baseline_deviations": s.baseline_deviations or [],
                "frames": [s.first_frame, s.last_frame],
                "wireshark_filter": s.wireshark_filter,
            }
            for s in sessions
        ],
        "servers": [f.serialise() for f in fingerprints.values()],
        "dns_policy": dns,
        "pqc": build_cbom(capture, sessions)["securemailscope"],
        "pqc_readiness": assess_pqc(sessions),
        "starttls": _starttls_section(sessions),
        "blast_radius": [r for r in dependency["blast_radius"] if r["kind"] == "finding"][:6],
        "ai_risk": {
            "index": ml_risk.capture_index(risk_results),
            "model": {k: v for k, v in ml_risk.model_card().items()
                      if k in ("name", "algorithm", "training_rows", "evaluation", "available", "limitations")},
            "sessions": sorted(
                ({"ref": s.ref, "server": f"{s.server_ip}:{s.server_port}", **(s.risk_detail or {})}
                 for s in sessions if s.risk_detail),
                key=lambda r: -r.get("score", 0),
            )[:12],
        },
        "priorities": [
            {k: r[k] for k in ("rank", "ref", "title", "severity", "priority", "tier", "tier_label", "factors")}
            for r in ranked if r["verdict"] == "FAIL"
        ][:12],
        "remediation": None if plan is None else {
            "baseline": plan["baseline"],
            "target": plan["target"],
            "method": plan["method"],
            "steps": [
                {k: st[k] for k in ("step", "title", "owner", "effort", "servers", "score_before",
                                     "score_after", "findings_after")}
                | {"software": st["software"], "addresses": [a["ref"] for a in st["addresses"]],
                   "snippets": st["playbook"]["snippets"], "verify": st["playbook"]["verify"],
                   "standards": st["playbook"]["standards"]}
                for st in plan["steps"]
            ],
        },
        "certificates": _certificates(sessions),
        "tls_stats": _tls_stats(sessions),
        "limitations": LIMITATIONS,
    }


def _certificates(sessions: list[EmailSession]) -> list[dict]:
    """One row per observed leaf certificate, with its validation outcome."""
    rows = []
    for s in sessions:
        cert = (s.tls_detail or {}).get("certificate") or {}
        if not cert.get("observed") or not cert.get("chain"):
            continue
        leaf = cert["chain"][0]
        issues = [
            label for key, label in (
                ("expired", "expired"), ("not_yet_valid", "not yet valid"),
                ("expiring_soon", "expiring soon"), ("weak_key", "weak key"),
                ("broken_signature", "weak signature hash"), ("self_signed", "self-signed"),
                ("chain_incomplete", "incomplete chain"), ("chain_invalid", "chain signature invalid"),
            ) if cert.get(key)
        ]
        if cert.get("hostname_match") is False:
            issues.append("hostname mismatch")
        rows.append({
            "session": s.ref,
            "server": f"{s.server_ip}:{s.server_port}",
            "subject": leaf.get("subject_cn") or leaf.get("subject"),
            "issuer": leaf.get("issuer_cn") or leaf.get("issuer"),
            "key": f"{leaf.get('public_key_algorithm')} {leaf.get('public_key_bits')}",
            "signature": leaf.get("signature_algorithm"),
            "not_before": (leaf.get("not_before") or "")[:10],
            "not_after": (leaf.get("not_after") or "")[:10],
            "chain_length": cert.get("chain_length"),
            "chain_trust": cert.get("chain_trust"),
            "issues": issues,
        })
    return rows


def _tls_stats(sessions: list[EmailSession]) -> dict:
    tls = [s for s in sessions if s.tls_version]
    suites: dict[str, dict] = {}
    for s in tls:
        if not s.tls_cipher_suite:
            continue
        entry = suites.setdefault(s.tls_cipher_suite, {
            "suite": s.tls_cipher_suite, "sessions": 0, "versions": set(),
            "forward_secrecy": s.tls_forward_secrecy, "aead": s.tls_aead,
            "weaknesses": [w for w in (((s.tls_detail or {}).get("cipher_suite") or {}).get("weaknesses") or [])],
        })
        entry["sessions"] += 1
        entry["versions"].add(s.tls_version)
    email = [s for s in sessions if s.protocol]
    return {
        "email_sessions": len(email),
        "tls_sessions": len(tls),
        "servers": len({(s.server_ip, s.server_port) for s in email}),
        "clients": len({s.client_ip for s in email}),
        "by_version": dict(Counter(s.tls_version for s in tls)),
        "by_group": dict(Counter(s.tls_selected_group or ("RSA key transport" if s.tls_forward_secrecy is False else "not visible") for s in tls)),
        "suites": sorted(
            ({**v, "versions": sorted(v["versions"])} for v in suites.values()),
            key=lambda r: -r["sessions"],
        ),
    }
