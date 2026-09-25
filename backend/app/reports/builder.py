"""Assemble the full report payload once, render it in several formats.

Both the JSON export and the HTML report read from this single structure, so
the machine-readable output and the human-readable one can never drift apart
and disagree about what was found.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.dnsx import audit as dns_audit
from app.engines.tshark import extract_dns
from app.models import Capture, EmailSession, Finding
from app.posture import build_fingerprints, compute
from app.pqc import build as build_cbom

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Stated in every report. These are the boundaries of what passive analysis can
# establish, and a report that omits them overstates its own authority.
LIMITATIONS = [
    "This is a passive analysis of a packet capture. No mail server was contacted, "
    "scanned or probed at any point.",
    "TLS application data remains encrypted. Message content was never read; the "
    "analysis covers handshakes, certificates, protocol dialogue and flow behaviour.",
    "TLS 1.3 encrypts the Certificate message (RFC 8446 §4.4.2), so certificates "
    "cannot be examined passively in TLS 1.3 sessions without session keys. "
    "Certificate coverage below 100% reflects this, not a server fault.",
    "Certificate chain trust cannot be fully validated without the enterprise trust "
    "store, so chain results are reported as UNKNOWN rather than as failures.",
    "A capture is a partial view. Sessions the capture could not fully observe are "
    "reported as UNKNOWN and excluded from scoring rather than assumed secure.",
    "Anomaly scores indicate deviation from observed norms. They are not evidence of "
    "an attack. Every verdict in this report comes from a deterministic rule.",
    "The posture score is SecureMailScope's own methodology, anchored to the cited "
    "standards, with weights published in policy.json. It is not an industry "
    "certification or rating.",
    "Where DNS was absent from the capture, email policy (MTA-STS, DANE, DMARC) is "
    "reported as not assessable — which is not the same as not published.",
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

    return {
        "report": {
            "title": "Email Cryptographic Security Posture Assessment",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "SecureMailScope 0.1.0",
            "problem_statement": "SIH26159 — NTRO",
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
        "limitations": LIMITATIONS,
    }
