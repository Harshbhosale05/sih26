"""Pipeline orchestration: capture -> flows -> streams -> sessions."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.detection import session_findings, starttls_stripping
from app.detection.cert_rules import session_certificate_findings
from app.detection.tls_rules import session_tls_findings
from app.dnsx import audit as dns_audit
from app.dnsx import detect as dns_detect
from app.engines.tshark import (
    extract_dns,
    extract_payloads,
    index_tcp_packets,
    probe_stream_openings,
)
from app.pqc import readiness_finding
from app.flows import build_stream_pair, index_flows, signature_hint
from app.models import Capture, CaptureStatus, EmailSession, Finding
from app.ml import anomaly as ml_anomaly
from app.posture import build_fingerprints, deviation_score, deviations_for
from app.protocols import EncryptionState, analyse_stream

logger = logging.getLogger(__name__)

# Protocol prefixes for human-facing session refs (SMTP-0001).
_REF_PREFIX = {"SMTP": "SMTP", "IMAP": "IMAP", "POP3": "POP3", None: "FLOW"}


@dataclass
class AnalysisSummary:
    total_packets: int = 0
    total_flows: int = 0
    candidate_flows: int = 0
    sessions: int = 0
    by_protocol: dict = field(default_factory=dict)
    by_state: dict = field(default_factory=dict)
    indeterminate: int = 0
    cleartext_credentials: int = 0
    findings: int = 0
    by_severity: dict = field(default_factory=dict)
    by_category: dict = field(default_factory=dict)
    baseline_deviations: int = 0
    anomalies: int = 0
    anomaly_available: bool = False
    anomaly_reason: str | None = None
    nonstandard_port_flows: int = 0
    dns_records: int = 0
    dns_domains: int = 0


def analyse_capture(db: Session, capture: Capture) -> AnalysisSummary:
    """Run the full Phase 1 pipeline and persist the reconstructed sessions.

    Re-running is idempotent: existing sessions for the capture are deleted
    first. Analysis must be repeatable as detectors improve, and stale rows
    from an older run would corrupt every count downstream.
    """
    pcap = Path(capture.stored_path)
    summary = AnalysisSummary()

    capture.status = CaptureStatus.ANALYZING
    db.commit()

    try:
        db.execute(delete(Finding).where(Finding.capture_id == capture.id))
        db.execute(delete(EmailSession).where(EmailSession.capture_id == capture.id))
        db.commit()

        # Certificate validity is judged against the capture's own clock, not
        # against now: a certificate that expired after the traffic was recorded
        # was not a problem at the time.
        capture_time = capture.first_packet_at or capture.uploaded_at

        # --- Pass 1: index every TCP flow, no payload -----------------------
        packets = index_tcp_packets(pcap)
        summary.total_packets = len(packets)
        flows = index_flows(packets)
        summary.total_flows = len(flows)

        candidates = [f for f in flows.values() if f.is_candidate]

        # --- Pass 1b: probe non-standard ports ------------------------------
        # Port alone would miss an SMTP server listening somewhere unexpected,
        # which is precisely the misconfiguration a posture assessment should
        # report. This reads only the first data segment of each remaining
        # flow, so it stays cheap even on a large capture.
        others = [f for f in flows.values() if not f.is_candidate and f.bytes_s2c > 0]
        if others:
            openings = probe_stream_openings(pcap, [f.stream_index for f in others])
            for flow in others:
                opening = openings.get(flow.stream_index)
                if opening and signature_hint(opening):
                    flow.port_hint = signature_hint(opening)
                    flow.is_candidate = True
                    candidates.append(flow)
                    summary.nonstandard_port_flows += 1

        # --- Pass 2: full payload for candidate flows -----------------------
        payloads = extract_payloads(pcap, [f.stream_index for f in candidates])
        summary.candidate_flows = len(candidates)

        counters: Counter = Counter()
        sessions: list[EmailSession] = []

        for flow in sorted(candidates, key=lambda f: f.first_frame):
            segments = payloads.get(flow.stream_index, [])
            if not segments:
                continue

            pair = build_stream_pair(
                flow.stream_index, segments, flow.client_ip, flow.client_port
            )
            analysis = analyse_stream(pair, flow, capture_time=capture_time)
            if analysis.protocol is None:
                continue

            prefix = _REF_PREFIX.get(analysis.protocol, "FLOW")
            counters[prefix] += 1
            ref = f"{prefix}-{counters[prefix]:04d}"

            enc = analysis.encryption
            state = enc.final_state if enc else EncryptionState.UNKNOWN

            row = EmailSession(
                capture_id=capture.id,
                ref=ref,
                stream_index=analysis.stream_index,
                protocol=analysis.protocol,
                detection_method=analysis.detection_method,
                client_ip=analysis.client_ip,
                client_port=analysis.client_port,
                server_ip=analysis.server_ip,
                server_port=analysis.server_port,
                server_banner=analysis.server_banner,
                encryption_state=state.value,
                state_transitions=[t.serialise() for t in enc.transitions] if enc else [],
                events=[e.serialise() for e in analysis.events],
                upgrade_advertised=enc.upgrade_advertised if enc else False,
                upgrade_advertised_mangled=enc.upgrade_advertised_mangled if enc else False,
                upgrade_requested=enc.upgrade_requested if enc else False,
                upgrade_succeeded=enc.upgrade_succeeded if enc else False,
                tls_established=enc.tls_established if enc else False,
                cleartext_auth_observed=enc.cleartext_auth_observed if enc else False,
                cleartext_mail_observed=enc.cleartext_mail_observed if enc else False,
                has_gaps=analysis.has_gaps,
                session_complete=analysis.session_complete,
                is_indeterminate=enc.is_indeterminate if enc else True,
                **_tls_columns(analysis.tls),
                first_frame=analysis.first_frame,
                last_frame=analysis.last_frame,
                start_time=analysis.start_time,
                end_time=analysis.end_time,
            )
            sessions.append(row)
            db.add(row)

            summary.by_protocol[analysis.protocol] = (
                summary.by_protocol.get(analysis.protocol, 0) + 1
            )
            summary.by_state[state.value] = summary.by_state.get(state.value, 0) + 1
            if row.is_indeterminate:
                summary.indeterminate += 1
            if row.cleartext_auth_observed:
                summary.cleartext_credentials += 1

        summary.sessions = len(sessions)
        db.flush()  # sessions need ids before findings can reference them

        # Behavioural intelligence runs before detection so the stripping
        # detector and the findings list can cite deviation context.
        _run_behavioural_analysis(sessions, summary)

        # DNS lives in the same capture: the lookups that preceded these
        # sessions are what turn "cleartext" into "cleartext in violation of a
        # policy the sender had already fetched".
        audit = dns_audit(extract_dns(pcap))
        summary.dns_records = audit.total_records
        summary.dns_domains = len(audit.domains)

        _run_detection(db, capture, sessions, summary, audit)

        capture.status = CaptureStatus.COMPLETE
        capture.error_message = None
        db.commit()

    except Exception as exc:  # noqa: BLE001 - record the failure on the capture
        logger.exception("analysis failed for capture %s", capture.id)
        db.rollback()
        capture.status = CaptureStatus.FAILED
        capture.error_message = f"{type(exc).__name__}: {exc}"[:500]
        db.commit()
        raise

    return summary


def _run_behavioural_analysis(
    sessions: list[EmailSession], summary: AnalysisSummary
) -> None:
    """Per-server fingerprints, deterministic deviation, then ML anomaly scores."""
    profiles = build_fingerprints(sessions)

    for session in sessions:
        profile = profiles.get(f"{session.server_ip}:{session.server_port}")
        if profile is None:
            continue
        deviations = deviations_for(session, profile)
        session.baseline_deviations = [d.serialise() for d in deviations]
        session.baseline_deviation_score = deviation_score(deviations)
        if deviations:
            summary.baseline_deviations += 1

    report = ml_anomaly.analyse(sessions)
    summary.anomaly_available = report.available
    summary.anomaly_reason = report.reason
    summary.anomalies = report.outliers

    for session in sessions:
        result = report.results.get(session.ref)
        if result is None:
            continue
        session.anomaly_score = result.score
        session.anomaly_attribution = result.attribution
        session.is_anomalous = result.is_outlier


def _tls_columns(tls) -> dict:
    """Flatten a TLSAnalysis into EmailSession columns.

    A session with no handshake gets Nones, not zeros or empty strings: "no TLS
    was observed" and "TLS was observed with no cipher" are different facts and
    must stay distinguishable downstream.
    """
    if tls is None or not tls.observed:
        return {"cert_observable": False, "tls_detail": None}

    suite = tls.cipher_suite
    return {
        "tls_version": tls.negotiated_version_name,
        "tls_cipher_suite": suite.name if suite else None,
        "tls_cipher_code": f"0x{suite.code:04X}" if suite else None,
        "tls_key_exchange": suite.key_exchange if suite else None,
        "tls_authentication": suite.authentication if suite else None,
        "tls_forward_secrecy": suite.forward_secrecy if suite else None,
        "tls_aead": suite.aead if suite else None,
        "tls_selected_group": tls.selected_group_name,
        "tls_sni": tls.sni,
        "tls_sni_status": tls.sni_status,
        "tls_ja3": tls.ja3,
        "tls_ja3s": tls.ja3s,
        "tls_ja4": tls.ja4,
        "tls_ja4s": tls.ja4s,
        "tls_pqc_offered": bool(tls.pqc_groups_offered),
        "tls_pqc_selected": bool(tls.pqc_group_selected),
        "tls_handshake_ms": tls.handshake_duration_ms,
        "cert_observable": tls.cert_observable,
        "cert_unobservable_reason": tls.cert_unobservable_reason,
        "tls_detail": tls.serialise(),
    }


def _run_detection(
    db: Session,
    capture: Capture,
    sessions: list[EmailSession],
    summary: AnalysisSummary,
    audit=None,
) -> None:
    """Deterministic detection: per-session rules, then cross-session analysis.

    Ordering matters for presentation, not correctness: findings are sorted by
    severity and then by first frame so the most serious problem in the capture
    is F-0001. An analyst reading top-down should hit the worst thing first.
    """
    drafts = []
    for session in sessions:
        drafts.extend(session_findings(session))
        drafts.extend(session_tls_findings(session))
        drafts.extend(session_certificate_findings(session))

    # Cross-session detection. This is where evidence that exists in no single
    # session gets found -- a server's capability behaviour compared against
    # itself across the capture.
    drafts.extend(starttls_stripping.detect(sessions))
    drafts.extend(readiness_finding(sessions))
    if audit is not None:
        drafts.extend(dns_detect(audit, sessions))

    resolved = [d.resolve() for d in drafts]
    resolved.sort(key=lambda f: (f["severity_rank"], f["first_frame"] or 0))

    for index, payload in enumerate(resolved, start=1):
        db.add(Finding(capture_id=capture.id, ref=f"F-{index:04d}", **payload))
        summary.by_severity[payload["severity"]] = (
            summary.by_severity.get(payload["severity"], 0) + 1
        )
        summary.by_category[payload["category"]] = (
            summary.by_category.get(payload["category"], 0) + 1
        )

    summary.findings = len(resolved)
