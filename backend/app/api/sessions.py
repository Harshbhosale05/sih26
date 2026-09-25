from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Capture, EmailSession
from app.services import analyse_capture

router = APIRouter(prefix="/api/captures", tags=["analysis"])


class SessionSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    ref: str
    protocol: str | None
    detection_method: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    server_banner: str | None
    encryption_state: str
    tls_established: bool
    upgrade_advertised: bool
    upgrade_advertised_mangled: bool
    upgrade_requested: bool
    cleartext_auth_observed: bool
    is_indeterminate: bool
    has_gaps: bool
    session_complete: bool
    first_frame: int
    last_frame: int
    wireshark_filter: str
    tls_version: str | None = None
    tls_cipher_suite: str | None = None
    tls_key_exchange: str | None = None
    tls_forward_secrecy: bool | None = None
    tls_aead: bool | None = None
    tls_selected_group: str | None = None
    tls_sni: str | None = None
    tls_ja3: str | None = None
    tls_ja4: str | None = None
    tls_ja4s: str | None = None
    tls_pqc_offered: bool = False
    tls_pqc_selected: bool = False
    cert_observable: bool = False
    cert_unobservable_reason: str | None = None
    baseline_deviation_score: float | None = None
    baseline_deviations: list | None = None
    anomaly_score: float | None = None
    anomaly_attribution: list | None = None
    is_anomalous: bool = False

    @classmethod
    def of(cls, row: EmailSession) -> "SessionSummary":
        return cls(
            session_id=row.id,
            ref=row.ref,
            protocol=row.protocol,
            detection_method=row.detection_method,
            client_ip=row.client_ip,
            client_port=row.client_port,
            server_ip=row.server_ip,
            server_port=row.server_port,
            server_banner=row.server_banner,
            encryption_state=row.encryption_state,
            tls_established=row.tls_established,
            upgrade_advertised=row.upgrade_advertised,
            upgrade_advertised_mangled=row.upgrade_advertised_mangled,
            upgrade_requested=row.upgrade_requested,
            cleartext_auth_observed=row.cleartext_auth_observed,
            is_indeterminate=row.is_indeterminate,
            has_gaps=row.has_gaps,
            session_complete=row.session_complete,
            first_frame=row.first_frame,
            last_frame=row.last_frame,
            wireshark_filter=row.wireshark_filter,
            tls_version=row.tls_version,
            tls_cipher_suite=row.tls_cipher_suite,
            tls_key_exchange=row.tls_key_exchange,
            tls_forward_secrecy=row.tls_forward_secrecy,
            tls_aead=row.tls_aead,
            tls_selected_group=row.tls_selected_group,
            tls_sni=row.tls_sni,
            tls_ja3=row.tls_ja3,
            tls_ja4=row.tls_ja4,
            tls_ja4s=row.tls_ja4s,
            tls_pqc_offered=row.tls_pqc_offered,
            tls_pqc_selected=row.tls_pqc_selected,
            cert_observable=row.cert_observable,
            cert_unobservable_reason=row.cert_unobservable_reason,
            baseline_deviation_score=row.baseline_deviation_score,
            baseline_deviations=row.baseline_deviations,
            anomaly_score=row.anomaly_score,
            anomaly_attribution=row.anomaly_attribution,
            is_anomalous=row.is_anomalous,
        )


class SessionDetail(SessionSummary):
    state_transitions: list | None = None
    events: list | None = None
    tls_detail: dict | None = None


class AnalysisResult(BaseModel):
    capture_id: str
    total_packets: int
    total_flows: int
    candidate_flows: int
    sessions: int
    by_protocol: dict
    by_encryption_state: dict
    indeterminate: int
    cleartext_credential_sessions: int
    findings: int
    by_severity: dict
    by_category: dict


def _get_capture(capture_id: str, db: Session) -> Capture:
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")
    return capture


@router.post("/{capture_id}/analyze", response_model=AnalysisResult)
def analyze(capture_id: str, db: Session = Depends(get_db)) -> AnalysisResult:
    """Run the reconstruction pipeline. Idempotent -- safe to re-run."""
    capture = _get_capture(capture_id, db)
    summary = analyse_capture(db, capture)
    return AnalysisResult(
        capture_id=capture.id,
        total_packets=summary.total_packets,
        total_flows=summary.total_flows,
        candidate_flows=summary.candidate_flows,
        sessions=summary.sessions,
        by_protocol=summary.by_protocol,
        by_encryption_state=summary.by_state,
        indeterminate=summary.indeterminate,
        cleartext_credential_sessions=summary.cleartext_credentials,
        findings=summary.findings,
        by_severity=summary.by_severity,
        by_category=summary.by_category,
    )


@router.get("/{capture_id}/sessions", response_model=list[SessionSummary])
def list_sessions(
    capture_id: str,
    protocol: str | None = Query(None),
    encryption_state: str | None = Query(None),
    db: Session = Depends(get_db),
) -> list[SessionSummary]:
    _get_capture(capture_id, db)
    stmt = select(EmailSession).where(EmailSession.capture_id == capture_id)
    if protocol:
        stmt = stmt.where(EmailSession.protocol == protocol.upper())
    if encryption_state:
        stmt = stmt.where(EmailSession.encryption_state == encryption_state.upper())
    rows = db.scalars(stmt.order_by(EmailSession.first_frame)).all()
    return [SessionSummary.of(r) for r in rows]


@router.get("/{capture_id}/sessions/{session_ref}", response_model=SessionDetail)
def get_session(
    capture_id: str, session_ref: str, db: Session = Depends(get_db)
) -> SessionDetail:
    """Full session detail: the transition timeline and every parsed event."""
    row = db.scalar(
        select(EmailSession).where(
            EmailSession.capture_id == capture_id, EmailSession.ref == session_ref
        )
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")

    base = SessionSummary.of(row).model_dump()
    return SessionDetail(
        **base,
        state_transitions=row.state_transitions,
        events=row.events,
        tls_detail=row.tls_detail,
    )
