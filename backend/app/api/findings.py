from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.detection import load_policy, starttls_stripping
from app.models import Capture, EmailSession, Finding

router = APIRouter(prefix="/api/captures", tags=["findings"])


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ref: str
    category: str
    severity: str
    verdict: str
    confidence: float
    detection_method: str
    title: str
    description: str
    rationale: str
    recommendation: str | None
    standard_refs: list | None
    session_ref: str | None
    evidence: dict | None
    evidence_frames: list | None
    wireshark_filter: str | None
    affected_sessions: int


@router.get("/{capture_id}/findings", response_model=list[FindingOut])
def list_findings(
    capture_id: str,
    severity: str | None = Query(None),
    category: str | None = Query(None),
    db: Session = Depends(get_db),
) -> list[Finding]:
    if db.get(Capture, capture_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")

    stmt = select(Finding).where(Finding.capture_id == capture_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.upper())
    if category:
        stmt = stmt.where(Finding.category == category)
    return list(
        db.scalars(stmt.order_by(Finding.severity_rank, Finding.first_frame)).all()
    )


@router.get("/{capture_id}/servers")
def server_profiles(capture_id: str, db: Session = Depends(get_db)) -> list[dict]:
    """Per-server capability profiles.

    The raw input to the stripping detector, exposed so an analyst can audit
    the baseline the finding claims rather than taking it on trust.
    """
    if db.get(Capture, capture_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")

    sessions = list(
        db.scalars(select(EmailSession).where(EmailSession.capture_id == capture_id)).all()
    )
    return starttls_stripping.server_profiles_payload(sessions)


@router.get("/policy/current", tags=["system"])
def current_policy() -> dict:
    """The active cryptographic policy.

    Exposed because the posture methodology is ours and stated openly -- every
    severity in the product is traceable to this document.
    """
    return load_policy()
