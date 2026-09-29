from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analytics import drift, explain, graph, starttls
from app.db import get_db
from app.models import Capture, CaptureStatus, EmailSession, Finding
from app.pqc.readiness import assess as assess_pqc

router = APIRouter(prefix="/api/captures", tags=["analytics"])
drift_router = APIRouter(prefix="/api/drift", tags=["drift"])


def _load(capture_id: str, db: Session) -> tuple[Capture, list[EmailSession], list[Finding]]:
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")
    sessions = list(
        db.scalars(select(EmailSession).where(EmailSession.capture_id == capture_id)).all()
    )
    findings = list(db.scalars(select(Finding).where(Finding.capture_id == capture_id)).all())
    return capture, sessions, findings


@router.get("/{capture_id}/starttls")
def starttls_analytics(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """STARTTLS funnel, failure points, per-server adoption and timeline."""
    _, sessions, _ = _load(capture_id, db)
    return starttls.analyse(sessions)


@router.get("/{capture_id}/pqc")
def pqc_readiness(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """PQC readiness score, harvest-now-decrypt-later exposure, migration steps."""
    _, sessions, _ = _load(capture_id, db)
    return assess_pqc(sessions)


@router.get("/{capture_id}/graph")
def dependency_graph(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Client → server → crypto dependency graph with per-weakness blast radius."""
    _, sessions, findings = _load(capture_id, db)
    return graph.build(sessions, findings)


@router.get("/{capture_id}/findings/{finding_ref}/explain")
def explain_finding(capture_id: str, finding_ref: str, db: Session = Depends(get_db)) -> dict:
    """The evidence chain behind one finding."""
    capture, sessions, findings = _load(capture_id, db)
    finding = next((f for f in findings if f.ref == finding_ref), None)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    session = next((s for s in sessions if s.ref == finding.session_ref), None)
    radius = next(
        (
            r for r in graph.build(sessions, findings)["blast_radius"]
            if r["kind"] == "finding" and r["key"] == finding.category
        ),
        None,
    )
    return explain.explain(capture, finding, session, radius)


def _snapshot(capture: Capture, db: Session) -> dict:
    _, sessions, findings = _load(capture.id, db)
    return drift.snapshot(capture, sessions, findings)


@drift_router.get("/timeline")
def drift_timeline(db: Session = Depends(get_db)) -> dict:
    """Posture metrics for every analysed capture, oldest first."""
    captures = db.scalars(
        select(Capture).where(Capture.status == CaptureStatus.COMPLETE)
    ).all()
    return drift.timeline([_snapshot(c, db) for c in captures])


@drift_router.get("/compare")
def drift_compare(
    baseline: str = Query(..., description="Baseline capture id"),
    current: str = Query(..., description="Current capture id"),
    db: Session = Depends(get_db),
) -> dict:
    """What changed cryptographically between two captures."""
    if baseline == current:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose two different captures")
    base, cur = db.get(Capture, baseline), db.get(Capture, current)
    if base is None or cur is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")
    for capture in (base, cur):
        if capture.status != CaptureStatus.COMPLETE:
            raise HTTPException(
                status.HTTP_409_CONFLICT, f"{capture.ref} has not been analysed yet"
            )
    return drift.compare(_snapshot(base, db), _snapshot(cur, db))
