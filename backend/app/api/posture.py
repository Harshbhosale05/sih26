from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.ml import anomaly as ml_anomaly
from app.models import Capture, EmailSession, Finding
from app.posture import build_fingerprints, compute

router = APIRouter(prefix="/api/captures", tags=["posture"])


def _sessions(capture_id: str, db: Session) -> list[EmailSession]:
    if db.get(Capture, capture_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")
    return list(
        db.scalars(select(EmailSession).where(EmailSession.capture_id == capture_id)).all()
    )


@router.get("/{capture_id}/posture")
def posture(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Posture score, per-server fingerprints and the anomaly report.

    The score always travels with its coverage: which dimensions were assessed,
    which were excluded for lack of evidence, and what share of the total weight
    that leaves. A number without that context is the thing this product exists
    to avoid printing.
    """
    sessions = _sessions(capture_id, db)
    findings = list(
        db.scalars(select(Finding).where(Finding.capture_id == capture_id)).all()
    )
    report = compute(sessions, findings)
    fingerprints = build_fingerprints(sessions)

    deviating = [
        {
            "session_ref": s.ref,
            "server": f"{s.server_ip}:{s.server_port}",
            "score": s.baseline_deviation_score,
            "deviations": s.baseline_deviations or [],
            "anomaly_score": s.anomaly_score,
            "is_anomalous": s.is_anomalous,
            "attribution": s.anomaly_attribution or [],
        }
        for s in sessions
        if s.baseline_deviations or s.is_anomalous
    ]
    deviating.sort(key=lambda d: (-(d["score"] or 0), -(d["anomaly_score"] or 0)))

    anomaly = ml_anomaly.analyse(sessions)

    return {
        "posture": report.serialise(),
        "fingerprints": [f.serialise() for f in fingerprints.values()],
        "deviations": deviating,
        "anomaly": {
            "available": anomaly.available,
            "reason": anomaly.reason,
            "model": anomaly.model,
            "sessions_scored": anomaly.sessions_scored,
            "outliers": anomaly.outliers,
            "disclaimer": (
                "An anomaly is deviating behaviour, not a confirmed attack. "
                "Every verdict in this report comes from deterministic rules; "
                "the model only adds multivariate context."
            ),
        },
    }
