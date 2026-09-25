from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Capture, EmailSession, Finding
from app.protocols import CLEARTEXT_STATES

router = APIRouter(prefix="/api/captures", tags=["overview"])

_SECURE_STATES = {"TLS_ESTABLISHED", "IMPLICIT_TLS"}
_CLEARTEXT = {s.value for s in CLEARTEXT_STATES}


@router.get("/{capture_id}/overview")
def overview(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Everything the dashboard's landing view needs, in one round trip."""
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")

    sessions = list(
        db.scalars(select(EmailSession).where(EmailSession.capture_id == capture_id)).all()
    )
    findings = list(
        db.scalars(select(Finding).where(Finding.capture_id == capture_id)).all()
    )

    states = Counter(s.encryption_state for s in sessions)
    protected = sum(n for st, n in states.items() if st in _SECURE_STATES)
    cleartext = sum(n for st, n in states.items() if st in _CLEARTEXT)
    indeterminate = sum(1 for s in sessions if s.is_indeterminate)

    tls_sessions = [s for s in sessions if s.tls_version]
    cert_observable = sum(1 for s in tls_sessions if s.cert_observable)

    return {
        "capture": {
            "capture_id": capture.id,
            "ref": capture.ref,
            "filename": capture.original_filename,
            "sha256": capture.sha256,
            "packet_count": capture.packet_count,
            "size_bytes": capture.size_bytes,
            "first_packet_at": capture.first_packet_at,
            "last_packet_at": capture.last_packet_at,
            "duration_seconds": capture.duration_seconds,
            "snaplen_truncated": capture.snaplen_truncated,
            "status": capture.status.value,
        },
        "sessions": {
            "total": len(sessions),
            "by_protocol": dict(Counter(s.protocol for s in sessions if s.protocol)),
            "by_state": dict(states),
            "protected": protected,
            "cleartext": cleartext,
            "indeterminate": indeterminate,
        },
        "findings": {
            "total": len(findings),
            "by_severity": dict(Counter(f.severity for f in findings)),
            "by_category": dict(Counter(f.category for f in findings)),
            "unknown_verdicts": sum(1 for f in findings if f.verdict == "UNKNOWN"),
        },
        "crypto": {
            "by_tls_version": dict(
                Counter(s.tls_version for s in tls_sessions if s.tls_version)
            ),
            "by_cipher": dict(
                Counter(s.tls_cipher_suite for s in tls_sessions if s.tls_cipher_suite)
            ),
            "forward_secrecy": sum(1 for s in tls_sessions if s.tls_forward_secrecy),
            "pqc_offered": sum(1 for s in tls_sessions if s.tls_pqc_offered),
            "pqc_selected": sum(1 for s in tls_sessions if s.tls_pqc_selected),
        },
        # Evidence coverage is a first-class output, not a footnote. A posture
        # score computed over data we could not observe is the failure mode this
        # product exists to avoid, so the denominator travels with the number.
        "coverage": {
            "tls_sessions": len(tls_sessions),
            "certificate_observable": cert_observable,
            "certificate_coverage_pct": round(
                100 * cert_observable / len(tls_sessions), 1
            ) if tls_sessions else None,
            "sessions_fully_observed": sum(1 for s in sessions if s.session_complete),
            "session_coverage_pct": round(
                100 * sum(1 for s in sessions if s.session_complete) / len(sessions), 1
            ) if sessions else None,
            "note": (
                "Certificate coverage is normally low on modern infrastructure: "
                "TLS 1.3 encrypts the Certificate message, so it cannot be read "
                "passively without session keys."
            ),
        },
    }
