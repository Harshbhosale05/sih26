from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.dnsx import audit as dns_audit
from app.engines.tshark import extract_dns
from app.models import Capture, EmailSession, Finding
from app.pcap import SliceError, extract, slice_path
from app.pqc import build as build_cbom
from app.reports import build as build_report
from app.reports import render as render_report

router = APIRouter(prefix="/api/captures", tags=["intelligence"])


def _load(capture_id: str, db: Session) -> tuple[Capture, list[EmailSession]]:
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")
    sessions = list(
        db.scalars(select(EmailSession).where(EmailSession.capture_id == capture_id)).all()
    )
    return capture, sessions


@router.get("/{capture_id}/dns")
def dns_policy(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Email transport-security policy derived from DNS in the same capture."""
    capture, _ = _load(capture_id, db)
    return dns_audit(extract_dns(Path(capture.stored_path))).serialise()


@router.get("/{capture_id}/cbom")
def cbom(capture_id: str, db: Session = Depends(get_db)) -> JSONResponse:
    """CycloneDX 1.6 Cryptographic Bill of Materials for the observed traffic."""
    capture, sessions = _load(capture_id, db)
    document = build_cbom(capture, sessions)
    return JSONResponse(
        document,
        headers={
            "Content-Disposition": f'attachment; filename="{capture.ref}-cbom.json"'
        },
    )


@router.get("/{capture_id}/report.json")
def report_json(capture_id: str, db: Session = Depends(get_db)) -> JSONResponse:
    """Full structured report for SOC/SIEM ingestion."""
    capture, sessions = _load(capture_id, db)
    findings = list(
        db.scalars(select(Finding).where(Finding.capture_id == capture_id)).all()
    )
    return JSONResponse(
        build_report(capture, sessions, findings),
        headers={
            "Content-Disposition": f'attachment; filename="{capture.ref}-report.json"'
        },
    )


@router.get("/{capture_id}/report.html", response_class=HTMLResponse)
def report_html(capture_id: str, db: Session = Depends(get_db)) -> HTMLResponse:
    """Formal assessment report. Print to PDF from the browser."""
    capture, sessions = _load(capture_id, db)
    findings = list(
        db.scalars(select(Finding).where(Finding.capture_id == capture_id)).all()
    )
    return HTMLResponse(render_report(build_report(capture, sessions, findings)))


def _slice_response(capture: Capture, ref: str, kind: str, display_filter: str):
    if not display_filter:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "No display filter available for this item"
        )
    source = Path(capture.stored_path)
    target = slice_path(source.parent, kind, ref)
    try:
        sliced = extract(source, display_filter, target, capture.sha256)
    except SliceError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    return FileResponse(
        path=str(sliced.path),
        media_type="application/vnd.tcpdump.pcap",
        filename=f"{capture.ref}-{ref}.pcapng",
        headers={
            # Chain of custody rides along in the response headers so the
            # downloaded file can always be tied back to its parent capture.
            "X-Evidence-Sha256": sliced.sha256,
            "X-Parent-Sha256": sliced.parent_sha256,
            "X-Frame-Count": str(sliced.frame_count),
            "X-Display-Filter": sliced.display_filter,
        },
    )


@router.get("/{capture_id}/sessions/{session_ref}/pcap")
def session_pcap(capture_id: str, session_ref: str, db: Session = Depends(get_db)):
    """Download just this session's frames, for verification in Wireshark."""
    capture, _ = _load(capture_id, db)
    session = db.scalar(
        select(EmailSession).where(
            EmailSession.capture_id == capture_id, EmailSession.ref == session_ref
        )
    )
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    return _slice_response(capture, session.ref, "session", session.wireshark_filter)


@router.get("/{capture_id}/findings/{finding_ref}/pcap")
def finding_pcap(capture_id: str, finding_ref: str, db: Session = Depends(get_db)):
    """Download the frames that prove a finding.

    Cut with the same display filter shown in the UI, so what an analyst
    verifies is exactly what the finding claims.
    """
    capture, _ = _load(capture_id, db)
    finding = db.scalar(
        select(Finding).where(
            Finding.capture_id == capture_id, Finding.ref == finding_ref
        )
    )
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return _slice_response(capture, finding.ref, "finding", finding.wireshark_filter)
