"""AI-assisted analysis endpoints: analyst brief, questions, attack paths,
client fingerprint clusters and the quantum risk forecast."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import assistant, attack_paths, brief, fingerprints, quantum_forecast
from app.analytics import graph, priority
from app.db import get_db
from app.models import Capture, EmailSession, Finding
from app.posture import compute
from app.pqc.readiness import assess as assess_pqc
from app.remediation import planner, simulator, software

router = APIRouter(prefix="/api/captures", tags=["ai"])
model_router = APIRouter(prefix="/api/models", tags=["models"])


def _load(capture_id: str, db: Session) -> tuple[Capture, list[EmailSession], list[Finding]]:
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")
    sessions = list(db.scalars(select(EmailSession).where(EmailSession.capture_id == capture_id)).all())
    findings = list(db.scalars(select(Finding).where(Finding.capture_id == capture_id)).all())
    findings.sort(key=lambda f: f.ref)
    return capture, sessions, findings


def _context(capture: Capture, sessions: list[EmailSession], findings: list[Finding], shelf_life: float = 10.0) -> assistant.Context:
    ctx: assistant.Context

    def plan():
        return planner.plan(capture, sessions, findings)

    providers = {
        "posture": lambda: compute(sessions, findings).serialise(),
        "graph": lambda: graph.build(sessions, findings),
        "priorities": lambda: priority.prioritise(findings, sessions, ctx.get("graph")["blast_radius"]),
        "attack": lambda: attack_paths.analyse(sessions, findings),
        "pqc": lambda: assess_pqc(sessions),
        "plan": plan,
        "forecast": lambda: quantum_forecast.forecast(
            sessions, capture.first_packet_at, shelf_life, ctx.get("plan")["steps"]
        ),
        "clusters": lambda: fingerprints.analyse(sessions),
        "software": lambda: list(software.by_server(sessions).values()),
        "simulate": lambda: (lambda fixes: simulator.project(capture, sessions, findings, fixes, with_graph=False)),
        "brief": lambda: brief.build(
            capture, sessions, findings,
            posture=ctx.get("posture"), priorities=ctx.get("priorities"), attack=ctx.get("attack"),
            pqc=ctx.get("pqc"), forecast=ctx.get("forecast"), clusters=ctx.get("clusters"), plan=ctx.get("plan"),
        ),
    }
    ctx = assistant.Context(capture, sessions, findings, providers)
    return ctx


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=500)


@router.get("/{capture_id}/ai/brief")
def analyst_brief(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Evidence-grounded narrative summary of the capture."""
    capture, sessions, findings = _load(capture_id, db)
    return _context(capture, sessions, findings).get("brief")


@router.post("/{capture_id}/ai/ask")
def ask(capture_id: str, body: AskRequest, db: Session = Depends(get_db)) -> dict:
    """Answer a natural-language question from the capture's evidence."""
    capture, sessions, findings = _load(capture_id, db)
    return assistant.ask(_context(capture, sessions, findings), body.question)


@router.get("/{capture_id}/ai/attack-paths")
def attack(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Findings correlated into adversary scenarios mapped to MITRE ATT&CK."""
    _, sessions, findings = _load(capture_id, db)
    return attack_paths.analyse(sessions, findings)


@router.get("/{capture_id}/ai/fingerprints")
def client_fingerprints(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Unsupervised clustering of client TLS stacks; novel stacks flagged."""
    _, sessions, _ = _load(capture_id, db)
    return fingerprints.analyse(sessions)


@router.get("/{capture_id}/ai/quantum-forecast")
def quantum(
    capture_id: str,
    shelf_life: float = Query(10.0, ge=0, le=50, description="Years the email must stay confidential"),
    db: Session = Depends(get_db),
) -> dict:
    """Mosca's inequality applied to the observed key exchange."""
    capture, sessions, findings = _load(capture_id, db)
    plan = planner.plan(capture, sessions, findings)
    return quantum_forecast.forecast(sessions, capture.first_packet_at, shelf_life, plan["steps"])


@model_router.get("/assistant")
def assistant_card() -> dict:
    """Model card for the question-intent classifier."""
    _, card = assistant.model()
    return {**card, "examples": assistant.EXAMPLES}
