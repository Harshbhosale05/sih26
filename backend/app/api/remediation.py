"""Remediation, simulation, prioritisation, risk and traceability endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analytics import explain, graph, priority
from app.db import get_db
from app.ml import risk as ml_risk
from app.models import Capture, EmailSession, Finding
from app.remediation import playbooks, planner, simulator, software
from app.tls.chain import trust_store_summary

router = APIRouter(prefix="/api/captures", tags=["remediation"])
model_router = APIRouter(prefix="/api/models", tags=["models"])


def _load(capture_id: str, db: Session) -> tuple[Capture, list[EmailSession], list[Finding]]:
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Capture not found")
    sessions = list(db.scalars(select(EmailSession).where(EmailSession.capture_id == capture_id)).all())
    findings = list(db.scalars(select(Finding).where(Finding.capture_id == capture_id)).all())
    findings.sort(key=lambda f: f.ref)
    return capture, sessions, findings


class FixRequest(BaseModel):
    id: str
    servers: list[str] | None = None


class SimulateRequest(BaseModel):
    fixes: list[FixRequest] = Field(default_factory=list)


@router.get("/{capture_id}/remediation")
def remediation_plan(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Ordered fix plan with projected posture after every step."""
    capture, sessions, findings = _load(capture_id, db)
    return planner.plan(capture, sessions, findings)


@router.post("/{capture_id}/simulate")
def simulate(capture_id: str, body: SimulateRequest, db: Session = Depends(get_db)) -> dict:
    """Project the capture as if the given fixes had been in place."""
    capture, sessions, findings = _load(capture_id, db)
    unknown = [f.id for f in body.fixes if f.id not in playbooks.FIXES]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown fix id(s): {', '.join(unknown)}")
    return simulator.project(capture, sessions, findings, [f.model_dump() for f in body.fixes])


@router.get("/{capture_id}/priorities")
def priorities(capture_id: str, db: Session = Depends(get_db)) -> list[dict]:
    """Findings ranked by priority with a factor-by-factor breakdown."""
    _, sessions, findings = _load(capture_id, db)
    radius = graph.build(sessions, findings)["blast_radius"]
    return priority.prioritise(findings, sessions, radius)


@router.get("/{capture_id}/risk")
def risk(capture_id: str, db: Session = Depends(get_db)) -> dict:
    """Per-session risk classes from our model, plus the capture-level index."""
    _, sessions, _ = _load(capture_id, db)
    rows = [
        {
            "ref": s.ref, "protocol": s.protocol, "server": f"{s.server_ip}:{s.server_port}",
            "client": s.client_ip, "encryption_state": s.encryption_state,
            "tls_version": s.tls_version, **(s.risk_detail or {}),
        }
        for s in sessions if s.risk_detail
    ]
    rows.sort(key=lambda r: -(r.get("score") or 0))
    results = {
        s.ref: ml_risk.RiskResult(
            session_ref=s.ref, risk_class=s.risk_class, confidence=s.risk_confidence or 0,
            score=s.risk_score or 0, probabilities={},
        )
        for s in sessions if s.risk_class
    }
    return {
        "index": ml_risk.capture_index(results),
        "sessions": rows,
        "unclassified": sum(1 for s in sessions if s.protocol and not s.risk_class),
        "model": ml_risk.model_card(),
    }


@router.get("/{capture_id}/findings/{finding_ref}/trace")
def trace(capture_id: str, finding_ref: str, db: Session = Depends(get_db)) -> dict:
    """End-to-end traceability for one finding.

    Evidence (capture hash → TCP stream → frames → protocol events → encryption
    state) → rule → finding → priority → fix for the detected software →
    projected effect of that fix on this capture.
    """
    capture, sessions, findings = _load(capture_id, db)
    finding = next((f for f in findings if f.ref == finding_ref), None)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    session = next((s for s in sessions if s.ref == finding.session_ref), None)

    dependency = graph.build(sessions, findings)
    radius = next(
        (r for r in dependency["blast_radius"] if r["kind"] == "finding" and r["key"] == finding.category),
        None,
    )
    chain = explain.explain(capture, finding, session, radius)
    ranked = priority.prioritise(findings, sessions, dependency["blast_radius"])
    prio = next((r for r in ranked if r["ref"] == finding.ref), None)

    identified = software.by_server(sessions)
    scope = sorted(planner._servers_of(finding, {s.ref: s for s in sessions}))
    target = identified.get(scope[0]) if scope else None
    fixes = playbooks.fix_for_category(finding.category)

    # The direct fix is not always sufficient: credentials leaked on a
    # *stripped* session stay exposed until the stripping is also defeated.
    # Search the smallest combination -- the direct fixes plus fixes for other
    # findings on the same session -- that actually clears this finding.
    projection = None
    applied: list = []
    if fixes and finding.verdict == "FAIL":
        pool = list(fixes)
        for other in findings:
            if other.verdict == "FAIL" and other.ref != finding.ref and (
                (finding.session_ref and other.session_ref == finding.session_ref)
            ):
                for f in playbooks.fix_for_category(other.category)[:1]:
                    if f not in pool:
                        pool.append(f)

        def run(combo):
            result = simulator.project(
                capture, sessions, findings,
                [{"id": f.id, "servers": scope or None} for f in combo], with_graph=True,
            )
            result["fixed_this_finding"] = any(
                r["ref"] == finding.ref for r in result["findings"]["resolved"]
            )
            return result

        candidates = [[f] for f in pool] + [
            [a, b] for i, a in enumerate(pool) for b in pool[i + 1:]
        ]
        for combo in candidates[:12]:
            result = run(combo)
            if result["fixed_this_finding"]:
                projection, applied = result, combo
                break
        if projection is None:
            applied = pool[:1]
            projection = run(applied)
        # Show the fixes that are applied first, then any alternatives.
        fixes = applied + [f for f in fixes if f not in applied]
        projection["applied_fixes"] = [f.id for f in applied]

    session_view = None
    if session is not None:
        session_view = {
            "ref": session.ref, "protocol": session.protocol, "stream_index": session.stream_index,
            "client": f"{session.client_ip}:{session.client_port}",
            "server": f"{session.server_ip}:{session.server_port}",
            "first_frame": session.first_frame, "last_frame": session.last_frame,
            "encryption_state": session.encryption_state,
            "state_transitions": session.state_transitions or [],
            "events": session.events or [],
            "tls_version": session.tls_version, "tls_cipher_suite": session.tls_cipher_suite,
            "risk": session.risk_detail,
            "wireshark_filter": session.wireshark_filter,
        }

    return {
        "capture": {
            "id": capture.id, "ref": capture.ref, "filename": capture.original_filename,
            "sha256": capture.sha256, "packets": capture.packet_count,
        },
        "finding": chain["finding"],
        "explanation": chain,
        "session": session_view,
        "priority": prio,
        "software": target,
        "scope": scope,
        "fixes": [playbooks.render(f, target) for f in fixes],
        "evidence_action": playbooks.EVIDENCE_ACTIONS.get(finding.category),
        "projection": projection,
    }


@router.get("/{capture_id}/software")
def server_software(capture_id: str, db: Session = Depends(get_db)) -> list[dict]:
    """Mail server product identified per server from banners and greetings."""
    _, sessions, _ = _load(capture_id, db)
    return list(software.by_server(sessions).values())


@model_router.get("/risk")
def risk_model_card() -> dict:
    """Model card for the session risk classifier."""
    return ml_risk.model_card()


@model_router.get("/fixes")
def fix_catalogue() -> list[dict]:
    """Every remediation playbook the simulator and planner know."""
    return [
        {"id": f.id, "title": f.title, "summary": f.summary, "resolves": sorted(f.resolves),
         "owner": f.owner, "effort": f.effort, "group": f.group, "standards": f.standards,
         "software": sorted(k for k in f.snippets if not k.startswith("_"))}
        for f in playbooks.FIXES.values()
    ]


@model_router.get("/trust-store")
def trust_store() -> dict:
    """Roots used for certificate chain anchoring."""
    return trust_store_summary()
