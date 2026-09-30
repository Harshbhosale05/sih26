"""Threat prioritisation: which finding does the analyst look at first?

Severity alone is a poor queue. Two HIGH findings are not equal when one
affects a single lab session and the other every client of the main relay, or
when one involves live credentials. Priority combines the deterministic
verdict with context -- exposure, blast radius, the risk model's view of the
affected sessions, and behavioural deviation -- into one ranked number.

Every factor and its contribution is returned. The weights are stated here,
not learned, so the ordering can be argued with.
"""

from __future__ import annotations

from app.models.finding import Finding
from app.models.session import EmailSession

_SEVERITY = {"CRITICAL": 1.0, "HIGH": 0.72, "MEDIUM": 0.45, "LOW": 0.2, "INFO": 0.0}

TIERS = [(70, "P1", "Act now"), (50, "P2", "This week"), (30, "P3", "Planned"), (0, "P4", "Backlog")]


def _tier(score: float) -> tuple[str, str]:
    for floor, tier, label in TIERS:
        if score >= floor:
            return tier, label
    return "P4", "Backlog"


def prioritise(
    findings: list[Finding], sessions: list[EmailSession], blast_radius: list[dict]
) -> list[dict]:
    by_ref = {s.ref: s for s in sessions}
    blast = {r["key"]: r for r in blast_radius if r["kind"] == "finding"}
    rows = []

    for f in findings:
        session = by_ref.get(f.session_ref) if f.session_ref else None
        radius = blast.get(f.category) or {}
        factors = []

        def add(name: str, points: float, detail: str, source: str) -> None:
            factors.append({"factor": name, "points": round(points, 1), "detail": detail, "source": source})

        add("Severity", 45 * _SEVERITY.get(f.severity, 0), f"{f.severity} from policy rule '{f.category}'", "rule")
        add("Confidence", 10 * f.confidence, f"rule confidence {round(f.confidence * 100)}%", "rule")

        creds = (f.evidence or {}).get("credentials") or []
        if f.category == "cleartext_credential_exposure" or (session and session.cleartext_auth_observed):
            add("Credential exposure", 15, f"{len(creds) or 1} credential(s) recoverable from capture", "evidence")
        elif session is not None and session.cleartext_mail_observed:
            add("Content exposure", 8, "message or mailbox data in cleartext", "evidence")

        if radius:
            add(
                "Blast radius", 0.15 * radius.get("blast_score", 0),
                f"{radius.get('dependent_clients', 0)} client(s) · {radius.get('clients_pct', 0)}% of observed clients depend on affected server(s)",
                "dependency graph",
            )
        spread = min(f.affected_sessions or 1, 20)
        if spread > 1:
            add("Recurrence", spread * 0.5, f"{f.affected_sessions} sessions affected", "correlation")

        if session is not None and session.risk_score is not None:
            add("Session risk (model)", 0.12 * session.risk_score,
                f"risk classifier: {session.risk_class} ({round(session.risk_score)}/100)", "ml")
        if session is not None and session.is_anomalous:
            add("Behavioural anomaly", 5, "session is an outlier against its server's population", "ml")

        total = sum(x["points"] for x in factors)
        if f.verdict == "UNKNOWN":
            total *= 0.3
            factors.append({"factor": "Verdict UNKNOWN", "points": 0, "detail": "score × 0.3 — evidence cannot support a conclusion", "source": "rule"})
        elif f.verdict == "PASS":
            total = 0

        total = round(min(total, 100), 1)
        tier, label = _tier(total)
        rows.append({
            "ref": f.ref, "category": f.category, "title": f.title, "severity": f.severity,
            "verdict": f.verdict, "session_ref": f.session_ref, "priority": total,
            "tier": tier, "tier_label": label, "factors": factors,
        })

    rows.sort(key=lambda r: (-r["priority"], r["ref"]))
    for rank, row in enumerate(rows, start=1):
        row["rank"] = rank
    return rows
