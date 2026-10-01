"""Analyst brief: an evidence-grounded narrative of the capture.

Written by content selection, not free text generation. Each sentence is built
from a computed fact (posture, the top-priority finding, the leading attack
scenario, PQC exposure, anomalies, the remediation plan) and carries the refs
that prove it, so every claim in the brief is one click from its evidence.
"""

from __future__ import annotations

from collections import Counter

from app.models.capture import Capture
from app.models.finding import Finding
from app.models.session import EmailSession

_RATING = [(80, "strong"), (60, "moderate"), (40, "weak"), (0, "poor")]


def _rating(score: int | None, critical: int) -> str:
    if score is None:
        return "not assessable"
    if critical:
        return "poor, because critical findings are present"
    return next(label for floor, label in _RATING if score >= floor)


def build(
    capture: Capture,
    sessions: list[EmailSession],
    findings: list[Finding],
    *,
    posture: dict,
    priorities: list[dict],
    attack: dict,
    pqc: dict,
    forecast: dict,
    clusters: dict,
    plan: dict | None,
) -> dict:
    email = [s for s in sessions if s.protocol]
    protected = sum(1 for s in email if s.encryption_state in ("TLS_ESTABLISHED", "IMPLICIT_TLS"))
    protos = ", ".join(f"{n} {p}" for p, n in Counter(s.protocol for s in email).most_common())
    fails = [p for p in priorities if p["verdict"] == "FAIL"]
    critical = sum(1 for p in fails if p["severity"] == "CRITICAL")
    creds = [s for s in email if s.cleartext_auth_observed]

    sentences: list[dict] = []

    def say(text: str, refs: list[str] | None = None, kind: str = "fact") -> None:
        sentences.append({"text": text, "refs": refs or [], "kind": kind})

    when = capture.first_packet_at.strftime("%d %b %Y") if capture.first_packet_at else "an unknown date"
    n = len(email)
    clients = len({s.client_ip for s in email})
    servers = len({(s.server_ip, s.server_port) for s in email})
    say(
        f"{n} email session{'s' if n != 1 else ''} ({protos or 'none'}) between {clients} client{'s' if clients != 1 else ''} "
        f"and {servers} server endpoint{'s' if servers != 1 else ''} {'were' if n != 1 else 'was'} reconstructed from traffic "
        f"captured on {when}; {protected} of {n} {'were' if n != 1 else 'was'} encrypted.",
    )
    say(
        f"Cryptographic posture is {_rating(posture['overall'], critical)}, scoring {posture['overall']}/100 "
        f"with {len(fails)} finding{'s' if len(fails) != 1 else ''} requiring action.",
        kind="assessment",
    )

    if fails:
        top = fails[0]
        say(
            f"The highest priority is {top['ref']}: {top['title']} ({top['severity'].lower()}, {top['tier']}), "
            + (f"on session {top['session_ref']}." if top.get("session_ref") else "across the environment."),
            [top["ref"]] + ([top["session_ref"]] if top.get("session_ref") else []),
            kind="risk",
        )
    if creds:
        say(
            f"Credentials were transmitted without encryption in {len(creds)} session{'s' if len(creds) != 1 else ''} "
            f"({', '.join(s.ref for s in creds[:4])}); the affected accounts should be treated as compromised.",
            [s.ref for s in creds[:4]],
            kind="risk",
        )

    scen = [s for s in attack.get("scenarios", []) if s["score"] >= 30]
    if scen:
        s0 = scen[0]
        techs = sorted({t["id"] for st in s0["stages"] for t in st["techniques"]})
        say(
            f"The evidence is most consistent with the scenario \"{s0['title']}\" (likelihood "
            f"{round(s0['likelihood'] * 100)}%, MITRE ATT&CK {', '.join(techs[:4])}).",
            s0["finding_refs"][:4],
            kind="risk",
        )

    if pqc.get("score") is not None:
        median = next((r for r in forecast.get("scenarios", []) if r["key"] == "median"), None)
        text = (
            f"Post-quantum readiness is {pqc['score']}/100 ({(pqc.get('level_label') or '').lower()}); "
            f"{pqc.get('hndl_exposed_pct', 0)}% of sessions use key exchange a future quantum computer could break."
        )
        if median:
            text += (
                f" With a {forecast['shelf_life_years']:g}-year shelf life and {forecast['migration_years']:g} years of migration, "
                f"Mosca's inequality gives \"{median['mosca_verdict'].lower()}\" for a {median['year']} quantum computer."
            )
        gap = [s for s in pqc.get("servers", []) if s.get("migration_gap")]
        if gap:
            text += f" Clients already offer hybrid ML-KEM to {', '.join(s['server'] for s in gap)}, which declines it."
        say(text, kind="pqc")

    anomalous = [s for s in email if s.is_anomalous]
    novel = [c for c in clusters.get("clusters", []) if c.get("novel")]
    if anomalous or novel:
        parts = []
        if anomalous:
            parts.append(f"{len(anomalous)} session(s) are statistical outliers ({', '.join(s.ref for s in anomalous[:3])})")
        if novel:
            parts.append(f"{sum(c['size'] for c in novel)} handshake(s) come from client TLS stacks seen nowhere else in the capture")
        joined = "; ".join(parts)
        say(joined[0].upper() + joined[1:] + ". These are deviations to review, not confirmed attacks.",
            [s.ref for s in anomalous[:3]] + [r for c in novel[:2] for r in c["sessions"][:1]], kind="anomaly")

    actions = []
    if plan and plan.get("steps"):
        for st in plan["steps"][:3]:
            actions.append({
                "title": st["title"],
                "fix_id": st["fix_id"],
                "servers": st["servers"],
                "score_after": st["score_after"],
                "addresses": [a["ref"] for a in st["addresses"]],
            })
        say(
            f"Applying the first {len(actions)} planned change{'s' if len(actions) != 1 else ''} is projected to raise "
            f"posture from {plan['baseline']['score']} to {plan['steps'][len(actions) - 1]['score_after']}.",
            kind="action",
        )

    return {"sentences": sentences, "actions": actions}
