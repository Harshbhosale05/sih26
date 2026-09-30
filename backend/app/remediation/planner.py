"""Remediation planner: which fix first, and how far does each one get you?

An administrator with twelve findings does not need twelve tickets; they need
the three changes that move the posture most for the least work. The planner
answers that with the simulator rather than a heuristic:

  1. Collect every fix that resolves at least one FAIL finding, scoped to the
     servers those findings are about.
  2. Greedily pick the next fix with the largest *simulated* improvement per
     unit of effort, given the fixes already chosen (fixes interact: enforcing
     TLS makes the cipher fix matter to more sessions). Improvement is
     severity-weighted risk removed plus twice the posture gain, because a
     severe finding can sit behind another finding's score cap and look free.
  3. Record the projected score after each step, so the plan doubles as a
     trajectory: 41 -> 68 -> 83 -> 90.

"""

from __future__ import annotations

from collections import defaultdict

from app.models.capture import Capture
from app.models.finding import Finding
from app.models.session import EmailSession
from app.remediation import playbooks, software
from app.remediation.playbooks import EVIDENCE_ACTIONS, FIXES
from app.remediation.simulator import score_only

_SEVERITY_POINTS = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}


def _servers_of(finding: Finding, by_ref: dict[str, EmailSession]) -> set[str]:
    servers: set[str] = set()
    evidence = finding.evidence or {}
    if finding.session_ref and finding.session_ref in by_ref:
        s = by_ref[finding.session_ref]
        servers.add(f"{s.server_ip}:{s.server_port}")
    if isinstance(evidence.get("server"), str):
        servers.add(evidence["server"])
    for key in evidence.get("servers") or []:
        if isinstance(key, str):
            servers.add(key)
    profile = evidence.get("server_profile") or {}
    if isinstance(profile, dict) and profile.get("server"):
        servers.add(profile["server"])
    return servers


def _weighted(by_severity: dict) -> int:
    return sum(_SEVERITY_POINTS.get(k, 0) * v for k, v in by_severity.items())


def candidates(sessions: list[EmailSession], findings: list[Finding]) -> list[dict]:
    """Every applicable fix, with the findings and servers it addresses."""
    by_ref = {s.ref: s for s in sessions}
    per_fix: dict[str, dict] = defaultdict(lambda: {"findings": [], "servers": set(), "categories": set()})
    for f in findings:
        if f.verdict != "FAIL":
            continue
        options = playbooks.fix_for_category(f.category)
        if not options:
            continue
        fix = options[0]
        entry = per_fix[fix.id]
        entry["findings"].append(f)
        entry["categories"].add(f.category)
        entry["servers"] |= _servers_of(f, by_ref)
    return [
        {
            "id": fid,
            "servers": sorted(v["servers"]),
            "findings": v["findings"],
            "categories": sorted(v["categories"]),
        }
        for fid, v in per_fix.items()
    ]


def plan(capture: Capture, sessions: list[EmailSession], findings: list[Finding]) -> dict:
    options = candidates(sessions, findings)
    identified = software.by_server(sessions)

    baseline_score, baseline_count, baseline_sev = score_only(capture, sessions, findings, [])
    chosen: list[dict] = []
    steps: list[dict] = []
    current_score, current_weight = baseline_score, _weighted(baseline_sev)
    remaining = list(options)

    while remaining:
        best = None
        for option in remaining:
            trial = chosen + [{"id": option["id"], "servers": option["servers"] or None}]
            score, count, sev = score_only(capture, sessions, findings, trial)
            gain = (score or 0) - (current_score or 0)
            weight_gain = current_weight - _weighted(sev)
            effort = FIXES[option["id"]].effort
            # Risk removed counts alongside score: a severe finding can hide
            # behind another cap, so score alone under-rates the fix for it.
            key = ((weight_gain + 2 * gain) / effort, gain, -effort)
            if best is None or key > best[0]:
                best = (key, option, score, count, sev, gain, weight_gain)
        _, option, score, count, sev, gain, weight_gain = best
        remaining.remove(option)
        if gain <= 0 and weight_gain <= 0 and count >= (steps[-1]["findings_after"] if steps else baseline_count):
            # Already covered by an earlier, broader fix: nothing left for it to do.
            continue
        chosen.append({"id": option["id"], "servers": option["servers"] or None})

        fix = FIXES[option["id"]]
        primary = identified.get(option["servers"][0]) if option["servers"] else None
        steps.append({
            "step": len(steps) + 1,
            "fix_id": fix.id,
            "title": fix.title,
            "group": fix.group,
            "owner": fix.owner,
            "effort": fix.effort,
            "servers": option["servers"],
            "software": [
                {"server": k, "name": identified[k]["name"], "version": identified[k].get("version")}
                for k in option["servers"] if k in identified
            ],
            "addresses": [
                {"ref": f.ref, "category": f.category, "severity": f.severity, "title": f.title}
                for f in option["findings"]
            ],
            "score_before": current_score,
            "score_after": score,
            "score_gain": gain,
            "findings_after": count,
            "severity_after": sev,
            "risk_points_removed": weight_gain,
            "playbook": playbooks.render(fix, primary),
        })
        current_score, current_weight = score, _weighted(sev)

    evidence_gaps = [
        {"category": cat, "action": action,
         "findings": [f.ref for f in findings if f.category == cat]}
        for cat, action in EVIDENCE_ACTIONS.items()
        if any(f.category == cat for f in findings)
    ]

    return {
        "baseline": {"score": baseline_score, "findings": baseline_count, "severity": baseline_sev},
        "target": {"score": current_score, "findings": steps[-1]["findings_after"] if steps else baseline_count},
        "steps": steps,
        "servers": list(identified.values()),
        "evidence_gaps": evidence_gaps,
        "method": (
            "Greedy plan over simulated outcomes: at each step the fix with the largest projected "
            "improvement per unit of effort is chosen, given the fixes already applied. Improvement "
            "= severity-weighted risk removed (critical 10, high 6, medium 3, low 1) + 2 × posture "
            "gain. Scores are projections from the same rules and scoring used on the real evidence."
        ),
    }
