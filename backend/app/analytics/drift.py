"""Cryptographic drift detection across captures.

A single capture is a photograph. Drift is what changed between photographs:
a server that negotiated TLS 1.3 last month and TLS 1.2 today, a JA4S that
silently changed (a new TLS stack was deployed), STARTTLS adoption that fell
after a network change, a PQC group that appeared.

Two captures of the same infrastructure are compared on three levels:

  * environment metrics  (posture, TLS 1.3 share, PFS share, adoption, ...)
  * per-server fingerprint (dominant version, suite, group, JA4S, outcome)
  * findings            (categories that appeared, resolved or persisted)

Every change is classified as a regression, an improvement or a neutral
change. Neutral is a real category: a JA4S change is not better or worse on its
own, but an unexplained change of TLS stack is exactly what an analyst wants
surfaced.

Servers are matched on ip:port. A server absent from one capture is reported as
added or removed — never as "improved", because not observing a server says
nothing about its configuration.
"""

from __future__ import annotations

from collections import Counter

from app.analytics.starttls import analyse as starttls_analyse
from app.models.capture import Capture
from app.models.finding import SEVERITY_ORDER, Finding
from app.models.session import EmailSession
from app.posture import compute as compute_posture
from app.pqc.readiness import assess as assess_pqc
from app.protocols import CLEARTEXT_STATES

_CLEARTEXT = {s.value for s in CLEARTEXT_STATES}
_SECURE = {"TLS_ESTABLISHED", "IMPLICIT_TLS"}

_VERSION_RANK = {"SSL 3.0": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}

# (key, label, unit, better) -- `better` says which direction is an improvement.
METRICS = [
    ("posture", "Posture score", "score", "higher"),
    ("pqc_readiness", "PQC readiness", "score", "higher"),
    ("starttls_adoption", "STARTTLS adoption", "pct", "higher"),
    ("encrypted_pct", "Sessions encrypted", "pct", "higher"),
    ("tls13_pct", "TLS 1.3 share", "pct", "higher"),
    ("deprecated_tls_pct", "Deprecated TLS share", "pct", "lower"),
    ("pfs_pct", "Forward secrecy", "pct", "higher"),
    ("aead_pct", "AEAD ciphers", "pct", "higher"),
    ("pqc_selected_pct", "PQC hybrid selected", "pct", "higher"),
    ("pqc_offered_pct", "Clients offering PQC", "pct", "higher"),
    ("credential_exposures", "Cleartext credential sessions", "count", "lower"),
    ("critical_findings", "Critical findings", "count", "lower"),
    ("high_findings", "High findings", "count", "lower"),
]

# Server fingerprint attributes and how to rank their values (None = neutral).
_SERVER_DIMENSIONS = {
    "tls_version": ("TLS version", lambda v: _VERSION_RANK.get(v)),
    "cipher_suite": ("Cipher suite", None),
    "cipher_strength": ("Cipher strength", lambda v: {"weak": 0, "legacy": 1, "aead": 2}.get(v)),
    "key_group": ("Key exchange group", None),
    "pqc": ("PQC key exchange", lambda v: {"classical": 0, "hybrid": 1}.get(v)),
    "ja4s": ("Server TLS fingerprint (JA4S)", None),
    "outcome": ("Encryption outcome", lambda v: 1 if v in _SECURE else 0),
    "starttls_advertised": ("STARTTLS advertised", lambda v: {"no": 0, "yes": 1}.get(v)),
}


def _pct(n: int, d: int) -> float | None:
    return round(100 * n / d, 1) if d else None


def _dominant(values: list) -> str | None:
    values = [v for v in values if v is not None]
    if not values:
        return None
    return str(Counter(values).most_common(1)[0][0])


def _cipher_strength(session: EmailSession) -> str | None:
    if not session.tls_cipher_suite:
        return None
    if ((session.tls_detail or {}).get("cipher_suite") or {}).get("weaknesses"):
        return "weak"
    return "aead" if session.tls_aead else "legacy"


def snapshot(capture: Capture, sessions: list[EmailSession], findings: list[Finding]) -> dict:
    email = [s for s in sessions if s.protocol and not s.is_indeterminate]
    tls = [s for s in email if s.tls_version]
    kex = [s for s in tls if s.tls_forward_secrecy is not None]
    severities = Counter(f.severity for f in findings if f.verdict == "FAIL")

    posture = compute_posture(sessions, findings)
    pqc = assess_pqc(sessions)
    starttls = starttls_analyse(sessions)

    metrics = {
        "posture": posture.overall,
        "pqc_readiness": pqc["score"],
        "starttls_adoption": starttls["summary"]["adoption_pct"],
        "encrypted_pct": _pct(sum(1 for s in email if s.encryption_state not in _CLEARTEXT), len(email)),
        "tls13_pct": _pct(sum(1 for s in tls if s.tls_version == "TLS 1.3"), len(tls)),
        "deprecated_tls_pct": _pct(
            sum(1 for s in tls if _VERSION_RANK.get(s.tls_version, 9) < 3), len(tls)
        ),
        "pfs_pct": _pct(sum(1 for s in kex if s.tls_forward_secrecy), len(kex)),
        "aead_pct": _pct(sum(1 for s in tls if s.tls_aead), len(tls)),
        "pqc_selected_pct": _pct(sum(1 for s in tls if s.tls_pqc_selected), len(tls)),
        "pqc_offered_pct": _pct(sum(1 for s in tls if s.tls_pqc_offered), len(tls)),
        "credential_exposures": sum(1 for s in email if s.cleartext_auth_observed),
        "critical_findings": severities.get("CRITICAL", 0),
        "high_findings": severities.get("HIGH", 0),
    }

    servers: dict[str, dict] = {}
    by_server: dict[str, list[EmailSession]] = {}
    for s in email:
        by_server.setdefault(f"{s.server_ip}:{s.server_port}", []).append(s)

    for key, rows in by_server.items():
        plaintext_start = [r for r in rows if r.encryption_state != "IMPLICIT_TLS"]
        servers[key] = {
            "sessions": len(rows),
            "protocol": _dominant([r.protocol for r in rows]),
            "tls_version": _dominant([r.tls_version for r in rows]),
            "cipher_suite": _dominant([r.tls_cipher_suite for r in rows]),
            "cipher_strength": _dominant([_cipher_strength(r) for r in rows]),
            "key_group": _dominant([r.tls_selected_group for r in rows]),
            "pqc": _dominant(
                ["hybrid" if r.tls_pqc_selected else "classical" for r in rows if r.tls_version]
            ),
            "ja4s": _dominant([r.tls_ja4s for r in rows]),
            "outcome": _dominant([r.encryption_state for r in rows]),
            "starttls_advertised": _dominant(
                ["yes" if r.upgrade_advertised else "no" for r in plaintext_start]
            ),
        }

    categories: dict[str, dict] = {}
    for f in findings:
        if f.verdict != "FAIL":
            continue
        entry = categories.setdefault(
            f.category, {"count": 0, "severity": f.severity, "title": f.title}
        )
        entry["count"] += 1
        if SEVERITY_ORDER.get(f.severity, 9) < SEVERITY_ORDER.get(entry["severity"], 9):
            entry["severity"] = f.severity

    return {
        "capture_id": capture.id,
        "ref": capture.ref,
        "filename": capture.original_filename,
        "observed_at": (capture.first_packet_at or capture.uploaded_at).isoformat()
        if (capture.first_packet_at or capture.uploaded_at) else None,
        "sessions": len(email),
        "metrics": metrics,
        "servers": servers,
        "finding_categories": categories,
    }


def _direction(before, after, better: str) -> str:
    if before is None or after is None:
        return "not_comparable"
    if abs(after - before) < 0.5:
        return "unchanged"
    improved = after > before if better == "higher" else after < before
    return "improved" if improved else "regressed"


def compare(baseline: dict, current: dict) -> dict:
    # --- Environment metrics -------------------------------------------------
    metric_rows = []
    for key, label, unit, better in METRICS:
        before = baseline["metrics"].get(key)
        after = current["metrics"].get(key)
        metric_rows.append({
            "key": key, "label": label, "unit": unit, "better": better,
            "baseline": before, "current": after,
            "delta": round(after - before, 1) if before is not None and after is not None else None,
            "direction": _direction(before, after, better),
        })

    # --- Servers -------------------------------------------------------------
    base_servers, cur_servers = baseline["servers"], current["servers"]
    server_rows = []
    for key in sorted(set(base_servers) | set(cur_servers)):
        before, after = base_servers.get(key), cur_servers.get(key)
        if before is None or after is None:
            server_rows.append({
                "server": key,
                "status": "added" if before is None else "removed",
                "changes": [],
                "baseline": before, "current": after,
            })
            continue

        changes = []
        for dim, (label, rank) in _SERVER_DIMENSIONS.items():
            old, new = before.get(dim), after.get(dim)
            if old == new or old is None or new is None:
                continue
            direction = "changed"
            if rank is not None:
                r_old, r_new = rank(old), rank(new)
                if r_old is not None and r_new is not None and r_old != r_new:
                    direction = "improved" if r_new > r_old else "regressed"
            changes.append({
                "dimension": dim, "label": label, "from": old, "to": new, "direction": direction,
            })

        status = "unchanged"
        if changes:
            dirs = {c["direction"] for c in changes}
            status = (
                "regressed" if "regressed" in dirs and "improved" not in dirs
                else "improved" if "improved" in dirs and "regressed" not in dirs
                else "mixed" if "regressed" in dirs
                else "changed"
            )
        server_rows.append({
            "server": key, "status": status, "changes": changes,
            "baseline": before, "current": after,
        })

    status_rank = {"regressed": 0, "mixed": 1, "changed": 2, "added": 3,
                   "removed": 4, "improved": 5, "unchanged": 6}
    server_rows.sort(key=lambda r: (status_rank[r["status"]], r["server"]))

    # --- Findings ------------------------------------------------------------
    base_cat, cur_cat = baseline["finding_categories"], current["finding_categories"]
    finding_rows = []
    for category in sorted(set(base_cat) | set(cur_cat)):
        before, after = base_cat.get(category), cur_cat.get(category)
        status = (
            "new" if before is None else "resolved" if after is None
            else "worse" if after["count"] > before["count"]
            else "better" if after["count"] < before["count"] else "persisting"
        )
        ref = after or before
        finding_rows.append({
            "category": category, "title": ref["title"], "severity": ref["severity"],
            "status": status,
            "baseline_count": before["count"] if before else 0,
            "current_count": after["count"] if after else 0,
        })
    finding_rows.sort(key=lambda r: (
        {"new": 0, "worse": 1, "persisting": 2, "better": 3, "resolved": 4}[r["status"]],
        SEVERITY_ORDER.get(r["severity"], 9),
    ))

    regressions = (
        sum(1 for m in metric_rows if m["direction"] == "regressed")
        + sum(1 for s in server_rows for c in s["changes"] if c["direction"] == "regressed")
        + sum(1 for f in finding_rows if f["status"] in ("new", "worse"))
    )
    improvements = (
        sum(1 for m in metric_rows if m["direction"] == "improved")
        + sum(1 for s in server_rows for c in s["changes"] if c["direction"] == "improved")
        + sum(1 for f in finding_rows if f["status"] in ("resolved", "better"))
    )
    neutral = sum(1 for s in server_rows for c in s["changes"] if c["direction"] == "changed")

    verdict = (
        "stable" if not (regressions or improvements or neutral)
        else "regressed" if regressions and not improvements
        else "improved" if improvements and not regressions
        else "mixed" if regressions
        else "changed"
    )

    return {
        "baseline": {k: baseline[k] for k in ("capture_id", "ref", "filename", "observed_at", "sessions")},
        "current": {k: current[k] for k in ("capture_id", "ref", "filename", "observed_at", "sessions")},
        "summary": {
            "verdict": verdict,
            "regressions": regressions,
            "improvements": improvements,
            "neutral_changes": neutral,
            "servers_compared": sum(1 for s in server_rows if s["status"] not in ("added", "removed")),
            "servers_added": sum(1 for s in server_rows if s["status"] == "added"),
            "servers_removed": sum(1 for s in server_rows if s["status"] == "removed"),
        },
        "metrics": metric_rows,
        "servers": server_rows,
        "findings": finding_rows,
        "method": (
            "Servers are matched on ip:port and compared on their dominant value per "
            "attribute. Direction is judged against published guidance (e.g. TLS 1.3 "
            "over 1.2, AEAD over legacy, hybrid PQC over classical). A change with no "
            "better/worse ordering, such as a new JA4S, is reported as neutral drift."
        ),
    }


def timeline(snapshots: list[dict]) -> dict:
    """Metric series across captures, oldest first, with step-by-step drift counts."""
    ordered = sorted(snapshots, key=lambda s: s["observed_at"] or "")
    steps = []
    for previous, current in zip(ordered, ordered[1:]):
        diff = compare(previous, current)
        steps.append({
            "from": previous["ref"], "to": current["ref"], **diff["summary"],
        })
    return {
        "metrics": [{"key": k, "label": l, "unit": u, "better": b} for k, l, u, b in METRICS],
        "points": [
            {k: s[k] for k in ("capture_id", "ref", "filename", "observed_at", "sessions")}
            | {"metrics": s["metrics"], "servers": len(s["servers"])}
            for s in ordered
        ],
        "steps": steps,
    }
