"""PQC readiness score and harvest-now-decrypt-later exposure.

The posture score answers "how secure is this traffic against today's
attacker". This answers the second question: "how much of it would survive an
attacker who records it now and decrypts it once a cryptographically relevant
quantum computer exists".

Everything here is read from cleartext handshake fields (supported_groups,
key_share, the selected group, the negotiated suite), so it is observable even
on TLS 1.3. Like the posture score, it ships with its formula and with each
component's evidence, and a component with no evidence is excluded, not
scored.

Exposure tiers, worst first:

    cleartext      readable today, quantum is irrelevant
    static_rsa     no forward secrecy: one recovered server key opens every
                   recorded session, classical or quantum
    classical      ephemeral (EC)DHE: each session needs its own break, which a
                   CRQC provides -- the textbook HNDL exposure
    pqc_hybrid     ML-KEM hybrid key exchange: resistant to Shor's algorithm
"""

from __future__ import annotations

from collections import Counter, defaultdict

from app.models.session import EmailSession
from app.protocols import CLEARTEXT_STATES

_CLEARTEXT = {s.value for s in CLEARTEXT_STATES}

TIERS = {
    "cleartext": {
        "label": "Cleartext",
        "risk": "critical",
        "explanation": "Readable by anyone on path today. PQC is irrelevant until this is encrypted.",
    },
    "static_rsa": {
        "label": "Static RSA (no forward secrecy)",
        "risk": "high",
        "explanation": (
            "One recovered server key decrypts every recorded session — the worst "
            "harvest-now-decrypt-later exposure."
        ),
    },
    "classical": {
        "label": "Classical ephemeral key exchange",
        "risk": "medium",
        "explanation": (
            "Forward secret against classical attackers; each session falls to a "
            "cryptographically relevant quantum computer (Shor)."
        ),
    },
    "pqc_hybrid": {
        "label": "PQC hybrid (ML-KEM)",
        "risk": "low",
        "explanation": "Key exchange includes ML-KEM (FIPS 203); resistant to known quantum attacks.",
    },
}

# Components of the readiness score and their weights.
_COMPONENTS = [
    ("pqc_key_exchange", "Hybrid PQC key exchange negotiated", 0.40),
    ("tls13", "TLS 1.3 negotiated (prerequisite for hybrid groups)", 0.20),
    ("client_capability", "Clients offering a PQC hybrid group", 0.15),
    ("forward_secrecy", "Ephemeral key exchange (limits blast radius of one key)", 0.15),
    ("encrypted", "Traffic encrypted at all", 0.10),
]

_NO_PQC_CEILING = 45

LEVELS = [
    (75, "ready", "Ready"),
    (50, "transitioning", "Transitioning"),
    (25, "early", "Early"),
    (0, "not_started", "Not started"),
]


def tier_of(session: EmailSession) -> str | None:
    if session.encryption_state in _CLEARTEXT:
        return "cleartext"
    if not session.tls_version:
        return None
    if session.tls_pqc_selected:
        return "pqc_hybrid"
    if session.tls_forward_secrecy is False:
        return "static_rsa"
    return "classical"


def _level(score: int | None) -> tuple[str, str] | tuple[None, None]:
    if score is None:
        return None, None
    for floor, key, label in LEVELS:
        if score >= floor:
            return key, label
    return LEVELS[-1][1], LEVELS[-1][2]


def assess(sessions: list[EmailSession]) -> dict:
    email = [s for s in sessions if s.protocol and not s.is_indeterminate]
    tls = [s for s in email if s.tls_version]
    kex_known = [s for s in tls if s.tls_forward_secrecy is not None]

    def pct(n: int, d: int) -> int | None:
        return round(100 * n / d) if d else None

    values = {
        "pqc_key_exchange": (sum(1 for s in tls if s.tls_pqc_selected), len(tls)),
        "tls13": (sum(1 for s in tls if s.tls_version == "TLS 1.3"), len(tls)),
        "client_capability": (sum(1 for s in tls if s.tls_pqc_offered), len(tls)),
        "forward_secrecy": (sum(1 for s in kex_known if s.tls_forward_secrecy), len(kex_known)),
        "encrypted": (
            sum(1 for s in email if s.encryption_state not in _CLEARTEXT), len(email)
        ),
    }

    components = []
    for key, label, weight in _COMPONENTS:
        good, total = values[key]
        score = pct(good, total)
        components.append(
            {
                "key": key,
                "label": label,
                "weight": weight,
                "score": score,
                "observed": good,
                "total": total,
                "assessed": score is not None,
            }
        )

    assessed = [c for c in components if c["assessed"]]
    weight = sum(c["weight"] for c in assessed)
    overall = round(sum(c["score"] * c["weight"] for c in assessed) / weight) if weight else None

    # Prerequisites are not migration. Without a single hybrid handshake the
    # estate has not started transitioning, however modern it is otherwise, so
    # the score is capped below that band -- the same worst-state rule the
    # posture score applies with finding ceilings.
    cap_note = None
    pqc_used, pqc_total = values["pqc_key_exchange"]
    if overall is not None and pqc_total and not pqc_used and overall > _NO_PQC_CEILING:
        overall = _NO_PQC_CEILING
        cap_note = (
            f"Capped at {_NO_PQC_CEILING}: no observed session negotiated a hybrid PQC "
            "group, so the prerequisites alone do not count as transitioning."
        )
    level_key, level_label = _level(overall)

    # --- Exposure --------------------------------------------------------------
    tiers = Counter(t for t in (tier_of(s) for s in email) if t)
    exposure = [
        {"tier": key, **meta, "sessions": tiers.get(key, 0),
         "pct": round(100 * tiers.get(key, 0) / len(email), 1) if email else 0.0}
        for key, meta in TIERS.items()
    ]
    hndl = tiers.get("static_rsa", 0) + tiers.get("classical", 0)

    # --- Per server ------------------------------------------------------------
    by_server: dict[str, list[EmailSession]] = defaultdict(list)
    for s in email:
        by_server[f"{s.server_ip}:{s.server_port}"].append(s)

    servers = []
    for key, rows in by_server.items():
        server_tiers = Counter(t for t in (tier_of(s) for s in rows) if t)
        server_tls = [s for s in rows if s.tls_version]
        groups = Counter(s.tls_selected_group for s in server_tls if s.tls_selected_group)
        worst = next((t for t in TIERS if server_tiers.get(t)), None)
        servers.append(
            {
                "server": key,
                "sessions": len(rows),
                "worst_tier": worst,
                "tiers": dict(server_tiers),
                "pqc_selected": sum(1 for s in server_tls if s.tls_pqc_selected),
                "clients_offering_pqc": sum(1 for s in server_tls if s.tls_pqc_offered),
                "tls13": sum(1 for s in server_tls if s.tls_version == "TLS 1.3"),
                "dominant_group": groups.most_common(1)[0][0] if groups else None,
                "migration_gap": bool(
                    any(s.tls_pqc_offered for s in server_tls)
                    and not any(s.tls_pqc_selected for s in server_tls)
                ),
            }
        )
    tier_rank = {t: i for i, t in enumerate(TIERS)}
    servers.sort(key=lambda r: (tier_rank.get(r["worst_tier"], 9), -r["sessions"]))

    actions = _actions(values, tiers, servers)

    return {
        "score": overall,
        "level": level_key,
        "level_label": level_label,
        "components": components,
        "formula": "sum(component x weight) / sum(weight), over components with evidence",
        "cap_note": cap_note,
        "exposure": exposure,
        "hndl_exposed_sessions": hndl,
        "hndl_exposed_pct": round(100 * hndl / len(email), 1) if email else None,
        "servers": servers,
        "actions": actions,
        "groups": _groups(sessions),
        "tls_versions": dict(Counter(s.tls_version for s in sessions if s.tls_version)),
        "framing": (
            "A migration-readiness measure, not a threat assessment. It reports how much "
            "observed traffic already uses quantum-resistant key exchange and what "
            "prevents the remainder from doing so."
        ),
        "standards": ["FIPS 203 (ML-KEM)", "CNSA 2.0", "NIST IR 8547", "RFC 8446"],
    }


def _groups(sessions: list[EmailSession]) -> list[dict]:
    """Key-exchange groups: how often clients offered each, how often servers chose it."""
    from app.tls.groups import PQC_HYBRID_GROUPS, name as group_name

    pqc_names = {group_name(g) for g in PQC_HYBRID_GROUPS}
    offered: Counter = Counter()
    selected: Counter = Counter()
    for s in sessions:
        detail = s.tls_detail or {}
        for g in set(detail.get("groups_offered") or []):
            offered[g] += 1
        if s.tls_selected_group:
            selected[s.tls_selected_group] += 1
    total = sum(1 for s in sessions if s.tls_version) or 1
    rows = [
        {
            "group": g,
            "pqc": g in pqc_names or "mlkem" in g.lower() or "kyber" in g.lower(),
            "offered": offered[g],
            "offered_pct": round(100 * offered[g] / total, 1),
            "selected": selected[g],
            "selected_pct": round(100 * selected[g] / total, 1),
        }
        for g in set(offered) | set(selected)
    ]
    rows.sort(key=lambda r: (not r["pqc"], -r["selected"], -r["offered"], r["group"]))
    return rows


def _actions(values: dict, tiers: Counter, servers: list[dict]) -> list[dict]:
    """Ordered migration steps, derived from what is actually blocking readiness."""
    actions = []
    if tiers.get("cleartext"):
        actions.append({
            "priority": 1,
            "title": "Encrypt the cleartext sessions first",
            "detail": f"{tiers['cleartext']} session(s) are readable today; PQC cannot help them.",
        })
    if tiers.get("static_rsa"):
        actions.append({
            "priority": 2,
            "title": "Remove static RSA key exchange",
            "detail": (
                f"{tiers['static_rsa']} session(s) lack forward secrecy. Restrict suites "
                "to ECDHE/TLS 1.3 so one key cannot unlock all recorded traffic."
            ),
        })
    tls13, total = values["tls13"]
    if total and tls13 < total:
        actions.append({
            "priority": 3,
            "title": "Move remaining servers to TLS 1.3",
            "detail": f"{total - tls13} of {total} handshakes were below TLS 1.3; hybrid groups need 1.3.",
        })
    gap = [s["server"] for s in servers if s["migration_gap"]]
    if gap:
        actions.append({
            "priority": 4,
            "title": "Enable X25519MLKEM768 on servers where clients are ready",
            "detail": f"Clients already offer hybrid PQC to {', '.join(gap[:5])} but the server declines.",
        })
    pqc, total = values["pqc_key_exchange"]
    if total and pqc < total and not gap:
        actions.append({
            "priority": 5,
            "title": "Enable hybrid PQC key exchange",
            "detail": "Deploy a TLS stack with ML-KEM hybrid groups (e.g. OpenSSL 3.5+, BoringSSL).",
        })
    return actions
