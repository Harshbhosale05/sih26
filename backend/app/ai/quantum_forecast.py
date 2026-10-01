"""Quantum risk forecast (Mosca's inequality).

Michele Mosca's rule states that data protected today is at risk if

    X + Y > Z

    X  how long the data must stay confidential (shelf life)
    Y  how long migrating to quantum-safe cryptography will take
    Z  time until a cryptographically relevant quantum computer (CRQC) exists

Email is the textbook case: messages are retained and stay sensitive for
years, so traffic recorded *today* with classical key exchange may be
decryptable within its own confidentiality period.

This module applies the inequality to what the capture actually shows:

  * each session's key-exchange tier (hybrid PQC / classical ephemeral /
    static RSA / cleartext) decides whether a CRQC is needed to read it at all;
  * Y is derived from the remediation plan for the observed servers (effort of
    the TLS 1.3 and hybrid-PQC changes still required), not assumed;
  * Z is not predicted. Three published expert-opinion scenarios are shown
    side by side, and the user can change X.

Outputs a verdict per scenario, the year each tier becomes readable, and the
share of today's sessions still inside their shelf life at that point.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.session import EmailSession
from app.pqc.readiness import tier_of

# Expert-opinion scenarios for the arrival of a CRQC able to break RSA-2048 /
# ECC-256. Illustrative planning horizons drawn from the Global Risk Institute
# Quantum Threat Timeline Report (2023/2024) and national migration deadlines
# (NSA CNSA 2.0 targets 2030-2033; NIST IR 8547 deprecates classical public-key
# algorithms by 2030 and disallows them by 2035).
SCENARIOS = [
    {"key": "early", "label": "Early", "year": 2030,
     "basis": "Pessimistic planning horizon; aligned with NIST IR 8547 deprecation (2030)."},
    {"key": "median", "label": "Median", "year": 2035,
     "basis": "Midpoint of expert estimates; NIST IR 8547 disallows classical key exchange from 2035."},
    {"key": "late", "label": "Late", "year": 2040,
     "basis": "Optimistic horizon; many experts still assign substantial probability before this date."},
]

TIER_LABEL = {
    "cleartext": "Cleartext",
    "static_rsa": "Static RSA (no forward secrecy)",
    "classical": "Classical ephemeral key exchange",
    "pqc_hybrid": "Hybrid post-quantum (ML-KEM)",
}

# Years to complete each migration step, by planner effort (1 low .. 3 high).
_EFFORT_YEARS = {1: 0.5, 2: 1.0, 3: 2.0}


def _migration_years(sessions: list[EmailSession], plan_steps: list[dict] | None) -> tuple[float, list[dict]]:
    """Y: time to reach quantum-safe key exchange on every observed server."""
    tls = [s for s in sessions if s.tls_version]
    parts: list[dict] = []
    if any(s.encryption_state not in ("TLS_ESTABLISHED", "IMPLICIT_TLS") for s in sessions if s.protocol):
        parts.append({"step": "Encrypt all sessions (enforce TLS)", "years": _EFFORT_YEARS[1]})
    if any(s.tls_version != "TLS 1.3" for s in tls):
        parts.append({"step": "Move remaining servers to TLS 1.3", "years": _EFFORT_YEARS[2]})
    if any(not s.tls_pqc_selected for s in tls):
        effort = next((st.get("effort", 3) for st in (plan_steps or []) if st.get("fix_id") == "enable_hybrid_pqc"), 3)
        parts.append({"step": "Deploy hybrid ML-KEM key exchange (OpenSSL 3.5+)", "years": _EFFORT_YEARS.get(effort, 2.0)})
    if any(not s.tls_pqc_offered for s in tls):
        parts.append({"step": "Upgrade clients that do not offer hybrid groups", "years": _EFFORT_YEARS[2]})
    # Steps overlap in practice; take the longest chain as the critical path.
    return (max((p["years"] for p in parts), default=0.0) + 0.5 * max(0, len(parts) - 1)), parts


def forecast(
    sessions: list[EmailSession],
    captured_at: datetime | None,
    shelf_life_years: float = 10.0,
    plan_steps: list[dict] | None = None,
) -> dict:
    email = [s for s in sessions if s.protocol]
    now = datetime.now(timezone.utc)
    capture_year = (captured_at or now).year + ((captured_at or now).timetuple().tm_yday / 366)
    today = now.year + now.timetuple().tm_yday / 366

    tiers: dict[str, int] = {k: 0 for k in TIER_LABEL}
    for s in email:
        t = tier_of(s)
        if t in tiers:
            tiers[t] += 1
    total = len(email) or 1
    quantum_exposed = tiers["classical"] + tiers["static_rsa"] + tiers["cleartext"]

    y_years, y_parts = _migration_years(email, plan_steps)
    x = float(shelf_life_years)
    secret_until = capture_year + x

    rows = []
    for sc in SCENARIOS:
        z_from_today = sc["year"] - today
        mosca_at_risk = x + y_years > z_from_today
        captured_exposed = secret_until > sc["year"]
        rows.append({
            **sc,
            "years_from_today": round(z_from_today, 1),
            "x_plus_y": round(x + y_years, 1),
            "mosca_verdict": "Act now" if mosca_at_risk else "Within margin",
            "mosca_margin_years": round(z_from_today - (x + y_years), 1),
            "captured_traffic_at_risk": captured_exposed,
            "exposed_sessions": quantum_exposed if captured_exposed else tiers["cleartext"] + tiers["static_rsa"],
            "exposed_pct": round(100 * (quantum_exposed if captured_exposed else tiers["cleartext"] + tiers["static_rsa"]) / total, 1),
            "years_of_exposure": round(max(0.0, secret_until - sc["year"]), 1),
        })

    readable_when = {
        "cleartext": "Now — readable by anyone on the path",
        "static_rsa": "On compromise of the server private key, or on CRQC arrival",
        "classical": "On CRQC arrival",
        "pqc_hybrid": "Not by a quantum computer alone (ML-KEM protects the key exchange)",
    }
    return {
        "shelf_life_years": x,
        "captured_year": round(capture_year, 2),
        "confidential_until": round(secret_until, 1),
        "migration_years": round(y_years, 1),
        "migration_steps": y_parts,
        "tiers": [
            {"tier": k, "label": v, "sessions": tiers[k], "pct": round(100 * tiers[k] / total, 1), "readable": readable_when[k]}
            for k, v in TIER_LABEL.items()
        ],
        "scenarios": rows,
        "summary": (
            f"Traffic in this capture must stay confidential until {secret_until:.0f} (shelf life {x:g} years). "
            f"Migration to quantum-safe key exchange is estimated at {y_years:.1f} years. "
            + (
                f"{quantum_exposed} of {len(email)} sessions rely on classical key exchange and would still be "
                f"within their confidentiality period if a quantum computer arrives in {SCENARIOS[1]['year']}."
                if quantum_exposed and secret_until > SCENARIOS[1]["year"]
                else "No classical session remains confidential beyond the median scenario."
            )
        ),
        "method": (
            "Mosca's inequality X + Y > Z. X is the data shelf life (adjustable). Y is estimated from the "
            "remaining migration steps for the observed servers. Z is shown for three published planning "
            "scenarios rather than predicted. Session tiers come from the negotiated key exchange."
        ),
        "sources": [
            "M. Mosca, 'Cybersecurity in an era with quantum computers: will we be ready?', IEEE S&P 2018",
            "Global Risk Institute, Quantum Threat Timeline Report",
            "NIST IR 8547 (draft), Transition to Post-Quantum Cryptography Standards",
            "NSA CNSA 2.0",
        ],
    }
