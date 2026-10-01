"""Session risk classification — SecureMailScope's own supervised model.

Where it sits: beside the rule engine, never in place of it. Rules decide
verdicts (a TLS 1.0 handshake *is* deprecated). The classifier answers a
different question an analyst asks when triaging hundreds of sessions: *taking
everything observable about this session together, how risky is it?* -- one
calibrated class and a 0-100 score, so sessions can be ranked and compared.

Trained offline (app/ml/train_risk.py) on a labelled corpus whose labels come
from the generator's true configuration, not from our rules. Ships as a small
artifact with a model card: metrics on held-out data, feature importances and
the labelling method, so nobody has to take the number on trust.

Explanations are exact Shapley values over risk-factor groups (see _groups):
"Credentials in cleartext: +1.0" reads as "this factor accounts for one
severity level of this session's risk", and the drivers sum exactly to the
risk above the session's own healthy baseline. No black box.
"""

from __future__ import annotations

from app.ml.runtime import native

import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from app.ml.features import RISK_FEATURE_LABELS, RISK_FEATURE_NAMES, risk_features
from app.models.session import EmailSession

logger = logging.getLogger(__name__)

ARTIFACT_DIR = Path(__file__).parent / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "risk_model.joblib"
CARD_PATH = ARTIFACT_DIR / "risk_model.json"

RISK_CLASSES = ["minimal", "low", "medium", "high", "critical"]


@dataclass
class RiskResult:
    session_ref: str
    risk_class: str
    confidence: float
    score: float                       # 0..100, expected severity scaled
    probabilities: dict[str, float]
    drivers: list[dict] = field(default_factory=list)
    baseline: float | None = None      # expected severity with every risk group reset

    def serialise(self) -> dict:
        return {
            "session_ref": self.session_ref,
            "risk_class": self.risk_class,
            "confidence": round(self.confidence, 3),
            "score": round(self.score, 1),
            "probabilities": {k: round(v, 3) for k, v in self.probabilities.items()},
            "drivers": self.drivers,
            "baseline_severity": self.baseline,
            "baseline_class": (
                RISK_CLASSES[min(round(self.baseline), len(RISK_CLASSES) - 1)]
                if self.baseline is not None else None
            ),
        }


@lru_cache(maxsize=1)
def _artifact() -> dict | None:
    if not MODEL_PATH.exists():
        logger.info("risk model artifact not found at %s", MODEL_PATH)
        return None
    try:
        import joblib

        artifact = joblib.load(MODEL_PATH)
    except Exception as exc:  # noqa: BLE001 - a bad artifact must not break analysis
        logger.warning("could not load risk model: %s", exc)
        return None
    if artifact.get("feature_names") != RISK_FEATURE_NAMES:
        logger.warning("risk model feature schema differs from code; retrain required")
        return None
    return artifact


def model_card() -> dict:
    if not CARD_PATH.exists():
        return {"available": False, "reason": "Risk model has not been trained. Run `make train`."}
    card = json.loads(CARD_PATH.read_text())
    card["available"] = _artifact() is not None
    return card


def available() -> bool:
    return _artifact() is not None


_IDX = {name: i for i, name in enumerate(RISK_FEATURE_NAMES)}


def _groups(x: list[float]) -> list[dict]:
    """Risk-factor groups that apply to this session, each with a consistent
    healthy state to reset to.

    Features are reset in groups, never one at a time: TLS 1.3 hides the
    certificate, so "this session but TLS 1.3" with certificate features still
    set is a combination the model has never seen and would answer arbitrarily.
    Each group's healthy state is one a real session could be in. Structural
    facts (protocol, port, whether a certificate was observable) are context,
    not risk, and are never reset.
    """
    v = {name: x[i] for name, i in _IDX.items()}
    groups: list[dict] = []

    def group(key: str, label: str, detail: str, healthy: dict[str, float]) -> None:
        changes = {_IDX[k]: val for k, val in healthy.items() if v[k] != val}
        if changes:
            groups.append({"key": key, "label": label, "detail": detail, "reset": changes})

    if not v["tls_established"]:
        group("cleartext_transport", "Cleartext transport", "session never established TLS", {
            "tls_established": 1, "upgrade_advertised": 1, "upgrade_requested": 1,
            "tls_version_rank": 4, "forward_secrecy": 1, "aead": 1, "cipher_key_bits": 256,
            "cleartext_mail": 0,
        })
        group("cleartext_credentials", "Credentials in cleartext", "AUTH / LOGIN / USER-PASS before TLS",
              {"cleartext_auth": 0})
        group("starttls_integrity", "STARTTLS tampering or refusal",
              "capability mangled in transit or upgrade refused",
              {"upgrade_mangled": 0, "upgrade_rejected": 0})
        return groups

    rank = v["tls_version_rank"]
    group("protocol_version", "Deprecated TLS version",
          {1: "SSL 3.0", 2: "TLS 1.0", 3: "TLS 1.1"}.get(int(rank), "") + " negotiated",
          {"tls_version_rank": max(rank, 4)})
    group("cipher", "Weak cipher / no forward secrecy",
          "static RSA, CBC, 3DES or RC4 negotiated",
          {"forward_secrecy": 1, "aead": 1, "cipher_weakness_count": 0,
           "cipher_key_bits": max(v["cipher_key_bits"], 128)})
    if v["cert_observable"]:
        group("cert_validity", "Certificate validity", "expired, not yet valid or near expiry", {
            "cert_expired": 0, "cert_not_yet_valid": 0, "cert_days_to_expiry": max(v["cert_days_to_expiry"], 365),
        })
        group("cert_strength", "Certificate key / signature", "weak key or broken signature hash", {
            "cert_weak_key": 0, "cert_broken_signature": 0, "cert_key_bits": max(v["cert_key_bits"], 3072),
        })
        group("cert_identity", "Certificate identity / chain", "hostname mismatch, self-signed or broken chain", {
            "cert_hostname_mismatch": 0, "cert_self_signed": 0, "cert_chain_incomplete": 0, "cert_chain_invalid": 0,
        })
    return groups


def _classify_impl(sessions: list[EmailSession]) -> dict[str, RiskResult]:
    """Risk class, score and Shapley-attributed drivers for each session.

    Drivers are exact Shapley values over the applicable risk-factor groups
    (at most five, so at most 32 coalitions per session, all predicted in one
    batch). They sum exactly to the session's expected severity above its own
    healthy baseline -- the same session with every risk group reset.
    """
    artifact = _artifact()
    usable = [s for s in sessions if s.protocol and not s.is_indeterminate]
    if artifact is None or not usable:
        return {}

    from itertools import combinations
    from math import factorial

    import numpy as np

    model = artifact["model"]
    classes = [int(c) for c in model.classes_]
    severity = np.array(classes, dtype=float)

    X = [risk_features(s) for s in usable]
    rows: list[list[float]] = []
    plans = []
    for x in X:
        groups = _groups(x)
        k = len(groups)
        coalitions = [frozenset(c) for r in range(k + 1) for c in combinations(range(k), r)]
        offset = len(rows)
        for coalition in coalitions:
            row = list(x)
            for g in coalition:
                for f, val in groups[g]["reset"].items():
                    row[f] = val
            rows.append(row)
        plans.append((groups, coalitions, offset))

    proba = model.predict_proba(np.array(rows, dtype=float))
    expected = proba @ severity

    results: dict[str, RiskResult] = {}
    for session, (groups, coalitions, offset) in zip(usable, plans):
        k = len(groups)
        value = {c: float(expected[offset + i]) for i, c in enumerate(coalitions)}
        p = proba[offset]  # the empty coalition: the session as observed
        top = int(np.argmax(p))
        e = value[frozenset()]
        baseline = value[frozenset(range(k))]

        drivers = []
        for g in range(k):
            phi = 0.0
            others = [i for i in range(k) if i != g]
            for r in range(len(others) + 1):
                weight = factorial(r) * factorial(k - r - 1) / factorial(k)
                for subset in combinations(others, r):
                    s_ = frozenset(subset)
                    phi += weight * (value[s_] - value[s_ | {g}])
            if abs(phi) >= 0.02:
                drivers.append({
                    "feature": groups[g]["key"],
                    "label": groups[g]["label"],
                    "detail": groups[g]["detail"],
                    "features": [RISK_FEATURE_LABELS[RISK_FEATURE_NAMES[f]] for f in groups[g]["reset"]],
                    "impact": round(phi, 2),
                })
        drivers.sort(key=lambda d: -abs(d["impact"]))
        results[session.ref] = RiskResult(
            session_ref=session.ref,
            risk_class=RISK_CLASSES[classes[top]],
            confidence=float(p[top]),
            score=100.0 * e / (len(RISK_CLASSES) - 1),
            probabilities={RISK_CLASSES[c]: float(p[j]) for j, c in enumerate(classes)},
            drivers=drivers,
            baseline=round(baseline, 2),
        )
    return results


def classify(sessions: list[EmailSession]) -> dict[str, RiskResult]:
    """Risk class, score and drivers per session (runs on the ML thread)."""
    return native(_classify_impl, sessions)


def apply(sessions: list[EmailSession]) -> dict[str, RiskResult]:
    """Classify and write results onto the session rows."""
    results = classify(sessions)
    for session in sessions:
        r = results.get(session.ref)
        session.risk_class = r.risk_class if r else None
        session.risk_score = r.score if r else None
        session.risk_confidence = r.confidence if r else None
        session.risk_detail = r.serialise() if r else None
    return results


def capture_index(results: dict[str, RiskResult]) -> dict | None:
    """Capture-level roll-up: distribution plus a tail-weighted index.

    The index weights the riskiest decile heavily: a mail estate with 95 clean
    sessions and 5 credential leaks is not "mostly fine", so a plain mean would
    understate it the same way the posture score's ceilings guard against.
    """
    if not results:
        return None
    scores = sorted((r.score for r in results.values()), reverse=True)
    k = max(1, len(scores) // 10)
    tail = sum(scores[:k]) / k
    mean = sum(scores) / len(scores)
    distribution = {c: 0 for c in RISK_CLASSES}
    for r in results.values():
        distribution[r.risk_class] += 1
    return {
        "index": round(0.6 * tail + 0.4 * mean, 1),
        "mean_score": round(mean, 1),
        "tail_score": round(tail, 1),
        "distribution": distribution,
        "sessions": len(results),
        "formula": "0.6 × mean score of riskiest 10% + 0.4 × mean score of all sessions",
    }
