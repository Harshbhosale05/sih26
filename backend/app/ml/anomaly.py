"""Unsupervised anomaly detection over session feature vectors.

Where this sits in the product: **last**. Every finding that can be computed has
already been computed deterministically by the time this runs. Isolation Forest
adds one thing the rules cannot -- a multivariate view, catching sessions that
are unremarkable on every individual axis but unusual in combination.

Three constraints kept deliberately:

1. **It never produces a verdict.** Output is an anomaly score and a
   per-feature attribution, surfaced as context on findings that already exist.
   "Anomalous" is not "attack", and the UI says so.

2. **It refuses to run on samples too small to mean anything.** A capture with
   twelve sessions cannot support an outlier model; forcing one produces
   confident noise. Below the floor we return nothing and say why.

3. **Attribution is mandatory.** A score with no explanation is unusable to an
   analyst, so every scored session reports which features pushed it out.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.ml.features import FEATURE_NAMES, extract_features
from app.models.session import EmailSession

logger = logging.getLogger(__name__)

# Below this, an outlier model is not meaningful. Isolation Forest partitions
# the feature space; with a handful of points every point looks isolated.
MIN_SESSIONS_FOR_MODEL = 20

# Expected share of outliers. Kept low: we are looking for the unusual few, and
# a high contamination value manufactures anomalies to fill its quota.
CONTAMINATION = 0.08


@dataclass
class AnomalyResult:
    session_ref: str
    score: float           # 0.0 normal .. 1.0 most anomalous
    is_outlier: bool
    attribution: list[dict] = field(default_factory=list)

    def serialise(self) -> dict:
        return {
            "session_ref": self.session_ref,
            "anomaly_score": round(self.score, 3),
            "is_outlier": self.is_outlier,
            "attribution": self.attribution,
        }


@dataclass
class AnomalyReport:
    available: bool
    reason: str | None = None
    model: str | None = None
    sessions_scored: int = 0
    outliers: int = 0
    results: dict[str, AnomalyResult] = field(default_factory=dict)

    def serialise(self) -> dict:
        return {
            "available": self.available,
            "reason": self.reason,
            "model": self.model,
            "sessions_scored": self.sessions_scored,
            "outliers": self.outliers,
            "results": [r.serialise() for r in self.results.values()],
        }


def analyse(sessions: list[EmailSession]) -> AnomalyReport:
    usable = [s for s in sessions if not s.is_indeterminate and s.protocol]

    if len(usable) < MIN_SESSIONS_FOR_MODEL:
        return AnomalyReport(
            available=False,
            reason=(
                f"Only {len(usable)} assessable session(s) in this capture; an outlier "
                f"model needs at least {MIN_SESSIONS_FOR_MODEL} to be meaningful. "
                "Deterministic rules and baseline deviation still apply."
            ),
        )

    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return AnomalyReport(
            available=False,
            reason="scikit-learn is not installed in this environment.",
        )

    matrix = np.array([extract_features(s) for s in usable], dtype=float)

    # Constant columns carry no information and make attribution meaningless
    # (a zero-variance feature can't explain anything). Drop them, and report
    # against the surviving names.
    variance = matrix.var(axis=0)
    keep = variance > 1e-9
    if not keep.any():
        return AnomalyReport(
            available=False,
            reason="Every session in this capture has identical features; nothing to separate.",
        )

    reduced = matrix[:, keep]
    kept_names = [n for n, k in zip(FEATURE_NAMES, keep) if k]

    model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=42,   # deterministic: the same capture must score identically
        n_jobs=1,
    )
    model.fit(reduced)

    raw = model.score_samples(reduced)     # higher = more normal
    predictions = model.predict(reduced)   # -1 outlier, 1 inlier

    # Map to 0..1 where 1 is most anomalous, scaled within this capture.
    lo, hi = float(raw.min()), float(raw.max())
    span = (hi - lo) or 1.0

    # Attribution: how far each feature sits from the population median, in
    # median-absolute-deviation units. Robust to the outliers we are hunting,
    # unlike a mean/stddev z-score which they would themselves distort.
    median = np.median(reduced, axis=0)
    mad = np.median(np.abs(reduced - median), axis=0)
    mad[mad < 1e-9] = 1.0

    report = AnomalyReport(
        available=True,
        model=f"IsolationForest(n_estimators=200, contamination={CONTAMINATION})",
        sessions_scored=len(usable),
    )

    for index, session in enumerate(usable):
        score = 1.0 - ((raw[index] - lo) / span)
        is_outlier = bool(predictions[index] == -1)
        if is_outlier:
            report.outliers += 1

        deviations = np.abs(reduced[index] - median) / mad
        top = np.argsort(deviations)[::-1][:4]
        attribution = [
            {
                "feature": kept_names[i],
                "value": round(float(reduced[index][i]), 3),
                "population_median": round(float(median[i]), 3),
                "deviation_mad": round(float(deviations[i]), 2),
            }
            for i in top
            if deviations[i] > 1.0
        ]

        report.results[session.ref] = AnomalyResult(
            session_ref=session.ref,
            score=float(score),
            is_outlier=is_outlier,
            attribution=attribution,
        )

    return report
