"""Train the session risk classifier on the labelled corpus.

    python -m app.ml.train_risk --corpus /testbed/output/corpus --out /out

Runs every corpus pcap through the *production* reconstruction pipeline, so
the model is trained on exactly the features it will see at inference time,
then joins each reconstructed session with its generator label by ref.

Outputs a joblib artifact and a JSON model card with held-out metrics,
cross-validation, confusion matrix and feature importances.
"""

from __future__ import annotations

import argparse
import json
import struct
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from app.ml.features import RISK_FEATURE_LABELS, RISK_FEATURE_NAMES, risk_features
from app.ml.risk import RISK_CLASSES


def _first_packet_time(pcap: Path) -> datetime:
    with pcap.open("rb") as fh:
        header = fh.read(24)
        magic = header[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        ts_sec, ts_frac = struct.unpack(endian + "II", fh.read(8))
    return datetime.fromtimestamp(ts_sec + ts_frac / 1e6, tz=timezone.utc)


def load_corpus(corpus: Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    from app.services.analysis import AnalysisSummary, reconstruct_sessions

    X, y, refs = [], [], []
    for pcap in sorted(corpus.glob("corpus-*.pcap")):
        labels = json.loads((corpus / f"{pcap.stem}.labels.json").read_text())
        sessions = reconstruct_sessions(pcap, _first_packet_time(pcap), AnalysisSummary())
        matched = 0
        for s in sessions:
            label = labels.get(s.ref)
            if label is None or s.is_indeterminate:
                continue
            X.append(risk_features(s))
            y.append(label["risk_index"])
            refs.append(f"{pcap.stem}/{s.ref}")
            matched += 1
        print(f"{pcap.name}: {len(sessions)} sessions reconstructed, {matched} labelled")
    return np.array(X, dtype=float), np.array(y, dtype=int), refs


def train(corpus: Path, out: Path, seed: int = 42) -> dict:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.inspection import permutation_importance
    from sklearn.metrics import classification_report, confusion_matrix, f1_score
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    import joblib
    import sklearn

    X, y, _ = load_corpus(corpus)
    print(f"training rows: {len(y)}")

    def make():
        return GradientBoostingClassifier(
            n_estimators=250, max_depth=3, learning_rate=0.08, subsample=0.9, random_state=seed,
        )

    cv = cross_val_score(make(), X, y, cv=StratifiedKFold(5, shuffle=True, random_state=seed),
                         scoring="f1_macro")

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=seed)
    holdout = make().fit(X_tr, y_tr)
    pred = holdout.predict(X_te)
    labels = sorted(set(y))
    report = classification_report(
        y_te, pred, labels=labels, target_names=[RISK_CLASSES[i] for i in labels],
        output_dict=True, zero_division=0,
    )
    perm = permutation_importance(holdout, X_te, y_te, n_repeats=8, random_state=seed,
                                  scoring="f1_macro")

    # Final model on everything.
    model = make().fit(X, y)

    # Healthy reference for occlusion explanations: the per-feature median of
    # sessions labelled minimal risk.
    reference = np.median(X[y == 0], axis=0).tolist()

    importances = sorted(
        (
            {
                "feature": name,
                "label": RISK_FEATURE_LABELS.get(name, name),
                "gain_importance": round(float(g), 4),
                "permutation_importance": round(float(p), 4),
            }
            for name, g, p in zip(RISK_FEATURE_NAMES, model.feature_importances_, perm.importances_mean)
        ),
        key=lambda r: -r["permutation_importance"] - r["gain_importance"],
    )

    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    card = {
        "name": "SecureMailScope session risk classifier",
        "version": datetime.now(timezone.utc).strftime("%Y.%m.%d"),
        "algorithm": "Gradient-boosted decision trees (scikit-learn GradientBoostingClassifier, "
                     "250 trees, depth 3)",
        "sklearn_version": sklearn.__version__,
        "classes": RISK_CLASSES,
        "features": len(RISK_FEATURE_NAMES),
        "training_rows": int(len(y)),
        "class_counts": {RISK_CLASSES[i]: int((y == i).sum()) for i in labels},
        "labelling": manifest.get("labelling"),
        "evaluation": {
            "cv_macro_f1_mean": round(float(cv.mean()), 4),
            "cv_macro_f1_std": round(float(cv.std()), 4),
            "cv_folds": 5,
            "holdout_rows": int(len(y_te)),
            "holdout_accuracy": round(float((pred == y_te).mean()), 4),
            "holdout_macro_f1": round(float(f1_score(y_te, pred, average="macro")), 4),
            "per_class": {
                k: {m: round(float(v), 3) for m, v in vals.items()}
                for k, vals in report.items() if k in RISK_CLASSES
            },
            "confusion_matrix": {
                "labels": [RISK_CLASSES[i] for i in labels],
                "matrix": confusion_matrix(y_te, pred, labels=labels).tolist(),
            },
        },
        "feature_importance": importances,
        "explanation_method": (
            "Exact Shapley values over risk-factor groups. Each applicable group (e.g. "
            "certificate validity, cipher strength, cleartext credentials) is reset to a "
            "consistent healthy state across every coalition; attributions sum exactly to the "
            "session's expected severity above its own healthy baseline."
        ),
        "limitations": [
            "Trained on synthetic sessions from the SecureMailScope lab generator. Accuracy "
            "on held-out synthetic data does not transfer one-to-one to production traffic.",
            "The classifier ranks and contextualises. Every verdict still comes from a "
            "deterministic, standards-cited rule.",
            "Sessions whose evidence is incomplete are not classified.",
        ],
    }

    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": model, "feature_names": RISK_FEATURE_NAMES, "reference": reference,
         "classes": RISK_CLASSES},
        out / "risk_model.joblib", compress=3,
    )
    (out / "risk_model.json").write_text(json.dumps(card, indent=2) + "\n")
    return card


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    card = train(args.corpus, args.out)
    print(json.dumps(card["evaluation"] | {"top_features": card["feature_importance"][:8]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
