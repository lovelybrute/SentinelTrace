from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from common import augment_text, read_jsonl


def metrics(y_true, y_pred, labels):
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_macro": round(float(precision_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0),
    }


def phishing_probabilities(pipeline, texts):
    classes = [str(label) for label in pipeline.classes_]
    if "PHISHING" not in classes:
        raise ValueError("The trained classifier must expose a PHISHING class.")
    return pipeline.predict_proba(texts)[:, classes.index("PHISHING")]


def calibrate_triage_thresholds(y_true, probabilities, max_fpr=0.10, max_fnr=0.02):
    """Choose conservative triage thresholds using calibration data only."""
    truth = np.asarray([str(label) for label in y_true])
    probs = np.asarray(probabilities, dtype=float)
    benign = truth == "LEGITIMATE"
    phishing = truth == "PHISHING"
    if not benign.any() or not phishing.any():
        raise ValueError("Calibration requires both LEGITIMATE and PHISHING records.")

    high_candidates = np.arange(0.50, 0.991, 0.01)
    eligible_high = [
        float(t) for t in high_candidates
        if float(np.mean(probs[benign] >= t)) <= max_fpr
    ]
    high = min(eligible_high) if eligible_high else 0.99

    low_candidates = np.arange(0.01, max(0.02, high - 0.04), 0.01)
    eligible_low = [
        float(t) for t in low_candidates
        if float(np.mean(probs[phishing] <= t)) <= max_fnr
    ]
    low = max(eligible_low) if eligible_low else 0.01
    if low >= high:
        low = max(0.01, high - 0.05)
    return round(low, 2), round(high, 2)


def triage_metrics(y_true, probabilities, low, high):
    truth = np.asarray([str(label) for label in y_true])
    probs = np.asarray(probabilities, dtype=float)
    verdicts = np.where(probs >= high, "PHISHING", np.where(probs <= low, "LEGITIMATE", "NEEDS_REVIEW"))
    auto = verdicts != "NEEDS_REVIEW"
    benign = truth == "LEGITIMATE"
    phishing = truth == "PHISHING"
    return {
        "legitimate_threshold": low,
        "phishing_threshold": high,
        "review_records": int(np.sum(~auto)),
        "review_rate": round(float(np.mean(~auto)), 4),
        "automatic_coverage": round(float(np.mean(auto)), 4),
        "automatic_decision_accuracy": round(float(np.mean(verdicts[auto] == truth[auto])), 4) if auto.any() else None,
        "benign_auto_flag_rate": round(float(np.mean(verdicts[benign] == "PHISHING")), 4),
        "phishing_auto_miss_rate": round(float(np.mean(verdicts[phishing] == "LEGITIMATE")), 4),
        "verdict_distribution": dict(Counter(verdicts.tolist())),
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Train, calibrate and evaluate SentinelTrace phishing models")
    p.add_argument("--dataset", type=Path, default=Path("ml/datasets/prepared.jsonl"))
    p.add_argument("--artifacts", type=Path, default=Path("ml/artifacts"))
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--calibration-size", type=float, default=0.15, help="Fraction of the development partition reserved for calibration")
    p.add_argument("--max-calibration-fpr", type=float, default=0.10)
    p.add_argument("--max-calibration-fnr", type=float, default=0.02)
    p.add_argument("--dataset-name", default="User-supplied labeled corpus")
    p.add_argument("--dataset-citation", default="Not supplied")
    p.add_argument(
        "--label-scope",
        default="Labels are accepted as supplied; independently verify their taxonomy before deployment.",
    )
    args = p.parse_args()
    rows = read_jsonl(args.dataset)
    texts, labels = [augment_text(r["text"]) for r in rows], [r["label"] for r in rows]
    sources = Counter(str(r.get("source") or "unknown") for r in rows)
    classes = sorted(set(labels))
    if classes != ["LEGITIMATE", "PHISHING"] or min(labels.count(c) for c in classes) < 10:
        raise SystemExit("Need LEGITIMATE and PHISHING labels with ten deduplicated records per label.")

    x_dev, x_test, y_dev, y_test = train_test_split(
        texts, labels, test_size=args.test_size, stratify=labels, random_state=42
    )
    x_fit, x_cal, y_fit, y_cal = train_test_split(
        x_dev, y_dev, test_size=args.calibration_size, stratify=y_dev, random_state=43
    )
    candidates = {
        "logistic_regression": LogisticRegression(max_iter=1500, class_weight="balanced", random_state=42),
        "sgd_log_loss": SGDClassifier(loss="log_loss", class_weight="balanced", random_state=42, max_iter=2000),
    }
    calibration_results, fitted = {}, {}
    for name, classifier in candidates.items():
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=75000, sublinear_tf=True)),
            ("classifier", classifier),
        ])
        pipe.fit(x_fit, y_fit)
        fitted[name] = pipe
        calibration_results[name] = metrics(y_cal, pipe.predict(x_cal), classes)

    winner = max(calibration_results, key=lambda name: calibration_results[name]["f1_macro"])
    selected = fitted[winner]
    low, high = calibrate_triage_thresholds(
        y_cal,
        phishing_probabilities(selected, x_cal),
        max_fpr=args.max_calibration_fpr,
        max_fnr=args.max_calibration_fnr,
    )
    test_results = metrics(y_test, selected.predict(x_test), classes)
    test_triage = triage_metrics(y_test, phishing_probabilities(selected, x_test), low, high)

    test_counts = {label: y_test.count(label) for label in classes}
    validation_status = "VALIDATED_HOLDOUT" if len(y_test) >= 200 and min(test_counts.values()) >= 50 else "PROTOTYPE_HOLDOUT"
    report = {
        "validation_status": validation_status,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        "dataset_records": len(rows),
        "dataset_name": args.dataset_name,
        "dataset_citation": args.dataset_citation,
        "source_distribution": dict(sorted(sources.items())),
        "label_scope": args.label_scope,
        "train_records": len(y_fit),
        "calibration_records": len(y_cal),
        "test_records": len(y_test),
        "labels": classes,
        "test_class_distribution": test_counts,
        "split": {
            "method": "deduplicated stratified fit/calibration/test",
            "fit_random_state": 42,
            "calibration_random_state": 43,
            "test_size": args.test_size,
            "calibration_size_of_development": args.calibration_size,
            "external_evaluation_used": False,
        },
        "selected_model": winner,
        "feature_contract": "sentineltrace_text_v1",
        "models": {winner: test_results},
        "candidate_calibration_metrics": calibration_results,
        "decision_policy": {
            "status": "CALIBRATED_TRIAGE",
            "verdicts": ["LEGITIMATE", "NEEDS_REVIEW", "PHISHING"],
            "thresholds": {"legitimate_max": low, "phishing_min": high},
            "targets": {
                "maximum_calibration_benign_auto_flag_rate": args.max_calibration_fpr,
                "maximum_calibration_phishing_auto_miss_rate": args.max_calibration_fnr,
            },
            "calibration_metrics": triage_metrics(y_cal, phishing_probabilities(selected, x_cal), low, high),
            "untouched_test_metrics": test_triage,
            "calibration_data_scope": "Training corpus calibration partition only; independent evaluation corpora are prohibited.",
        },
        "limitations": (
            "Thresholds and holdout results apply only to the supplied training corpus. NEEDS_REVIEW is intentional "
            "abstention, not an error. Independent cross-dataset and recent real-world validation remain required."
        ),
    }
    args.artifacts.mkdir(parents=True, exist_ok=True)
    model_path = args.artifacts / "phishing_model.joblib"
    joblib.dump({"pipeline": selected, "metadata": report}, model_path)
    (args.artifacts / "phishing_model.joblib.sha256").write_text(
        hashlib.sha256(model_path.read_bytes()).hexdigest() + "\n", encoding="ascii"
    )
    (args.artifacts / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
