from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

import joblib
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


def main() -> None:
    p = argparse.ArgumentParser(description="Train and evaluate SentinelTrace phishing models")
    p.add_argument("--dataset", type=Path, default=Path("ml/datasets/prepared.jsonl"))
    p.add_argument("--artifacts", type=Path, default=Path("ml/artifacts"))
    p.add_argument("--test-size", type=float, default=0.2)
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
    if len(classes) < 2 or min(labels.count(c) for c in classes) < 5:
        raise SystemExit("Need at least two labels and five deduplicated records per label.")
    x_train, x_test, y_train, y_test = train_test_split(texts, labels, test_size=args.test_size, stratify=labels, random_state=42)
    candidates = {
        "logistic_regression": LogisticRegression(max_iter=1500, class_weight="balanced", random_state=42),
        "sgd_log_loss": SGDClassifier(loss="log_loss", class_weight="balanced", random_state=42, max_iter=2000),
    }
    results, fitted = {}, {}
    for name, classifier in candidates.items():
        pipe = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=75000, sublinear_tf=True)), ("classifier", classifier)])
        pipe.fit(x_train, y_train)
        fitted[name] = pipe
        results[name] = metrics(y_test, pipe.predict(x_test), classes)
    winner = max(results, key=lambda name: results[name]["f1_macro"])
    test_counts = {label: y_test.count(label) for label in classes}
    validation_status = "VALIDATED_HOLDOUT" if len(y_test) >= 200 and min(test_counts.values()) >= 50 else "PROTOTYPE_HOLDOUT"
    dataset_sha = hashlib.sha256(args.dataset.read_bytes()).hexdigest()
    report = {
        "validation_status": validation_status,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": dataset_sha,
        "dataset_records": len(rows),
        "dataset_name": args.dataset_name,
        "dataset_citation": args.dataset_citation,
        "source_distribution": dict(sorted(sources.items())),
        "label_scope": args.label_scope,
        "train_records": len(y_train),
        "test_records": len(y_test),
        "labels": classes,
        "test_class_distribution": test_counts,
        "split": {"method": "deduplicated stratified holdout", "random_state": 42, "test_size": args.test_size},
        "selected_model": winner,
        "feature_contract": "sentineltrace_text_v1",
        "models": results,
        "limitations": (
            "Holdout results apply only to the supplied corpus. Random holdout can overestimate "
            "generalization when messages share corpus-specific patterns; independent cross-dataset "
            "and recent real-world validation remain required."
        ),
    }
    args.artifacts.mkdir(parents=True, exist_ok=True)
    model_path = args.artifacts / "phishing_model.joblib"
    joblib.dump({"pipeline": fitted[winner], "metadata": report}, model_path)
    (args.artifacts / "phishing_model.joblib.sha256").write_text(
        hashlib.sha256(model_path.read_bytes()).hexdigest() + "\n", encoding="ascii"
    )
    (args.artifacts / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
