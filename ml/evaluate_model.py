"""Evaluate a frozen SentinelTrace model without fitting or modifying it."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score

from common import augment_text, read_jsonl


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, default=Path("ml/artifacts/phishing_model.joblib"))
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("ml/benchmarks/evaluation.json"))
    args = parser.parse_args()
    artifact = joblib.load(args.model)
    pipeline = artifact["pipeline"]
    rows = read_jsonl(args.dataset)
    labels = sorted(set(str(row["label"]) for row in rows))
    truth = [str(row["label"]) for row in rows]
    predicted = list(pipeline.predict([augment_text(str(row["text"])) for row in rows]))
    report = {
        "evaluation_status": "SYNTHETIC_CHALLENGE_ONLY",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "training_performed": False,
        "dataset": str(args.dataset),
        "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        "records": len(rows),
        "label_distribution": dict(Counter(truth)),
        "accuracy": round(float(accuracy_score(truth, predicted)), 4),
        "precision_macro": round(float(precision_score(truth, predicted, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(truth, predicted, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(truth, predicted, average="macro", zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(truth, predicted, labels=labels).tolist(),
        "classification_report": classification_report(truth, predicted, labels=labels, output_dict=True, zero_division=0),
        "limitations": "Synthetic regression evidence only. It does not replace recent, independently labeled real-world validation.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
