"""Normalize the independent Zenodo validation corpus without using it for training."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("ml/external/phishing_validation_zenodo.jsonl"))
    args = parser.parse_args()
    rows = []
    with args.input.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for record in csv.DictReader(handle):
            text = (record.get("Email Text") or "").strip()
            raw = (record.get("Email Type") or "").strip().lower()
            label = "LEGITIMATE" if raw == "safe email" else "PHISHING" if raw == "phishing email" else None
            if text and label:
                rows.append({"text": text, "label": label, "source": "zenodo:13474746", "synthetic": None})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    print(json.dumps({
        "records": len(rows),
        "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
        "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "citation": "Miltchev, Rangelov, Genchev (2024), Phishing validation emails dataset, DOI 10.5281/zenodo.13474746",
        "training_use": False,
    }, indent=2))


if __name__ == "__main__":
    main()
