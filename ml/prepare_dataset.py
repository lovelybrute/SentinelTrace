from __future__ import annotations

import argparse
import csv
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, Iterable, List

from common import fingerprint, write_jsonl


def eml_text(path: Path) -> str:
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    parts = [f"Subject: {message.get('Subject', '')}"]
    body = message.get_body(preferencelist=("plain",))
    if body:
        try: parts.append(body.get_content())
        except Exception: pass
    return "\n".join(parts)


def directory_rows(directory: Path, label: str) -> Iterable[Dict[str, str]]:
    for path in sorted(directory.rglob("*")):
        if path.is_file() and not path.name.startswith("."):
            try: text = eml_text(path)
            except Exception: continue
            if text.strip(): yield {"text": text, "label": label, "source": str(path)}


def csv_rows(path: Path) -> Iterable[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            text, label = (row.get("text") or "").strip(), (row.get("label") or "").strip().upper()
            if text and label: yield {"text": text, "label": label, "source": row.get("source", path.name)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a deduplicated SentinelTrace email corpus")
    parser.add_argument("--legitimate-dir", type=Path)
    parser.add_argument("--phishing-dir", type=Path)
    parser.add_argument("--csv", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, default=Path("ml/datasets/prepared.jsonl"))
    args = parser.parse_args()
    rows: List[Dict[str, str]] = []
    if args.legitimate_dir: rows.extend(directory_rows(args.legitimate_dir, "LEGITIMATE"))
    if args.phishing_dir: rows.extend(directory_rows(args.phishing_dir, "PHISHING"))
    for path in args.csv: rows.extend(csv_rows(path))
    unique: Dict[str, Dict[str, str]] = {}
    conflicts = set()
    for row in rows:
        key = fingerprint(row["text"])
        if key in unique and unique[key]["label"] != row["label"]: conflicts.add(key)
        else: unique[key] = {**row, "fingerprint": key}
    prepared = [row for key, row in unique.items() if key not in conflicts]
    if not prepared: raise SystemExit("No usable records found. Provide directories or CSV files.")
    write_jsonl(args.output, prepared)
    counts: Dict[str, int] = {}
    for row in prepared: counts[row["label"]] = counts.get(row["label"], 0) + 1
    print({"output": str(args.output), "records": len(prepared), "labels": counts, "conflicts_removed": len(conflicts)})


if __name__ == "__main__": main()
