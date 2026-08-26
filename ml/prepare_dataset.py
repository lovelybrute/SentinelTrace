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


def parquet_rows(path: Path) -> Iterable[Dict[str, str]]:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise SystemExit(
            "Parquet input requires pyarrow. Install it with: python -m pip install pyarrow"
        ) from exc

    columns = ["subject", "body", "urls", "sender_domain", "source", "label"]
    parquet_file = parquet.ParquetFile(path)
    available = set(parquet_file.schema.names)
    missing = {"body", "label"} - available
    if missing:
        raise SystemExit(f"Parquet dataset is missing required columns: {sorted(missing)}")

    selected = [column for column in columns if column in available]
    for batch in parquet_file.iter_batches(batch_size=2048, columns=selected):
        for record in batch.to_pylist():
            raw_label = record.get("label")
            if raw_label in (0, 0.0, "0", "LEGITIMATE", "SAFE"):
                label = "LEGITIMATE"
            elif raw_label in (1, 1.0, "1", "PHISHING", "MALICIOUS"):
                label = "PHISHING"
            else:
                continue
            text = "\n".join(
                part
                for part in (
                    f"Subject: {record.get('subject') or ''}",
                    f"Sender-Domain: {record.get('sender_domain') or ''}",
                    record.get("body") or "",
                    f"URLs: {record.get('urls') or ''}",
                )
                if part.strip()
            )
            if text.strip():
                yield {
                    "text": text,
                    "label": label,
                    "source": str(record.get("source") or path.name),
                }


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a deduplicated SentinelTrace email corpus")
    parser.add_argument("--legitimate-dir", type=Path)
    parser.add_argument("--phishing-dir", type=Path)
    parser.add_argument("--csv", type=Path, action="append", default=[])
    parser.add_argument("--parquet", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, default=Path("ml/datasets/prepared.jsonl"))
    args = parser.parse_args()
    rows: List[Dict[str, str]] = []
    if args.legitimate_dir: rows.extend(directory_rows(args.legitimate_dir, "LEGITIMATE"))
    if args.phishing_dir: rows.extend(directory_rows(args.phishing_dir, "PHISHING"))
    for path in args.csv: rows.extend(csv_rows(path))
    for path in args.parquet: rows.extend(parquet_rows(path))
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
