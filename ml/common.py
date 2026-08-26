from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

URL_RE = re.compile(r"https?://\S+", re.I)
URGENCY = ("urgent", "immediately", "verify", "suspended", "within 24", "action required")
FINANCE = ("invoice", "wire transfer", "bank account", "gift card", "payment", "payroll")
CREDENTIAL = ("password", "login", "one-time password", "otp", "credential")


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def fingerprint(text: str) -> str:
    return hashlib.sha256(normalized_text(text).encode("utf-8", "ignore")).hexdigest()


def augment_text(text: str) -> str:
    low = text.lower()
    tokens: List[str] = []
    if URL_RE.search(text): tokens.append("__HAS_URL__")
    if any(x in low for x in URGENCY): tokens.append("__URGENCY__")
    if any(x in low for x in FINANCE): tokens.append("__FINANCIAL_REQUEST__")
    if any(x in low for x in CREDENTIAL): tokens.append("__CREDENTIAL_REQUEST__")
    if "spf=fail" in low: tokens.append("__SPF_FAIL__")
    if "dmarc=fail" in low: tokens.append("__DMARC_FAIL__")
    if "dkim=none" in low or "dkim=fail" in low: tokens.append("__DKIM_RISK__")
    if "reply-to:" in low: tokens.append("__REPLY_TO_PRESENT__")
    return " ".join(tokens + [text])


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip(): rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows: handle.write(json.dumps(row, ensure_ascii=False) + "\n")
