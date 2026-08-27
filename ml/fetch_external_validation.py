"""Download the independent Zenodo validation corpus with provenance checks."""
from __future__ import annotations

import argparse
import hashlib
import urllib.request
from pathlib import Path

URL = "https://zenodo.org/api/records/13474746/files/Phishing_validation_emails.csv/content"
EXPECTED_MD5 = "1bf8ec0fe3f67e12dd275ce5b2b91b69"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("ml/external/phishing_validation_emails.csv"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(URL, timeout=120) as response:
        payload = response.read()
    digest = hashlib.md5(payload, usedforsecurity=False).hexdigest()
    if digest != EXPECTED_MD5:
        raise SystemExit(f"Checksum mismatch: expected {EXPECTED_MD5}, received {digest}")
    args.output.write_bytes(payload)
    print({"output": str(args.output), "bytes": len(payload), "md5": digest, "source": URL})


if __name__ == "__main__":
    main()
