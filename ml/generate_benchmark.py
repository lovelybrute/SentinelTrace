"""Generate deterministic, privacy-safe challenge sets for regression testing.

These records are synthetic. They are never counted as real-world validation or
mixed into the MeAJOR training corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

SEED = 26106
NAMES = ["Aarav", "Diya", "Ishaan", "Kavya", "Meera", "Rahul", "Sanjay", "Zoya"]
ORGS = ["National Institute", "District Office", "State Bank", "University Portal", "Railway Services", "Health Mission"]
DATES = ["12 September", "18 October", "3 November", "27 December"]

BENIGN = [
    ("Meeting minutes: {org}", "Hello {name}, attached are the approved meeting minutes. No action is required before {date}."),
    ("Library renewal notice", "Dear {name}, your borrowed title is due on {date}. Renew through the bookmarked university portal."),
    ("Monthly account statement available", "Your statement is available in the official mobile application. We will never ask for an OTP or password by email."),
    ("Scheduled maintenance", "The {org} portal will be unavailable on {date}. Existing passwords remain valid and no verification is required."),
    ("Workshop registration confirmed", "Registration for the cyber awareness workshop is confirmed for {name}. Venue details are attached."),
]

CREDENTIAL = [
    ("Urgent: mailbox will be disabled", "Verify your account immediately at hxxps://mail-{token}.example/login or access will be removed today."),
    ("KYC verification pending", "Your account is restricted. Confirm PAN, password and OTP at https://secure-{token}.example/kyc."),
    ("Shared document requires login", "{name} shared a confidential file. Sign in at https://docs-{token}.example/auth to view it."),
    ("Password expires in 30 minutes", "Keep your {org} access active by entering your current password at http://{token}.example/reset."),
]

BEC = [
    ("Confidential payment request", "I am in a meeting. Transfer INR {amount} to the new vendor account and do not call. Send confirmation now."),
    ("Updated bank details for invoice", "Please replace our beneficiary details and release invoice {invoice} today. This request is confidential."),
    ("Purchase gift cards urgently", "Buy {count} gift cards for the executive team. Reply with the codes and keep this between us."),
    ("CEO request", "{name}, process an emergency wire of INR {amount}. I cannot speak by phone; acknowledge only by email."),
]

EVASIVE = [
    ("Security notification", "V e r i f y your m a i l b o x at hxxps[:]//{token}[.]example before {date}."),
    ("Payment reversal", "A refund is waiting. Open the encoded link: https://{token}.example/%6c%6f%67%69%6e and confirm your OTP."),
    ("Document protected", "Enable content in the attached file, then sign in through {token}.example to decrypt the document."),
    ("Unusual sign-in", "We blocked an unusual sign-in. Avoid suspension: copy hxxp://{token}.example into your browser and authenticate."),
]


def render(templates, label: str, pack: str, count: int, rng: random.Random):
    rows = []
    for index in range(count):
        subject, body = templates[index % len(templates)]
        values = {
            "name": rng.choice(NAMES), "org": rng.choice(ORGS), "date": rng.choice(DATES),
            "token": hashlib.sha256(f"{pack}-{index}-{SEED}".encode()).hexdigest()[:10],
            "amount": f"{rng.randrange(18, 950) * 1000:,}", "invoice": f"INV-{rng.randrange(10000, 99999)}",
            "count": rng.choice([5, 10, 20, 25]),
        }
        text = f"Subject: {subject.format(**values)}\n{body.format(**values)}"
        rows.append({"text": text, "label": label, "source": f"synthetic:{pack}", "synthetic": True, "pack": pack})
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("ml/benchmarks"))
    parser.add_argument("--records-per-pack", type=int, default=100)
    args = parser.parse_args()
    rng = random.Random(SEED)
    packs = {
        "legitimate_institutional": render(BENIGN, "LEGITIMATE", "legitimate_institutional", args.records_per_pack, rng),
        "credential_phishing": render(CREDENTIAL, "PHISHING", "credential_phishing", args.records_per_pack, rng),
        "bec_invoice_fraud": render(BEC, "PHISHING", "bec_invoice_fraud", args.records_per_pack, rng),
        "evasive_phishing": render(EVASIVE, "PHISHING", "evasive_phishing", args.records_per_pack, rng),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"schema": "sentineltrace_benchmark_v1", "seed": SEED, "synthetic": True, "training_use": False, "packs": {}}
    combined = []
    for name, rows in packs.items():
        path = args.output_dir / f"{name}.jsonl"
        path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest["packs"][name] = {"records": len(rows), "sha256": digest, "labels": sorted(set(row["label"] for row in rows))}
        combined.extend(rows)
    combined_path = args.output_dir / "all_synthetic_challenges.jsonl"
    combined_path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in combined), encoding="utf-8")
    manifest["combined"] = {"records": len(combined), "sha256": hashlib.sha256(combined_path.read_bytes()).hexdigest()}
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
