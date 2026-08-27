# SentinelTrace challenge benchmarks

These files are deterministic, privacy-safe, **synthetic robustness training and
regression records**. The current model uses them for robustness augmentation;
their post-training score must not be described as independent validation.

Regenerate and evaluate them from the repository root:

```bash
python ml/generate_benchmark.py
python ml/evaluate_model.py --dataset ml/benchmarks/all_synthetic_challenges.jsonl
```

The four packs cover legitimate institutional messages, credential phishing,
business-email-compromise/invoice fraud, and evasive or obfuscated phishing.
`manifest.json` records the deterministic seed and SHA-256 digest of each pack.
