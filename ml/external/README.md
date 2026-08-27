# Independent validation evidence

The deployed model is evaluated against the 2,000-record **Phishing validation
emails dataset** by Miltchev, Rangelov and Genchev (2024), DOI
[`10.5281/zenodo.13474746`](https://doi.org/10.5281/zenodo.13474746).
The publisher describes it as a balanced mixture of real-world and artificially
generated safe/phishing emails. It is never included in training.

The raw corpus is not committed. Reproduce the evaluation from the repository
root:

```bash
python ml/fetch_external_validation.py
python ml/prepare_external_validation.py \
  --input ml/external/phishing_validation_emails.csv
python ml/evaluate_model.py \
  --dataset ml/external/phishing_validation_zenodo.jsonl \
  --output ml/external/evaluation.json \
  --evaluation-status INDEPENDENT_MIXED_REAL_SYNTHETIC_VALIDATION \
  --dataset-name "Phishing validation emails dataset" \
  --dataset-citation "Miltchev, Rangelov, Genchev (2024), DOI 10.5281/zenodo.13474746"
```

`comparison.json` records the frozen before/after results. The independent
dataset improved model selection, but its limitations remain: English language,
a mixture of real and artificial messages, and no guarantee of coverage for
current campaigns or Indian-language traffic.
