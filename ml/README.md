# SentinelTrace ML workflow

This directory trains a binary `LEGITIMATE`/`PHISHING` probability model and converts its score into three operational verdicts: `LEGITIMATE`, `NEEDS_REVIEW`, or `PHISHING`.

## Prepare data

Input can be folders of RFC 5322 messages or CSV files with `text,label,source` columns.

```bash
python ml/prepare_dataset.py --legitimate-dir data/ham --phishing-dir data/phishing
python ml/prepare_dataset.py --csv data/labeled_emails.csv
```

Preparation hashes normalized content, removes exact duplicates, and drops contradictory duplicate labels. Do not commit raw corpora: public email collections can contain personal information and have their own licenses. Spam must never be relabeled as phishing.

## Train, calibrate, and test

```bash
python ml/train_model.py
```

The training corpus is split into isolated fit, calibration, and test partitions:

- Candidate selection uses only the calibration partition.
- The calibration partition sets conservative legitimate and phishing thresholds.
- Scores between those thresholds abstain with `NEEDS_REVIEW`.
- Final same-corpus metrics are computed once on the untouched test partition.
- Independent evaluation datasets are never used for fitting, model selection, or threshold calibration.

Optional controls:

```bash
python ml/train_model.py \
  --calibration-size 0.15 \
  --max-calibration-fpr 0.10 \
  --max-calibration-fnr 0.02
```

The report records dataset hashes, split policy, thresholds, abstention rate, automatic coverage, class support, confusion matrices, precision, recall, F1, and limitations. The backend activates an artifact only when the untouched test set has at least 200 records and at least 50 records per class. Smaller runs remain `PROTOTYPE_HOLDOUT`.

## Independent evaluation

Use `ml/evaluate_model.py` only after the artifact is frozen. Never pass the independent 2,000-message benchmark to `prepare_dataset.py` or `train_model.py`. It is evaluation-only evidence and must remain excluded from calibration as well as training.
