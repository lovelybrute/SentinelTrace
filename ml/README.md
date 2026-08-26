# SentinelTrace ML workflow

This directory trains a binary `LEGITIMATE`/`PHISHING` classifier with a held-out evaluation set.

## Prepare data

Input can be folders of RFC 5322 messages or CSV files with `text,label,source` columns.

```bash
python ml/prepare_dataset.py --legitimate-dir data/ham --phishing-dir data/phishing
python ml/prepare_dataset.py --csv data/labeled_emails.csv
```

Preparation hashes normalized content, removes exact duplicates, and drops contradictory duplicate labels. Do not commit raw corpora: public email collections can contain personal information and have their own licenses.

## Train and evaluate

```bash
python ml/train_model.py
```

Logistic Regression and SGD log-loss models are compared on the same stratified holdout. Selection uses macro F1. The output contains the dataset hash, split policy, class support, confusion matrix, precision, recall, F1, and limitations.

The backend activates an artifact only when the test set has at least 200 records and at least 50 records per class. Smaller runs remain `PROTOTYPE_HOLDOUT`. Spam must never be relabeled as phishing.
