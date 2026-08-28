from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ml"))

from train_model import calibrate_triage_thresholds, triage_metrics
from validated_model import ValidatedPhishingModel


class FakePipeline:
    classes_ = np.array(["LEGITIMATE", "PHISHING"])

    def __init__(self, phishing_probability: float):
        self.phishing_probability = phishing_probability

    def predict_proba(self, _texts):
        return np.array([[1.0 - self.phishing_probability, self.phishing_probability]])


def test_calibration_creates_ordered_review_band():
    truth = ["LEGITIMATE"] * 5 + ["PHISHING"] * 5
    probabilities = np.array([0.02, 0.05, 0.12, 0.30, 0.65, 0.10, 0.55, 0.72, 0.90, 0.98])
    low, high = calibrate_triage_thresholds(truth, probabilities, max_fpr=0.20, max_fnr=0.20)
    assert 0.0 < low < high <= 1.0
    report = triage_metrics(truth, probabilities, low, high)
    assert report["review_records"] > 0
    assert 0.0 <= report["automatic_coverage"] <= 1.0


def test_runtime_returns_needs_review_inside_calibrated_band():
    model = ValidatedPhishingModel.__new__(ValidatedPhishingModel)
    model.pipeline = FakePipeline(0.55)
    model.metadata = {
        "decision_policy": {
            "status": "CALIBRATED_TRIAGE",
            "thresholds": {"legitimate_max": 0.25, "phishing_min": 0.80},
        }
    }
    result = model.predict("Please review the attached document")
    assert result is not None
    assert result["label"] == "PHISHING"
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["decision_policy"]["status"] == "CALIBRATED_TRIAGE"


def test_legacy_artifact_is_not_claimed_as_calibrated():
    model = ValidatedPhishingModel.__new__(ValidatedPhishingModel)
    model.pipeline = FakePipeline(0.70)
    model.metadata = {}
    result = model.predict("Urgent login required")
    assert result is not None
    assert result["verdict"] == "PHISHING"
    assert result["decision_policy"]["status"] == "LEGACY_BINARY_FALLBACK"
