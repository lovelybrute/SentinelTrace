from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "verify_deployment.py"
SPEC = importlib.util.spec_from_file_location("verify_deployment", MODULE_PATH)
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def response(payload: dict):
    return 200, "application/json", __import__("json").dumps(payload)


def test_metrics_contract_accepts_valid_holdout(monkeypatch):
    monkeypatch.setattr(
        verify,
        "fetch",
        lambda *_: response(
            {
                "validation_status": "VALIDATED_HOLDOUT",
                "dataset_records": 106159,
                "selected_model": "logistic_regression",
                "models": {"logistic_regression": {"accuracy": 0.9874}},
            }
        ),
    )
    result = verify.check_metrics("https://backend.example", 1, 0)
    assert result["dataset_records"] == 106159


def test_metrics_contract_rejects_unvalidated_claim(monkeypatch):
    monkeypatch.setattr(
        verify,
        "fetch",
        lambda *_: response(
            {
                "validation_status": "NOT_TRAINED",
                "dataset_records": 0,
                "models": {},
            }
        ),
    )
    with pytest.raises(verify.CheckFailure, match="VALIDATED_HOLDOUT"):
        verify.check_metrics("https://backend.example", 1, 0)


def test_guardian_contract_preserves_unknown_verdict(monkeypatch):
    monkeypatch.setattr(
        verify,
        "fetch",
        lambda *_: response(
            {
                "domain": "example.org",
                "verdict": "unknown",
                "risk_score": 25,
                "privacy": "Only the normalized domain was checked.",
            }
        ),
    )
    result = verify.check_guardian("https://backend.example", 1, 0)
    assert result["verdict"] == "unknown"


@pytest.mark.parametrize("score", [-1, 101, None])
def test_guardian_contract_rejects_invalid_score(monkeypatch, score):
    monkeypatch.setattr(
        verify,
        "fetch",
        lambda *_: response(
            {
                "domain": "example.org",
                "verdict": "low_risk",
                "risk_score": score,
                "privacy": "Domain only.",
            }
        ),
    )
    with pytest.raises(verify.CheckFailure, match="risk_score"):
        verify.check_guardian("https://backend.example", 1, 0)


def test_production_urls_require_https():
    with pytest.raises(verify.CheckFailure, match="HTTPS"):
        verify.secure_base_url("http://example.org", allow_http=False)
    assert verify.secure_base_url("https://example.org/", allow_http=False) == "https://example.org"
