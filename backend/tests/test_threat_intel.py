import pytest

from config import settings
from threat_intel import classify_indicator, guardian_verdict, lookup, _cache


def test_indicator_validation():
    assert classify_indicator("8.8.8.8") == "ip"
    assert classify_indicator("example.org") == "domain"
    with pytest.raises(ValueError):
        classify_indicator("https://example.org/path")


def test_lookup_without_provider_keys(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    _cache.clear()
    result = lookup("8.8.8.8")
    assert result["providers"]["virustotal"]["status"] == "not_configured"
    assert result["providers"]["abuseipdb"]["status"] == "not_configured"


def test_api_rejects_url(client):
    response = client.get("/intel/lookup", params={"indicator": "https://example.org/a"})
    assert response.status_code == 400


def test_guardian_verdict_blocks_multiple_malicious_engines(monkeypatch):
    monkeypatch.setattr(
        "threat_intel.lookup",
        lambda value: {
            "indicator": value,
            "providers": {
                "virustotal": {
                    "status": "ok",
                    "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 40},
                }
            },
            "cache": "miss",
        },
    )
    result = guardian_verdict("danger.example")
    assert result["verdict"] == "dangerous"
    assert result["risk_score"] == 85


def test_guardian_verdict_does_not_call_unknown_safe(monkeypatch):
    monkeypatch.setattr(
        "threat_intel.lookup",
        lambda value: {
            "indicator": value,
            "providers": {"virustotal": {"status": "not_configured"}},
            "cache": "miss",
        },
    )
    result = guardian_verdict("unknown.example")
    assert result["verdict"] == "unknown"
    assert result["risk_score"] == 25
    assert result["confidence"] == "low"
