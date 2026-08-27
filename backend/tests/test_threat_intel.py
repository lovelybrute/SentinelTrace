import pytest

from config import settings
from threat_intel import classify_indicator, lookup, _cache


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
