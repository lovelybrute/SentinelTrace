import os
import pytest
from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient):
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["project"] == "SentinelTrace AI"
    assert data["problem"] == "SIH26106"
    assert data["status"] == "online"


def test_stats_endpoint(client: TestClient):
    resp = client.get("/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_emails" in data
    assert "flagged_emails" in data


def test_analyze_sample_phishing(client: TestClient, sample_emails_dir: str):
    file_path = os.path.join(sample_emails_dir, "phishing_email.eml")
    if not os.path.exists(file_path):
        pytest.skip("Sample phishing email not found")

    with open(file_path, "rb") as f:
        resp = client.post("/analyze", files={"file": ("phishing_email.eml", f, "message/rfc822")})

    assert resp.status_code == 200
    data = resp.json()
    assert "evidence" in data
    assert "threat_assessment" in data
    assert "forensics" in data
    assert data["evidence"]["content_hash"] is not None
    assert "sha512" in data["evidence"]
    assert "iocs" in data
    assert "mitre_mappings" in data


def test_cases_lifecycle(client: TestClient):
    # 1. Create Case
    create_resp = client.post("/cases", json={
        "title": "Suspicious Phishing Investigation Test",
        "description": "Automated test case",
        "severity": "HIGH"
    })
    assert create_resp.status_code == 200
    case_data = create_resp.json()
    case_id = case_data["case_id"]

    # 2. Add Note
    note_resp = client.post(f"/cases/{case_id}/notes", json={
        "author": "Forensic Lead",
        "note": "Initial IOC extraction confirmed malicious lookalike domain."
    })
    assert note_resp.status_code == 200

    # 3. List Cases
    list_resp = client.get("/cases")
    assert list_resp.status_code == 200
    cases = list_resp.json()
    assert any(c["case_id"] == case_id for c in cases)
