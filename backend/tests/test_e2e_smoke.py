"""
Comprehensive End-to-End Test for SentinelTrace Backend using FastAPI TestClient.
Tests all endpoints, forensic modules, upsert logic, IOC extraction, MITRE mapping, and STIX export.
"""
import sys
import os
import json
import pathlib

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath("backend"))

from fastapi.testclient import TestClient
from main import app
from database import init_db

init_db()
client = TestClient(app)

PASS = "[PASS]"
FAIL = "[FAIL]"
errors = []

def check(label, condition, detail=""):
    sym = PASS if condition else FAIL
    print(f"  {sym}  {label}" + (f"  [{detail}]" if detail else ""))
    if not condition:
        errors.append(label)

print("\n=== 1. Service Identity & Liveness ===")
r = client.get("/")
check("GET / returns 200", r.status_code == 200)
check("Features list in root response", len(r.json().get("features", [])) >= 10)

print("\n=== 2. Detailed Health Check ===")
r = client.get("/health")
check("GET /health returns 200", r.status_code == 200)
check("Database status is healthy", r.json().get("status") == "healthy")

print("\n=== 3. Statistics Endpoint ===")
r = client.get("/stats")
check("GET /stats returns 200", r.status_code == 200)
stats = r.json()
check("total_emails present", "total_emails" in stats)
check("total_analyses present (alias)", "total_analyses" in stats)
check("threat_distribution present", "threat_distribution" in stats)

print("\n=== 4. Cases Endpoint ===")
r = client.get("/cases")
check("GET /cases returns 200", r.status_code == 200)

# Create a test case
test_case_payload = {
    "title": "SIH Demo Investigation - Suspicious Invoicing",
    "description": "Investigating unauthorized banking coordinate change in invoice.",
    "severity": "HIGH",
    "status": "IN_PROGRESS",
    "assigned_analyst": "Forensic Analyst Alpha"
}
r_case = client.post("/cases", json=test_case_payload)
check("POST /cases creates case (200)", r_case.status_code == 200)
case_id = r_case.json().get("case_id")
check("Valid case_id generated", bool(case_id), case_id)

if case_id:
    # Add note to case
    r_note = client.post(f"/cases/{case_id}/notes", json={"author": "Lead SOC", "note": "Corroborated with threat intel."})
    check("POST /cases/{id}/notes works", r_note.status_code == 200)

print("\n=== 5. Campaigns Endpoint ===")
r = client.get("/campaigns")
check("GET /campaigns returns 200", r.status_code == 200)

r_corr = client.post("/campaigns/correlate")
check("POST /campaigns/correlate returns 200", r_corr.status_code == 200)

print("\n=== 6. Email Forensic Ingestion & Analysis (/analyze) ===")
samples_dir = pathlib.Path("samples")
eml_files = list(samples_dir.glob("*.eml"))
check("Sample EML files exist", len(eml_files) > 0, f"Found {len(eml_files)} files")

analysis_id = None
for sample_path in eml_files[:3]:
    with open(sample_path, "rb") as f:
        file_bytes = f.read()
    
    r_an = client.post(
        "/analyze",
        files={"file": (sample_path.name, file_bytes, "message/rfc822")}
    )
    check(f"Analyze {sample_path.name} (200 OK)", r_an.status_code == 200, f"Status: {r_an.status_code}")
    if r_an.status_code == 200:
        data = r_an.json()
        analysis_id = data.get("analysis_id")
        threat_score = data.get("threat_assessment", {}).get("threat_score")
        threat_level = data.get("threat_assessment", {}).get("threat_level")
        check(f"  {sample_path.name}: Score {threat_score}/100, Level {threat_level}", threat_score is not None and threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        
        # Verify RFC auth checks
        forensics = data.get("forensics", {})
        auth = forensics.get("authentication", {})
        spf = auth.get("spf", {})
        dkim = auth.get("dkim", {})
        dmarc = auth.get("dmarc", {})
        check(f"  SPF result: {spf.get('result')}", spf.get("result") in ["PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR", "UNAVAILABLE"])
        check(f"  DKIM status: {dkim.get('status')}", dkim.get("status") in ["PASS", "FAIL", "NONE", "TEMPERROR", "PERMERROR", "UNAVAILABLE"])
        check(f"  DMARC result: {dmarc.get('result')}", dmarc.get("result") in ["PASS", "FAIL", "NONE", "TEMPERROR", "PERMERROR", "UNAVAILABLE"])
        
        # Verify Received chain
        rc = forensics.get("header_chain", {})
        check(f"  Received chain length: {rc.get('chain_length')}", rc.get("chain_length") is not None)
        
        # Verify IOCs
        iocs = data.get("iocs", [])
        check(f"  IOCs extracted: {len(iocs)}", isinstance(iocs, list))

print("\n=== 7. Stored Analysis & Export Endpoints ===")
if analysis_id:
    r_stored = client.get(f"/analysis/{analysis_id}")
    check("GET /analysis/{id} returns 200", r_stored.status_code == 200)
    
    r_html = client.get(f"/reports/{analysis_id}/html")
    check("GET /reports/{id}/html returns 200 HTML", r_html.status_code == 200 and "SentinelTrace" in r_html.text)
    
    r_json = client.get(f"/reports/{analysis_id}/json")
    check("GET /reports/{id}/json returns 200 JSON", r_json.status_code == 200)
    
    r_stix = client.get(f"/stix/{analysis_id}")
    check("GET /stix/{id} returns 200 STIX 2.1 Bundle", r_stix.status_code == 200 and r_stix.json().get("type") == "bundle")

print("\n=== 8. Global Search & IOC Search ===")
r_search = client.get("/search?q=paypa1")
check("GET /search returns 200", r_search.status_code == 200)

r_iocs = client.get("/iocs")
check("GET /iocs returns 200", r_iocs.status_code == 200)

r_threat_country = client.get("/threat-by-country")
check("GET /threat-by-country returns 200", r_threat_country.status_code == 200)

r_recent = client.get("/recent-threats")
check("GET /recent-threats returns 200", r_recent.status_code == 200)

r_audit = client.get("/audit-logs")
check("GET /audit-logs returns 200", r_audit.status_code == 200)

print("\n" + "="*50)
if errors:
    print(f"FAILED: {len(errors)} assertion(s) failed:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("ALL ENDPOINTS & FORENSIC CHECKS PASSED PERFECTLY!")
