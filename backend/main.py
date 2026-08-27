import os
import tempfile
import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, status, Depends, Query, Response, Request
from pydantic import BaseModel, EmailStr
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from config import settings
from email_parser import EmailForensicParser
from database import (
    init_db, get_db, EmailAnalysis, ThreatAlert, SenderReputation,
    Case, EvidenceItem, IOCRecord, CampaignRecord, AuditLogEntry
)
from report_generator import ReportGenerator
from stix_exporter import STIXExporter
from validated_model import read_model_metrics
from auth import authenticate, configured_users, decode_token, issue_token


# ============================================================
# SENTINELTRACE AI FORENSIC PLATFORM
# SIH Problem Statement ID: 26106
# ============================================================

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform "
        "(Smart India Hackathon SIH26106 - AICTE Cyber Security Cell)"
    ),
    version=settings.VERSION,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database schema
init_db()

# Report & STIX generators
report_gen = ReportGenerator()
stix_exp = STIXExporter()

_login_attempts: dict[str, list[float]] = {}


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def _session_payload(claims: dict) -> dict:
    return {
        "analystId": claims["analyst_id"], "displayName": claims["display_name"],
        "email": claims["sub"], "role": claims["role"], "unit": claims["unit"],
        "signedInAt": datetime.fromtimestamp(claims["iat"], timezone.utc).isoformat(), "demo": False,
    }


def log_audit(db: Session, action: str, description: str, case_id: Optional[str] = None, evidence_id: Optional[str] = None, user: str = "Analyst"):
    """Write tamper-evident chain-of-custody audit log entry."""
    try:
        entry = AuditLogEntry(
            user=user,
            action=action,
            case_id=case_id,
            evidence_id=evidence_id,
            description=description
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        print(f"[WARN] Audit logging warning: {str(e)}")


# ============================================================
# HEALTH & IDENTITY
# ============================================================

@app.get("/")
def home():
    """Service identity and liveness check."""
    return {
        "project": settings.PROJECT_NAME,
        "problem": settings.PROBLEM_ID,
        "version": settings.VERSION,
        "status": "online",
        "module": "Email Forensic Intelligence Platform",
        "features": [
            "RFC 7208 SPF Evaluation",
            "RFC 6376 DKIM Verification",
            "RFC 7489 DMARC Alignment",
            "SMTP Received-Chain Timeline",
            "Origin Infrastructure Assessment",
            "Lookalike & Typosquatting Detection",
            "Business Email Compromise (BEC) Engine",
            "Safe Static Attachment Inspection",
            "URL Security & SSRF Protection",
            "AI/ML Threat Classification",
            "Explainable Hybrid Threat Scoring",
            "Cross-Email Campaign Correlation",
            "MITRE ATT&CK Mapping",
            "OASIS STIX 2.1 Export",
            "SOC Case Management & Audit Trail"
        ]
    }


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Detailed platform diagnostics."""
    db_ok = True
    try:
        db.query(EmailAnalysis).count()
    except Exception:
        db_ok = False

    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": settings.ENVIRONMENT,
        "max_upload_size_mb": settings.MAX_UPLOAD_SIZE_BYTES / (1024 * 1024),
        "real_login": "configured" if configured_users() else "disabled",
        "production_secret_configured": settings.JWT_SECRET != "sentineltrace-dev-secret-key-change-in-production-2026",
    }


@app.post("/auth/login")
def login(credentials: LoginRequest, request: Request):
    """Verify a configured analyst and issue a short-lived signed access token."""
    if not configured_users():
        raise HTTPException(status_code=503, detail="Real analyst login is not configured. Use the labelled demo mode or contact the administrator.")
    key = f"{request.client.host if request.client else 'unknown'}:{credentials.email.lower()}"
    now = datetime.now(timezone.utc).timestamp()
    attempts = [stamp for stamp in _login_attempts.get(key, []) if now - stamp < 300]
    if len(attempts) >= 5:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in five minutes.")
    user = authenticate(credentials.email, credentials.password)
    if not user:
        attempts.append(now)
        _login_attempts[key] = attempts
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    _login_attempts.pop(key, None)
    token = issue_token(credentials.email, user)
    claims = decode_token(token)
    return {"access_token": token, "token_type": "bearer", "expires_in": settings.ACCESS_TOKEN_TTL_MINUTES * 60, "session": _session_payload(claims or {})}


@app.get("/auth/me")
def current_user(request: Request):
    authorization = request.headers.get("authorization", "")
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    claims = decode_token(token)
    if not claims:
        raise HTTPException(status_code=401, detail="Missing, invalid, or expired access token.")
    return _session_payload(claims)


@app.get("/model/metrics")
def model_metrics():
    """Return persisted held-out evaluation metrics, or an explicit not-trained state."""
    return read_model_metrics()


# ============================================================
# EMAIL FORENSIC ANALYSIS
# ============================================================

@app.post("/analyze")
async def analyze_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Primary forensic ingestion and analysis endpoint.
    Accepts raw .eml RFC-5322 files, preserves cryptographic chain-of-custody,
    runs the full forensic intelligence suite, and persists findings to database.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file selected."
        )

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Please upload an RFC-5322 .eml email file."
        )

    if file.content_type and file.content_type.lower() not in {
        "message/rfc822", "application/octet-stream", "text/plain", "application/eml"
    }:
        raise HTTPException(status_code=400, detail="Invalid content type. Upload an RFC-5322 email message.")

    content = await file.read()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded email file is empty."
        )

    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES / (1024*1024):.1f}MB."
        )

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".eml")
    temp_path = temp_file.name

    try:
        temp_file.write(content)
        temp_file.close()

        # Execute full forensic intelligence pipeline
        parser = EmailForensicParser(temp_path)
        result = parser.parse()
        result["evidence"]["filename"] = file.filename

        # Generate unique evidence ID
        evidence_id = f"EV-{uuid.uuid4().hex[:12].upper()}"
        result["evidence_id"] = evidence_id

        # Persist Evidence Item
        try:
            ev_record = EvidenceItem(
                evidence_id=evidence_id,
                original_filename=file.filename,
                file_size_bytes=len(content),
                sha256=result["evidence"]["sha256"],
                sha512=result["evidence"]["sha512"],
                mime_type="message/rfc822"
            )
            db.add(ev_record)
            db.commit()
        except Exception as e:
            print(f"[WARN] Evidence persistence warning: {str(e)}")

        # Persist Analysis Record
        sender = result["evidence"].get("from", "")
        recipient = result["evidence"].get("to", "")
        content_hash = result["evidence"].get("sha256", "")
        threat_score = result["threat_assessment"].get("threat_score", 0)
        threat_level = result["threat_assessment"].get("threat_level", "LOW")

        sender_locations = result.get("geolocation", {}).get("sender_locations", [])
        sender_country = sender_locations[0].get("country") if sender_locations else None
        sender_city = sender_locations[0].get("city") if sender_locations else None
        sender_ip = sender_locations[0].get("ip") if sender_locations else None
        origin_infra = result.get("forensics", {}).get("origin_assessment", {}).get("probable_source_infrastructure")

        try:
            # Upsert: check if this exact email has already been analyzed
            existing = db.query(EmailAnalysis).filter(
                EmailAnalysis.content_hash == content_hash
            ).first()

            if existing:
                # Update threat assessment for repeat analysis
                existing.threat_score = threat_score
                existing.threat_level = threat_level
                existing.full_analysis = json.dumps(result)
                existing.is_flagged = threat_level in ["HIGH", "CRITICAL"]
                db.commit()
                db.refresh(existing)
                result["analysis_id"] = existing.id
                result["storage_status"] = "updated"
            else:
                db_record = EmailAnalysis(
                    filename=file.filename,
                    sender_email=sender,
                    recipient_email=recipient,
                    subject=result["evidence"].get("subject", ""),
                    threat_score=threat_score,
                    threat_level=threat_level,
                    content_hash=content_hash,
                    sha512_hash=result["evidence"].get("sha512"),
                    message_id=result["evidence"].get("message_id", ""),
                    sender_country=sender_country,
                    sender_city=sender_city,
                    sender_ip=sender_ip,
                    probable_infrastructure=origin_infra,
                    url_count=len(result["threat_indicators"].get("urls", [])),
                    ip_count=len(result["threat_indicators"].get("ip_addresses", [])),
                    attachment_count=len(result.get("attachments", [])),
                    full_analysis=json.dumps(result),
                    is_flagged=threat_level in ["HIGH", "CRITICAL"]
                )
                db.add(db_record)
                db.commit()
                db.refresh(db_record)
                result["analysis_id"] = db_record.id
                result["storage_status"] = "success"

                # Persist extracted IOCs (only for new analyses)
                for ioc in result.get("iocs", []):
                    ioc_entry = IOCRecord(
                        ioc_type=ioc.get("type"),
                        value=ioc.get("value"),
                        source=ioc.get("source"),
                        confidence=ioc.get("confidence", 90),
                        is_malicious=(threat_score >= 50)
                    )
                    db.add(ioc_entry)
                db.commit()

            # Audit log
            log_audit(
                db,
                action="ANALYZED",
                description=f"Ingested and analyzed email '{file.filename}' (SHA-256: {content_hash[:16]}...) — Threat Score: {threat_score}/100 ({threat_level})",
                evidence_id=evidence_id
            )

        except Exception as db_err:
            print(f"[WARN] Database storage warning: {str(db_err)}")
            result["analysis_id"] = None
            result["storage_status"] = "warning"
            result["storage_warning"] = "Analysis completed but database persistence degraded."

        return result

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email forensic analysis failed: {str(e)}"
        )
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ============================================================
# BULK ANALYSIS
# ============================================================

@app.post("/bulk-analyze")
async def bulk_analyze_emails(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db)
):
    """
    Batch analyze multiple .eml files simultaneously and detect shared campaign patterns.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")

    summary = {
        "total_analyzed": len(files),
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "guarded_count": 0,
        "low_count": 0,
        "campaigns_detected": [],
        "results": []
    }

    campaign_correlator = parser_instance = None

    for file in files:
        if not file.filename or not file.filename.lower().endswith(".eml"):
            continue

        content = await file.read()
        if not content:
            continue

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".eml")
        temp_path = temp_file.name
        try:
            temp_file.write(content)
            temp_file.close()

            p = EmailForensicParser(temp_path)
            res = p.parse()
            res["evidence"]["filename"] = file.filename

            threat_level = res["threat_assessment"].get("threat_level", "LOW")
            if threat_level == "CRITICAL":
                summary["critical_count"] += 1
            elif threat_level == "HIGH":
                summary["high_count"] += 1
            elif threat_level == "MEDIUM":
                summary["medium_count"] += 1
            elif threat_level == "GUARDED":
                summary["guarded_count"] += 1
            else:
                summary["low_count"] += 1

            summary["results"].append({
                "filename": file.filename,
                "sender": res["evidence"].get("from"),
                "subject": res["evidence"].get("subject"),
                "threat_score": res["threat_assessment"].get("threat_score"),
                "threat_level": threat_level,
                "classification": res["threat_assessment"].get("classification"),
                "observed_ip": res["forensics"].get("origin_assessment", {}).get("observed_ip"),
                "country": (res.get("geolocation", {}).get("sender_locations", [{}]) or [{}])[0].get("country")
            })

            # Check campaign
            camp = res.get("campaign_correlation", {})
            if camp.get("matched_campaign_id") and camp.get("matched_campaign_id") not in summary["campaigns_detected"]:
                summary["campaigns_detected"].append(camp.get("matched_campaign_id"))

        except Exception as e:
            summary["results"].append({
                "filename": file.filename,
                "error": str(e)
            })
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    return summary


# ============================================================
# SOC CASE MANAGEMENT
# ============================================================

@app.get("/cases")
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db)
):
    """List all investigation cases."""
    query = db.query(Case)
    if status_filter:
        query = query.filter(Case.status == status_filter.upper())
    cases = query.order_by(desc(Case.created_at)).all()

    return [
        {
            "id": c.id,
            "case_id": c.case_id,
            "title": c.title,
            "description": c.description,
            "severity": c.severity,
            "status": c.status,
            "assigned_analyst": c.assigned_analyst,
            "notes": json.loads(c.notes) if c.notes else [],
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None
        }
        for c in cases
    ]


@app.post("/cases")
def create_case(
    payload: dict,
    db: Session = Depends(get_db)
):
    """Create a new incident investigation case."""
    case_num = db.query(Case).count() + 1
    case_id = f"ST-2026-{case_num:05d}"

    new_case = Case(
        case_id=case_id,
        title=payload.get("title", f"Email Threat Investigation {case_id}"),
        description=payload.get("description", ""),
        severity=payload.get("severity", "HIGH"),
        status=payload.get("status", "NEW"),
        assigned_analyst=payload.get("assigned_analyst", "Lead Analyst")
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    log_audit(db, action="CASE_CREATED", description=f"Created investigation case {case_id}: {new_case.title}", case_id=case_id)

    return {
        "case_id": new_case.case_id,
        "title": new_case.title,
        "status": new_case.status,
        "severity": new_case.severity,
        "created_at": new_case.created_at.isoformat()
    }


@app.post("/cases/{case_id}/notes")
def add_case_note(
    case_id: str,
    payload: dict,
    db: Session = Depends(get_db)
):
    """Append an analyst note to an existing case."""
    c = db.query(Case).filter(Case.case_id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    notes_list = json.loads(c.notes) if c.notes else []
    new_note = {
        "author": payload.get("author", "Analyst"),
        "note": payload.get("note", ""),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    notes_list.append(new_note)
    c.notes = json.dumps(notes_list)
    db.commit()

    log_audit(db, action="NOTE_ADDED", description=f"Added investigation note to case {case_id}", case_id=case_id)
    return {"status": "success", "case_id": case_id, "notes_count": len(notes_list)}


# ============================================================
# IOC & GLOBAL SEARCH
# ============================================================

@app.get("/iocs")
def get_iocs(
    ioc_type: Optional[str] = Query(None, alias="type"),
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Retrieve normalized IOCs extracted from analyzed emails."""
    query = db.query(IOCRecord)
    if ioc_type:
        query = query.filter(IOCRecord.ioc_type == ioc_type.upper())
    records = query.order_by(desc(IOCRecord.first_seen)).limit(limit).all()

    return [
        {
            "id": r.id,
            "type": r.ioc_type,
            "value": r.value,
            "source": r.source,
            "confidence": r.confidence,
            "is_malicious": r.is_malicious,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None
        }
        for r in records
    ]


@app.get("/search")
def global_search(
    q: str = Query(..., min_length=2),
    db: Session = Depends(get_db)
):
    """Global investigation search across sender emails, subjects, Message-IDs, hashes, and IOCs."""
    query_str = f"%{q.strip()}%"

    matching_analyses = db.query(EmailAnalysis).filter(
        or_(
            EmailAnalysis.sender_email.ilike(query_str),
            EmailAnalysis.subject.ilike(query_str),
            EmailAnalysis.message_id.ilike(query_str),
            EmailAnalysis.content_hash.ilike(query_str),
            EmailAnalysis.sender_ip.ilike(query_str)
        )
    ).limit(20).all()

    matching_iocs = db.query(IOCRecord).filter(
        IOCRecord.value.ilike(query_str)
    ).limit(20).all()

    return {
        "query": q,
        "matching_emails": [
            {
                "id": a.id,
                "sender": a.sender_email,
                "subject": a.subject,
                "threat_score": a.threat_score,
                "threat_level": a.threat_level,
                "analyzed_at": a.analyzed_at.isoformat() if a.analyzed_at else None
            }
            for a in matching_analyses
        ],
        "matching_iocs": [
            {
                "type": i.ioc_type,
                "value": i.value,
                "source": i.source,
                "confidence": i.confidence
            }
            for i in matching_iocs
        ]
    }


# ============================================================
# REPORTS & STIX EXPORT
# ============================================================

@app.get("/reports/{analysis_id}/html", response_class=HTMLResponse)
def get_html_report(
    analysis_id: int,
    db: Session = Depends(get_db)
):
    """Generate a printable HTML forensic investigation report."""
    record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not record or not record.full_analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    analysis_data = json.loads(record.full_analysis)
    log_audit(db, action="REPORT_GENERATED", description=f"Exported HTML forensic report for analysis ID {analysis_id}")
    return report_gen.generate_html_report(analysis_data)


@app.get("/reports/{analysis_id}/json")
def get_json_report(
    analysis_id: int,
    db: Session = Depends(get_db)
):
    """Export complete forensic findings in JSON format."""
    record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not record or not record.full_analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    return json.loads(record.full_analysis)


@app.get("/stix/{analysis_id}")
def export_stix(
    analysis_id: int,
    db: Session = Depends(get_db)
):
    """Export STIX 2.1 Threat Intelligence bundle for the analyzed email."""
    record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not record or not record.full_analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    analysis_data = json.loads(record.full_analysis)
    bundle = stix_exp.export_bundle(analysis_data)
    log_audit(db, action="EXPORT_GENERATED", description=f"Exported STIX 2.1 CTI bundle for analysis ID {analysis_id}")
    return bundle


# ============================================================
# CAMPAIGN INTELLIGENCE
# ============================================================

@app.get("/campaigns")
def get_campaigns(
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """
    Return detected email campaign clusters.
    Campaigns are groups of related malicious emails sharing common
    infrastructure, sender patterns, or payload signatures.
    """
    campaigns = db.query(CampaignRecord).order_by(
        desc(CampaignRecord.created_at)
    ).limit(limit).all()

    return [
        {
            "campaign_id": c.campaign_id,
            "name": c.name,
            "description": c.description,
            "email_count": c.email_count,
            "threat_level": c.threat_level,
            "first_seen": c.first_seen.isoformat() if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in campaigns
    ]


@app.post("/campaigns/correlate")
def trigger_campaign_correlation(db: Session = Depends(get_db)):
    """
    Manually trigger campaign correlation across all stored analyses.
    Uses Jaccard similarity on shared infrastructure IOCs.
    """
    from campaign_correlator import CampaignCorrelator
    correlator = CampaignCorrelator()
    analyses = db.query(EmailAnalysis).filter(
        EmailAnalysis.full_analysis.isnot(None)
    ).order_by(desc(EmailAnalysis.analyzed_at)).limit(200).all()

    payloads = []
    for a in analyses:
        try:
            payloads.append(json.loads(a.full_analysis))
        except Exception:
            pass

    if len(payloads) < 2:
        return {"status": "insufficient_data", "message": "At least 2 stored analyses are required for correlation.", "campaigns_found": 0}

    try:
        campaign_result = correlator.correlate_all(payloads)
        campaigns_found = len(campaign_result.get("campaigns", []))
        return {
            "status": "complete",
            "analyses_processed": len(payloads),
            "campaigns_found": campaigns_found,
            "result": campaign_result
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "campaigns_found": 0}


# ============================================================
# AUDIT LOGS
# ============================================================

@app.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Retrieve chain-of-custody and platform activity audit logs."""
    logs = db.query(AuditLogEntry).order_by(desc(AuditLogEntry.timestamp)).limit(limit).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "user": l.user,
            "action": l.action,
            "case_id": l.case_id,
            "evidence_id": l.evidence_id,
            "description": l.description
        }
        for l in logs
    ]


# ============================================================
# EXISTING STATS & REPORTING (PRESERVED)
# ============================================================

@app.get("/stats")
def get_statistics(db: Session = Depends(get_db)):
    """Get overall threat statistics."""
    total_emails = db.query(EmailAnalysis).count()
    flagged_emails = db.query(EmailAnalysis).filter(EmailAnalysis.is_flagged == True).count()
    critical_emails = db.query(EmailAnalysis).filter(EmailAnalysis.threat_level == "CRITICAL").count()
    high_emails = db.query(EmailAnalysis).filter(EmailAnalysis.threat_level == "HIGH").count()

    avg_threat_score = db.query(EmailAnalysis.threat_score).filter(EmailAnalysis.threat_score > 0).all()
    avg_score = (sum([x[0] for x in avg_threat_score]) / len(avg_threat_score)) if avg_threat_score else 0

    return {
        "total_emails": total_emails,
        "total_analyses": total_emails,   # alias for frontend compatibility
        "flagged_emails": flagged_emails,
        "critical_threats": critical_emails,
        "high_threats": high_emails,
        "average_threat_score": round(avg_score, 2),
        "threat_distribution": {
            "CRITICAL": critical_emails,
            "HIGH": high_emails,
            "MEDIUM": db.query(EmailAnalysis).filter(EmailAnalysis.threat_level == "MEDIUM").count(),
            "LOW": db.query(EmailAnalysis).filter(EmailAnalysis.threat_level == "LOW").count(),
        },
        "flagged_percentage": round((flagged_emails / total_emails * 100) if total_emails > 0 else 0, 2)
    }


@app.get("/recent-threats")
def get_recent_threats(
    db: Session = Depends(get_db),
    limit: int = 10
):
    """Get recent flagged threat emails."""
    threats = db.query(EmailAnalysis).filter(
        EmailAnalysis.is_flagged == True
    ).order_by(
        desc(EmailAnalysis.analyzed_at)
    ).limit(limit).all()

    return [
        {
            "id": t.id,
            "sender": t.sender_email,
            "subject": t.subject,
            "threat_score": t.threat_score,
            "threat_level": t.threat_level,
            "country": t.sender_country,
            "analyzed_at": t.analyzed_at.isoformat() if t.analyzed_at else None
        }
        for t in threats
    ]


@app.get("/threat-by-country")
def get_threats_by_country(db: Session = Depends(get_db)):
    """Get threat distribution by sender country."""
    from sqlalchemy import func
    results = db.query(
        EmailAnalysis.sender_country,
        func.count(EmailAnalysis.id).label("count"),
        func.avg(EmailAnalysis.threat_score).label("avg_score")
    ).filter(
        EmailAnalysis.sender_country.isnot(None)
    ).group_by(
        EmailAnalysis.sender_country
    ).order_by(
        func.count(EmailAnalysis.id).desc()
    ).limit(20).all()

    return [
        {
            "country": r[0],
            "email_count": r[1],
            "average_threat_score": round(float(r[2]) if r[2] else 0, 2)
        }
        for r in results
    ]


@app.get("/analysis/{analysis_id}")
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db)
):
    """Retrieve detailed stored analysis by ID."""
    record = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis record not found"
        )

    return {
        "id": record.id,
        "filename": record.filename,
        "sender": record.sender_email,
        "recipient": record.recipient_email,
        "subject": record.subject,
        "threat_score": record.threat_score,
        "threat_level": record.threat_level,
        "geolocation": {
            "country": record.sender_country,
            "city": record.sender_city,
            "ip": record.sender_ip
        },
        "artifacts": {
            "urls": record.url_count,
            "ips": record.ip_count,
            "attachments": record.attachment_count
        },
        "analyzed_at": record.analyzed_at.isoformat() if record.analyzed_at else None,
        "full_analysis": json.loads(record.full_analysis) if record.full_analysis else {}
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("main:app", host=host, port=port, reload=False)
