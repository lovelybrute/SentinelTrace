import os
import tempfile
import json
from fastapi import FastAPI, File, UploadFile, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from email_parser import EmailForensicParser
from database import init_db, get_db, EmailAnalysis, SenderReputation
from advanced_forensics import AdvancedForensics


# ============================================================
# SENTINELTRACE AI
# SIH26106
# ============================================================

app = FastAPI(
    title="SentinelTrace AI",
    description=(
        "AI-Powered Email Threat Detection, "
        "Geolocation and Forensic Intelligence Platform"
    ),
    version="0.1.0",
)

# ============================================================
# CORS MIDDLEWARE
# ============================================================

# Configure CORS origins from environment in production. Use a comma-separated
# `ALLOWED_ORIGINS` env var (e.g. "https://app.example.com,https://admin.example.com").
allowed = os.getenv("ALLOWED_ORIGINS")
if allowed:
    allow_origins = [o.strip() for o in allowed.split(",") if o.strip()]
else:
    allow_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
init_db()


# ============================================================
# HOME / HEALTH CHECK
# ============================================================

@app.get("/")
def home():

    return {
        "project": "SentinelTrace AI",
        "problem": "SIH26106",
        "status": "online",
        "module": "Email Forensic Parser",
    }


# ============================================================
# EMAIL ANALYSIS
# ============================================================

@app.post("/analyze")
async def analyze_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    # --------------------------------------------------------
    # Validate file
    # --------------------------------------------------------

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file selected."
        )


    if not file.filename.lower().endswith(
        ".eml"
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please upload an .eml email file."
        )


    # --------------------------------------------------------
    # Read uploaded email
    # --------------------------------------------------------

    content = await file.read()


    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded email file is empty."
        )


    # --------------------------------------------------------
    # Create temporary file
    # --------------------------------------------------------

    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".eml"
    )


    temp_path = temp_file.name


    try:

        temp_file.write(content)
        temp_file.close()


        # Parse email
        email_parser = EmailForensicParser(temp_path)
        result = email_parser.parse()

        # Store original filename
        result["evidence"]["filename"] = file.filename

        # Add advanced forensics
        forensics = AdvancedForensics()
        result["forensics"] = {
            "authentication": forensics.analyze_authentication(result),
            "spoofing_analysis": forensics.detect_spoofing(result),
            "header_chain": forensics.analyze_header_chain(
                result.get("evidence", {}).get("received_headers", [])
            )
        }

        # Save to database
        sender = result["evidence"].get("from", "")
        recipient = result["evidence"].get("to", "")
        content_hash = result["evidence"].get("content_hash", "")
        threat_score = result["threat_assessment"].get("threat_score", 0)
        threat_level = result["threat_assessment"].get("threat_level", "LOW")

        sender_locations = result.get("geolocation", {}).get("sender_locations", [])
        sender_country = sender_locations[0].get("country") if sender_locations else None
        sender_city = sender_locations[0].get("city") if sender_locations else None
        sender_ip = sender_locations[0].get("ip") if sender_locations else None

        # Try to save to database, but don't fail if there's a constraint error
        try:
            db_record = EmailAnalysis(
                filename=file.filename,
                sender_email=sender,
                recipient_email=recipient,
                subject=result["evidence"].get("subject", ""),
                threat_score=threat_score,
                threat_level=threat_level,
                content_hash=content_hash,
                message_id=result["evidence"].get("message_id", ""),
                sender_country=sender_country,
                sender_city=sender_city,
                sender_ip=sender_ip,
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
        except Exception as db_err:
            # If database error occurs, still return analysis but mark as warning
            print(f"[WARN] Database storage warning: {str(db_err)}")
            result["analysis_id"] = None
            result["storage_status"] = "warning"
            result["storage_warning"] = "Analysis completed successfully but could not save to database. This may happen if the same email was analyzed before."
        
        return result


    except Exception as e:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email analysis failed: {str(e)}"
        )


    finally:

        if os.path.exists(temp_path):
            os.remove(temp_path)


# ============================================================
# ANALYTICS & REPORTING
# ============================================================

@app.get("/stats")
def get_statistics(db: Session = Depends(get_db)):
    """Get overall threat statistics"""

    total_emails = db.query(EmailAnalysis).count()
    flagged_emails = db.query(EmailAnalysis).filter(
        EmailAnalysis.is_flagged == True
    ).count()
    
    critical_emails = db.query(EmailAnalysis).filter(
        EmailAnalysis.threat_level == "CRITICAL"
    ).count()
    
    high_emails = db.query(EmailAnalysis).filter(
        EmailAnalysis.threat_level == "HIGH"
    ).count()

    avg_threat_score = db.query(
        EmailAnalysis.threat_score
    ).filter(
        EmailAnalysis.threat_score > 0
    ).all()

    avg_score = (
        sum([x[0] for x in avg_threat_score]) / len(avg_threat_score)
        if avg_threat_score
        else 0
    )

    return {
        "total_emails": total_emails,
        "flagged_emails": flagged_emails,
        "critical_threats": critical_emails,
        "high_threats": high_emails,
        "average_threat_score": round(avg_score, 2),
        "flagged_percentage": round(
            (flagged_emails / total_emails * 100) if total_emails > 0 else 0,
            2
        )
    }


@app.get("/recent-threats")
def get_recent_threats(
    db: Session = Depends(get_db),
    limit: int = 10
):
    """Get recent high-threat emails"""

    threats = db.query(EmailAnalysis).filter(
        EmailAnalysis.is_flagged == True
    ).order_by(
        EmailAnalysis.analyzed_at.desc()
    ).limit(limit).all()

    return [
        {
            "id": t.id,
            "sender": t.sender_email,
            "subject": t.subject,
            "threat_score": t.threat_score,
            "threat_level": t.threat_level,
            "country": t.sender_country,
            "analyzed_at": t.analyzed_at.isoformat()
        }
        for t in threats
    ]


@app.get("/threat-by-country")
def get_threats_by_country(db: Session = Depends(get_db)):
    """Get threat distribution by sender country"""

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
    """Retrieve detailed analysis by ID"""

    record = db.query(EmailAnalysis).filter(
        EmailAnalysis.id == analysis_id
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
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
        "analyzed_at": record.analyzed_at.isoformat(),
        "full_analysis": json.loads(record.full_analysis) if record.full_analysis else {}
    }


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    reload_flag = os.getenv("RELOAD", "false").lower() in ("1", "true", "yes")
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=reload_flag,
    )