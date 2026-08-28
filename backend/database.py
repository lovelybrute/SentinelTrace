import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from config import settings

def normalize_database_url(database_url: str) -> str:
    """Return a SQLAlchemy-compatible URL for provider-issued Postgres URLs."""
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql://", 1)
    return database_url


DATABASE_URL = normalize_database_url(settings.DATABASE_URL)

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300,
    )

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


# ============================================================
# CORE FORENSIC MODELS (EXISTING PRESERVED)
# ============================================================

class EmailAnalysis(Base):
    """Store complete email analysis results"""
    __tablename__ = "email_analysis"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    sender_email = Column(String, index=True)
    recipient_email = Column(String)
    subject = Column(String)

    # Threat assessment
    threat_score = Column(Float, index=True)
    threat_level = Column(String, index=True)  # LOW, GUARDED, MEDIUM, HIGH, CRITICAL

    # Forensics & Integrity
    content_hash = Column(String, index=True)  # SHA-256
    sha512_hash = Column(String, nullable=True)
    message_id = Column(String, index=True)

    # Geolocation & Origin
    sender_country = Column(String, index=True)
    sender_city = Column(String)
    sender_ip = Column(String, index=True)
    probable_infrastructure = Column(String, nullable=True)

    # Artifact counts
    url_count = Column(Integer, default=0)
    ip_count = Column(Integer, default=0)
    attachment_count = Column(Integer, default=0)

    # Complete structured forensic payload
    full_analysis = Column(Text)

    # Metadata & Triage
    analyzed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    is_flagged = Column(Boolean, default=False, index=True)
    flag_reason = Column(String, nullable=True)
    case_id = Column(String, nullable=True, index=True)


class ThreatAlert(Base):
    """Individual threat indicators and alerts"""
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    email_analysis_id = Column(Integer, index=True)
    threat_type = Column(String, index=True)  # phishing, malware, bec, spoofing
    risk_factor = Column(String)
    severity = Column(String, index=True)  # low, medium, high, critical
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SenderReputation(Base):
    """Cached domain and sender reputation entries"""
    __tablename__ = "sender_reputation"

    id = Column(Integer, primary_key=True, index=True)
    email_address = Column(String, unique=True, index=True)
    sender_name = Column(String, nullable=True)
    reputation_score = Column(Float, default=50.0)
    total_emails = Column(Integer, default=1)
    flagged_count = Column(Integer, default=0)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ============================================================
# SOC & CASE MANAGEMENT MODELS (NEW)
# ============================================================

class Case(Base):
    """SOC Case Management Record"""
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, unique=True, index=True)  # e.g. ST-2026-00041
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, default="NEW", index=True)  # NEW, TRIAGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    assigned_analyst = Column(String, default="Lead Analyst")
    notes = Column(Text, default="[]")  # JSON string of note objects
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class EvidenceItem(Base):
    """Evidence preservation record with chain-of-custody hashes"""
    __tablename__ = "evidence_items"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String, unique=True, index=True)
    case_id = Column(String, index=True, nullable=True)
    original_filename = Column(String, nullable=False)
    file_size_bytes = Column(Integer, default=0)
    sha256 = Column(String, index=True, nullable=False)
    sha512 = Column(String, nullable=False)
    mime_type = Column(String, default="message/rfc822")
    analyst_user = Column(String, default="Analyst")
    ingestion_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class IOCRecord(Base):
    """Extracted Indicator of Compromise for search and graph analysis"""
    __tablename__ = "ioc_records"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String, index=True)  # IPV4, IPV6, DOMAIN, URL, SHA256, EMAIL_ADDRESS
    value = Column(String, index=True)
    source = Column(String)  # HEADER_FROM, URL_HOST, ATTACHMENT, etc.
    confidence = Column(Integer, default=90)
    is_malicious = Column(Boolean, default=False, index=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    case_id = Column(String, index=True, nullable=True)


class CampaignRecord(Base):
    """Clustered threat campaigns"""
    __tablename__ = "campaign_records"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(String, unique=True, index=True)  # e.g. CAMP-2026-PAYP-001
    name = Column(String, nullable=False)
    target_sector = Column(String, default="Enterprise")
    confidence_score = Column(Integer, default=80)
    email_count = Column(Integer, default=1)
    tactics = Column(Text, default="[]")  # JSON list
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class AuditLogEntry(Base):
    """Tamper-evident audit trail for chain of custody and analyst actions"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user = Column(String, default="system")
    action = Column(String, index=True)  # UPLOAD, PARSED, ANALYZED, CASE_CREATED, REPORT_GENERATED, etc.
    case_id = Column(String, index=True, nullable=True)
    evidence_id = Column(String, index=True, nullable=True)
    description = Column(Text, nullable=False)


# Initialize Database Tables & Migrations
def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Safe SQLite column migrations for existing databases
    if DATABASE_URL.startswith("sqlite"):
        import sqlite3
        db_path = DATABASE_URL.replace("sqlite:///", "").replace("sqlite://", "")
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(email_analysis)")
                existing_cols = [row[1] for row in cursor.fetchall()]
                
                columns_to_add = [
                    ("sha512_hash", "TEXT"),
                    ("probable_infrastructure", "TEXT"),
                    ("case_id", "TEXT")
                ]
                for col_name, col_type in columns_to_add:
                    if col_name not in existing_cols:
                        cursor.execute(f"ALTER TABLE email_analysis ADD COLUMN {col_name} {col_type}")
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[INFO] Migration check note: {e}")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
