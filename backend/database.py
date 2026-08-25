import os
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentineltrace.db")

# Use SQLite-specific connect args when the URL indicates a sqlite file.
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


# ============================================================
# DATABASE MODELS
# ============================================================

class EmailAnalysis(Base):
    """Store email analysis results"""

    __tablename__ = "email_analysis"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, unique=False)
    sender_email = Column(String, index=True)
    recipient_email = Column(String)
    subject = Column(String)
    
    # Threat assessment
    threat_score = Column(Float)
    threat_level = Column(String)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Forensics
    content_hash = Column(String, index=True)  # Not unique - allow multiple analyses
    message_id = Column(String)
    
    # Geolocation
    sender_country = Column(String)
    sender_city = Column(String)
    sender_ip = Column(String)
    
    # Artifacts
    url_count = Column(Integer, default=0)
    ip_count = Column(Integer, default=0)
    attachment_count = Column(Integer, default=0)
    
    # Results storage
    full_analysis = Column(Text)  # JSON string
    
    # Metadata
    analyzed_at = Column(DateTime, default=datetime.utcnow)
    is_flagged = Column(Boolean, default=False)
    flag_reason = Column(String, nullable=True)


class ThreatAlert(Base):
    """Store threat alerts for reporting"""

    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    email_analysis_id = Column(Integer)
    threat_type = Column(String)  # phishing, malware, spam, etc
    risk_factor = Column(String)
    severity = Column(String)  # low, medium, high, critical
    created_at = Column(DateTime, default=datetime.utcnow)


class SenderReputation(Base):
    """Cache sender reputation scores"""

    __tablename__ = "sender_reputation"

    id = Column(Integer, primary_key=True, index=True)
    email_address = Column(String, unique=True, index=True)
    sender_name = Column(String)
    reputation_score = Column(Float)
    total_emails = Column(Integer, default=1)
    flagged_count = Column(Integer, default=0)
    last_seen = Column(DateTime, default=datetime.utcnow)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    """Initialize database and create tables"""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
