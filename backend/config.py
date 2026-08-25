import os
from typing import List
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "SentinelTrace AI"
    PROBLEM_ID: str = "SIH26106"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./sentineltrace.db")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "sentineltrace-dev-secret-key-change-in-production-2026")
    ALLOWED_ORIGINS: List[str] = [
        o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()
    ]
    MAX_UPLOAD_SIZE_BYTES: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(10 * 1024 * 1024)))  # 10MB
    DNS_TIMEOUT_SECONDS: float = float(os.getenv("DNS_TIMEOUT_SECONDS", "4.0"))
    GEO_TIMEOUT_SECONDS: float = float(os.getenv("GEO_TIMEOUT_SECONDS", "4.0"))
    GEO_API_URL: str = os.getenv("GEO_API_URL", "http://ip-api.com/json")
    ENABLE_ML_CLASSIFICATION: bool = os.getenv("ENABLE_ML_CLASSIFICATION", "true").lower() in ("1", "true", "yes")

settings = Settings()
