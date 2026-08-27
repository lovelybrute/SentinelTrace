"""Small, dependency-free production authentication boundary.

Users are supplied by AUTH_USERS_JSON; passwords are never stored in source.
The token format is an HS256 JWT and password verification uses PBKDF2-SHA256.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from config import settings


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, iterations: int = 310_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, raw_iterations, raw_salt, raw_digest = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), _unb64(raw_salt), int(raw_iterations)
        )
        return hmac.compare_digest(candidate, _unb64(raw_digest))
    except (ValueError, TypeError):
        return False


def configured_users() -> dict[str, dict[str, Any]]:
    if not settings.AUTH_USERS_JSON.strip():
        return {}
    try:
        payload = json.loads(settings.AUTH_USERS_JSON)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(email).strip().lower(): value for email, value in payload.items() if isinstance(value, dict)}


def authenticate(email: str, password: str) -> dict[str, Any] | None:
    user = configured_users().get(email.strip().lower())
    # Always run PBKDF2 to reduce account-enumeration timing differences.
    dummy = "pbkdf2_sha256$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    if not user:
        verify_password(password, dummy)
        return None
    password_hash = str(user.get("password_hash", ""))
    return user if verify_password(password, password_hash) else None


def issue_token(email: str, user: dict[str, Any]) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": email.strip().lower(),
        "iat": now,
        "exp": now + settings.ACCESS_TOKEN_TTL_MINUTES * 60,
        "jti": secrets.token_urlsafe(12),
        "role": user.get("role", "SOC_ANALYST"),
        "display_name": user.get("display_name", email.split("@")[0]),
        "unit": user.get("unit", "Security Operations"),
        "analyst_id": user.get("analyst_id", "USR-01"),
    }
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(settings.JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(signature)}"


def decode_token(token: str) -> dict[str, Any] | None:
    try:
        head, body, signature = token.split(".", 2)
        expected = hmac.new(settings.JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(signature)):
            return None
        payload = json.loads(_unb64(body))
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
