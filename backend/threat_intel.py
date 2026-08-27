"""Optional, bounded threat-intelligence lookups.

No provider key is required to run SentinelTrace. Inputs are restricted to a
literal IP or DNS hostname; arbitrary URLs are rejected to avoid SSRF behavior.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Any

import requests

from config import settings

DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def classify_indicator(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        if DOMAIN.fullmatch(candidate):
            return "domain"
    raise ValueError("Indicator must be a literal IPv4/IPv6 address or valid DNS hostname.")


def lookup(value: str) -> dict[str, Any]:
    indicator = value.strip().lower().rstrip(".")
    kind = classify_indicator(indicator)
    cached = _cache.get(indicator)
    if cached and time.time() - cached[0] < 900:
        return {**cached[1], "cache": "hit"}
    providers: dict[str, Any] = {}
    if settings.VIRUSTOTAL_API_KEY:
        path_kind = "ip_addresses" if kind == "ip" else "domains"
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/{path_kind}/{indicator}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}, timeout=5,
            )
            response.raise_for_status()
            attributes = response.json().get("data", {}).get("attributes", {})
            providers["virustotal"] = {"status": "ok", "last_analysis_stats": attributes.get("last_analysis_stats", {})}
        except requests.RequestException as exc:
            providers["virustotal"] = {"status": "unavailable", "detail": type(exc).__name__}
    else:
        providers["virustotal"] = {"status": "not_configured"}
    if kind == "ip" and settings.ABUSEIPDB_API_KEY:
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90}, timeout=5,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            providers["abuseipdb"] = {"status": "ok", "abuse_confidence_score": data.get("abuseConfidenceScore"), "reports": data.get("totalReports")}
        except requests.RequestException as exc:
            providers["abuseipdb"] = {"status": "unavailable", "detail": type(exc).__name__}
    else:
        providers["abuseipdb"] = {"status": "not_applicable" if kind != "ip" else "not_configured"}
    result = {"indicator": indicator, "type": kind, "providers": providers, "cache": "miss", "attribution_limit": "Reputation is an investigative signal, not proof of operator identity or physical location."}
    _cache[indicator] = (time.time(), result)
    return result
