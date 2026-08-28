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


def guardian_verdict(value: str) -> dict[str, Any]:
    """Return a conservative, browser-safe reputation verdict for a domain."""
    if classify_indicator(value) != "domain":
        raise ValueError("Browser Guardian accepts DNS hostnames only.")

    result = lookup(value)
    vt = result["providers"].get("virustotal", {})
    stats = vt.get("last_analysis_stats", {}) if vt.get("status") == "ok" else {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)

    if malicious >= 5:
        verdict, score = "dangerous", 95
    elif malicious >= 2:
        verdict, score = "dangerous", 85
    elif malicious == 1 or suspicious >= 2:
        verdict, score = "suspicious", 70
    elif suspicious == 1:
        verdict, score = "caution", 45
    elif harmless > 0:
        verdict, score = "low_risk", 10
    else:
        verdict, score = "unknown", 25

    reasons: list[str] = []
    if malicious:
        reasons.append(f"{malicious} reputation engine(s) marked this domain malicious.")
    if suspicious:
        reasons.append(f"{suspicious} reputation engine(s) marked this domain suspicious.")
    if not reasons and harmless:
        reasons.append("No configured reputation engine currently flags this domain.")
    if not reasons:
        reasons.append("No conclusive reputation evidence is currently available.")

    return {
        "domain": result["indicator"],
        "verdict": verdict,
        "risk_score": score,
        "confidence": "high" if malicious >= 2 else "medium" if malicious or suspicious else "low",
        "reasons": reasons,
        "provider_summary": {
            "virustotal": {
                "status": vt.get("status", "unavailable"),
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
            }
        },
        "cache": result["cache"],
        "checked_at": int(time.time()),
        "privacy": "Only the normalized domain was checked; no page path, query, content, cookies, or browsing history was submitted.",
        "limitation": "Reputation is an investigative signal, not proof of safety, operator identity, or physical location.",
    }
