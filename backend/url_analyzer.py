import ipaddress
import re
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List, Optional
from lookalike_detector import LookalikeDetector

try:
    import tldextract
    TLD_AVAILABLE = True
except ImportError:
    TLD_AVAILABLE = False


class URLAnalyzer:
    """
    URL safety and threat analysis engine.
    Analyzes URLs statically to identify shorteners, IP-based destinations,
    credential harvesting paths, obfuscation, and brand impersonation without
    triggering arbitrary attacker code or exposing internal network to SSRF.
    """

    KNOWN_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
        "rebrand.ly", "rb.gy", "v.gd", "cutt.ly", "shorturl.at", "tiny.cc",
        "qr.ae", "goo.gl", "bitly.com", "adf.ly", "lnkd.in"
    }

    SUSPICIOUS_TLDS = {
        "xyz", "top", "click", "loan", "work", "gq", "cf", "ml", "tk",
        "ga", "surf", "buzz", "live", "club", "rest", "cam", "icu"
    }

    CREDENTIAL_PATHS = [
        "login", "signin", "sign-in", "log-in", "verify", "verification",
        "auth", "authentication", "account-update", "password", "reset-password",
        "secure-login", "webmail", "cpanel", "banking", "billing", "confirm"
    ]

    def __init__(self):
        self.lookalike_detector = LookalikeDetector()

    def is_ssrf_safe_ip(self, ip_str: str) -> bool:
        """Verify whether an IP address is a safe public route (prevents SSRF)."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return not (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_reserved or
                ip_obj.is_link_local or
                ip_obj.is_multicast or
                str(ip_obj) == "169.254.169.254"
            )
        except ValueError:
            return False

    def analyze_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Perform comprehensive static threat inspection on a URL.
        """
        clean_url = raw_url.strip()
        parsed = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")

        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        port = parsed.port
        scheme = parsed.scheme.lower()

        # Domain extraction
        if TLD_AVAILABLE:
            ext = tldextract.extract(hostname)
            registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            subdomain = ext.subdomain
            tld = ext.suffix
        else:
            parts = hostname.split(".")
            registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
            tld = parts[-1] if len(parts) > 1 else ""

        risk_score = 0
        risk_level = "LOW"
        indicators: List[str] = []

        # 1. IP-based URL Check
        is_ip_host = False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip_host = True
            risk_score += 45
            indicators.append(f"IP-based host destination: {hostname} (evades domain reputation)")
            if not self.is_ssrf_safe_ip(hostname):
                risk_score += 30
                indicators.append(f"Private/Internal network IP destination (potential SSRF payload): {hostname}")
        except ValueError:
            pass

        # 2. URL Shortener Detection
        is_shortened = (hostname in self.KNOWN_SHORTENERS) or (registered_domain in self.KNOWN_SHORTENERS)
        if is_shortened:
            risk_score += 25
            indicators.append(f"Shortened URL redirection service: {hostname}")

        # 3. Lookalike / Brand Impersonation in URL Hostname
        lookalike_info = self.lookalike_detector.check_domain(hostname)
        if lookalike_info.get("is_lookalike"):
            risk_score += 50
            indicators.extend(lookalike_info.get("evidence", []))

        # 4. Credential Harvesting Path Detection
        path_lower = path.lower()
        matched_paths = [p for p in self.CREDENTIAL_PATHS if p in path_lower]
        if matched_paths and not is_shortened:
            risk_score += 20
            indicators.append(f"Credential harvesting path pattern: '{matched_paths[0]}'")

        # 5. Suspicious TLD Detection
        if tld in self.SUSPICIOUS_TLDS:
            risk_score += 20
            indicators.append(f"High-abuse top-level domain: .{tld}")

        # 6. Excessive Subdomain Depth
        sub_count = len(subdomain.split(".")) if subdomain else 0
        if sub_count >= 3:
            risk_score += 25
            indicators.append(f"Excessive subdomain nesting depth ({sub_count} levels): '{subdomain}'")

        # 7. Non-standard HTTP Ports
        if port and port not in (80, 443, 8080):
            risk_score += 20
            indicators.append(f"Unusual destination port: :{port}")

        # 8. Obfuscated / Double Encoded Characters
        unquoted = unquote(clean_url)
        if "%2e" in clean_url.lower() or "%2f" in clean_url.lower() or "%3d" in clean_url.lower():
            risk_score += 25
            indicators.append("Hex/URL encoded directory traversal or delimiter evasion detected.")

        # Determine risk level
        risk_score = min(100, max(0, risk_score))
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 45:
            risk_level = "HIGH"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "url": clean_url,
            "scheme": scheme,
            "hostname": hostname,
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "path": path,
            "port": port,
            "is_ip_host": is_ip_host,
            "is_shortened": is_shortened,
            "is_lookalike": lookalike_info.get("is_lookalike", False),
            "impersonated_brand": lookalike_info.get("impersonated_brand"),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
            "evidence": indicators if indicators else ["URL syntax conforms to standard benign destination."]
        }
