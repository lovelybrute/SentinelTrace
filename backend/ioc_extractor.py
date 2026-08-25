import ipaddress
import re
from typing import Dict, Any, List, Set
from urllib.parse import urlparse

try:
    import tldextract
    TLD_AVAILABLE = True
except ImportError:
    TLD_AVAILABLE = False


class IOCExtractor:
    """
    Dedicated Indicators of Compromise (IOC) extraction and normalization engine.
    Extracts IPv4, IPv6, domains, URLs, email addresses, file hashes, and message identifiers.
    Validates strictly with Python's ipaddress module.
    """

    IP_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
        r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    )

    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    URL_PATTERN = re.compile(r"https?://[^\s<>'\"`\[\]]+", re.IGNORECASE)
    HASH_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

    def __init__(self):
        pass

    def extract_all(self, email_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract, normalize, and classify all IOCs from an analyzed email structure.
        """
        iocs: List[Dict[str, Any]] = []
        seen_keys: Set[str] = set()

        def add_ioc(ioc_type: str, value: str, source: str, confidence: int = 90, is_malicious: bool = False):
            val_norm = value.strip().lower()
            key = f"{ioc_type}:{val_norm}"
            if key in seen_keys or not val_norm:
                return
            seen_keys.add(key)
            iocs.append({
                "type": ioc_type,
                "value": value.strip(),
                "source": source,
                "confidence": confidence,
                "is_malicious": is_malicious
            })

        evidence = email_data.get("evidence", {})
        body = evidence.get("body_preview", "")
        received_chain = email_data.get("forensics", {}).get("header_chain", {}).get("chronological_hops", [])

        # 1. Message-ID
        msg_id = evidence.get("message_id")
        if msg_id:
            add_ioc("MESSAGE_ID", msg_id, "HEADER_MESSAGE_ID", confidence=100)

        # 2. Email Addresses
        for field, src in [("from", "HEADER_FROM"), ("to", "HEADER_TO"), ("reply_to", "HEADER_REPLY_TO")]:
            raw_field = evidence.get(field, "")
            emails = self.EMAIL_PATTERN.findall(raw_field)
            for em in emails:
                add_ioc("EMAIL_ADDRESS", em, src, confidence=95)

        # Body emails
        for em in email_data.get("threat_indicators", {}).get("emails", []):
            add_ioc("EMAIL_ADDRESS", em, "EMAIL_BODY", confidence=85)

        # 3. IP Addresses from Received Chain
        for hop in received_chain:
            ip_str = hop.get("from_ip")
            if ip_str:
                try:
                    ip_obj = ipaddress.ip_address(ip_str.strip())
                    if ip_obj.is_global:
                        add_ioc("IPV4" if ip_obj.version == 4 else "IPV6", str(ip_obj), f"RECEIVED_HOP_{hop.get('hop_number', 1)}", confidence=90)
                    else:
                        add_ioc("IP_INTERNAL", str(ip_obj), f"RECEIVED_HOP_{hop.get('hop_number', 1)}", confidence=70)
                except ValueError:
                    pass

        # 4. URLs
        for url in email_data.get("threat_indicators", {}).get("urls", []):
            add_ioc("URL", url, "EMAIL_BODY", confidence=90)
            parsed = urlparse(url if "://" in url else f"http://{url}")
            if parsed.hostname:
                if TLD_AVAILABLE:
                    ext = tldextract.extract(parsed.hostname)
                    if ext.domain and ext.suffix:
                        add_ioc("DOMAIN", f"{ext.domain}.{ext.suffix}", "URL_HOST_DOMAIN", confidence=90)
                else:
                    parts = parsed.hostname.split(".")
                    if len(parts) >= 2:
                        add_ioc("DOMAIN", ".".join(parts[-2:]), "URL_HOST_DOMAIN", confidence=85)

        # 5. Attachment Hashes
        for att in email_data.get("attachments", []):
            sha256 = att.get("sha256") or att.get("hash")
            if sha256:
                add_ioc("SHA256", sha256, f"ATTACHMENT_{att.get('filename', 'file')}", confidence=100)
            sha512 = att.get("sha512")
            if sha512:
                add_ioc("SHA512", sha512, f"ATTACHMENT_{att.get('filename', 'file')}", confidence=100)

        # 6. Sender Domain & DKIM Domain
        sender_domain = email_data.get("forensics", {}).get("authentication", {}).get("sender_domain")
        if sender_domain:
            add_ioc("DOMAIN", sender_domain, "HEADER_SENDER_DOMAIN", confidence=95)

        dkim_domain = email_data.get("forensics", {}).get("authentication", {}).get("dkim", {}).get("signing_domain")
        if dkim_domain:
            add_ioc("DOMAIN", dkim_domain, "DKIM_SIGNING_DOMAIN", confidence=95)

        return iocs
