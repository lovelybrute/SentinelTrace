import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, parseaddr
from html import unescape
from typing import Dict, Any, List, Optional, Tuple

from geolocation import GeoLocationIntelligence
from advanced_forensics import AdvancedForensics
from received_parser import ReceivedHeaderParser
from origin_analyzer import OriginAnalyzer
from lookalike_detector import LookalikeDetector
from bec_detector import BECDetector
from attachment_analyzer import AttachmentAnalyzer
from url_analyzer import URLAnalyzer
from ioc_extractor import IOCExtractor
from ml_engine import MLThreatEngine
from threat_scorer import ThreatScorer
from campaign_correlator import CampaignCorrelator
from mitre_mapper import MITREMapper


class EmailForensicParser:
    """
    Forensic-grade RFC 5322/MIME Email Parser and Intelligence Engine.
    Performs complete structural extraction, cryptographic integrity hashing (SHA-256 & SHA-512),
    relay chain reconstruction, authentication validation, IOC indexing, ML threat classification,
    and MITRE ATT&CK mapping.
    """

    IP_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
        r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    )

    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    URL_PATTERN = re.compile(r"https?://[^\s<>'\"`\[\]]+", re.IGNORECASE)

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.geo_intelligence = GeoLocationIntelligence()
        self.forensics = AdvancedForensics()
        self.received_parser = ReceivedHeaderParser()
        self.origin_analyzer = OriginAnalyzer()
        self.lookalike_detector = LookalikeDetector()
        self.bec_detector = BECDetector()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.ioc_extractor = IOCExtractor()
        self.ml_engine = MLThreatEngine()
        self.threat_scorer = ThreatScorer()
        self.campaign_correlator = CampaignCorrelator()
        self.mitre_mapper = MITREMapper()

    def calculate_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate SHA-256 and SHA-512 digests for cryptographic chain of custody."""
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest()
        }

    def extract_urls(self, text: str) -> List[str]:
        """Extract unique URLs from text content."""
        if not text:
            return []
        found = self.URL_PATTERN.findall(text)
        return list(dict.fromkeys(found))

    def extract_ips(self, text: str) -> List[str]:
        """Extract and validate unique IP addresses using ipaddress module."""
        if not text:
            return []
        raw_ips = self.IP_PATTERN.findall(text)
        valid_ips = []
        for ip in raw_ips:
            try:
                ip_obj = ipaddress.ip_address(ip.strip())
                if str(ip_obj) not in valid_ips:
                    valid_ips.append(str(ip_obj))
            except ValueError:
                pass
        return valid_ips

    def extract_emails(self, text: str) -> List[str]:
        """Extract unique email addresses from text."""
        if not text:
            return []
        found = self.EMAIL_PATTERN.findall(text)
        return list(dict.fromkeys(found))

    def _decode_part(self, part) -> str:
        """Safely decode an individual MIME body part to str."""
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            return ""

        if payload is None:
            return ""

        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="ignore")
        except (LookupError, UnicodeDecodeError):
            return payload.decode("utf-8", errors="ignore")

    def html_to_text(self, html: str) -> str:
        """Flatten HTML into searchable plain text preserving link destinations."""
        if not html:
            return ""
        # Drop script and style tags completely
        text = re.sub(r"<(script|style|head)\b[^>]*>.*?</\1>", " ", html, flags=re.IGNORECASE | re.DOTALL)
        # Expose link destinations next to anchor text
        text = re.sub(r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", r"\2 \1 ", text, flags=re.IGNORECASE | re.DOTALL)
        # Preserve newlines on paragraph / line break tags
        text = re.sub(r"<(br|/p|/div|/tr|/h[1-6]|/li)\b[^>]*>", "\n", text, flags=re.IGNORECASE)
        # Strip all remaining HTML tags
        text = re.sub(r"<[^>]+>", " ", text)
        text = unescape(text)
        text = text.replace("\xa0", " ")
        text = re.sub(r"[ \t\r\f\v]+", " ", text)
        text = re.sub(r"\n\s*\n\s*", "\n\n", text)
        return text.strip()

    def extract_body(self, message) -> Tuple[str, str]:
        """
        Walk complete MIME tree to extract readable plain text and raw HTML.
        Returns (plain_text_body, raw_html_body).
        """
        plain_text = ""
        html_content = ""

        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()
            decoded = self._decode_part(part)

            if not decoded:
                continue

            if content_type == "text/plain" and not plain_text:
                plain_text = decoded
            elif content_type == "text/html" and not html_content:
                html_content = decoded

        effective_text = plain_text or self.html_to_text(html_content) or ""
        return effective_text, html_content

    def extract_attachments(self, message) -> List[Dict[str, Any]]:
        """
        Extract attachment metadata and static security analysis from all MIME parts.
        """
        attachments = []
        seen = set()

        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue

            disposition = part.get_content_disposition()
            filename = part.get_filename()

            if disposition != "attachment" and not filename:
                continue

            if not filename:
                continue

            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None

            if payload is None:
                payload = b""

            # Run static forensic attachment analyzer
            analysis = self.attachment_analyzer.analyze_attachment(
                filename=filename,
                content_bytes=payload,
                declared_mime_type=part.get_content_type()
            )

            key = (filename, analysis["sha256"])
            if key in seen:
                continue
            seen.add(key)

            attachments.append({
                "filename": analysis["filename"],
                "size": analysis["size_bytes"],
                "hash": analysis["sha256"],
                "sha256": analysis["sha256"],
                "sha512": analysis["sha512"],
                "risk_level": analysis["risk_level"],
                "risk_score": analysis["risk_score"],
                "is_dangerous": analysis["is_dangerous"],
                "indicators": analysis["indicators"]
            })

        return attachments

    def extract_received_headers(self, message) -> List[Dict[str, Any]]:
        """Extract all Received headers in original presentation sequence."""
        raw_list = message.get_all("Received", [])
        return [{"raw": h} for h in raw_list]

    def parse(self) -> Dict[str, Any]:
        """
        Execute the full SentinelTrace email forensic intelligence pipeline.
        """
        with open(self.file_path, "rb") as f:
            raw_bytes = f.read()

        hashes = self.calculate_hashes(raw_bytes)
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        body_text, html_content = self.extract_body(message)
        received_raw = self.extract_received_headers(message)
        attachments = self.extract_attachments(message)

        # Extended Header Fields
        from_header = message.get("From", "")
        to_header = message.get("To", "")
        cc_header = message.get("Cc", "")
        bcc_header = message.get("Bcc", "")
        reply_to_header = message.get("Reply-To", "")
        return_path = message.get("Return-Path", "")
        subject_header = message.get("Subject", "")
        date_header = str(message.get("Date", ""))
        message_id = message.get("Message-ID", "")
        auth_results = message.get("Authentication-Results", "")
        dkim_sig = message.get("DKIM-Signature", "")
        x_originating_ip = message.get("X-Originating-IP", "")
        x_mailer = message.get("X-Mailer", "") or message.get("User-Agent", "")

        # 1. Received Chain Timeline Analysis
        chain_analysis = self.received_parser.analyze_chain(received_raw)
        earliest_source = chain_analysis.get("earliest_external_source") or {}
        sending_ip = earliest_source.get("ip") if earliest_source.get("ip") != "Unknown" else None

        # 2. Extract Threat Indicators (URLs, IPs, Emails)
        urls = self.extract_urls(f"{subject_header} {body_text}")
        url_analyses = [self.url_analyzer.analyze_url(u) for u in urls]
        body_ips = self.extract_ips(body_text)
        body_emails = self.extract_emails(body_text)

        # 3. Geolocation Intelligence
        sender_locations = self.geo_intelligence.analyze_sender_location(received_raw)

        # 4. Authentication Analysis (SPF + DKIM + DMARC)
        prelim_data = {
            "evidence": {
                "from": from_header,
                "dkim_signature": dkim_sig
            }
        }
        auth_analysis = self.forensics.analyze_authentication(prelim_data, sending_ip=sending_ip)

        # 5. Origin Assessment
        primary_geo = sender_locations[0] if sender_locations else None
        origin_assessment = self.origin_analyzer.assess_origin(
            chain_analysis=chain_analysis,
            geo_data=primary_geo,
            auth_data=auth_analysis
        )

        # 6. Lookalike Domain Detection
        sender_domain = auth_analysis.get("sender_domain") or ""
        lookalike_analysis = self.lookalike_detector.check_domain(sender_domain)

        # 7. BEC Detection
        bec_analysis = self.bec_detector.analyze(
            from_header=from_header,
            reply_to_header=reply_to_header,
            subject=subject_header,
            body_text=body_text
        )

        # 8. Assemble Preliminary Forensic Context
        forensic_context = {
            "authentication": auth_analysis,
            "spoofing_analysis": self.forensics.detect_spoofing({"evidence": {"from": from_header}, "threat_indicators": {"emails": body_emails}}),
            "header_chain": chain_analysis,
            "origin_assessment": origin_assessment,
            "lookalike_analysis": lookalike_analysis,
            "bec_analysis": bec_analysis,
            "attachment_analysis": attachments,
            "url_analysis": url_analyses
        }

        # 9. Campaign Correlation
        campaign_match = self.campaign_correlator.correlate_email({
            "evidence": {"from": from_header, "subject": subject_header},
            "forensics": forensic_context,
            "lookalike_analysis": lookalike_analysis,
            "threat_indicators": {"urls": urls, "ip_addresses": body_ips},
            "attachments": attachments
        })

        # 10. ML Threat Prediction
        ml_prediction = self.ml_engine.predict({
            "evidence": {"from": from_header, "subject": subject_header, "body_preview": body_text[:600]},
            "forensics": forensic_context,
            "lookalike_analysis": lookalike_analysis,
            "attachment_analysis": attachments,
            "url_analysis": url_analyses,
            "bec_analysis": bec_analysis
        })

        # 11. Final Explainable Threat Score
        threat_assessment = self.threat_scorer.compute_score(
            forensic_data=forensic_context,
            ml_prediction=ml_prediction,
            geo_data=primary_geo or {},
            campaign_correlation=campaign_match
        )

        # 12. IOC Extraction & Normalization
        structured_payload_for_iocs = {
            "evidence": {
                "from": from_header,
                "to": to_header,
                "reply_to": reply_to_header,
                "message_id": message_id,
                "body_preview": body_text
            },
            "forensics": forensic_context,
            "threat_indicators": {"urls": urls, "emails": body_emails, "ip_addresses": body_ips},
            "attachments": attachments
        }
        extracted_iocs = self.ioc_extractor.extract_all(structured_payload_for_iocs)

        # 13. MITRE ATT&CK Mapping
        mitre_mappings = self.mitre_mapper.map_techniques({
            "threat_assessment": threat_assessment,
            "forensics": forensic_context,
            "attachment_analysis": attachments,
            "url_analysis": url_analyses,
            "bec_analysis": bec_analysis,
            "lookalike_analysis": lookalike_analysis
        })

        # Assemble Master Payload
        return {
            "evidence": {
                "from": from_header,
                "to": to_header,
                "cc": cc_header,
                "bcc": bcc_header,
                "reply_to": reply_to_header,
                "return_path": return_path,
                "subject": subject_header,
                "date": date_header,
                "message_id": message_id,
                "x_originating_ip": x_originating_ip,
                "x_mailer": x_mailer,
                "content_hash": hashes["sha256"],
                "sha256": hashes["sha256"],
                "sha512": hashes["sha512"],
                "authentication_results": auth_results,
                "dkim_signature": dkim_sig,
                "received_headers": received_raw,
                "body_preview": body_text[:600],
                "filename": None
            },
            "geolocation": {
                "sender_locations": sender_locations,
                "location_count": len(sender_locations)
            },
            "threat_indicators": {
                "urls": urls,
                "ip_addresses": body_ips,
                "emails": body_emails
            },
            "url_analysis": url_analyses,
            "attachments": attachments,
            "attachment_analysis": attachments,
            "forensics": forensic_context,
            "lookalike_analysis": lookalike_analysis,
            "bec_analysis": bec_analysis,
            "ml_prediction": ml_prediction,
            "campaign_correlation": campaign_match,
            "mitre_mappings": mitre_mappings,
            "iocs": extracted_iocs,
            "threat_assessment": threat_assessment
        }
