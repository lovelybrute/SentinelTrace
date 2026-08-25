import re
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html import unescape
from geolocation import GeoLocationIntelligence
from threat_intelligence import ThreatIntelligence


# ============================================================
# EMAIL FORENSIC PARSER
# ============================================================

class EmailForensicParser:

    def __init__(self, file_path):
        self.file_path = file_path
        self.geo_intelligence = GeoLocationIntelligence()
        self.threat_intelligence = ThreatIntelligence()

    # --------------------------------------------------------
    # SHA-256 EVIDENCE HASH
    # --------------------------------------------------------

    def calculate_hash(self, data):

        return hashlib.sha256(data).hexdigest()

    # --------------------------------------------------------
    # EXTRACT URLS
    # --------------------------------------------------------

    def extract_urls(self, text):

        if not text:
            return []

        url_pattern = r'https?://[^\s<>"\'\]]+'

        urls = re.findall(
            url_pattern,
            text
        )

        # Remove duplicates
        return list(dict.fromkeys(urls))

    # --------------------------------------------------------
    # EXTRACT IP ADDRESSES
    # --------------------------------------------------------

    def extract_ips(self, text):

        if not text:
            return []

        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

        ips = re.findall(
            ip_pattern,
            text
        )

        # Remove duplicates
        return list(dict.fromkeys(ips))

    # --------------------------------------------------------
    # EXTRACT EMAIL ADDRESSES
    # --------------------------------------------------------

    def extract_emails(self, text):

        if not text:
            return []

        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

        emails = re.findall(
            email_pattern,
            text
        )

        # Remove duplicates
        return list(dict.fromkeys(emails))

    # --------------------------------------------------------
    # EXTRACT EMAIL BODY
    # --------------------------------------------------------

    def extract_body(self, message):
        """
        Recover the readable body text of a message.

        A real-world email nests parts arbitrarily deep — a typical phishing
        message is multipart/mixed wrapping multipart/alternative wrapping
        text/plain and text/html. Only inspecting the top level meant nested
        and HTML-only messages produced an empty body, which in turn starved
        URL/IP/address extraction and understated the threat score.

        Strategy: walk the whole tree, prefer the first readable text/plain
        part, and fall back to de-tagged text/html when no plain part exists.
        """

        plain_text = ""
        html_text = ""

        for part in message.walk():

            # Skip container parts and anything the sender marked as a
            # file download rather than message content.
            if part.get_content_maintype() == "multipart":
                continue

            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            if content_type not in ("text/plain", "text/html"):
                continue

            decoded = self._decode_part(part)

            if not decoded:
                continue

            if content_type == "text/plain" and not plain_text:
                plain_text = decoded

            elif content_type == "text/html" and not html_text:
                html_text = decoded

            if plain_text:
                break

        if plain_text:
            return plain_text

        if html_text:
            return self.html_to_text(html_text)

        return ""

    # --------------------------------------------------------
    # DECODE A SINGLE MIME PART
    # --------------------------------------------------------

    def _decode_part(self, part):
        """
        Decode one part's payload to str, tolerating every way this can fail.

        get_payload(decode=True) returns None for an empty or container
        payload, which previously raised AttributeError and surfaced as a
        500 from /analyze.
        """

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

    # --------------------------------------------------------
    # HTML TO TEXT
    # --------------------------------------------------------

    def html_to_text(self, html):
        """
        Flatten HTML into analysable text.

        Anchor targets are kept inline as "text (href)" so that URL
        extraction still sees links that only ever appear in an href, and so
        that anchor-text/destination mismatches remain visible downstream.
        """

        if not html:
            return ""

        # Drop non-content elements entirely, including their inner text.
        text = re.sub(
            r"<(script|style|head)\b[^>]*>.*?</\1>",
            " ",
            html,
            flags=re.IGNORECASE | re.DOTALL
        )

        # Surface href targets next to their visible anchor text. The URL is
        # separated by whitespace only: wrapping it in brackets would leave
        # punctuation glued to the URL, and extract_urls() stops at
        # whitespace, so a trailing ")" would end up inside the indicator.
        text = re.sub(
            r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
            r"\2 \1 ",
            text,
            flags=re.IGNORECASE | re.DOTALL
        )

        # Preserve line structure before stripping the remaining tags.
        text = re.sub(
            r"<(br|/p|/div|/tr|/h[1-6]|/li)\b[^>]*>",
            "\n",
            text,
            flags=re.IGNORECASE
        )

        text = re.sub(r"<[^>]+>", " ", text)

        # Resolve the entities that actually matter for parsing.
        text = unescape(text)

        # Normalise non-breaking spaces introduced by &nbsp; so that
        # whitespace-delimited extraction behaves predictably.
        text = text.replace("\xa0", " ")

        # Collapse runs of whitespace without destroying paragraph breaks.
        text = re.sub(r"[ \t\r\f\v]+", " ", text)
        text = re.sub(r"\n\s*\n\s*", "\n\n", text)

        return text.strip()

    # --------------------------------------------------------
    # EXTRACT ATTACHMENTS
    # --------------------------------------------------------

    def extract_attachments(self, message):
        """
        Collect attachments from anywhere in the MIME tree.

        Nested multipart/mixed structures previously hid attachments from the
        top-level-only scan, so a malicious payload one level down was never
        hashed or reported.
        """

        attachments = []
        seen = set()

        for part in message.walk():

            if part.get_content_maintype() == "multipart":
                continue

            disposition = part.get_content_disposition()
            filename = part.get_filename()

            # Treat any part carrying a filename as an attachment: some
            # malicious senders omit or misspell Content-Disposition to slip
            # past naive filters.
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

            digest = self.calculate_hash(payload)

            # A repeated filename+hash pair is the same artefact seen twice.
            key = (filename, digest)

            if key in seen:
                continue

            seen.add(key)

            attachments.append({
                "filename": filename,
                "size": len(payload),
                "hash": digest
            })

        return attachments

    # --------------------------------------------------------
    # EXTRACT RECEIVED HEADERS
    # --------------------------------------------------------

    def extract_received_headers(self, message):

        received_headers = message.get_all("Received", [])

        parsed_headers = []

        for header in received_headers:

            parsed_headers.append({
                "raw": header
            })

        return parsed_headers

    # --------------------------------------------------------
    # PARSE EMAIL
    # --------------------------------------------------------

    def parse(self):

        with open(
            self.file_path,
            "rb"
        ) as file:

            raw_data = file.read()


        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            raw_data
        )


        body = self.extract_body(
            message
        )


        received_headers = (
            self.extract_received_headers(
                message
            )
        )


        attachments = (
            self.extract_attachments(
                message
            )
        )


        # Authentication headers

        authentication_results = (
            message.get(
                "Authentication-Results",
                ""
            )
        )

        dkim_signature = (
            message.get(
                "DKIM-Signature",
                ""
            )
        )

        # Geolocation analysis
        sender_locations = (
            self.geo_intelligence.analyze_sender_location(
                received_headers
            )
        )

        # Build intermediate result
        email_analysis = {
            "evidence": {},
            "threat_indicators": {},
            "geolocation": {
                "sender_locations": sender_locations,
                "location_count": len(sender_locations)
            },
            "attachments": []
        }

        # Perform threat scoring
        threat_assessment = (
            self.threat_intelligence.calculate_threat_score(
                {
                    "evidence": {
                        "from": message.get("From", ""),
                        "subject": message.get("Subject", ""),
                        "dkim_signature": dkim_signature
                    },
                    "threat_indicators": {
                        "urls": self.extract_urls(body),
                        "emails": self.extract_emails(body)
                    },
                    "geolocation": email_analysis["geolocation"],
                    "attachments": self.extract_attachments(message)
                }
            )
        )

        return {

            # ----------------------------------------------
            # Evidence
            # ----------------------------------------------

            "evidence": {

                "from": message.get("From", ""),
                "to": message.get("To", ""),
                "subject": message.get("Subject", ""),
                "date": str(
                    message.get("Date", "")
                ),
                "message_id": message.get(
                    "Message-ID",
                    ""
                ),

                # Content hash for integrity
                "content_hash": self.calculate_hash(
                    raw_data
                ),

                # Authentication
                "authentication_results": (
                    authentication_results
                ),

                "dkim_signature": dkim_signature,

                "received_headers": received_headers,

                # Content analysis
                "body_preview": body[:500],

            },

            # ----------------------------------------------
            # Geolocation Intelligence
            # ----------------------------------------------

            "geolocation": {

                "sender_locations": sender_locations,
                "location_count": len(sender_locations)

            },

            # ----------------------------------------------
            # Threat Indicators
            # ----------------------------------------------

            "threat_indicators": {

                "urls":
                    self.extract_urls(
                        body
                    ),

                "ip_addresses":
                    self.extract_ips(
                        body
                    ),

                "emails":
                    self.extract_emails(
                        body
                    )
            },

            # ----------------------------------------------
            # Attachments
            # ----------------------------------------------

            "attachments":
                attachments,

            # ----------------------------------------------
            # Threat Assessment
            # ----------------------------------------------

            "threat_assessment": threat_assessment
        }
