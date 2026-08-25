import re
from datetime import datetime


# ============================================================
# THREAT INTELLIGENCE & RISK SCORING
# ============================================================

class ThreatIntelligence:

    def __init__(self):
        self.suspicious_domains = [
            "bit.ly", "tinyurl.com", "goo.gl",
            "ow.ly", "short.link"
        ]

    # --------------------------------------------------------
    # THREAT SCORING ENGINE
    # --------------------------------------------------------

    def calculate_threat_score(self, email_data):
        """
        Calculate overall threat score (0-100)
        Higher = more suspicious
        """

        score = 0
        risk_factors = []

        # Check for phishing indicators
        phishing_risk = self._check_phishing_indicators(
            email_data
        )
        score += phishing_risk["score"]
        risk_factors.extend(phishing_risk["factors"])

        # Check for suspicious attachments
        attachment_risk = self._check_attachment_risk(
            email_data
        )
        score += attachment_risk["score"]
        risk_factors.extend(attachment_risk["factors"])

        # Check for spam/malicious URLs
        url_risk = self._check_url_risk(
            email_data
        )
        score += url_risk["score"]
        risk_factors.extend(url_risk["factors"])

        # Check sender reputation
        sender_risk = self._check_sender_risk(
            email_data
        )
        score += sender_risk["score"]
        risk_factors.extend(sender_risk["factors"])

        # Cap score at 100
        final_score = min(score, 100)

        # Determine threat level
        if final_score >= 75:
            threat_level = "CRITICAL"
        elif final_score >= 50:
            threat_level = "HIGH"
        elif final_score >= 25:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        return {
            "threat_score": final_score,
            "threat_level": threat_level,
            "risk_factors": risk_factors
        }

    # --------------------------------------------------------
    # PHISHING INDICATORS CHECK
    # --------------------------------------------------------

    def _check_phishing_indicators(self, email_data):

        score = 0
        factors = []

        evidence = email_data.get("evidence", {})
        threat_indicators = email_data.get(
            "threat_indicators",
            {}
        )

        # Check for mismatched sender and domain
        sender = evidence.get("from", "").lower()
        subject = evidence.get("subject", "").lower()

        if sender and not sender.endswith("@" + self._extract_domain(sender)):
            score += 15
            factors.append(
                "Suspicious sender format"
            )

        # Check for urgent/action keywords
        urgent_keywords = [
            "verify", "confirm", "act now",
            "urgent", "immediate", "click here",
            "update account", "suspended", "locked"
        ]

        subject_lower = subject.lower()

        for keyword in urgent_keywords:

            if keyword in subject_lower:
                score += 10
                factors.append(
                    f"Phishing keyword detected: '{keyword}'"
                )
                break

        # Check for suspicious URLs
        urls = threat_indicators.get("urls", [])

        for url in urls:

            for suspicious_domain in self.suspicious_domains:

                if suspicious_domain in url:
                    score += 15
                    factors.append(
                        f"Shortened URL detected: {url}"
                    )
                    break

        # Check for mismatched email addresses
        emails = threat_indicators.get("emails", [])

        for email in emails:

            if email != sender:
                score += 5
                factors.append(
                    f"Different email address in content: {email}"
                )

        return {
            "score": min(score, 30),
            "factors": factors
        }

    # --------------------------------------------------------
    # ATTACHMENT RISK CHECK
    # --------------------------------------------------------

    def _check_attachment_risk(self, email_data):

        score = 0
        factors = []

        attachments = email_data.get(
            "attachments",
            []
        )

        if len(attachments) == 0:
            return {"score": 0, "factors": []}

        # Dangerous file extensions
        dangerous_extensions = [
            ".exe", ".bat", ".cmd", ".com",
            ".pif", ".scr", ".vbs", ".js",
            ".jar", ".zip", ".rar", ".7z"
        ]

        for attachment in attachments:

            filename = attachment.get(
                "filename",
                ""
            ).lower()

            for ext in dangerous_extensions:

                if filename.endswith(ext):
                    score += 20
                    factors.append(
                        f"Dangerous file type: {filename}"
                    )
                    break

            # Check for large files (potential malware)
            size = attachment.get("size", 0)

            if size > 10_000_000:  # 10MB
                score += 10
                factors.append(
                    f"Large suspicious file: {filename} ({size} bytes)"
                )

        # Multiple attachments can be suspicious
        if len(attachments) > 3:
            score += 5
            factors.append(
                f"Multiple attachments ({len(attachments)})"
            )

        return {
            "score": min(score, 30),
            "factors": factors
        }

    # --------------------------------------------------------
    # URL RISK CHECK
    # --------------------------------------------------------

    def _check_url_risk(self, email_data):

        score = 0
        factors = []

        threat_indicators = email_data.get(
            "threat_indicators",
            {}
        )

        urls = threat_indicators.get("urls", [])

        if len(urls) == 0:
            return {"score": 0, "factors": []}

        # Check for suspicious URL patterns
        for url in urls:

            # IP-based URLs (instead of domain names)
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
                score += 15
                factors.append(
                    f"IP-based URL detected: {url}"
                )

            # Very long URLs (can hide malicious intent)
            if len(url) > 100:
                score += 10
                factors.append(
                    f"Suspiciously long URL detected"
                )

            # URL encoding (can hide malicious characters)
            if "%2" in url or "%3" in url:
                score += 10
                factors.append(
                    f"URL encoding detected (obfuscation): {url}"
                )

        return {
            "score": min(score, 25),
            "factors": factors
        }

    # --------------------------------------------------------
    # SENDER REPUTATION CHECK
    # --------------------------------------------------------

    def _check_sender_risk(self, email_data):

        score = 0
        factors = []

        evidence = email_data.get("evidence", {})
        geolocation = email_data.get(
            "geolocation",
            {}
        )

        sender = evidence.get("from", "").lower()

        # Check for generic/suspicious sender names
        suspicious_names = [
            "admin", "support", "noreply",
            "do-not-reply", "mailer-daemon"
        ]

        sender_name = sender.split("@")[0].lower()

        if sender_name in suspicious_names:
            score += 10
            factors.append(
                f"Generic sender name: {sender_name}"
            )

        # Check DKIM signature (authentication)
        dkim = evidence.get("dkim_signature", "")

        if not dkim:
            score += 10
            factors.append(
                "No DKIM signature (authentication failed)"
            )

        # Check sender location
        sender_locations = geolocation.get(
            "sender_locations",
            []
        )

        if sender_locations:

            for location in sender_locations:

                threat_level = location.get(
                    "threat_level",
                    ""
                )

                if threat_level == "high":
                    score += 15
                    country = location.get(
                        "country",
                        "Unknown"
                    )
                    factors.append(
                        f"Sender IP flagged as high-threat: {country}"
                    )

        return {
            "score": min(score, 25),
            "factors": factors
        }

    # --------------------------------------------------------
    # EXTRACT DOMAIN FROM EMAIL
    # --------------------------------------------------------

    def _extract_domain(self, email):

        if "@" not in email:
            return ""

        return email.split("@")[1]
