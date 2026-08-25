import re
try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
from datetime import datetime
from email.utils import parseaddr


# ============================================================
# ADVANCED EMAIL FORENSICS
# ============================================================

class AdvancedForensics:

    def __init__(self):
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 5
            self.resolver.lifetime = 10
        else:
            self.resolver = None

    # --------------------------------------------------------
    # DKIM VALIDATION
    # --------------------------------------------------------

    def validate_dkim(self, dkim_signature, sender_domain):
        """
        Validate DKIM signature authenticity
        """

        if not dkim_signature:
            return {
                "valid": False,
                "status": "missing",
                "message": "No DKIM signature found"
            }

        try:

            # Extract DKIM key id
            if "d=" in dkim_signature:
                domain_match = re.search(
                    r'd=([^;]+)',
                    dkim_signature
                )
                dkim_domain = domain_match.group(1) if domain_match else None

                if dkim_domain != sender_domain:
                    return {
                        "valid": False,
                        "status": "domain_mismatch",
                        "message": f"DKIM domain '{dkim_domain}' doesn't match sender domain '{sender_domain}'",
                        "severity": "high"
                    }

            return {
                "valid": True,
                "status": "signed",
                "message": "Email is DKIM signed"
            }

        except Exception as e:

            return {
                "valid": False,
                "status": "error",
                "message": str(e)
            }

    # --------------------------------------------------------
    # SPF RECORD CHECK
    # --------------------------------------------------------

    def check_spf_record(self, sender_domain):
        """
        Check SPF record for sender domain
        """

        if not DNS_AVAILABLE:
            return {
                "found": False,
                "status": "dns_unavailable",
                "message": "DNS module not available",
                "severity": "low"
            }

        try:

            # Query TXT records for SPF
            answers = self.resolver.resolve(
                sender_domain,
                'TXT'
            )

            spf_records = []

            for rdata in answers:

                txt_value = str(rdata).strip('"')

                if txt_value.startswith('v=spf1'):
                    spf_records.append(txt_value)

            if spf_records:

                return {
                    "found": True,
                    "records": spf_records,
                    "status": "pass",
                    "message": "Valid SPF record found"
                }

            else:

                return {
                    "found": False,
                    "status": "no_spf",
                    "message": f"No SPF record found for {sender_domain}",
                    "severity": "medium"
                }

        except dns.exception.DNSException as e:

            return {
                "found": False,
                "status": "dns_error",
                "message": f"DNS lookup failed: {str(e)}",
                "severity": "low"
            }

        except Exception as e:

            return {
                "found": False,
                "status": "error",
                "message": str(e)
            }

    # --------------------------------------------------------
    # DMARC RECORD CHECK
    # --------------------------------------------------------

    def check_dmarc_record(self, sender_domain):
        """
        Check DMARC policy for sender domain
        """

        if not DNS_AVAILABLE:
            return {
                "found": False,
                "status": "dns_unavailable",
                "message": "DNS module not available"
            }

        try:

            # Query _dmarc subdomain
            dmarc_domain = f"_dmarc.{sender_domain}"

            answers = self.resolver.resolve(
                dmarc_domain,
                'TXT'
            )

            dmarc_records = []

            for rdata in answers:

                txt_value = str(rdata).strip('"')

                if txt_value.startswith('v=DMARC1'):
                    dmarc_records.append(txt_value)

            if dmarc_records:

                # Parse policy
                policy = "none"
                for record in dmarc_records:
                    if "p=reject" in record:
                        policy = "reject"
                    elif "p=quarantine" in record:
                        policy = "quarantine"

                return {
                    "found": True,
                    "policy": policy,
                    "records": dmarc_records,
                    "status": "pass",
                    "message": f"DMARC policy: {policy}"
                }

            else:

                return {
                    "found": False,
                    "status": "no_dmarc",
                    "message": f"No DMARC record for {sender_domain}",
                    "severity": "low"
                }

        except dns.exception.DNSException:

            return {
                "found": False,
                "status": "dns_error",
                "message": f"No DMARC record found",
                "severity": "low"
            }

        except Exception as e:

            return {
                "found": False,
                "status": "error",
                "message": str(e)
            }

    # --------------------------------------------------------
    # EXTRACT SENDER DOMAIN
    # --------------------------------------------------------

    def extract_sender_domain(self, email_address):
        """
        Extract the domain from a From header.

        The header is a full RFC-5322 address field, not a bare address, so it
        may carry a display name and angle brackets:

            Finance Department <finance@paypa1-security.com>

        Naively splitting on "@" leaves a trailing ">" on the domain, which
        makes every downstream SPF/DMARC lookup fail and forces DKIM into a
        false "domain_mismatch". parseaddr() unwraps the address properly.
        """

        if not email_address:
            return None

        # parseaddr returns ("display name", "addr@domain"); it tolerates a
        # bare address, angle-bracket form, and quoted display names.
        _, address = parseaddr(email_address)

        # Fall back to the raw value when the header is malformed enough that
        # parseaddr gives up but an address is still recoverable.
        if "@" not in address:
            address = email_address

        if "@" not in address:
            return None

        domain = address.rsplit("@", 1)[1].strip().lower()

        # Strip any stray delimiters left by a malformed header.
        domain = domain.strip("<>[](),;\"' \t")

        return domain or None

    # --------------------------------------------------------
    # ANALYZE EMAIL HEADERS
    # --------------------------------------------------------

    def analyze_authentication(self, email_data):
        """
        Comprehensive authentication analysis
        """

        evidence = email_data.get("evidence", {})
        sender = evidence.get("from", "")
        sender_domain = self.extract_sender_domain(sender)

        authentication = {
            "sender": sender,
            "sender_domain": sender_domain,
            "dkim": None,
            "spf": None,
            "dmarc": None,
            "overall_trust_score": 0
        }

        if not sender_domain:
            return authentication

        # Check DKIM
        dkim_sig = evidence.get("dkim_signature", "")
        authentication["dkim"] = self.validate_dkim(
            dkim_sig,
            sender_domain
        )

        # Check SPF
        authentication["spf"] = self.check_spf_record(
            sender_domain
        )

        # Check DMARC
        authentication["dmarc"] = self.check_dmarc_record(
            sender_domain
        )

        # Calculate trust score
        trust_score = 50  # Base score

        if authentication["dkim"]["valid"]:
            trust_score += 20

        if authentication["spf"]["found"]:
            trust_score += 15

        if authentication["dmarc"]["found"]:
            trust_score += 15

        authentication["overall_trust_score"] = min(100, trust_score)

        return authentication

    # --------------------------------------------------------
    # DETECT SPOOFING ATTEMPTS
    # --------------------------------------------------------

    def detect_spoofing(self, email_data):
        """
        Detect email spoofing attempts
        """

        evidence = email_data.get("evidence", {})
        threat_indicators = email_data.get(
            "threat_indicators",
            {}
        )

        spoofing_indicators = {
            "detected": False,
            "confidence": 0,
            "factors": []
        }

        sender = evidence.get("from", "").lower()
        body_emails = [
            e.lower() for e in threat_indicators.get(
                "emails",
                []
            )
        ]

        # Check if sender domain different from email in body
        sender_domain = self.extract_sender_domain(sender)

        for body_email in body_emails:

            body_domain = self.extract_sender_domain(
                body_email
            )

            if (body_domain and sender_domain and
                body_domain != sender_domain):

                spoofing_indicators["detected"] = True
                spoofing_indicators["confidence"] += 25
                spoofing_indicators["factors"].append(
                    f"Body contains email from different domain: {body_email}"
                )

        # Check for common spoofing patterns
        if re.search(
            r'verify.+account|confirm.+identity|update.+payment',
            evidence.get("subject", "").lower()
        ):
            spoofing_indicators["detected"] = True
            spoofing_indicators["confidence"] += 20
            spoofing_indicators["factors"].append(
                "Subject contains common spoofing keywords"
            )

        spoofing_indicators["confidence"] = min(
            100,
            spoofing_indicators["confidence"]
        )

        return spoofing_indicators

    # --------------------------------------------------------
    # HEADER CHAIN ANALYSIS
    # --------------------------------------------------------

    def analyze_header_chain(self, received_headers):
        """
        Analyze email header chain for anomalies
        """

        if not received_headers:
            return {
                "chain_length": 0,
                "anomalies": [],
                "analysis": "No Received headers found"
            }

        chain_analysis = {
            "chain_length": len(received_headers),
            "anomalies": [],
            "hop_analysis": []
        }

        prev_server = None

        for i, header in enumerate(received_headers):

            raw = header.get("raw", "")

            # Extract server info
            server_match = re.search(
                r'from\s+([^\s\[]+)',
                raw
            )
            current_server = server_match.group(1) if server_match else "Unknown"

            chain_analysis["hop_analysis"].append({
                "hop": i + 1,
                "server": current_server,
                "raw": raw[:100] + "..." if len(raw) > 100 else raw
            })

            # Detect suspicious patterns
            if "localhost" in raw.lower():
                chain_analysis["anomalies"].append(
                    f"Localhost detected in hop {i + 1}"
                )

            if "[127.0.0.1]" in raw:
                chain_analysis["anomalies"].append(
                    f"Internal IP in hop {i + 1}"
                )

            prev_server = current_server

        return chain_analysis
