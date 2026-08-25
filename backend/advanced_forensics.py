from email.utils import parseaddr
from typing import Dict, Any, List, Optional

from spf_evaluator import SPFEvaluator
from dkim_verifier import DKIMVerifier
from dmarc_analyzer import DMARCAnalyzer
from received_parser import ReceivedHeaderParser
from origin_analyzer import OriginAnalyzer
from lookalike_detector import LookalikeDetector
from bec_detector import BECDetector


class AdvancedForensics:
    """
    Forensic Orchestration Suite.
    Integrates real SPF evaluation, DKIM cryptographic inspection, DMARC alignment analysis,
    Received-chain timeline reconstruction, origin assessment, lookalike detection, and BEC analysis.
    """

    def __init__(self):
        self.spf_evaluator = SPFEvaluator()
        self.dkim_verifier = DKIMVerifier()
        self.dmarc_analyzer = DMARCAnalyzer()
        self.received_parser = ReceivedHeaderParser()
        self.origin_analyzer = OriginAnalyzer()
        self.lookalike_detector = LookalikeDetector()
        self.bec_detector = BECDetector()

    def extract_sender_domain(self, email_address: Optional[str]) -> Optional[str]:
        """Unwrap RFC-5322 address headers and extract clean lowercase domain."""
        if not email_address:
            return None
        _, address = parseaddr(email_address)
        if "@" not in address:
            address = email_address
        if "@" not in address:
            return None
        domain = address.rsplit("@", 1)[1].strip().lower().strip("<>[](),;\"' \t")
        return domain or None

    def analyze_authentication(
        self,
        email_data: Dict[str, Any],
        sending_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive RFC-compliant authentication analysis (SPF + DKIM + DMARC + Alignment).
        """
        evidence = email_data.get("evidence", {})
        sender = evidence.get("from", "")
        sender_domain = self.extract_sender_domain(sender)
        dkim_sig = evidence.get("dkim_signature", "")

        # 1. DKIM Verification
        dkim_res = self.dkim_verifier.verify(dkim_sig, sender_domain)

        # 2. SPF Evaluation (Against observed sending IP or earliest hop)
        spf_res = self.spf_evaluator.evaluate(sender_domain or "", sending_ip)

        # 3. DMARC Evaluation & Identifier Alignment
        dmarc_res = self.dmarc_analyzer.evaluate(sender_domain or "", spf_res, dkim_res)

        # Compute Trust Score based on genuine cryptographic and policy verification
        trust_score = 30  # Baseline unauthenticated message
        if dkim_res.get("status") == "PASS":
            trust_score += 30
        elif dkim_res.get("signature_present"):
            trust_score += 10

        if spf_res.get("is_pass"):
            trust_score += 20
        elif spf_res.get("record_present"):
            trust_score += 5

        if dmarc_res.get("result") == "PASS":
            trust_score += 20

        # Penalize hard authentication failures / spoofing
        if spf_res.get("result") == "FAIL" or dmarc_res.get("result") == "FAIL":
            trust_score = max(5, trust_score - 25)

        return {
            "sender": sender,
            "sender_domain": sender_domain,
            "dkim": dkim_res,
            "spf": spf_res,
            "dmarc": dmarc_res,
            "overall_trust_score": min(100, max(0, trust_score))
        }

    def detect_spoofing(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect display name spoofing, domain mismatches, and lookalikes.
        """
        evidence = email_data.get("evidence", {})
        sender = evidence.get("from", "")
        sender_domain = self.extract_sender_domain(sender)

        # Run lookalike domain check
        lookalike = self.lookalike_detector.check_domain(sender_domain or "")

        factors: List[str] = []
        confidence = 0
        detected = False

        if lookalike.get("is_lookalike"):
            detected = True
            confidence += 60
            factors.extend(lookalike.get("evidence", []))

        # Check body emails vs sender domain
        body_emails = email_data.get("threat_indicators", {}).get("emails", [])
        for be in body_emails:
            b_domain = self.extract_sender_domain(be)
            if b_domain and sender_domain and b_domain != sender_domain:
                if b_domain not in ("example.com", "localhost"):
                    factors.append(f"Content cites external domain email: {be}")
                    confidence += 15
                    detected = True

        return {
            "detected": detected,
            "confidence": min(100, confidence),
            "lookalike_match": lookalike.get("is_lookalike", False),
            "impersonated_brand": lookalike.get("impersonated_brand"),
            "factors": factors
        }

    def analyze_header_chain(self, received_headers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Reconstruct chronological transmission path and detect relay anomalies.
        """
        return self.received_parser.analyze_chain(received_headers)
