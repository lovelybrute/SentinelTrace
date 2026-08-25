import re
from email.utils import parseaddr
from typing import Dict, Any, List, Optional


class BECDetector:
    """
    Dedicated Business Email Compromise (BEC) and executive impersonation classifier.
    Analyzes display name spoofing, Reply-To mismatches, financial diversion keywords,
    urgency, secrecy requests, and gift card scams.
    """

    EXECUTIVE_TITLES = [
        "ceo", "chief executive officer", "cfo", "chief financial officer",
        "coo", "chief operating officer", "cto", "president", "managing director",
        "executive director", "director of finance", "vp", "vice president",
        "chairman", "board member", "founder"
    ]

    FINANCIAL_TERMS = [
        "wire transfer", "bank routing", "swift code", "iban", "account number",
        "routing number", "direct deposit", "payroll change", "payroll routing",
        "updated bank details", "new banking information", "remittance advice",
        "invoice attached", "unpaid invoice", "settlement payment", "funds transfer"
    ]

    GIFT_CARD_TERMS = [
        "gift card", "apple gift card", "itunes card", "google play card",
        "steam card", "amazon gift card", "scratch the back", "send the codes",
        "claim code"
    ]

    SECRECY_TERMS = [
        "strictly confidential", "keep this between us", "do not call",
        "in a meeting", "cannot take calls", "discreetly", "confidential inquiry",
        "private transaction", "sensitive matter"
    ]

    URGENCY_TERMS = [
        "urgent", "immediately", "asap", "before end of day", "time sensitive",
        "critical priority", "handle this promptly", "right away"
    ]

    FREE_MAIL_PROVIDERS = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
        "protonmail.com", "mail.com", "yandex.com", "icloud.com"
    ]

    def __init__(self):
        pass

    def analyze(
        self,
        from_header: str,
        reply_to_header: Optional[str] = None,
        subject: str = "",
        body_text: str = ""
    ) -> Dict[str, Any]:
        """
        Evaluate message headers and content for Business Email Compromise indicators.
        """
        display_name, sender_addr = parseaddr(from_header or "")
        sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

        reply_to_display, reply_to_addr = parseaddr(reply_to_header or "")
        reply_to_domain = reply_to_addr.split("@")[-1].lower() if "@" in reply_to_addr else ""

        full_text = f"{subject}\n{body_text}".lower()

        detected = False
        primary_category = "NONE"
        confidence = 0
        factors: List[str] = []

        # 1. Executive Display Name Spoofing Check
        name_lower = display_name.lower()
        claimed_exec_title = None
        for title in self.EXECUTIVE_TITLES:
            if title in name_lower:
                claimed_exec_title = title
                break

        # Check if display name claims an executive identity but sends from a free or unrelated mailbox
        is_free_mail = sender_domain in self.FREE_MAIL_PROVIDERS
        if claimed_exec_title and is_free_mail:
            detected = True
            confidence += 40
            primary_category = "EXECUTIVE_IMPERSONATION"
            factors.append(
                f"Executive title '{claimed_exec_title}' in display name '{display_name}' sent from public webmail address ({sender_addr})."
            )

        # 2. Reply-To Hijack / Mismatch Check
        if reply_to_addr and reply_to_addr.lower() != sender_addr.lower():
            if reply_to_domain != sender_domain:
                detected = True
                confidence += 35
                factors.append(
                    f"Reply-To mismatch: Replies directed to different domain ({reply_to_addr}) than sender ({sender_addr})."
                )

        # 3. Financial Diversion / Wire Transfer Analysis
        matched_fin = [t for t in self.FINANCIAL_TERMS if t in full_text]
        if matched_fin:
            detected = True
            confidence += 30
            if "payroll" in " ".join(matched_fin):
                primary_category = "PAYROLL_CHANGE"
            elif "invoice" in " ".join(matched_fin):
                primary_category = "INVOICE_FRAUD"
            else:
                primary_category = "WIRE_TRANSFER_REQUEST"
            factors.append(f"Financial diversion terminology detected: {', '.join(matched_fin[:3])}")

        # 4. Gift Card Scam Detection
        matched_gc = [t for t in self.GIFT_CARD_TERMS if t in full_text]
        if matched_gc:
            detected = True
            confidence += 45
            primary_category = "GIFT_CARD_SCAM"
            factors.append(f"Gift card solicitation patterns detected: {', '.join(matched_gc[:3])}")

        # 5. Secrecy & Exclusivity Pressure
        matched_sec = [t for t in self.SECRECY_TERMS if t in full_text]
        if matched_sec:
            confidence += 20
            factors.append(f"Secrecy/isolation request: '{matched_sec[0]}'")

        # 6. Urgency Keywords
        matched_urg = [t for t in self.URGENCY_TERMS if t in full_text]
        if matched_urg:
            confidence += 15
            factors.append(f"Urgency/action pressure markers detected: '{matched_urg[0]}'")

        # Set final classification
        confidence_capped = min(98, max(0, confidence))
        if confidence_capped < 30:
            detected = False
            primary_category = "NONE"

        return {
            "bec_detected": detected,
            "category": primary_category,
            "confidence_score": confidence_capped if detected else 0,
            "display_name_spoofing": bool(claimed_exec_title and is_free_mail),
            "reply_to_mismatch": bool(reply_to_addr and reply_to_domain != sender_domain),
            "risk_factors": factors,
            "evidence": factors if detected else ["No BEC indicators identified."]
        }
