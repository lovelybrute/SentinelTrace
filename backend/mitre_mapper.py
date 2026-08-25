from typing import Dict, Any, List


class MITREMapper:
    """
    MITRE ATT&CK Framework Mapping Engine.
    Maps verified email threat telemetry to Enterprise ATT&CK matrix techniques with supporting evidence.
    """

    def __init__(self):
        pass

    def map_techniques(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Produce a mapped list of MITRE ATT&CK techniques justified by observed evidence.
        """
        mappings: List[Dict[str, Any]] = []

        threat = analysis_result.get("threat_assessment", {})
        forensics = analysis_result.get("forensics", {})
        attachments = analysis_result.get("attachment_analysis", []) or analysis_result.get("attachments", [])
        urls = analysis_result.get("url_analysis", []) or analysis_result.get("threat_indicators", {}).get("urls", [])
        bec = analysis_result.get("bec_analysis", {})
        lookalike = analysis_result.get("lookalike_analysis", {})

        # 1. T1566.001 Spearphishing Attachment
        dangerous_atts = [a for a in attachments if isinstance(a, dict) and (a.get("is_dangerous") or a.get("risk_level") in ("CRITICAL", "HIGH"))]
        if dangerous_atts:
            mappings.append({
                "technique_id": "T1566.001",
                "technique_name": "Phishing: Spearphishing Attachment",
                "tactic": "Initial Access",
                "confidence_score": 95,
                "evidence": [f"Suspicious executable or script attachment: '{dangerous_atts[0].get('filename')}'"]
            })

            # Check for T1036.007 Double Extension
            if any(a.get("has_double_extension") for a in dangerous_atts):
                mappings.append({
                    "technique_id": "T1036.007",
                    "technique_name": "Masquerading: Double File Extension",
                    "tactic": "Defense Evasion",
                    "confidence_score": 90,
                    "evidence": ["Attachment filename uses multiple extensions to conceal true executable type."]
                })

        # 2. T1566.002 Spearphishing Link
        phishing_urls = [u for u in urls if isinstance(u, dict) and u.get("risk_level") in ("CRITICAL", "HIGH")]
        if phishing_urls or (urls and threat.get("threat_score", 0) >= 60 and not dangerous_atts):
            mappings.append({
                "technique_id": "T1566.002",
                "technique_name": "Phishing: Spearphishing Link",
                "tactic": "Initial Access",
                "confidence_score": 90,
                "evidence": [f"Malicious or deceptive link embedded in message body: '{phishing_urls[0].get('url') if phishing_urls else urls[0]}'"]
            })

        # 3. T1598 Phishing for Information / Credential Harvesting
        if lookalike.get("is_lookalike") or (bec.get("category") == "CREDENTIAL_HARVESTING"):
            mappings.append({
                "technique_id": "T1598.003",
                "technique_name": "Phishing for Information: Spearphishing Link",
                "tactic": "Reconnaissance",
                "confidence_score": 85,
                "evidence": [f"Lookalike domain '{lookalike.get('domain')}' targeting brand '{lookalike.get('impersonated_brand')}' credentials."]
            })

        # 4. T1036 Masquerading / Display Name Spoofing
        if bec.get("display_name_spoofing") or lookalike.get("is_lookalike"):
            mappings.append({
                "technique_id": "T1036",
                "technique_name": "Masquerading",
                "tactic": "Defense Evasion",
                "confidence_score": 88,
                "evidence": ["Executive identity or brand impersonation identified in email headers."]
            })

        # 5. T1586 Compromised Email Account (BEC / Account takeover indicator)
        if bec.get("bec_detected") and bec.get("category") in ("PAYROLL_CHANGE", "WIRE_TRANSFER_REQUEST", "INVOICE_FRAUD"):
            mappings.append({
                "technique_id": "T1586.002",
                "technique_name": "Compromised Accounts: Email Accounts",
                "tactic": "Resource Development",
                "confidence_score": 75,
                "evidence": [f"Business Email Compromise tactic: {bec.get('category')}"]
            })

        # Default fallback if general phishing detected
        if not mappings and threat.get("threat_score", 0) >= 50:
            mappings.append({
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "tactic": "Initial Access",
                "confidence_score": 70,
                "evidence": ["General email phishing indicators observed across headers and content."]
            })

        return mappings
