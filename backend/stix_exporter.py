import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List


class STIXExporter:
    """
    OASIS STIX 2.1 Compatible Threat Intelligence Export Engine.
    Serializes forensic indicators, email observables, MITRE techniques, and campaigns into STIX 2.1 JSON.
    """

    def __init__(self):
        pass

    def export_bundle(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a STIX 2.1 Bundle from SentinelTrace analysis telemetry.
        """
        bundle_id = f"bundle--{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        objects: List[Dict[str, Any]] = []

        evidence = analysis_result.get("evidence", {})
        threat = analysis_result.get("threat_assessment", {})
        iocs = analysis_result.get("iocs", [])
        mitre = analysis_result.get("mitre_mappings", [])
        campaign = analysis_result.get("campaign_correlation", {})

        # 1. Identity Object (SentinelTrace Platform)
        identity_id = f"identity--{uuid.uuid4()}"
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "SentinelTrace AI Forensic Platform",
            "identity_class": "system"
        })

        # 2. Campaign Object (if matched)
        campaign_obj_id = None
        if campaign.get("matched_campaign_id"):
            campaign_obj_id = f"campaign--{uuid.uuid4()}"
            objects.append({
                "type": "campaign",
                "spec_version": "2.1",
                "id": campaign_obj_id,
                "created": now_iso,
                "modified": now_iso,
                "name": campaign.get("campaign_name", "Unassigned Threat Campaign"),
                "description": campaign.get("description", "Correlated email threat activity cluster.")
            })

        # 3. MITRE Attack Pattern Objects
        attack_pattern_ids = []
        for m in mitre:
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            attack_pattern_ids.append(ap_id)
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_iso,
                "modified": now_iso,
                "name": m.get("technique_name", "Phishing"),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": m.get("technique_id", "T1566")
                    }
                ]
            })

        # 4. Indicator Objects for Extracted IOCs
        for ioc in iocs:
            ioc_type = ioc.get("type")
            val = ioc.get("value")
            if not val:
                continue

            pattern = None
            if ioc_type == "IPV4":
                pattern = f"[ipv4-addr:value = '{val}']"
            elif ioc_type == "IPV6":
                pattern = f"[ipv6-addr:value = '{val}']"
            elif ioc_type == "DOMAIN":
                pattern = f"[domain-name:value = '{val}']"
            elif ioc_type == "URL":
                safe_val = val.replace("'", "\\'")
                pattern = f"[url:value = '{safe_val}']"
            elif ioc_type == "SHA256":
                pattern = f"[file:hashes.'SHA-256' = '{val}']"
            elif ioc_type == "EMAIL_ADDRESS":
                pattern = f"[email-addr:value = '{val}']"

            if pattern:
                ind_id = f"indicator--{uuid.uuid4()}"
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"SentinelTrace IOC: {ioc_type} {val}",
                    "indicator_types": ["malicious-activity" if threat.get("threat_score", 0) >= 50 else "anomalous-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                    "confidence": ioc.get("confidence", 85)
                })

                # Relate to campaign if present
                if campaign_obj_id:
                    objects.append({
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": f"relationship--{uuid.uuid4()}",
                        "created": now_iso,
                        "modified": now_iso,
                        "relationship_type": "indicates",
                        "source_ref": ind_id,
                        "target_ref": campaign_obj_id
                    })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
