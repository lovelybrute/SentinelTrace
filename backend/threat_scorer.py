from typing import Dict, Any, List


class ThreatScorer:
    """
    Hybrid explainable threat scoring engine.
    Synthesizes Forensic Rules (35%), ML Predictions (40%), Infrastructure Reputation (15%),
    and Campaign History (10%) into a transparent 0-100 score.
    Separates strong evidence from contextual signals without bad heuristics.
    """

    def __init__(self):
        pass

    def compute_score(
        self,
        forensic_data: Dict[str, Any],
        ml_prediction: Dict[str, Any],
        geo_data: Dict[str, Any],
        campaign_correlation: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate calibrated hybrid threat score with full signal breakdown.
        """
        signals: List[Dict[str, Any]] = []

        # ----------------------------------------------------
        # 1. Forensic Rule Signals (Max 35 points towards total)
        # ----------------------------------------------------
        rule_points = 0.0

        # Lookalike Domain Check (STRONG)
        lookalike = forensic_data.get("lookalike_analysis", {})
        if lookalike.get("is_lookalike"):
            sim = lookalike.get("similarity_score", 0.8)
            pts = round(25 * sim, 1)
            rule_points += pts
            signals.append({
                "signal": f"Brand impersonation / lookalike domain ({lookalike.get('impersonated_brand', 'brand')})",
                "points": pts,
                "weight_category": "STRONG"
            })

        # Dangerous Attachment Check (STRONG)
        attachments = forensic_data.get("attachment_analysis", [])
        dangerous_atts = [a for a in attachments if a.get("is_dangerous")]
        if dangerous_atts:
            pts = 30.0
            rule_points += pts
            signals.append({
                "signal": f"High-risk attachment payload ({dangerous_atts[0].get('filename')})",
                "points": pts,
                "weight_category": "STRONG"
            })

        # BEC / Executive Impersonation Check (STRONG)
        bec = forensic_data.get("bec_analysis", {})
        if bec.get("bec_detected"):
            pts = round(25 * (bec.get("confidence_score", 50) / 100), 1)
            rule_points += pts
            signals.append({
                "signal": f"Business Email Compromise pattern: {bec.get('category', 'BEC')}",
                "points": pts,
                "weight_category": "STRONG"
            })

        # Malicious URL / IP URL Check (MODERATE)
        urls = forensic_data.get("url_analysis", [])
        ip_urls = [u for u in urls if u.get("is_ip_host")]
        short_urls = [u for u in urls if u.get("is_shortened")]
        if ip_urls:
            rule_points += 15
            signals.append({
                "signal": f"IP-based direct host URL ({ip_urls[0].get('hostname')})",
                "points": 15,
                "weight_category": "MODERATE"
            })
        elif short_urls:
            rule_points += 10
            signals.append({
                "signal": f"Shortened destination URL ({short_urls[0].get('hostname')})",
                "points": 10,
                "weight_category": "MODERATE"
            })

        # Authentication Failures (MODERATE)
        auth = forensic_data.get("authentication", {})
        dmarc = auth.get("dmarc", {})
        spf = auth.get("spf", {})
        dkim = auth.get("dkim", {})

        if dmarc.get("result") == "FAIL":
            rule_points += 15
            signals.append({
                "signal": "DMARC authentication policy failure (unaligned domain)",
                "points": 15,
                "weight_category": "MODERATE"
            })
        elif spf.get("result") == "FAIL" or dkim.get("status") == "FAIL":
            rule_points += 10
            signals.append({
                "signal": "Cryptographic authentication mismatch (SPF/DKIM fail)",
                "points": 10,
                "weight_category": "MODERATE"
            })

        # Chain Anomalies (CONTEXTUAL)
        chain = forensic_data.get("header_chain", {})
        if chain.get("anomalies"):
            rule_points += 5
            signals.append({
                "signal": f"Relay chain timing/structure anomalies ({len(chain.get('anomalies'))} detected)",
                "points": 5,
                "weight_category": "CONTEXTUAL"
            })

        forensic_subscore = min(100.0, rule_points)

        # ----------------------------------------------------
        # 2. ML Probability Component (Max 40 points towards total)
        # ----------------------------------------------------
        # Prefer the independently trained binary model for the risk score.
        # The prototype multi-class model remains useful for naming the likely
        # attack subtype, but its tiny synthetic baseline must not drive the
        # quantitative ML contribution when validated probabilities exist.
        prototype_probs = ml_prediction.get("probabilities", {})
        validated = ml_prediction.get("validated_binary_model", {})
        validated_probs = validated.get("probabilities", {}) if isinstance(validated, dict) else {}
        validated_phishing_prob = validated_probs.get("PHISHING")

        if isinstance(validated_phishing_prob, (int, float)) and 0 <= validated_phishing_prob <= 1:
            ml_subscore = round(float(validated_phishing_prob) * 100.0, 1)
            ml_probability_source = "VALIDATED_BINARY_MODEL"
        else:
            legit_prob = float(prototype_probs.get("LEGITIMATE", 0.5))
            ml_subscore = round((1.0 - legit_prob) * 100.0, 1)
            ml_probability_source = "PROTOTYPE_MULTICLASS_FALLBACK"

        if ml_subscore > 50:
            signals.append({
                "signal": (
                    f"Validated phishing probability ({ml_subscore:.1f}%)"
                    if ml_probability_source == "VALIDATED_BINARY_MODEL"
                    else f"Prototype ML threat classification ({ml_prediction.get('primary_classification', 'THREAT')})"
                ),
                "points": round(ml_subscore * 0.4, 1),
                "weight_category": "STRONG"
            })

        # ----------------------------------------------------
        # 3. Infrastructure Reputation Component (Max 15 points)
        # ----------------------------------------------------
        origin = forensic_data.get("origin_assessment", {})
        origin_class = origin.get("classification", "UNKNOWN")
        rep_subscore = 0.0

        if origin_class in ("VPS", "CLOUD_HOSTING", "TOR_EXIT", "OPEN_RELAY"):
            rep_subscore = 70.0
            signals.append({
                "signal": f"Observed infrastructure hosted on commercial cloud/VPS ({origin.get('organization', 'Hosting Provider')})",
                "points": 10.5,
                "weight_category": "CONTEXTUAL"
            })
        else:
            rep_subscore = 20.0

        # ----------------------------------------------------
        # 4. Campaign Correlation Component (Max 10 points)
        # ----------------------------------------------------
        camp_subscore = 0.0
        if campaign_correlation.get("matched_campaign_id"):
            camp_subscore = 85.0
            signals.append({
                "signal": f"Correlated with known attack campaign: {campaign_correlation.get('matched_campaign_id')}",
                "points": 8.5,
                "weight_category": "STRONG"
            })

        # ----------------------------------------------------
        # Synthesis (35% Forensic + 40% ML + 15% Reputation + 10% Campaign)
        # ----------------------------------------------------
        final_score = (
            (forensic_subscore * 0.35) +
            (ml_subscore * 0.40) +
            (rep_subscore * 0.15) +
            (camp_subscore * 0.10)
        )

        final_score = min(100, max(0, int(round(final_score))))

        # Classify Risk Level
        if final_score >= 81:
            threat_level = "CRITICAL"
        elif final_score >= 61:
            threat_level = "HIGH"
        elif final_score >= 41:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        # Overall Classification
        classification = ml_prediction.get("primary_classification", "SUSPICIOUS")
        if final_score <= 20:
            classification = "LEGITIMATE"
        elif dangerous_atts:
            classification = "MALWARE_DELIVERY"
        elif bec.get("bec_detected") and bec.get("confidence_score", 0) >= 50:
            classification = "BEC"
        elif lookalike.get("is_lookalike"):
            classification = "PHISHING"

        # Prioritized Recommendations
        recommendations = []
        if dangerous_atts:
            recommendations.append({"priority": "HIGH", "action": f"Quarantine and submit attachment ({dangerous_atts[0].get('filename')}) to isolated sandbox analysis."})
        if lookalike.get("is_lookalike"):
            recommendations.append({"priority": "HIGH", "action": f"Block domain '{lookalike.get('registered_domain')}' and notify brand protection team of typosquatting."})
        if ip_urls or short_urls:
            recommendations.append({"priority": "HIGH", "action": "Add extracted destination URLs to web proxy and DNS-layer perimeter blocklist."})
        if bec.get("bec_detected"):
            recommendations.append({"priority": "HIGH", "action": "Verify out-of-band with purported sender prior to executing any financial or credential action."})
        if origin.get("observed_ip"):
            recommendations.append({"priority": "MEDIUM", "action": f"Query SIEM for historical ingress telemetry matching gateway IP {origin.get('observed_ip')}."})
        recommendations.append({"priority": "LOW", "action": "Preserve cryptographic evidence container and export STIX/IOC package for threat hunting."})

        return {
            "threat_score": final_score,
            "threat_level": threat_level,
            "classification": classification,
            "confidence_score": ml_prediction.get("confidence_score", 85),
            "score_breakdown": {
                "forensic_rules_contribution": round(forensic_subscore * 0.35, 1),
                "ml_model_contribution": round(ml_subscore * 0.40, 1),
                "infrastructure_contribution": round(rep_subscore * 0.15, 1),
                "campaign_contribution": round(camp_subscore * 0.10, 1),
                "ml_probability_source": ml_probability_source,
                "validated_phishing_probability": (
                    round(float(validated_phishing_prob) * 100.0, 1)
                    if isinstance(validated_phishing_prob, (int, float)) else None
                ),
                "prototype_primary_classification": ml_prediction.get("primary_classification"),
                "prototype_confidence": ml_prediction.get("confidence_score"),
            },
            "top_contributing_signals": sorted(signals, key=lambda s: s["points"], reverse=True)[:6],
            "risk_factors": [s["signal"] for s in signals],
            "investigation_recommendations": recommendations,
            "evaluation_notice": "Hybrid scoring synthesizes forensic verification, ML classification, and infrastructure intelligence."
        }
