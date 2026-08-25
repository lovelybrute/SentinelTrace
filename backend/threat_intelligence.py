from typing import Dict, Any
from threat_scorer import ThreatScorer
from ml_engine import MLThreatEngine
from campaign_correlator import CampaignCorrelator


class ThreatIntelligence:
    """
    Threat Intelligence and Risk Scoring Adapter.
    Delegates to the hybrid explainable ThreatScorer, MLThreatEngine, and CampaignCorrelator.
    """

    def __init__(self):
        self.threat_scorer = ThreatScorer()
        self.ml_engine = MLThreatEngine()
        self.campaign_correlator = CampaignCorrelator()

    def calculate_threat_score(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate calibrated hybrid threat score (0-100) with explainable signals.
        """
        ml_prediction = self.ml_engine.predict(email_data)
        campaign_match = self.campaign_correlator.correlate_email(email_data)
        geo = email_data.get("geolocation", {})

        return self.threat_scorer.compute_score(
            forensic_data=email_data.get("forensics", {}),
            ml_prediction=ml_prediction,
            geo_data=geo,
            campaign_correlation=campaign_match
        )
