from threat_scorer import ThreatScorer


def _score(ml_prediction):
    return ThreatScorer().compute_score(
        forensic_data={},
        ml_prediction=ml_prediction,
        geo_data={},
        campaign_correlation={},
    )


def test_validated_probability_drives_ml_contribution():
    result = _score({
        "primary_classification": "LEGITIMATE",
        "confidence_score": 90.0,
        "probabilities": {"LEGITIMATE": 0.9, "PHISHING": 0.1},
        "validated_binary_model": {
            "label": "PHISHING",
            "probabilities": {"LEGITIMATE": 0.2, "PHISHING": 0.8},
        },
    })

    breakdown = result["score_breakdown"]
    assert breakdown["ml_probability_source"] == "VALIDATED_BINARY_MODEL"
    assert breakdown["validated_phishing_probability"] == 80.0
    assert breakdown["ml_model_contribution"] == 32.0


def test_prototype_probability_is_an_explicit_fallback():
    result = _score({
        "primary_classification": "SUSPICIOUS",
        "confidence_score": 70.0,
        "probabilities": {"LEGITIMATE": 0.25, "SUSPICIOUS": 0.75},
        "validated_binary_model": {"status": "UNAVAILABLE"},
    })

    breakdown = result["score_breakdown"]
    assert breakdown["ml_probability_source"] == "PROTOTYPE_MULTICLASS_FALLBACK"
    assert breakdown["validated_phishing_probability"] is None
    assert breakdown["ml_model_contribution"] == 30.0
