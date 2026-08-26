from ml_engine import MLThreatEngine


def test_ml_engine_discloses_prototype_training_limits():
    engine = MLThreatEngine()
    result = engine.predict({})

    assert result["external_validation_status"] in {
        "NOT_VALIDATED_ON_PUBLIC_CORPUS",
        "NOT_APPLICABLE_RULE_ENGINE",
    }
    assert "limitations" in result
    assert "accuracy" not in result


def test_ml_engine_training_metadata_is_explicit():
    engine = MLThreatEngine()

    assert engine.TRAINING_SOURCE == "synthetic attack-archetype baseline"
    assert engine.TRAINING_SAMPLE_COUNT == 17
