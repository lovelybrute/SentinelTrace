from ml_engine import MLThreatEngine
from validated_model import ValidatedPhishingModel, read_model_metrics


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


def test_validated_model_missing_artifact_is_honest(tmp_path):
    model = ValidatedPhishingModel(str(tmp_path / "missing.joblib"))
    assert not model.ready
    assert model.predict("test") is None
    assert model.error == "trained artifact not found"


def test_metrics_state_is_explicit():
    result = read_model_metrics()
    assert result["validation_status"] in {
        "NOT_TRAINED", "PROTOTYPE_HOLDOUT", "VALIDATED_HOLDOUT", "INVALID_ARTIFACT"
    }
