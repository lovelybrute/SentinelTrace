from __future__ import annotations

import json
import os
import re
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import joblib
except ImportError:
    joblib = None


class ValidatedPhishingModel:
    """Loads only locally trained artifacts that meet minimum holdout support."""

    def __init__(self, artifact_path: Optional[str] = None):
        default = Path(__file__).resolve().parents[1] / "ml" / "artifacts" / "phishing_model.joblib"
        self.path = Path(artifact_path or os.getenv("PHISHING_MODEL_PATH", str(default)))
        self.pipeline = None
        self.metadata: Dict[str, Any] = {}
        self.error: Optional[str] = None
        self._load()

    def _load(self) -> None:
        if joblib is None:
            self.error = "joblib unavailable"
            return
        if not self.path.exists():
            self.error = "trained artifact not found"
            return
        digest_path = self.path.with_suffix(self.path.suffix + ".sha256")
        if not digest_path.exists():
            self.error = "artifact integrity file not found"
            return
        expected = digest_path.read_text(encoding="ascii").strip().lower()
        actual = hashlib.sha256(self.path.read_bytes()).hexdigest()
        if expected != actual:
            self.error = "artifact integrity check failed"
            return
        try:
            bundle = joblib.load(self.path)
            metadata = bundle.get("metadata", {})
            if metadata.get("validation_status") != "VALIDATED_HOLDOUT":
                self.error = "artifact has not met minimum holdout support"
                self.metadata = metadata
                return
            self.pipeline, self.metadata = bundle["pipeline"], metadata
        except Exception as exc:
            self.error = f"artifact load failed: {exc}"

    @property
    def ready(self) -> bool:
        return self.pipeline is not None

    def predict(self, text: str) -> Optional[Dict[str, Any]]:
        if not self.ready: return None
        probabilities = self.pipeline.predict_proba([_augment_text(text)])[0]
        classes = list(self.pipeline.classes_)
        distribution = {str(label): round(float(prob), 4) for label, prob in zip(classes, probabilities)}
        label = str(classes[int(probabilities.argmax())])
        return {"label": label, "probabilities": distribution, "model_metadata": self.metadata}


def _augment_text(text: str) -> str:
    """Keep inference identical to the versioned training feature contract."""
    low = text.lower()
    tokens = []
    if re.search(r"https?://\S+", text, re.I): tokens.append("__HAS_URL__")
    if any(x in low for x in ("urgent", "immediately", "verify", "suspended", "within 24", "action required")): tokens.append("__URGENCY__")
    if any(x in low for x in ("invoice", "wire transfer", "bank account", "gift card", "payment", "payroll")): tokens.append("__FINANCIAL_REQUEST__")
    if any(x in low for x in ("password", "login", "one-time password", "otp", "credential")): tokens.append("__CREDENTIAL_REQUEST__")
    if "spf=fail" in low: tokens.append("__SPF_FAIL__")
    if "dmarc=fail" in low: tokens.append("__DMARC_FAIL__")
    if "dkim=none" in low or "dkim=fail" in low: tokens.append("__DKIM_RISK__")
    if "reply-to:" in low: tokens.append("__REPLY_TO_PRESENT__")
    return " ".join(tokens + [text])


def read_model_metrics() -> Dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "ml" / "artifacts" / "metrics.json"
    if not path.exists():
        return {"validation_status": "NOT_TRAINED", "message": "Run ml/prepare_dataset.py and ml/train_model.py with a labeled corpus."}
    try: return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc: return {"validation_status": "INVALID_ARTIFACT", "message": str(exc)}
