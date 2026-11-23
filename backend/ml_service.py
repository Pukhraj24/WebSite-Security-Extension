"""
Production Machine Learning Inference Service for Phishing URL Detection (Phase 9B).

Encapsulates the offline V2 HistGradientBoostingClassifier, providing safe,
non-blocking URL predictions that complement the deterministic rule engine.

Safety & Engineering Guarantees:
1. Reuses validated V2 40-feature extraction pipeline without duplicate code.
2. Verified SHA-256 model artifact integrity check before loading.
3. Model is loaded once at application startup; never reloaded per request.
4. Non-blocking async execution via asyncio.to_thread prevents event loop lag.
5. Strict failure isolation: failures in ML return safe fallbacks, never
   disrupting live deterministic website analysis or security controls.
6. ML heuristics cannot override or downgrade deterministic critical findings.
"""

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import joblib
import pandas as pd

# Reuse validated 40-feature extraction pipeline from ml/src/
try:
    from ml.src.url_features_v2 import extract_url_features_v2, FEATURE_NAMES_V2
except ImportError:
    import sys
    _ML_SRC = str(Path(__file__).resolve().parent.parent / "ml" / "src")
    if _ML_SRC not in sys.path:
        sys.path.insert(0, _ML_SRC)
    from url_features_v2 import extract_url_features_v2, FEATURE_NAMES_V2

logger = logging.getLogger(__name__)

# Model Artifact Specification
DEFAULT_MODEL_REL_PATH = Path("ml/models/experiments/best_model_v2.joblib")
EXPECTED_SHA256 = "37eb91e08e40642768a40dedbcc70969d39ed33a209d45aee52967be16c59be7"
EXPECTED_FEATURE_COUNT = 40
EXPECTED_CLASSES = [0, 1]

# Operational Thresholds (Phase 9 Policy)
THRESHOLD_HIGH = 0.85      # High phishing heuristic (96.1% precision, 91.8% recall)
THRESHOLD_CRITICAL = 0.95  # Critical phishing heuristic (98.6% precision, 0.36% FPR)

# Global Cached State (Loaded once during lifespan)
_CACHED_MODEL = None
_MODEL_INITIALIZED = False
_MODEL_AVAILABLE = False
_LOAD_ERROR: Optional[str] = None
_MODEL_METADATA: Dict[str, Any] = {
    "model_name": "HistGradientBoosting",
    "model_version": "v2.0.0",
    "feature_count": EXPECTED_FEATURE_COUNT,
    "feature_schema": "v2_extended"
}


def _get_project_root() -> Path:
    """Resolve project root directory whether executing from backend/ or root."""
    parent = Path(__file__).resolve().parent
    if (parent.parent / DEFAULT_MODEL_REL_PATH).exists():
        return parent.parent
    return parent


def _verify_sha256(file_path: Path, expected_hash: str) -> bool:
    """Compute and verify SHA-256 digest of an artifact file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest().lower() == expected_hash.lower()


def load_ml_model(
    artifact_path: Optional[Path] = None,
    expected_hash: Optional[str] = None
) -> bool:
    """
    Load and validate the V2 ML model artifact into memory once.
    Fails safely without raising exceptions so deterministic analysis continues.
    """
    global _CACHED_MODEL, _MODEL_INITIALIZED, _MODEL_AVAILABLE, _LOAD_ERROR

    _MODEL_INITIALIZED = True
    path = artifact_path or (_get_project_root() / DEFAULT_MODEL_REL_PATH)
    target_hash = expected_hash or EXPECTED_SHA256

    if not path.exists():
        _MODEL_AVAILABLE = False
        _CACHED_MODEL = None
        _LOAD_ERROR = "Model artifact file not found"
        logger.warning(f"Model artifact not found at: {path}")
        return False

    # 1. Verify SHA-256 integrity before deserialization
    if not _verify_sha256(path, target_hash):
        _MODEL_AVAILABLE = False
        _CACHED_MODEL = None
        _LOAD_ERROR = "SHA-256 hash mismatch for model artifact"
        logger.error(f"SHA-256 hash mismatch for model artifact: {path}")
        return False

    # 2. Safely deserialize model
    try:
        model = joblib.load(path)
    except Exception as err:
        _MODEL_AVAILABLE = False
        _CACHED_MODEL = None
        _LOAD_ERROR = "Failed to deserialize model artifact"
        logger.error(f"Failed to load model artifact: {err}")
        return False

    # 3. Verify model capabilities, schema, and class mapping
    if not hasattr(model, "predict_proba"):
        _MODEL_AVAILABLE = False
        _CACHED_MODEL = None
        _LOAD_ERROR = "Model lacks predict_proba method"
        logger.error(_LOAD_ERROR)
        return False

    if getattr(model, "n_features_in_", 0) != EXPECTED_FEATURE_COUNT:
        _MODEL_AVAILABLE = False
        _CACHED_MODEL = None
        _LOAD_ERROR = f"Expected {EXPECTED_FEATURE_COUNT} features, got {getattr(model, 'n_features_in_', 0)}"
        logger.error(_LOAD_ERROR)
        return False

    model_features = list(getattr(model, "feature_names_in_", []))
    if model_features and model_features != FEATURE_NAMES_V2:
        _MODEL_AVAILABLE = False
        _CACHED_MODEL = None
        _LOAD_ERROR = "Model feature schema ordering mismatch"
        logger.error(_LOAD_ERROR)
        return False

    model_classes = list(getattr(model, "classes_", []))
    if model_classes != EXPECTED_CLASSES:
        _MODEL_AVAILABLE = False
        _CACHED_MODEL = None
        _LOAD_ERROR = f"Model classes {model_classes} do not match expected binary classes [0, 1]"
        logger.error(_LOAD_ERROR)
        return False

    _CACHED_MODEL = model
    _MODEL_AVAILABLE = True
    _LOAD_ERROR = None
    logger.info("V2 ML Phishing Detection Model loaded and verified successfully.")
    return True


def get_model_status() -> Dict[str, Any]:
    """Expose operational ML diagnostic status."""
    return {
        "available": _MODEL_AVAILABLE,
        "model_name": _MODEL_METADATA["model_name"],
        "model_version": _MODEL_METADATA["model_version"],
        "feature_count": _MODEL_METADATA["feature_count"],
        "error": _LOAD_ERROR,
        "thresholds": {
            "high": THRESHOLD_HIGH,
            "critical": THRESHOLD_CRITICAL
        }
    }


def predict_url_phishing_sync(url: str) -> Dict[str, Any]:
    """
    Synchronous offline feature extraction and model prediction.
    Isolated and safe: returns structured dictionary and never raises exceptions.
    """
    # Ensure model has attempted loading
    if not _MODEL_INITIALIZED:
        load_ml_model()

    if not _MODEL_AVAILABLE or _CACHED_MODEL is None:
        return {
            "available": False,
            "url": url,
            "phishing_probability": None,
            "legitimate_probability": None,
            "is_phishing": False,
            "classification": "unavailable",
            "heuristic_severity": None,
            "error": _LOAD_ERROR or "ML inference service unavailable"
        }

    # Input validation
    if not isinstance(url, str) or not url.strip():
        return {
            "available": True,
            "url": str(url) if url is not None else None,
            "phishing_probability": None,
            "legitimate_probability": None,
            "is_phishing": False,
            "classification": "invalid_input",
            "heuristic_severity": None,
            "error": "URL cannot be empty or non-string"
        }

    url_str = url.strip()
    if len(url_str) > 2048:
        return {
            "available": True,
            "url": url_str[:64] + "... (truncated)",
            "phishing_probability": None,
            "legitimate_probability": None,
            "is_phishing": False,
            "classification": "invalid_input",
            "heuristic_severity": None,
            "error": "URL exceeds maximum permissible length of 2048 characters"
        }

    try:
        # Extract 40 lexical features completely offline
        features = extract_url_features_v2(url_str, schema_version="v2_extended")
        feature_vector = [features.get(name, 0.0) for name in FEATURE_NAMES_V2]

        # Use DataFrame to guarantee named feature alignment without sklearn warning
        input_df = pd.DataFrame([feature_vector], columns=FEATURE_NAMES_V2)
        probs = _CACHED_MODEL.predict_proba(input_df)[0]

        prob_legit = float(probs[0])
        prob_phish = float(probs[1])

        # Classify based on Phase 9 threshold policy
        if prob_phish >= THRESHOLD_CRITICAL:
            classification = "phishing"
            heuristic_severity = "critical"
            is_phishing = True
        elif prob_phish >= THRESHOLD_HIGH:
            classification = "phishing"
            heuristic_severity = "high"
            is_phishing = True
        else:
            classification = "legitimate"
            heuristic_severity = None
            is_phishing = False

        return {
            "available": True,
            "url": url_str,
            "phishing_probability": round(prob_phish, 4),
            "legitimate_probability": round(prob_legit, 4),
            "is_phishing": is_phishing,
            "classification": classification,
            "heuristic_severity": heuristic_severity,
            "thresholds": {
                "high": THRESHOLD_HIGH,
                "critical": THRESHOLD_CRITICAL
            },
            "model_name": _MODEL_METADATA["model_name"],
            "model_version": _MODEL_METADATA["model_version"],
            "feature_count": EXPECTED_FEATURE_COUNT
        }

    except Exception as err:
        logger.error(f"Prediction failed for URL '{url_str}': {err}")
        return {
            "available": False,
            "url": url_str,
            "phishing_probability": None,
            "legitimate_probability": None,
            "is_phishing": False,
            "classification": "error",
            "heuristic_severity": None,
            "error": f"Prediction execution failed: {err}"
        }


async def predict_url_phishing(url: str) -> Dict[str, Any]:
    """
    Asynchronous, non-blocking wrapper for ML phishing prediction.
    Offloads synchronous CPU inference to threadpool to protect event loop latency.
    """
    return await asyncio.to_thread(predict_url_phishing_sync, url)
