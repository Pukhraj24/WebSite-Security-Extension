"""
Offline Inference and Prediction Interface for Website Security Extension (Phase 7).

Accepts a URL string, validates length and syntax, extracts offline lexical
features, and runs model inference using the versioned model artifact.

Design Rules:
1. STRICT ZERO NETWORK REQUESTS: Never connects to, crawls, or fetches the URL.
2. Safe boundary validation: Rejects empty, non-string, or oversized (> 2048 chars) inputs.
3. Isolated from production: Does not touch FastAPI routes or extension content scripts.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional

import joblib

# Support imports whether run as script or module
try:
    from .url_features import extract_url_features, extract_features_vector, FEATURE_NAMES_V1
except ImportError:
    from url_features import extract_url_features, extract_features_vector, FEATURE_NAMES_V1


# Default artifact locations
DEFAULT_MODEL_PATH = Path("ml/models/phishing_detector_v1.joblib")
DEFAULT_METADATA_PATH = Path("ml/models/model_metadata.json")

# In-memory cached model and metadata
_CACHED_MODEL = None
_CACHED_METADATA = None


def load_model_and_metadata(
    model_path: Optional[str] = None,
    metadata_path: Optional[str] = None
) -> tuple:
    """Load and cache the trained model pipeline and metadata."""
    global _CACHED_MODEL, _CACHED_METADATA

    m_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
    meta_path = Path(metadata_path) if metadata_path else DEFAULT_METADATA_PATH

    if _CACHED_MODEL is None:
        if not m_path.exists():
            raise FileNotFoundError(
                f"Model artifact not found at '{m_path}'. "
                "Please run 'python ml/src/train.py' first to train and save the model."
            )
        _CACHED_MODEL = joblib.load(m_path)

    if _CACHED_METADATA is None:
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                _CACHED_METADATA = json.load(f)
        else:
            _CACHED_METADATA = {
                "model_name": "PhishingClassifier",
                "model_version": "v1.0.0",
                "tuned_threshold": 0.80,
                "feature_names": FEATURE_NAMES_V1
            }

    return _CACHED_MODEL, _CACHED_METADATA


def predict_url(
    url: str,
    model_path: Optional[str] = None,
    metadata_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Perform offline phishing prediction on a candidate URL.

    Args:
        url: The candidate URL string.
        model_path: Optional custom path to model artifact.
        metadata_path: Optional custom path to metadata JSON.

    Returns:
        Structured prediction dictionary including class, score, threshold,
        and extracted lexical features.
    """
    # 1. Input Validation
    if not isinstance(url, str) or not url.strip():
        return {
            "valid": False,
            "error": "URL cannot be empty or non-string.",
            "url": str(url) if url is not None else None,
            "predicted_class": None,
            "phishing_probability": None
        }

    url_str = url.strip()

    # Length protection (aligned with API boundary of 2048 chars)
    if len(url_str) > 2048:
        return {
            "valid": False,
            "error": "URL exceeds maximum permissible length of 2048 characters.",
            "url": url_str[:64] + "... (truncated)",
            "predicted_class": None,
            "phishing_probability": None
        }

    # 2. Load model and schema
    model, metadata = load_model_and_metadata(model_path, metadata_path)
    feature_names = metadata.get("feature_names", FEATURE_NAMES_V1)
    threshold = float(metadata.get("tuned_threshold", 0.50))
    version = metadata.get("model_version", "v1.0.0")
    model_name = metadata.get("model_name", "HistGradientBoosting")

    # 3. Extract offline features (strict zero network requests)
    features_dict = extract_url_features(url_str, schema_version="v1_published")
    feature_vector = [features_dict.get(k, 0.0) for k in feature_names]

    # 4. Predict probability and class using DataFrame with feature names
    import pandas as pd
    input_df = pd.DataFrame([feature_vector], columns=feature_names)

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(input_df)[0]
        phishing_prob = float(probs[1])
    else:
        pred_raw = int(model.predict(input_df)[0])
        phishing_prob = float(pred_raw)

    is_phishing = bool(phishing_prob >= threshold)
    predicted_class = 1 if is_phishing else 0
    predicted_label = "phishing" if is_phishing else "legitimate"

    return {
        "valid": True,
        "url": url_str,
        "is_phishing": is_phishing,
        "predicted_class": predicted_class,
        "predicted_label": predicted_label,
        "phishing_probability": round(phishing_prob, 4),
        "decision_threshold": round(threshold, 4),
        "model_name": model_name,
        "model_version": version,
        "extracted_features": features_dict
    }


if __name__ == "__main__":
    test_url = sys.argv[1] if len(sys.argv) > 1 else "https://www.google.com"
    print(f"Predicting for URL: {test_url}")
    result = predict_url(test_url)
    print(json.dumps({k: v for k, v in result.items() if k != "extracted_features"}, indent=2))
