"""
Tests for Production ML Inference Service (Phase 9B).

Validates model loading, SHA-256 integrity, schema validation, probability extraction,
threshold classifications, fault isolation, non-blocking async execution, and health endpoints.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

# Ensure backend and project root are on sys.path
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import ml_service
from ml_service import (
    load_ml_model,
    get_model_status,
    predict_url_phishing_sync,
    predict_url_phishing,
    EXPECTED_SHA256,
    EXPECTED_FEATURE_COUNT,
    THRESHOLD_HIGH,
    THRESHOLD_CRITICAL,
)
from main import app


@pytest.fixture(autouse=True)
def preserve_ml_service_state():
    """Ensure global ML service state is saved and restored around every test."""
    orig_model = ml_service._CACHED_MODEL
    orig_init = ml_service._MODEL_INITIALIZED
    orig_avail = ml_service._MODEL_AVAILABLE
    orig_err = ml_service._LOAD_ERROR
    yield
    ml_service._CACHED_MODEL = orig_model
    ml_service._MODEL_INITIALIZED = orig_init
    ml_service._MODEL_AVAILABLE = orig_avail
    ml_service._LOAD_ERROR = orig_err


# ==============================================================================
# 1. Model Loading & Hash Verification
# ==============================================================================

def test_model_loading_success():
    """Verify standard model artifact loads successfully with verified SHA-256."""
    success = load_ml_model()
    assert success is True
    assert ml_service._MODEL_AVAILABLE is True
    assert ml_service._LOAD_ERROR is None
    assert ml_service._CACHED_MODEL is not None

    status = get_model_status()
    assert status["available"] is True
    assert status["feature_count"] == EXPECTED_FEATURE_COUNT
    assert status["thresholds"]["high"] == THRESHOLD_HIGH
    assert status["thresholds"]["critical"] == THRESHOLD_CRITICAL


def test_model_loading_hash_mismatch(tmp_path):
    """Verify loading fails safely when SHA-256 hash does not match expected."""
    corrupt_file = tmp_path / "corrupt_model.joblib"
    corrupt_file.write_bytes(b"tampered model content")

    success = load_ml_model(artifact_path=corrupt_file, expected_hash=EXPECTED_SHA256)
    assert success is False
    assert ml_service._MODEL_AVAILABLE is False
    assert ml_service._CACHED_MODEL is None
    assert "SHA-256 hash mismatch" in (ml_service._LOAD_ERROR or "")


def test_model_loading_file_not_found(tmp_path):
    """Verify loading fails safely when model artifact file does not exist."""
    non_existent = tmp_path / "missing_model.joblib"
    success = load_ml_model(artifact_path=non_existent)
    assert success is False
    assert ml_service._MODEL_AVAILABLE is False
    assert "not found" in (ml_service._LOAD_ERROR or "")


# ==============================================================================
# 2. Schema Validation & Integrity Checks
# ==============================================================================

def test_schema_validation_and_features():
    """Verify loaded model possesses exactly 40 input features and classes [0, 1]."""
    load_ml_model()
    model = ml_service._CACHED_MODEL
    assert getattr(model, "n_features_in_", None) == 40
    assert list(getattr(model, "classes_", [])) == [0, 1]
    assert hasattr(model, "predict_proba")


def test_schema_mismatch_wrong_feature_count(tmp_path):
    """Verify model with incorrect feature count is rejected."""
    fake_file = tmp_path / "fake.joblib"
    fake_file.write_bytes(b"dummy")

    bad_model = MagicMock()
    bad_model.predict_proba = MagicMock()
    bad_model.n_features_in_ = 22  # Wrong count
    bad_model.classes_ = [0, 1]

    with patch("joblib.load", return_value=bad_model), \
         patch("ml_service._verify_sha256", return_value=True):
        success = load_ml_model(artifact_path=fake_file)
        assert success is False
        assert "Expected 40 features" in (ml_service._LOAD_ERROR or "")


def test_schema_mismatch_wrong_classes(tmp_path):
    """Verify model with non-binary or wrong class labels is rejected."""
    fake_file = tmp_path / "fake.joblib"
    fake_file.write_bytes(b"dummy")

    bad_model = MagicMock()
    bad_model.predict_proba = MagicMock()
    bad_model.n_features_in_ = 40
    bad_model.classes_ = [1, 2]  # Wrong classes

    with patch("joblib.load", return_value=bad_model), \
         patch("ml_service._verify_sha256", return_value=True):
        success = load_ml_model(artifact_path=fake_file)
        assert success is False
        assert "do not match expected binary classes [0, 1]" in (ml_service._LOAD_ERROR or "")


# ==============================================================================
# 3. Probability Extraction & Output Structure
# ==============================================================================

def test_positive_class_probability_extraction():
    """Verify probabilities are valid floats summing to 1.0 with correct class 1 mapping."""
    load_ml_model()
    result = predict_url_phishing_sync("https://www.example.com")
    assert result["available"] is True
    assert isinstance(result["phishing_probability"], float)
    assert isinstance(result["legitimate_probability"], float)
    assert 0.0 <= result["phishing_probability"] <= 1.0
    assert 0.0 <= result["legitimate_probability"] <= 1.0
    assert pytest.approx(result["phishing_probability"] + result["legitimate_probability"], 0.01) == 1.0


def test_benign_url_classification():
    """Verify reputable benign URL produces low phishing probability and legitimate label."""
    load_ml_model()
    result = predict_url_phishing_sync("https://www.google.com")
    assert result["available"] is True
    assert result["phishing_probability"] < 0.15
    assert result["is_phishing"] is False
    assert result["classification"] == "legitimate"
    assert result["heuristic_severity"] is None


def test_suspicious_url_classification():
    """Verify deceptive IP-based URL produces high phishing probability and critical/high alert."""
    load_ml_model()
    suspicious_url = "http://192.168.1.1/paypal/login-account-update/verify-secure-ssl-token.php?id=8234872348"
    result = predict_url_phishing_sync(suspicious_url)
    assert result["available"] is True
    assert result["phishing_probability"] >= THRESHOLD_HIGH
    assert result["is_phishing"] is True
    assert result["classification"] == "phishing"
    assert result["heuristic_severity"] in ("high", "critical")


# ==============================================================================
# 4. Threshold Classifications Policy
# ==============================================================================

def test_threshold_critical_boundary():
    """Verify probability >= 0.95 triggers critical severity."""
    mock_model = MagicMock()
    mock_model.predict_proba.return_value = [[0.04, 0.96]]  # 96% phishing
    with patch.object(ml_service, "_CACHED_MODEL", mock_model), \
         patch.object(ml_service, "_MODEL_INITIALIZED", True), \
         patch.object(ml_service, "_MODEL_AVAILABLE", True):
        result = predict_url_phishing_sync("https://suspicious-site.example/login")
        assert result["phishing_probability"] == 0.96
        assert result["is_phishing"] is True
        assert result["classification"] == "phishing"
        assert result["heuristic_severity"] == "critical"


def test_threshold_high_boundary():
    """Verify probability in [0.85, 0.95) triggers high severity."""
    mock_model = MagicMock()
    mock_model.predict_proba.return_value = [[0.11, 0.89]]  # 89% phishing
    with patch.object(ml_service, "_CACHED_MODEL", mock_model), \
         patch.object(ml_service, "_MODEL_INITIALIZED", True), \
         patch.object(ml_service, "_MODEL_AVAILABLE", True):
        result = predict_url_phishing_sync("https://suspicious-site.example/login")
        assert result["phishing_probability"] == 0.89
        assert result["is_phishing"] is True
        assert result["classification"] == "phishing"
        assert result["heuristic_severity"] == "high"


def test_threshold_below_high():
    """Verify probability < 0.85 classifies as legitimate with no heuristic severity."""
    mock_model = MagicMock()
    mock_model.predict_proba.return_value = [[0.20, 0.80]]  # 80% phishing (below high threshold)
    with patch.object(ml_service, "_CACHED_MODEL", mock_model), \
         patch.object(ml_service, "_MODEL_INITIALIZED", True), \
         patch.object(ml_service, "_MODEL_AVAILABLE", True):
        result = predict_url_phishing_sync("https://subtle-site.example")
        assert result["phishing_probability"] == 0.80
        assert result["is_phishing"] is False
        assert result["classification"] == "legitimate"
        assert result["heuristic_severity"] is None


# ==============================================================================
# 5. Fault Isolation & Model Unavailability
# ==============================================================================

def test_model_unavailability_isolation():
    """Verify inference returns safe structured fallback without raising when model unavailable."""
    ml_service._MODEL_INITIALIZED = True
    ml_service._MODEL_AVAILABLE = False
    ml_service._CACHED_MODEL = None
    ml_service._LOAD_ERROR = "Model intentionally disabled for test"

    result = predict_url_phishing_sync("https://example.com")
    assert result["available"] is False
    assert result["phishing_probability"] is None
    assert result["is_phishing"] is False
    assert result["classification"] == "unavailable"
    assert result["error"] == "Model intentionally disabled for test"


def test_prediction_exception_isolation():
    """Verify exceptions inside feature extraction or predict_proba are trapped safely."""
    mock_model = MagicMock()
    mock_model.predict_proba.side_effect = RuntimeError("Simulated inference failure")
    with patch.object(ml_service, "_CACHED_MODEL", mock_model), \
         patch.object(ml_service, "_MODEL_INITIALIZED", True), \
         patch.object(ml_service, "_MODEL_AVAILABLE", True):
        result = predict_url_phishing_sync("https://example.com")
        assert result["available"] is False
        assert result["is_phishing"] is False
        assert result["classification"] == "error"
        assert "Simulated inference failure" in (result["error"] or "")


# ==============================================================================
# 6. Input Validation
# ==============================================================================

def test_input_validation_empty_or_none():
    """Verify empty string or whitespace returns invalid_input classification."""
    load_ml_model()
    for bad_input in ["", "   ", "\t\n"]:
        res = predict_url_phishing_sync(bad_input)
        assert res["classification"] == "invalid_input"
        assert res["phishing_probability"] is None


def test_input_validation_oversized_url():
    """Verify URLs exceeding 2048 characters are safely rejected."""
    load_ml_model()
    huge_url = "https://example.com/" + ("a" * 2100)
    res = predict_url_phishing_sync(huge_url)
    assert res["classification"] == "invalid_input"
    assert "exceeds maximum permissible length" in (res["error"] or "")


# ==============================================================================
# 7. Asynchronous Non-Blocking Execution
# ==============================================================================

def test_async_prediction_execution():
    """Verify async wrapper offloads inference properly and returns expected structure."""
    import asyncio
    load_ml_model()
    res = asyncio.run(predict_url_phishing("https://www.example.com"))
    assert res["available"] is True
    assert isinstance(res["phishing_probability"], float)
    assert res["classification"] in ("legitimate", "phishing")


# ==============================================================================
# 8. Diagnostics Endpoint & Main App Lifespan
# ==============================================================================

def test_health_ml_endpoint():
    """Verify /health/ml returns diagnostic status of the ML inference service."""
    client = TestClient(app)
    response = client.get("/health/ml")
    assert response.status_code == 200
    data = response.json()
    assert "available" in data
    assert "model_name" in data
    assert "model_version" in data
    assert "thresholds" in data
    assert data["thresholds"]["high"] == THRESHOLD_HIGH
    assert data["thresholds"]["critical"] == THRESHOLD_CRITICAL
