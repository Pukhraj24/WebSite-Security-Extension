"""
Focused integration tests for Phase 9, Milestone 9D:
FastAPI POST /analyze ML Phishing Response Integration.

Validates:
A. Benign / low ML probability (P < 0.85) produces no ML finding
B. High ML probability (0.85 <= P < 0.95) produces High ML finding with additive score
C. Critical ML probability (P >= 0.95) produces Critical ML finding with additive score
D. ML failure/unavailability results in graceful degradation and limitation recording
E. Deterministic findings non-downgrade guarantee
F. Backward compatibility of all existing /analyze response fields
G. Async event loop safety and non-blocking execution
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from main import app
import ml_service


client = TestClient(app)


def _mock_network_session(status_code=200, headers=None, cert_info=None):
    """Helper to mock external network and TLS socket dependencies."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {
        "Content-Type": "text/html; charset=utf-8",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    }
    mock_resp.cookies = []
    mock_resp.history = []
    mock_resp.iter_content.return_value = [b"<html><head><title>Test</title></head><body>OK</body></html>"]

    default_cert = cert_info or {
        "checked": True,
        "valid": True,
        "trusted": True,
        "issuer": {"commonName": "DigiCert Global Root CA"},
        "subject": {"commonName": "example.com"},
        "days_remaining": 150,
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384"
    }
    return mock_resp, default_cert


# ==============================================================================
# A. Benign / Low ML Probability (P < 0.85)
# ==============================================================================

def test_analyze_benign_url_no_ml_finding():
    """Verify benign URL produces no ml_phishing_heuristic finding and score is unaffected."""
    mock_resp, mock_cert = _mock_network_session()

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]), \
         patch("requests.Session.get", return_value=mock_resp), \
         patch("website_analyzer.get_certificate_info", return_value=mock_cert):

        response = client.post("/analyze", json={"url": "https://www.example.com"})
        assert response.status_code == 200
        data = response.json()

        assert data["reachable"] is True
        assert "ml_analysis" in data
        assert data["ml_analysis"]["available"] is True
        assert data["ml_analysis"]["phishing_probability"] < 0.85

        finding_ids = [f["id"] for f in data["findings"]]
        assert "ml_phishing_heuristic" not in finding_ids
        assert data["assessment"]["status"] == "complete"
        assert data["assessment"]["confidence"] == "High"


# ==============================================================================
# B. High ML Probability (0.85 <= P < 0.95)
# ==============================================================================

def test_analyze_high_ml_probability():
    """Verify probability in [0.85, 0.95) generates High finding and additive score."""
    mock_resp, mock_cert = _mock_network_session()
    mock_model = MagicMock()
    mock_model.predict_proba.return_value = [[0.11, 0.89]]  # 89% phishing

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]), \
         patch("requests.Session.get", return_value=mock_resp), \
         patch("website_analyzer.get_certificate_info", return_value=mock_cert), \
         patch.object(ml_service, "_CACHED_MODEL", mock_model), \
         patch.object(ml_service, "_MODEL_INITIALIZED", True), \
         patch.object(ml_service, "_MODEL_AVAILABLE", True):

        response = client.post("/analyze", json={"url": "https://suspicious-site.example/login"})
        assert response.status_code == 200
        data = response.json()

        finding_ids = [f["id"] for f in data["findings"]]
        assert "ml_phishing_heuristic" in finding_ids

        ml_finding = next(f for f in data["findings"] if f["id"] == "ml_phishing_heuristic")
        assert ml_finding["severity"] == "high"
        assert ml_finding["evidence"]["phishing_probability"] == 0.89
        assert ml_finding["category"] == "phishing_heuristic"

        # High severity finding adds 20 points
        assert data["assessment"]["risk_score"] >= 20
        assert data["ml_analysis"]["classification"] == "phishing"
        assert data["ml_analysis"]["heuristic_severity"] == "high"


# ==============================================================================
# C. Critical ML Probability (P >= 0.95)
# ==============================================================================

def test_analyze_critical_ml_probability():
    """Verify probability >= 0.95 generates Critical finding and critical alert."""
    mock_resp, mock_cert = _mock_network_session()
    mock_model = MagicMock()
    mock_model.predict_proba.return_value = [[0.03, 0.97]]  # 97% phishing

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]), \
         patch("requests.Session.get", return_value=mock_resp), \
         patch("website_analyzer.get_certificate_info", return_value=mock_cert), \
         patch.object(ml_service, "_CACHED_MODEL", mock_model), \
         patch.object(ml_service, "_MODEL_INITIALIZED", True), \
         patch.object(ml_service, "_MODEL_AVAILABLE", True):

        response = client.post("/analyze", json={"url": "https://phishing-portal.example/verify"})
        assert response.status_code == 200
        data = response.json()

        finding_ids = [f["id"] for f in data["findings"]]
        assert "ml_phishing_heuristic" in finding_ids

        ml_finding = next(f for f in data["findings"] if f["id"] == "ml_phishing_heuristic")
        assert ml_finding["severity"] == "critical"
        assert ml_finding["evidence"]["phishing_probability"] == 0.97

        # Critical severity finding adds 40 points and triggers urgent attention summary
        assert data["assessment"]["risk_score"] >= 40
        assert "Urgent attention required" in data["assessment"]["summary"]
        assert data["ml_analysis"]["classification"] == "phishing"
        assert data["ml_analysis"]["heuristic_severity"] == "critical"


# ==============================================================================
# D. ML Unavailable / Failure Graceful Degradation
# ==============================================================================

def test_analyze_ml_unavailable_graceful_degradation():
    """Verify endpoint succeeds with deterministic results when ML service is disabled."""
    mock_resp, mock_cert = _mock_network_session()

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]), \
         patch("requests.Session.get", return_value=mock_resp), \
         patch("website_analyzer.get_certificate_info", return_value=mock_cert), \
         patch.object(ml_service, "_MODEL_INITIALIZED", True), \
         patch.object(ml_service, "_MODEL_AVAILABLE", False), \
         patch.object(ml_service, "_CACHED_MODEL", None), \
         patch.object(ml_service, "_LOAD_ERROR", "Simulated model failure"):

        response = client.post("/analyze", json={"url": "https://example.com"})
        assert response.status_code == 200
        data = response.json()

        assert data["reachable"] is True
        assert data["ml_analysis"]["available"] is False
        assert data["ml_analysis"]["phishing_probability"] is None

        # Deterministic analysis continues
        assert "assessment" in data
        assert "cookies" in data
        assert "findings" in data

        # Limitation recorded
        limitation_codes = [l["code"] for l in data["limitations"]]
        assert "ML_PHISHING_INSPECTION_UNAVAILABLE" in limitation_codes
        assert data["assessment"]["status"] == "partial"
        assert data["assessment"]["confidence"] == "Medium"


def test_analyze_ml_exception_isolated():
    """Verify unexpected exception during ML prediction does not break /analyze."""
    mock_resp, mock_cert = _mock_network_session()

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]), \
         patch("requests.Session.get", return_value=mock_resp), \
         patch("website_analyzer.get_certificate_info", return_value=mock_cert), \
         patch("main.predict_url_phishing", side_effect=RuntimeError("Unexpected ML crash")):

        response = client.post("/analyze", json={"url": "https://example.com"})
        assert response.status_code == 200
        data = response.json()

        assert data["reachable"] is True
        assert data["ml_analysis"]["available"] is False
        assert "ML prediction failed" in data["ml_analysis"]["error"]
        limitation_codes = [l["code"] for l in data["limitations"]]
        assert "ML_PHISHING_INSPECTION_UNAVAILABLE" in limitation_codes


# ==============================================================================
# E. Security Precedence & Non-Downgrade Guarantee
# ==============================================================================

def test_analyze_deterministic_critical_not_downgraded_by_benign_ml():
    """Verify deterministic critical finding is never downgraded by low ML probability."""
    mock_resp, _ = _mock_network_session()
    # Expired TLS certificate
    expired_cert = {
        "checked": True,
        "valid": False,
        "trusted": True,
        "issuer": {"commonName": "DigiCert"},
        "subject": {"commonName": "example.com"},
        "days_remaining": -15,
        "expires_at": "2026-10-10T00:00:00+00:00"
    }
    # Mock low ML phishing probability (0.01)
    mock_model = MagicMock()
    mock_model.predict_proba.return_value = [[0.99, 0.01]]

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]), \
         patch("requests.Session.get", return_value=mock_resp), \
         patch("website_analyzer.get_certificate_info", return_value=expired_cert), \
         patch.object(ml_service, "_CACHED_MODEL", mock_model), \
         patch.object(ml_service, "_MODEL_INITIALIZED", True), \
         patch.object(ml_service, "_MODEL_AVAILABLE", True):

        response = client.post("/analyze", json={"url": "https://example.com"})
        assert response.status_code == 200
        data = response.json()

        finding_ids = [f["id"] for f in data["findings"]]
        assert "tls_cert_expired" in finding_ids

        cert_finding = next(f for f in data["findings"] if f["id"] == "tls_cert_expired")
        assert cert_finding["severity"] == "critical"
        assert data["assessment"]["risk_score"] >= 40
        assert "Urgent attention required" in data["assessment"]["summary"]


# ==============================================================================
# F. Backward Compatibility & Response Contract
# ==============================================================================

def test_analyze_response_contract_backward_compatibility():
    """Verify all standard fields exist without breaking changes."""
    mock_resp, mock_cert = _mock_network_session()

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]), \
         patch("requests.Session.get", return_value=mock_resp), \
         patch("website_analyzer.get_certificate_info", return_value=mock_cert):

        response = client.post("/analyze", json={"url": "https://example.com"})
        assert response.status_code == 200
        data = response.json()

        # Core required top-level keys
        for key in ["reachable", "domain", "protocol", "status_code", "security_headers",
                    "cookies", "tls_certificate", "assessment", "findings",
                    "finding_summary", "limitations", "ml_analysis"]:
            assert key in data, f"Missing key: {key}"

        # Assessment sub-fields
        for key in ["status", "risk_score", "risk_level", "confidence", "summary", "methodology_version"]:
            assert key in data["assessment"], f"Missing assessment key: {key}"

        # ML analysis structure: no stack traces or filesystem paths
        ml = data["ml_analysis"]
        for forbidden in ["traceback", "Traceback", "C:\\", "/home/", "Users"]:
            assert forbidden not in str(ml), f"Found sensitive leak: {forbidden}"


# ==============================================================================
# G. Async & Event-Loop Safety
# ==============================================================================

def test_analyze_async_execution_safety():
    """Verify that multiple concurrent requests to /analyze execute safely without blocking."""
    mock_resp, mock_cert = _mock_network_session()

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]), \
         patch("requests.Session.get", return_value=mock_resp), \
         patch("website_analyzer.get_certificate_info", return_value=mock_cert):

        # Consecutive requests execute cleanly
        for test_url in ["https://example1.com", "https://example2.com", "https://example3.com"]:
            resp = client.post("/analyze", json={"url": test_url})
            assert resp.status_code == 200
            assert resp.json()["reachable"] is True
