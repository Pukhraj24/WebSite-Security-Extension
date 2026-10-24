"""
Integration and API endpoint tests for FastAPI application.
"""

from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import pytest

from main import app


client = TestClient(app)


def test_home_endpoint():
    """Verify that root endpoint returns service info."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "Website Security API is running!" in data.get("message", "")


def test_health_endpoint():
    """Verify that health check endpoint returns healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


@pytest.mark.parametrize("blocked_url, expected_code", [
    ("http://127.0.0.1:8000/", "RESTRICTED_IP_ADDRESS"),
    ("http://localhost:8000/", "RESTRICTED_IP_ADDRESS"),
    ("http://192.168.1.1/", "RESTRICTED_IP_ADDRESS"),
    ("http://10.0.0.1/admin", "RESTRICTED_IP_ADDRESS"),
    ("http://169.254.169.254/latest/meta-data/", "RESTRICTED_IP_ADDRESS"),
    ("file:///etc/passwd", "INVALID_URL"),
    ("ftp://ftp.example.com", "INVALID_URL"),
    ("http://admin:secret@example.com", "INVALID_URL"),
])
def test_analyze_endpoint_ssrf_blocking(blocked_url, expected_code):
    """
    Verify that the /analyze API blocks internal, private, and invalid URLs
    with HTTP 400 and structured error responses.
    """
    response = client.post("/analyze", json={"url": blocked_url})
    assert response.status_code == 400

    data = response.json()
    assert data.get("reachable") is False
    assert "error" in data
    assert data["error"]["code"] == expected_code
    assert "Traceback" not in response.text
    assert "Traceback" not in data["error"].get("message", "")


def test_analyze_endpoint_success_mocked():
    """
    Verify that valid website analysis returns HTTP 200 with complete
    website metadata, security headers, and cookie analysis.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    }
    mock_resp.cookies = []
    mock_resp.history = []
    mock_resp.iter_content.return_value = [b"<html>Mocked page</html>"]

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", return_value=mock_resp):
            with patch("website_analyzer.get_certificate_info") as mock_cert:
                mock_cert.return_value = {
                    "checked": True,
                    "valid": True,
                    "trusted": True,
                    "issuer": {"commonName": "DigiCert"},
                    "subject": {"commonName": "example.com"},
                    "days_remaining": 120,
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384"
                }

                response = client.post("/analyze", json={"url": "https://example.com"})
                assert response.status_code == 200

                data = response.json()
                assert data["reachable"] is True
                assert data["domain"] == "example.com"
                assert data["protocol"] == "HTTPS"
                assert data["status_code"] == 200
                assert data["security_headers"]["hsts"]["present"] is True
                assert data["security_headers"]["hsts"]["value"] == "max-age=31536000; includeSubDomains"
                assert data["security_headers"]["x_frame_options"]["present"] is True
                assert data["security_headers"]["x_frame_options"]["value"] == "DENY"
                assert "cookies" in data
                assert data["cookies"]["cookie_count"] == 0
                assert data["tls_certificate"]["valid"] is True
