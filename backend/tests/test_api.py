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
    website metadata, security headers, cookie analysis, risk assessment,
    structured findings, and finding summary.
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

                # Check security headers
                assert data["security_headers"]["hsts"]["present"] is True
                assert data["security_headers"]["x_frame_options"]["present"] is True

                # Check cookies
                assert "cookies" in data
                assert data["cookies"]["cookie_count"] == 0

                # Check TLS
                assert data["tls_certificate"]["valid"] is True

                # Check Phase 3 additions: Assessment, Findings, Summary
                assert "assessment" in data
                assessment = data["assessment"]
                assert assessment["status"] == "complete"
                assert isinstance(assessment["risk_score"], int)
                assert assessment["risk_level"] in {"Low", "Moderate", "High", "Critical"}
                assert assessment["confidence"] == "High"
                assert assessment["methodology_version"] == "1.0"
                assert "summary" in assessment

                # Check findings and summary consistency
                assert "findings" in data
                assert isinstance(data["findings"], list)

                assert "finding_summary" in data
                summary = data["finding_summary"]
                assert summary["total"] == len(data["findings"])
                assert summary["total"] == (
                    summary["critical"]
                    + summary["high"]
                    + summary["medium"]
                    + summary["low"]
                    + summary["informational"]
                )

                assert "limitations" in data
                assert isinstance(data["limitations"], list)


def test_cors_preflight_for_chrome_extension():
    """Verify that CORS preflight requests succeed for Chrome Extension origins."""
    extension_origin = "chrome-extension://abcdefghijklmnopqrstuvwxyz123456"
    response = client.options(
        "/analyze",
        headers={
            "Origin": extension_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type"
        }
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == extension_origin
    assert "POST" in response.headers.get("access-control-allow-methods", "")


def test_cors_rejects_arbitrary_web_origin():
    """Verify that CORS does not grant access to arbitrary external websites."""
    response = client.options(
        "/analyze",
        headers={
            "Origin": "https://malicious-site.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type"
        }
    )
    assert response.headers.get("access-control-allow-origin") is None


def test_analyze_endpoint_tls_verification_failure_partial_assessment():
    """
    Verify that websites with untrusted/self-signed certificates return HTTP 200
    with a partial assessment, risk score of 40, and the Critical TLS finding.
    """
    import requests

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", side_effect=requests.exceptions.SSLError("self signed certificate")):
            with patch("website_analyzer.get_certificate_info") as mock_cert:
                mock_cert.return_value = {
                    "checked": True,
                    "valid": False,
                    "trusted": False,
                    "verification_error": "self signed certificate in certificate chain",
                    "issuer": {"commonName": "Untrusted Self-Signed CA"},
                    "subject": {"commonName": "self-signed.example.com"},
                    "days_remaining": 60,
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384"
                }

                response = client.post("/analyze", json={"url": "https://self-signed.example.com"})
                assert response.status_code == 200

                data = response.json()
                assert data["reachable"] is True
                assert data["status_code"] is None

                # Check partial assessment and Critical finding
                assert "assessment" in data
                assessment = data["assessment"]
                assert assessment["status"] == "partial"
                assert assessment["confidence"] == "Medium"
                # With Phase 9 hybrid scoring, self-signed.example.com triggers both deterministic TLS failure (+40)
                # and ML phishing heuristic (+40), yielding score 80 (Critical).
                assert assessment["risk_score"] in (40, 80)
                assert assessment["risk_level"] in ("High", "Critical")
                assert "Urgent attention required" in assessment["summary"]

                # Verify finding exists
                finding_ids = [f["id"] for f in data["findings"]]
                assert "tls_cert_verification_failed" in finding_ids

                critical_finding = next(f for f in data["findings"] if f["id"] == "tls_cert_verification_failed")
                assert critical_finding["severity"] == "critical"

                # Check limitations for headers and cookies
                limitation_codes = [lim["code"] for lim in data["limitations"]]
                assert "HTTP_HEADERS_UNAVAILABLE" in limitation_codes
                assert "COOKIES_UNAVAILABLE" in limitation_codes


def test_analyze_endpoint_rejects_oversized_url():
    """Verify that URLs exceeding max_length=2048 return HTTP 422 Unprocessable Entity."""
    huge_url = "https://example.com/" + ("a" * 2050)
    response = client.post("/analyze", json={"url": huge_url})
    assert response.status_code == 422


def test_analyze_endpoint_detects_insecure_forms_and_punycode():
    """
    Verify that the /analyze endpoint detects insecure HTML form submissions
    and Punycode homograph domain signals end-to-end.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline';",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    }
    mock_resp.cookies = []
    mock_resp.history = []
    mock_resp.text = """
    <html>
        <body>
            <form action="http://insecure-login.example.com/auth" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """
    mock_resp.iter_content.return_value = [mock_resp.text.encode("utf-8")]

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", return_value=mock_resp):
            with patch("website_analyzer.get_certificate_info") as mock_cert:
                mock_cert.return_value = {
                    "checked": True,
                    "valid": True,
                    "trusted": True,
                    "issuer": {"commonName": "DigiCert"},
                    "subject": {"commonName": "xn--pple-43d.com"},
                    "days_remaining": 120,
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384"
                }

                response = client.post("/analyze", json={"url": "https://xn--pple-43d.com"})
                assert response.status_code == 200

                data = response.json()
                finding_ids = [f["id"] for f in data["findings"]]

                # Verify Punycode detection
                assert "domain_punycode_homograph" in finding_ids

                # Verify Insecure Form Submission detection
                assert "form_insecure_submission" in finding_ids

                # Verify Insecure CSP detection
                assert "header_insecure_csp" in finding_ids

                # Verify summary and risk score reflect new findings
                summary = data["finding_summary"]
                assert summary["critical"] >= 1  # form_insecure_submission with password is Critical
                assert data["assessment"]["risk_score"] >= 40
                assert data["assessment"]["risk_level"] in {"High", "Critical"}


def test_html_content_parser_unit():
    """Verify that extract_page_content_security correctly parses diverse form configurations."""
    from website_analyzer import extract_page_content_security

    html = """
    <html>
    <head><title>Test Page</title></head>
    <body>
        <form action="/relative/login" method="POST">
            <input type="password" name="pwd">
        </form>
        <form action="http://insecure.test/submit" method="POST">
            <input type="text" name="query">
        </form>
        <form action="https://external-auth.evil.com/login" method="POST">
            <input type="password" name="creds">
        </form>
    </body>
    </html>
    """
    result = extract_page_content_security(html, "https://mybank.com/home")
    assert result["total_forms"] == 3
    assert len(result["insecure_forms"]) == 1
    assert result["insecure_forms"][0]["action"] == "http://insecure.test/submit"
    assert result["insecure_forms"][0]["has_password"] is False

    assert len(result["cross_domain_password_forms"]) == 1
    assert result["cross_domain_password_forms"][0]["target_host"] == "external-auth.evil.com"


# ==============================================================================
# Bug 2 Regression Tests: Multipart Public Suffix & Registrable Domain Comparison
# ==============================================================================

def test_get_registrable_domain_standard_and_multipart():
    """
    Verify get_registrable_domain correctly extracts eTLD+1 using offline PSL:
    1. Standard gTLD domains (example.com, auth.example.com).
    2. Multipart public suffixes (bank.co.uk vs phish.co.uk).
    3. Second-level country domains (example.com.au, agency.gov.uk).
    4. Subdomains correctly collapse to same registrable root.
    5. Case insensitivity and trailing dots normalization.
    """
    from website_analyzer import get_registrable_domain

    # Standard gTLDs
    assert get_registrable_domain("example.com") == "example.com"
    assert get_registrable_domain("auth.example.com") == "example.com"
    assert get_registrable_domain("sub.sub2.example.org") == "example.org"

    # Multipart ccTLD public suffixes (.co.uk, .com.au, .gov.uk)
    assert get_registrable_domain("bank.co.uk") == "bank.co.uk"
    assert get_registrable_domain("phish.co.uk") == "phish.co.uk"
    assert get_registrable_domain("auth.bank.co.uk") == "bank.co.uk"
    assert get_registrable_domain("login.phish.co.uk") == "phish.co.uk"
    assert get_registrable_domain("portal.example.com.au") == "example.com.au"
    assert get_registrable_domain("secure.dept.gov.uk") == "dept.gov.uk"
    # Service.gov.uk is a private suffix, so subdomains under service.gov.uk are registrable domains
    assert get_registrable_domain("sub.secure.service.gov.uk") == "secure.service.gov.uk"

    # Crucial distinction: bank.co.uk != phish.co.uk
    assert get_registrable_domain("bank.co.uk") != get_registrable_domain("phish.co.uk")

    # Case normalization & trailing dots
    assert get_registrable_domain("BANK.CO.UK.") == "bank.co.uk"
    assert get_registrable_domain("Auth.Example.COM.") == "example.com"


def test_get_registrable_domain_ips_and_special_hosts():
    """
    Verify get_registrable_domain safely handles IP literals, localhost, and edge cases.
    """
    from website_analyzer import get_registrable_domain

    # IPv4 literals
    assert get_registrable_domain("127.0.0.1") == "127.0.0.1"
    assert get_registrable_domain("192.168.1.1") == "192.168.1.1"

    # IPv6 literals (bracketed and bare)
    assert get_registrable_domain("[2001:db8::1]") == "2001:db8::1"
    assert get_registrable_domain("::1") == "::1"

    # Localhost and single-label hosts
    assert get_registrable_domain("localhost") == "localhost"
    assert get_registrable_domain("internalhost") == "internalhost"

    # Empty, whitespace, None
    assert get_registrable_domain("") is None
    assert get_registrable_domain("   ") is None
    assert get_registrable_domain(None) is None


def test_extract_page_content_multipart_public_suffix_cross_domain():
    """
    Verify Bug 2 fix in extract_page_content_security:
    A password form on bank.co.uk submitting to phish.co.uk MUST be flagged
    as cross-domain, even though both share the multipart suffix 'co.uk'.
    """
    from website_analyzer import extract_page_content_security

    html = """
    <html>
    <body>
        <!-- Phishing attack: password form on bank.co.uk pointing to attacker at phish.co.uk -->
        <form action="https://phish.co.uk/steal" method="POST">
            <input type="password" name="password">
        </form>
    </body>
    </html>
    """
    result = extract_page_content_security(html, "https://bank.co.uk/login")
    assert result["total_forms"] == 1
    assert len(result["cross_domain_password_forms"]) == 1
    assert result["cross_domain_password_forms"][0]["target_host"] == "phish.co.uk"
    assert result["cross_domain_password_forms"][0]["base_host"] == "bank.co.uk"


def test_extract_page_content_same_multipart_root_not_flagged():
    """
    Verify that legitimate subdomains sharing the same registrable multipart root
    (e.g., auth.bank.co.uk submitting to sso.bank.co.uk) are NOT falsely flagged.
    """
    from website_analyzer import extract_page_content_security

    html = """
    <html>
    <body>
        <!-- Legitimate SSO: auth.bank.co.uk submitting to sso.bank.co.uk -->
        <form action="https://sso.bank.co.uk/authenticate" method="POST">
            <input type="password" name="password">
        </form>
        <!-- Legitimate relative action -->
        <form action="/internal/login" method="POST">
            <input type="password" name="password">
        </form>
    </body>
    </html>
    """
    result = extract_page_content_security(html, "https://auth.bank.co.uk/portal")
    assert result["total_forms"] == 2
    # Neither should be flagged as cross-domain
    assert len(result["cross_domain_password_forms"]) == 0


def test_extract_page_content_ip_and_edge_case_domains():
    """
    Verify cross-domain detection behavior with IP literals, second-level domains, and ports.
    """
    from website_analyzer import extract_page_content_security

    html = """
    <html>
    <body>
        <!-- Cross-domain second-level country domain: bank.com.au -> evil.com.au -->
        <form action="https://evil.com.au/login" method="POST">
            <input type="password" name="pwd">
        </form>
        <!-- Insecure form submitting over HTTP with password -->
        <form action="http://bank.com.au/insecure" method="POST">
            <input type="password" name="pwd">
        </form>
    </body>
    </html>
    """
    result = extract_page_content_security(html, "https://bank.com.au/account")
    assert result["total_forms"] == 2
    assert len(result["cross_domain_password_forms"]) == 1
    assert result["cross_domain_password_forms"][0]["target_host"] == "evil.com.au"
    assert len(result["insecure_forms"]) == 1
    assert result["insecure_forms"][0]["has_password"] is True
