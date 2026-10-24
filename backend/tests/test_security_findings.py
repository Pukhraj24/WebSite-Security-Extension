"""
Unit tests for Structured Security Findings Engine (security_findings.py).
"""

import json
import pytest

from security_findings import (
    generate_security_findings,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFORMATIONAL
)


# ==============================================================================
# 1. Transport & Redirect Finding Tests
# ==============================================================================

def test_unencrypted_http_finding():
    """Verify that plain HTTP generates transport_http_unencrypted with High severity."""
    data = {
        "reachable": True,
        "protocol": "HTTP",
        "url": "http://example.com",
        "final_url": "http://example.com/",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": None
    }
    findings, limitations = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "transport_http_unencrypted" in f_ids

    http_finding = next(f for f in findings if f["id"] == "transport_http_unencrypted")
    assert http_finding["severity"] == SEVERITY_HIGH


def test_https_to_http_downgrade_finding():
    """Verify that HTTPS to HTTP downgrade generates redirect_https_to_http_downgrade (Critical)."""
    data = {
        "reachable": True,
        "protocol": "HTTP",
        "url": "https://example.com/login",
        "final_url": "http://example.com/insecure",
        "redirect_chain": [
            {"status_code": 302, "url": "https://example.com/login", "location": "http://example.com/insecure"}
        ],
        "security_headers": {},
        "tls_certificate": None
    }
    findings, limitations = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "redirect_https_to_http_downgrade" in f_ids

    downgrade = next(f for f in findings if f["id"] == "redirect_https_to_http_downgrade")
    assert downgrade["severity"] == SEVERITY_CRITICAL


# ==============================================================================
# 2. TLS Certificate Finding Tests
# ==============================================================================

def test_tls_cert_expired_finding():
    """Verify that expired certificate triggers tls_cert_expired (Critical)."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://expired.example.com",
        "final_url": "https://expired.example.com/",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": {
            "checked": True,
            "valid": False,
            "trusted": True,
            "days_remaining": -5,
            "expires_at": "2026-10-19T00:00:00+00:00"
        }
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "tls_cert_expired" in f_ids

    expired_finding = next(f for f in findings if f["id"] == "tls_cert_expired")
    assert expired_finding["severity"] == SEVERITY_CRITICAL


def test_tls_cert_verification_failed_finding():
    """Verify that untrusted certificate triggers tls_cert_verification_failed (Critical)."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://self-signed.example.com",
        "final_url": "https://self-signed.example.com/",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": {
            "checked": True,
            "valid": False,
            "trusted": False,
            "verification_error": "self-signed certificate",
            "days_remaining": 100
        }
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "tls_cert_verification_failed" in f_ids

    untrusted_finding = next(f for f in findings if f["id"] == "tls_cert_verification_failed")
    assert untrusted_finding["severity"] == SEVERITY_CRITICAL


def test_tls_cert_expiring_soon_finding():
    """Verify that certificate with <= 30 days remaining triggers tls_cert_expiring_soon (Medium)."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://expiring.example.com",
        "final_url": "https://expiring.example.com/",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": {
            "checked": True,
            "valid": True,
            "trusted": True,
            "days_remaining": 15,
            "expires_at": "2026-11-08T00:00:00+00:00"
        }
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "tls_cert_expiring_soon" in f_ids

    expiring_finding = next(f for f in findings if f["id"] == "tls_cert_expiring_soon")
    assert expiring_finding["severity"] == SEVERITY_MEDIUM


# ==============================================================================
# 3. Security Headers Finding Tests
# ==============================================================================

def test_missing_hsts_on_https():
    """Verify that missing HSTS on an HTTPS response emits header_missing_hsts (Medium)."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "redirect_chain": [],
        "security_headers": {
            "hsts": {"present": False, "value": None},
            "csp": {"present": True, "value": "default-src 'self'"},
            "x_frame_options": {"present": True, "value": "DENY"},
            "x_content_type_options": {"present": True, "value": "nosniff"}
        },
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60}
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "header_missing_hsts" in f_ids

    hsts_finding = next(f for f in findings if f["id"] == "header_missing_hsts")
    assert hsts_finding["severity"] == SEVERITY_MEDIUM


def test_missing_csp_finding():
    """Verify that missing CSP emits header_missing_csp (Medium)."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "redirect_chain": [],
        "security_headers": {
            "csp": {"present": False, "value": None}
        },
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60}
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "header_missing_csp" in f_ids


def test_framing_protection_overlap():
    """
    Verify that if CSP specifies 'frame-ancestors', missing X-Frame-Options
    does NOT trigger a clickjacking framing protection warning.
    """
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "redirect_chain": [],
        "security_headers": {
            "csp": {"present": True, "value": "default-src 'self'; frame-ancestors 'none'"},
            "x_frame_options": {"present": False, "value": None}
        },
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60}
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "header_missing_x_frame_options" not in f_ids


# ==============================================================================
# 4. Cookie Security & Value Non-Disclosure Tests
# ==============================================================================

def test_cookie_findings_grouping_and_non_disclosure():
    """
    Verify that cookie findings:
    1. Group identical missing attributes across cookies.
    2. Contain affected cookie names.
    3. NEVER contain raw cookie values.
    """
    secret_token_1 = "SEC_TOKEN_ABC123456"
    secret_token_2 = "SEC_TOKEN_DEF789012"

    cookie_data = {
        "cookie_count": 2,
        "cookie_details": [
            {
                "name": "sess_1",
                "value": secret_token_1,  # Must never leak
                "secure": False,
                "httponly": False,
                "samesite": None,
                "path": "/"
            },
            {
                "name": "sess_2",
                "value": secret_token_2,  # Must never leak
                "secure": False,
                "httponly": False,
                "samesite": None,
                "path": "/"
            }
        ]
    }

    website_data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60}
    }

    findings, _ = generate_security_findings(website_data, cookie_data)
    findings_str = json.dumps(findings)

    # Check non-disclosure
    assert secret_token_1 not in findings_str
    assert secret_token_2 not in findings_str

    # Check grouped findings
    f_ids = [f["id"] for f in findings]
    assert "cookies_missing_secure" in f_ids
    assert "cookies_missing_httponly" in f_ids
    assert "cookies_missing_samesite" in f_ids

    secure_f = next(f for f in findings if f["id"] == "cookies_missing_secure")
    assert secure_f["evidence"]["total_affected"] == 2
    assert "sess_1" in secure_f["evidence"]["affected_cookies"]
    assert "sess_2" in secure_f["evidence"]["affected_cookies"]


def test_deterministic_finding_order():
    """
    Verify findings are deterministically sorted by severity descending:
    Critical -> High -> Medium -> Low -> Informational
    """
    website_data = {
        "reachable": True,
        "protocol": "HTTP",  # Generates High
        "url": "http://example.com",
        "final_url": "http://example.com/",
        "redirect_chain": [
            {"status_code": 302, "url": "https://example.com", "location": "http://example.com"} # Generates Critical
        ],
        "security_headers": {
            "csp": {"present": False, "value": None},  # Generates Medium
            "x_content_type_options": {"present": False, "value": None},  # Generates Low
            "permissions_policy": {"present": False, "value": None}  # Generates Informational
        },
        "tls_certificate": None
    }

    findings, _ = generate_security_findings(website_data)
    severities = [f["severity"] for f in findings]

    # Verify severity hierarchy is strictly non-increasing
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    ranked_values = [rank[s] for s in severities]
    assert ranked_values == sorted(ranked_values, reverse=True)
