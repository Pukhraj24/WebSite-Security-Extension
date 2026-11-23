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


# ==============================================================================
# 5. Domain Identity & Hostname Tests (Phase 6 Rules)
# ==============================================================================

def test_url_ip_address_host_finding():
    """Verify that raw IP address hostname generates url_ip_address_host (Medium)."""
    data = {
        "reachable": True,
        "protocol": "HTTP",
        "url": "http://93.184.215.14/",
        "final_url": "http://93.184.215.14/",
        "hostname": "93.184.215.14",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": None
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "url_ip_address_host" in f_ids

    ip_finding = next(f for f in findings if f["id"] == "url_ip_address_host")
    assert ip_finding["severity"] == SEVERITY_MEDIUM
    assert ip_finding["category"] == "domain_identity"
    assert ip_finding["evidence"]["ip_version"] == "IPv4"
    assert ip_finding["evidence"]["hostname"] == "93.184.215.14"


def test_domain_punycode_homograph_finding():
    """Verify that Punycode domain generates domain_punycode_homograph (Medium)."""
    # xn--pple-43d.com is Punycode for арple.com (Cyrillic 'а')
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://xn--pple-43d.com/",
        "final_url": "https://xn--pple-43d.com/",
        "hostname": "xn--pple-43d.com",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60}
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "domain_punycode_homograph" in f_ids

    puny_finding = next(f for f in findings if f["id"] == "domain_punycode_homograph")
    assert puny_finding["severity"] == SEVERITY_MEDIUM
    assert puny_finding["category"] == "domain_identity"
    assert "xn--pple-43d" in puny_finding["evidence"]["punycode_labels"]
    assert "decoded_domain" in puny_finding["evidence"]


# ==============================================================================
# 6. Deprecated TLS & Insecure CSP Tests (Phase 6 Rules)
# ==============================================================================

@pytest.mark.parametrize("deprecated_proto", ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"])
def test_tls_deprecated_version_finding(deprecated_proto):
    """Verify that obsolete TLS/SSL versions generate tls_deprecated_version (High)."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://legacy.example.com",
        "final_url": "https://legacy.example.com/",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": {
            "checked": True,
            "valid": True,
            "trusted": True,
            "days_remaining": 90,
            "tls_version": deprecated_proto,
            "cipher": "DES-CBC3-SHA"
        }
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "tls_deprecated_version" in f_ids

    deprecated_f = next(f for f in findings if f["id"] == "tls_deprecated_version")
    assert deprecated_f["severity"] == SEVERITY_HIGH
    assert deprecated_f["evidence"]["tls_version"] == deprecated_proto


def test_header_insecure_csp_unsafe_inline():
    """Verify that CSP with 'unsafe-inline' generates header_insecure_csp (Low)."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "redirect_chain": [],
        "security_headers": {
            "csp": {
                "present": True,
                "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https:;"
            }
        },
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60}
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "header_insecure_csp" in f_ids
    assert "header_missing_csp" not in f_ids

    csp_f = next(f for f in findings if f["id"] == "header_insecure_csp")
    assert csp_f["severity"] == SEVERITY_LOW
    assert "'unsafe-inline'" in csp_f["evidence"]["insecure_directives"]


def test_header_secure_csp_no_insecure_finding():
    """Verify that strict CSP without unsafe directives produces no CSP findings."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "redirect_chain": [],
        "security_headers": {
            "csp": {
                "present": True,
                "value": "default-src 'none'; script-src 'self' 'nonce-rAnd0m'; object-src 'none';"
            }
        },
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60}
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "header_insecure_csp" not in f_ids
    assert "header_missing_csp" not in f_ids


# ==============================================================================
# 7. Page Content Form & Credential Security Tests (Phase 6 Rules)
# ==============================================================================

def test_form_insecure_submission_finding():
    """Verify that forms posting to unencrypted HTTP trigger form_insecure_submission."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60},
        "page_content": {
            "total_forms": 1,
            "insecure_forms": [
                {"action": "http://example.com/login", "method": "POST", "has_password": True}
            ],
            "cross_domain_password_forms": []
        }
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "form_insecure_submission" in f_ids

    form_f = next(f for f in findings if f["id"] == "form_insecure_submission")
    assert form_f["severity"] == SEVERITY_CRITICAL  # Critical because password input is transmitted over HTTP
    assert form_f["evidence"]["contains_password_input"] is True
    assert form_f["evidence"]["insecure_form_count"] == 1


def test_form_external_credential_destination_finding():
    """Verify that password forms submitting to unrelated external domain are flagged."""
    data = {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://bank.example.com/login",
        "final_url": "https://bank.example.com/login",
        "redirect_chain": [],
        "security_headers": {},
        "tls_certificate": {"checked": True, "valid": True, "trusted": True, "days_remaining": 60},
        "page_content": {
            "total_forms": 1,
            "insecure_forms": [],
            "cross_domain_password_forms": [
                {
                    "action": "https://credential-harvester.com/collect",
                    "target_host": "credential-harvester.com",
                    "base_host": "bank.example.com"
                }
            ]
        }
    }
    findings, _ = generate_security_findings(data)
    f_ids = [f["id"] for f in findings]
    assert "form_external_credential_destination" in f_ids

    cross_f = next(f for f in findings if f["id"] == "form_external_credential_destination")
    assert cross_f["severity"] == SEVERITY_HIGH
    assert cross_f["category"] == "page_content"
    assert "credential-harvester.com" in cross_f["evidence"]["target_hosts"]
