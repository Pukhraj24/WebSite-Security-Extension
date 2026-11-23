"""
Tests for Hybrid Rule + Machine Learning Assessment Integration (Milestone 9C).

Validates threshold-based ML finding generation, additive hybrid risk scoring,
strict non-downgrade precedence of deterministic findings, score boundedness [0, 100],
and fault isolation when ML is unavailable.
"""

import pytest
from security_findings import (
    generate_security_findings,
    evaluate_ml_phishing,
    CATEGORY_PHISHING,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)
from risk_scorer import (
    calculate_risk,
    calculate_finding_summary,
    LEVEL_LOW,
    LEVEL_MODERATE,
    LEVEL_HIGH,
    LEVEL_CRITICAL,
)


@pytest.fixture
def clean_website_data():
    """Minimal baseline website data with secure transport and valid certificate."""
    return {
        "reachable": True,
        "protocol": "HTTPS",
        "url": "https://secure-example.com",
        "final_url": "https://secure-example.com/",
        "hostname": "secure-example.com",
        "redirect_chain": [],
        "tls_certificate": {
            "checked": True,
            "valid": True,
            "trusted": True,
            "days_remaining": 120
        },
        "security_headers": {
            "hsts": {"present": True, "value": "max-age=31536000"},
            "csp": {"present": True, "value": "default-src 'self'"},
            "x_content_type_options": {"present": True, "value": "nosniff"},
            "x_frame_options": {"present": True, "value": "DENY"},
            "referrer_policy": {"present": True, "value": "strict-origin-when-cross-origin"},
            "permissions_policy": {"present": True, "value": "camera=()"},
            "cross_origin_opener_policy": {"present": True, "value": "same-origin"}
        },
        "domain_identity": {
            "is_ip_address": False,
            "is_punycode": False
        },
        "page_content": {
            "total_forms": 0,
            "insecure_forms": [],
            "cross_domain_password_forms": []
        }
    }


# ==============================================================================
# 1. Threshold-Based Finding Generation
# ==============================================================================

def test_ml_probability_below_high_threshold():
    """Verify ML probability < 0.85 generates no phishing finding."""
    ml_result = {
        "available": True,
        "url": "https://secure-example.com",
        "phishing_probability": 0.35,
        "is_phishing": False,
        "classification": "legitimate",
        "heuristic_severity": None,
        "model_name": "HistGradientBoosting",
        "model_version": "v2.0.0",
        "feature_count": 40
    }
    findings = evaluate_ml_phishing(ml_result)
    assert len(findings) == 0


def test_ml_probability_high_threshold():
    """Verify ML probability in [0.85, 0.95) generates High severity finding."""
    ml_result = {
        "available": True,
        "url": "https://suspicious-domain.xyz/login",
        "phishing_probability": 0.88,
        "is_phishing": True,
        "classification": "phishing",
        "heuristic_severity": "high",
        "model_name": "HistGradientBoosting",
        "model_version": "v2.0.0",
        "feature_count": 40
    }
    findings = evaluate_ml_phishing(ml_result)
    assert len(findings) == 1
    f = findings[0]
    assert f["id"] == "ml_phishing_heuristic"
    assert f["category"] == CATEGORY_PHISHING
    assert f["severity"] == SEVERITY_HIGH
    assert f["confidence"] == "high"
    assert f["evidence"]["phishing_probability"] == 0.88
    assert f["evidence"]["threshold_applied"] == 0.85


def test_ml_probability_critical_threshold():
    """Verify ML probability >= 0.95 generates Critical severity finding."""
    ml_result = {
        "available": True,
        "url": "http://192.168.1.1/paypal/verify-token.php",
        "phishing_probability": 0.985,
        "is_phishing": True,
        "classification": "phishing",
        "heuristic_severity": "critical",
        "model_name": "HistGradientBoosting",
        "model_version": "v2.0.0",
        "feature_count": 40
    }
    findings = evaluate_ml_phishing(ml_result)
    assert len(findings) == 1
    f = findings[0]
    assert f["id"] == "ml_phishing_heuristic"
    assert f["category"] == CATEGORY_PHISHING
    assert f["severity"] == SEVERITY_CRITICAL
    assert f["confidence"] == "high"
    assert f["evidence"]["phishing_probability"] == 0.985
    assert f["evidence"]["threshold_applied"] == 0.95


# ==============================================================================
# 2. Additive Hybrid Risk Scoring & Boundedness
# ==============================================================================

def test_hybrid_scoring_additive_impact(clean_website_data):
    """Verify ML findings contribute additive weight and elevate risk band."""
    # Baseline with no findings: score = 0
    base_findings, _ = generate_security_findings(clean_website_data)
    base_assessment = calculate_risk(base_findings)
    assert base_assessment["risk_score"] == 0
    assert base_assessment["risk_level"] == LEVEL_LOW

    # With High ML finding: weight +20 -> score = 20 (Moderate)
    ml_high = {
        "available": True,
        "url": clean_website_data["url"],
        "phishing_probability": 0.90,
        "is_phishing": True,
        "classification": "phishing"
    }
    high_findings, _ = generate_security_findings(clean_website_data, ml_result=ml_high)
    high_assessment = calculate_risk(high_findings)
    assert high_assessment["risk_score"] == 20
    assert high_assessment["risk_level"] == LEVEL_MODERATE

    # With Critical ML finding: weight +40 -> score = 40 (High band, with critical override)
    ml_crit = {
        "available": True,
        "url": clean_website_data["url"],
        "phishing_probability": 0.97,
        "is_phishing": True,
        "classification": "phishing"
    }
    crit_findings, _ = generate_security_findings(clean_website_data, ml_result=ml_crit)
    crit_assessment = calculate_risk(crit_findings)
    assert crit_assessment["risk_score"] == 40
    assert any(f["severity"] == "critical" for f in crit_findings)
    assert "Urgent attention required" in crit_assessment["summary"]


def test_score_remains_strictly_bounded_0_to_100(clean_website_data):
    """Verify score never exceeds 100 even with stacked deterministic and ML critical findings."""
    # Add multiple severe deterministic issues
    clean_website_data["protocol"] = "HTTP"  # Missing HTTPS: +20
    clean_website_data["tls_certificate"] = {
        "checked": True,
        "valid": False,
        "trusted": True,
        "days_remaining": -10,
        "expires_at": "2026-10-10T00:00:00+00:00"
    }  # Expired cert: +40
    clean_website_data["security_headers"] = {}  # Missing headers: +8, +8, etc.

    ml_crit = {
        "available": True,
        "url": "http://expired-site.com",
        "phishing_probability": 0.99,
        "is_phishing": True,
        "classification": "phishing"
    }
    findings, _ = generate_security_findings(clean_website_data, ml_result=ml_crit)
    assessment = calculate_risk(findings)

    assert 0 <= assessment["risk_score"] <= 100
    assert assessment["risk_score"] == 100
    assert assessment["risk_level"] == LEVEL_CRITICAL


# ==============================================================================
# 3. Security Precedence & Non-Downgrade Guarantee
# ==============================================================================

def test_ml_cannot_downgrade_deterministic_critical_findings(clean_website_data):
    """
    Verify that when deterministic critical vulnerabilities exist,
    a low or benign ML probability (0.01) NEVER downgrades or suppresses the finding.
    """
    # Deterministic critical flaw: expired TLS certificate (+40)
    clean_website_data["tls_certificate"] = {
        "checked": True,
        "valid": False,
        "trusted": True,
        "days_remaining": -5,
        "expires_at": "2026-10-19T00:00:00+00:00"
    }

    # ML predicts very low phishing probability (0.02)
    benign_ml = {
        "available": True,
        "url": clean_website_data["url"],
        "phishing_probability": 0.02,
        "is_phishing": False,
        "classification": "legitimate"
    }

    findings, _ = generate_security_findings(clean_website_data, ml_result=benign_ml)
    assessment = calculate_risk(findings)

    # Deterministic expired certificate finding MUST be present
    cert_findings = [f for f in findings if f["id"] == "tls_cert_expired"]
    assert len(cert_findings) == 1
    assert cert_findings[0]["severity"] == "critical"

    # Score MUST reflect the critical deterministic finding (>= 40)
    assert assessment["risk_score"] >= 40
    assert "Urgent attention required" in assessment["summary"]


def test_coexisting_deterministic_and_ml_findings(clean_website_data):
    """Verify both deterministic and ML findings coexist cleanly in the finding list."""
    clean_website_data["page_content"]["insecure_forms"] = [{
        "action": "http://insecure-login.com/auth",
        "method": "POST",
        "has_password": True
    }]

    ml_crit = {
        "available": True,
        "url": "https://deceptive-site.com",
        "phishing_probability": 0.96,
        "is_phishing": True,
        "classification": "phishing"
    }

    findings, _ = generate_security_findings(clean_website_data, ml_result=ml_crit)
    finding_ids = [f["id"] for f in findings]

    assert "form_insecure_submission" in finding_ids
    assert "ml_phishing_heuristic" in finding_ids

    # Both are Critical
    summary = calculate_finding_summary(findings)
    assert summary["critical"] >= 2


# ==============================================================================
# 4. Fault Isolation & Fallback Behavior
# ==============================================================================

def test_ml_failure_isolation_records_limitation(clean_website_data):
    """Verify that when ML fails or is unavailable, deterministic analysis completes with limitation."""
    ml_error = {
        "available": False,
        "url": clean_website_data["url"],
        "error": "Model artifact hash verification failed"
    }

    findings, limitations = generate_security_findings(clean_website_data, ml_result=ml_error)
    assessment = calculate_risk(findings, assessment_context={"reachable": True, "limitations": limitations})

    # No phishing finding should be fabricated
    assert not any(f["id"] == "ml_phishing_heuristic" for f in findings)

    # Assessment status and limitation noted
    ml_limitations = [l for l in limitations if l["code"] == "ML_PHISHING_INSPECTION_UNAVAILABLE"]
    assert len(ml_limitations) == 1
    assert "Model artifact hash verification failed" in ml_limitations[0]["message"]
    assert assessment["status"] == "partial"
    assert assessment["confidence"] == "Medium"


def test_backward_compatibility_when_ml_omitted(clean_website_data):
    """Verify existing two-argument call generate_security_findings(website_data, cookie_data) works."""
    findings, limitations = generate_security_findings(clean_website_data)
    assert isinstance(findings, list)
    assert isinstance(limitations, list)
    assert not any(f["id"] == "ml_phishing_heuristic" for f in findings)
