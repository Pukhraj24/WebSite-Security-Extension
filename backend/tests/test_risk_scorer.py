"""
Unit tests for Risk Scoring Engine (risk_scorer.py).
"""

import pytest

from risk_scorer import (
    calculate_risk,
    calculate_finding_summary,
    get_risk_level,
    METHODOLOGY_VERSION,
    LEVEL_LOW,
    LEVEL_MODERATE,
    LEVEL_HIGH,
    LEVEL_CRITICAL,
    LEVEL_UNKNOWN,
    STATUS_COMPLETE,
    STATUS_PARTIAL,
    STATUS_UNKNOWN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN
)


def make_test_finding(
    finding_id: str,
    severity: str = "low",
    category: str = "security_headers",
    title: str = "Test Finding"
) -> dict:
    """Helper to generate mock findings for scoring tests."""
    return {
        "id": finding_id,
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": "high",
        "summary": "Mock finding summary",
        "evidence": {},
        "impact": "Mock impact",
        "recommendation": "Mock recommendation",
        "affected_component": "Test Component"
    }


# ==============================================================================
# 1. Base Weights and Aggregation Tests
# ==============================================================================

def test_zero_findings_produces_zero_score():
    """Verify that zero findings produces risk_score = 0 and Low risk level."""
    result = calculate_risk(findings=[], assessment_context={"reachable": True})
    assert result["risk_score"] == 0
    assert result["risk_level"] == LEVEL_LOW
    assert result["status"] == STATUS_COMPLETE
    assert result["confidence"] == CONFIDENCE_HIGH
    assert result["methodology_version"] == METHODOLOGY_VERSION
    assert "not a guarantee" in result["summary"].lower()


def test_single_low_finding_score():
    """Verify that 1 Low finding adds 3 points (0-19 = Low)."""
    findings = [make_test_finding("f1", severity="low")]
    result = calculate_risk(findings)
    assert result["risk_score"] == 3
    assert result["risk_level"] == LEVEL_LOW


def test_single_medium_finding_score():
    """Verify that 1 Medium finding adds 8 points (0-19 = Low)."""
    findings = [make_test_finding("f1", severity="medium")]
    result = calculate_risk(findings)
    assert result["risk_score"] == 8
    assert result["risk_level"] == LEVEL_LOW


def test_single_high_finding_score():
    """Verify that 1 High finding adds 20 points (20-39 = Moderate)."""
    findings = [make_test_finding("f1", severity="high")]
    result = calculate_risk(findings)
    assert result["risk_score"] == 20
    assert result["risk_level"] == LEVEL_MODERATE


def test_single_critical_finding_score():
    """Verify that 1 Critical finding adds 40 points (40-59 = High)."""
    findings = [make_test_finding("f1", severity="critical")]
    result = calculate_risk(findings)
    assert result["risk_score"] == 40
    assert result["risk_level"] == LEVEL_HIGH
    assert "urgent attention required" in result["summary"].lower()


def test_multiple_findings_aggregate_correctly():
    """
    Verify arithmetic combination:
    1 High (20) + 2 Medium (16) + 1 Low (3) = 39 (Moderate)
    """
    findings = [
        make_test_finding("f_high", severity="high"),
        make_test_finding("f_med1", severity="medium"),
        make_test_finding("f_med2", severity="medium"),
        make_test_finding("f_low", severity="low"),
    ]
    result = calculate_risk(findings)
    assert result["risk_score"] == 39
    assert result["risk_level"] == LEVEL_MODERATE


def test_score_caps_at_100():
    """Verify that score never exceeds 100 even with excessive critical findings."""
    # 3 Critical (120) + 2 High (40) = 160 -> capped at 100
    findings = [
        make_test_finding("c1", severity="critical"),
        make_test_finding("c2", severity="critical"),
        make_test_finding("c3", severity="critical"),
        make_test_finding("h1", severity="high"),
        make_test_finding("h2", severity="high"),
    ]
    result = calculate_risk(findings)
    assert result["risk_score"] == 100
    assert result["risk_level"] == LEVEL_CRITICAL


def test_informational_findings_do_not_increase_score():
    """Verify that informational findings carry 0 weight."""
    findings = [
        make_test_finding("info1", severity="informational"),
        make_test_finding("info2", severity="informational"),
        make_test_finding("info3", severity="informational"),
    ]
    result = calculate_risk(findings)
    assert result["risk_score"] == 0
    assert result["risk_level"] == LEVEL_LOW


def test_duplicate_findings_deduplicated():
    """Verify that duplicate finding IDs do not artificially inflate the score."""
    findings = [
        make_test_finding("dup_finding", severity="high"),
        make_test_finding("dup_finding", severity="high"),  # duplicate ID
    ]
    result = calculate_risk(findings)
    assert result["risk_score"] == 20  # counted once, not 40


# ==============================================================================
# 2. Risk Level Exact Boundaries Tests
# ==============================================================================

@pytest.mark.parametrize("score, expected_level", [
    (0, LEVEL_LOW),
    (10, LEVEL_LOW),
    (19, LEVEL_LOW),         # Low boundary max
    (20, LEVEL_MODERATE),    # Moderate boundary min
    (30, LEVEL_MODERATE),
    (39, LEVEL_MODERATE),    # Moderate boundary max
    (40, LEVEL_HIGH),        # High boundary min
    (50, LEVEL_HIGH),
    (59, LEVEL_HIGH),        # High boundary max
    (60, LEVEL_CRITICAL),    # Critical boundary min
    (80, LEVEL_CRITICAL),
    (100, LEVEL_CRITICAL),   # Absolute max
])
def test_exact_risk_level_boundaries(score, expected_level):
    """Verify every documented score boundary maps to the correct risk level."""
    assert get_risk_level(score) == expected_level


# ==============================================================================
# 3. Assessment Completeness & Confidence Tests
# ==============================================================================

def test_unreachable_target_produces_unknown_assessment():
    """Verify that unreachable targets return risk_score = None and Unknown status."""
    result = calculate_risk(
        findings=[],
        assessment_context={"reachable": False}
    )
    assert result["risk_score"] is None
    assert result["risk_level"] == LEVEL_UNKNOWN
    assert result["status"] == STATUS_UNKNOWN
    assert result["confidence"] == CONFIDENCE_UNKNOWN
    assert "could not be performed" in result["summary"]


def test_partial_assessment_with_limitations():
    """Verify that assessments with limitations return partial status and medium confidence."""
    limitations = [{
        "code": "TLS_INSPECTION_INCOMPLETE",
        "message": "TLS details unavailable"
    }]
    result = calculate_risk(
        findings=[make_test_finding("f1", severity="low")],
        assessment_context={"reachable": True, "limitations": limitations}
    )
    assert result["risk_score"] == 3
    assert result["status"] == STATUS_PARTIAL
    assert result["confidence"] == CONFIDENCE_MEDIUM


# ==============================================================================
# 4. Finding Summary Calculation Tests
# ==============================================================================

def test_finding_summary_counts():
    """Verify that calculate_finding_summary accurately tallies each severity."""
    findings = [
        make_test_finding("c1", severity="critical"),
        make_test_finding("h1", severity="high"),
        make_test_finding("h2", severity="high"),
        make_test_finding("m1", severity="medium"),
        make_test_finding("l1", severity="low"),
        make_test_finding("i1", severity="informational"),
    ]
    summary = calculate_finding_summary(findings)
    assert summary["critical"] == 1
    assert summary["high"] == 2
    assert summary["medium"] == 1
    assert summary["low"] == 1
    assert summary["informational"] == 1
    assert summary["total"] == 6
