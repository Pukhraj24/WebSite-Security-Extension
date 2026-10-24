"""
Risk Scoring Engine for Website Security & Cookie Analyzer.

Calculates an explainable, deterministic, heuristic risk assessment based on
observable security findings and context.

Design Principles:
1. Explainable heuristic model based on documented severity weights.
2. Distinct underlying risks (deduplicated by stable ID).
3. Zero score does NOT imply 100% security or absence of malware/vulnerabilities.
4. Score of 100 does NOT imply site is actively malicious or compromised.
5. Confidence and Assessment Status are separated from the numerical score.
6. Unknown assessments do not fabricate numerical scores (returns null/None).
7. Zero network requests or hidden global state.
"""

from typing import Dict, Any, List, Optional, Tuple


# ==============================================================================
# Scoring Model Constants
# ==============================================================================

METHODOLOGY_VERSION = "1.0"

# Severity constants
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFORMATIONAL = "informational"

# Severity to weight mapping
SEVERITY_WEIGHTS: Dict[str, int] = {
    SEVERITY_CRITICAL: 40,
    SEVERITY_HIGH: 20,
    SEVERITY_MEDIUM: 8,
    SEVERITY_LOW: 3,
    SEVERITY_INFORMATIONAL: 0
}

# Score bands (Named constants)
SCORE_MIN = 0
SCORE_MAX = 100

BAND_LOW_MAX = 19
BAND_MODERATE_MAX = 39
BAND_HIGH_MAX = 59

LEVEL_LOW = "Low"
LEVEL_MODERATE = "Moderate"
LEVEL_HIGH = "High"
LEVEL_CRITICAL = "Critical"
LEVEL_UNKNOWN = "Unknown"

# Confidence levels
CONFIDENCE_HIGH = "High"
CONFIDENCE_MEDIUM = "Medium"
CONFIDENCE_LOW = "Low"
CONFIDENCE_UNKNOWN = "Unknown"

# Assessment status
STATUS_COMPLETE = "complete"
STATUS_PARTIAL = "partial"
STATUS_UNKNOWN = "unknown"


# ==============================================================================
# Helper Functions
# ==============================================================================

def get_risk_level(score: int) -> str:
    """
    Map numerical score (0-100) to its designated risk level category.

    Bands:
      0–19: Low
      20–39: Moderate
      40–59: High
      60–100: Critical
    """
    if score <= BAND_LOW_MAX:
        return LEVEL_LOW
    elif score <= BAND_MODERATE_MAX:
        return LEVEL_MODERATE
    elif score <= BAND_HIGH_MAX:
        return LEVEL_HIGH
    else:
        return LEVEL_CRITICAL


def calculate_finding_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculate counts of findings across each severity level."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "total": 0
    }

    for finding in findings:
        sev = finding.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
            counts["total"] += 1

    return counts


def generate_risk_summary(
    risk_score: Optional[int],
    risk_level: str,
    finding_summary: Dict[str, int],
    has_critical_override: bool
) -> str:
    """
    Generate an evidence-based, human-readable summary of the assessment.
    Avoids irresponsible claims (e.g., '100% safe' or 'definitely malicious').
    """
    if risk_score is None or risk_level == LEVEL_UNKNOWN:
        return (
            "Assessment could not be completed because insufficient observable evidence "
            "was collected from the target website."
        )

    parts = []

    if has_critical_override:
        parts.append(
            "Urgent attention required: one or more Critical severity findings were detected "
            "that warrant immediate remediation."
        )
    elif risk_level == LEVEL_LOW:
        parts.append(
            "Low observed risk: the website demonstrates strong baseline security configurations, "
            "though minor defense-in-depth improvements may remain."
        )
    elif risk_level == LEVEL_MODERATE:
        parts.append(
            "Moderate observed risk: several recommended security configurations (such as standard "
            "security headers or cookie flags) are absent or need adjustment."
        )
    elif risk_level == LEVEL_HIGH:
        parts.append(
            "High observed risk: multiple significant security controls are missing or improperly "
            "configured, increasing susceptibility to common web attacks."
        )
    else:  # Critical
        parts.append(
            "Critical observed risk: severe security issues (such as invalid transport encryption or "
            "major configuration lapses) were observed."
        )

    # Breakdown clause
    c = finding_summary["critical"]
    h = finding_summary["high"]
    m = finding_summary["medium"]
    l = finding_summary["low"]

    breakdown = []
    if c:
        breakdown.append(f"{c} critical")
    if h:
        breakdown.append(f"{h} high")
    if m:
        breakdown.append(f"{m} medium")
    if l:
        breakdown.append(f"{l} low")

    if breakdown:
        parts.append(f"Identified {', '.join(breakdown)} issue(s).")
    else:
        parts.append("No active vulnerabilities or missing controls were observed.")

    parts.append(
        "Note: This score evaluates observable external configurations only and is not a "
        "guarantee of application security or absence of malware."
    )

    return " ".join(parts)


# ==============================================================================
# Public Risk Scorer
# ==============================================================================

def calculate_risk(
    findings: List[Dict[str, Any]],
    assessment_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Calculate an explainable, deterministic risk assessment from normalized findings.

    Args:
        findings: List of normalized security finding dictionaries.
        assessment_context: Context metadata (reachable, limitations, etc.).

    Returns:
        Structured risk assessment dictionary matching the API schema.
    """
    context = assessment_context or {}
    reachable = context.get("reachable", True)
    limitations = context.get("limitations", [])

    # If the target was unreachable or fatal error occurred, return Unknown assessment
    if not reachable:
        return {
            "status": STATUS_UNKNOWN,
            "risk_score": None,
            "risk_level": LEVEL_UNKNOWN,
            "confidence": CONFIDENCE_UNKNOWN,
            "summary": "Assessment could not be performed because the website was unreachable.",
            "methodology_version": METHODOLOGY_VERSION
        }

    # Deduplicate findings by stable 'id'
    unique_findings = {}
    for f in findings:
        f_id = f.get("id")
        if f_id and f_id not in unique_findings:
            unique_findings[f_id] = f

    # Calculate raw weight sum
    raw_score = 0
    has_critical_override = False

    for f in unique_findings.values():
        sev = f.get("severity", "").lower()
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        raw_score += weight
        if sev == SEVERITY_CRITICAL:
            has_critical_override = True

    # Clamp score to [0, 100]
    risk_score = min(SCORE_MAX, max(SCORE_MIN, raw_score))

    # Map to risk level band
    risk_level = get_risk_level(risk_score)

    # Determine assessment status and confidence based on completeness
    if limitations:
        status = STATUS_PARTIAL
        confidence = CONFIDENCE_MEDIUM
    else:
        status = STATUS_COMPLETE
        confidence = CONFIDENCE_HIGH

    # Generate summary
    finding_summary = calculate_finding_summary(list(unique_findings.values()))
    summary = generate_risk_summary(
        risk_score=risk_score,
        risk_level=risk_level,
        finding_summary=finding_summary,
        has_critical_override=has_critical_override
    )

    return {
        "status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "summary": summary,
        "methodology_version": METHODOLOGY_VERSION
    }
