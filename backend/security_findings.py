"""
Structured Security Findings Engine.

Converts observable website metadata, TLS certificate status, HTTP security headers,
and cookie configurations into standardized, actionable security findings.

Design Rules:
1. Zero network calls or external state. Deterministic output for identical input.
2. Controlled categories and severity levels.
3. Stable finding IDs for programmatic indexing.
4. Grouping of repeated cookie issues to prevent score inflation.
5. Absolute confidentiality: cookie values and secrets are NEVER included.
6. Honest evaluation: unavailable checks are reported as limitations, not vulnerabilities.
"""

from typing import Dict, Any, List, Optional, Tuple
import re


# ==============================================================================
# Controlled Constants
# ==============================================================================

# Severity levels (lowercase)
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFORMATIONAL = "informational"

# Categories (lowercase)
CATEGORY_TRANSPORT = "transport_security"
CATEGORY_TLS = "tls_certificate"
CATEGORY_HEADERS = "security_headers"
CATEGORY_COOKIES = "cookie_security"
CATEGORY_REDIRECTS = "redirects"
CATEGORY_LIMITATIONS = "assessment_limitations"

# Confidence levels
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_UNKNOWN = "unknown"

# Severity sorting order (higher index = higher priority)
SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
    SEVERITY_INFORMATIONAL: 0
}


# ==============================================================================
# Finding Generator Helper
# ==============================================================================

def create_finding(
    finding_id: str,
    title: str,
    category: str,
    severity: str,
    confidence: str,
    summary: str,
    evidence: Dict[str, Any],
    impact: str,
    recommendation: str,
    affected_component: str,
    references: Optional[List[str]] = None,
    limitations: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Construct a normalized, validated security finding dictionary."""
    return {
        "id": finding_id,
        "title": title,
        "category": category,
        "severity": severity.lower(),
        "confidence": confidence.lower(),
        "summary": summary,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "affected_component": affected_component,
        "references": references or [],
        "limitations": limitations or []
    }


# ==============================================================================
# Finding Rule Evaluators
# ==============================================================================

def evaluate_transport_security(website_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate transport protocol (HTTP vs HTTPS) and redirect chain transitions."""
    findings = []
    protocol = website_data.get("protocol", "").upper()
    final_url = website_data.get("final_url", "").lower()
    initial_url = website_data.get("url", "").lower()
    redirect_chain = website_data.get("redirect_chain", [])

    is_final_https = final_url.startswith("https://")
    is_initial_https = initial_url.startswith("https://")

    # Check for HTTPS-to-HTTP downgrade across redirects
    for i, hop in enumerate(redirect_chain):
        hop_url = hop.get("url", "").lower()
        location = hop.get("location", "").lower()
        if hop_url.startswith("https://") and location.startswith("http://"):
            findings.append(create_finding(
                finding_id="redirect_https_to_http_downgrade",
                title="HTTPS-to-HTTP Redirect Downgrade Detected",
                category=CATEGORY_REDIRECTS,
                severity=SEVERITY_CRITICAL,
                confidence=CONFIDENCE_HIGH,
                summary="The connection transitioned from encrypted HTTPS to unencrypted HTTP during redirection.",
                evidence={
                    "hop_index": i,
                    "from_url": hop.get("url"),
                    "to_location": hop.get("location")
                },
                impact="An attacker in a position to intercept network traffic could exploit this downgrade to intercept or modify communication (SSL stripping).",
                recommendation="Ensure all redirects maintain HTTPS and never redirect secure traffic to unencrypted HTTP.",
                affected_component="HTTP Redirection Chain",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"]
            ))
            break

    # Unencrypted HTTP transport used
    if protocol == "HTTP" and not is_final_https:
        findings.append(create_finding(
            finding_id="transport_http_unencrypted",
            title="Unencrypted HTTP Transport in Use",
            category=CATEGORY_TRANSPORT,
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_HIGH,
            summary="The website communicates over plain HTTP without TLS encryption.",
            evidence={
                "initial_url": website_data.get("url"),
                "final_url": website_data.get("final_url"),
                "protocol": protocol
            },
            impact="All data transmitted between the client and server is sent in plaintext and can be intercepted or manipulated by eavesdroppers.",
            recommendation="Deploy a valid TLS certificate and configure the web server to automatically redirect all HTTP traffic to HTTPS.",
            affected_component="Web Server Transport Layer",
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"]
        ))
    elif is_initial_https and is_final_https:
        findings.append(create_finding(
            finding_id="transport_https_enforced",
            title="Encrypted HTTPS Transport Enforced",
            category=CATEGORY_TRANSPORT,
            severity=SEVERITY_INFORMATIONAL,
            confidence=CONFIDENCE_HIGH,
            summary="The connection is established and maintained over encrypted HTTPS.",
            evidence={"final_url": website_data.get("final_url"), "protocol": protocol},
            impact="Network eavesdroppers cannot inspect or modify traffic in transit.",
            recommendation="Continue maintaining HTTPS enforcement and monitor certificate validity.",
            affected_component="Web Server Transport Layer",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"]
        ))

    # Excessive redirect chain (> 3 redirects)
    if len(redirect_chain) > 3:
        findings.append(create_finding(
            finding_id="redirect_chain_excessive",
            title="Excessive HTTP Redirect Chain",
            category=CATEGORY_REDIRECTS,
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            summary=f"The connection required {len(redirect_chain)} redirects before reaching the destination.",
            evidence={"redirect_count": len(redirect_chain)},
            impact="Long redirect chains increase connection latency, mobile battery consumption, and attack surface for intermediate interception.",
            recommendation="Consolidate redirect rules on the server so clients reach the final destination in a single hop.",
            affected_component="HTTP Redirection Configuration"
        ))

    return findings


def evaluate_tls_certificate(website_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate TLS certificate validity, expiration, trust, and connection details."""
    findings = []
    tls_cert = website_data.get("tls_certificate")

    # If TLS check wasn't performed (e.g. plain HTTP site without HTTPS)
    if not tls_cert or not tls_cert.get("checked", False):
        return findings

    valid = tls_cert.get("valid", False)
    trusted = tls_cert.get("trusted", True)
    days_remaining = tls_cert.get("days_remaining")
    verification_error = tls_cert.get("verification_error")

    # Verification failure / Untrusted certificate (e.g., self-signed, invalid CA)
    if not trusted or verification_error:
        findings.append(create_finding(
            finding_id="tls_cert_verification_failed",
            title="TLS Certificate Verification Failed",
            category=CATEGORY_TLS,
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            summary="The TLS certificate failed trust validation against standard Certificate Authorities.",
            evidence={
                "verification_error": verification_error,
                "issuer": tls_cert.get("issuer"),
                "subject": tls_cert.get("subject")
            },
            impact="Browsers will display full-page security warnings and reject connections. Users risk connecting to an imposter or man-in-the-middle proxy.",
            recommendation="Replace the untrusted or self-signed certificate with a certificate issued by a trusted, recognized Certificate Authority.",
            affected_component="TLS Certificate",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"]
        ))
        return findings

    # Certificate expired
    if days_remaining is not None and days_remaining < 0:
        findings.append(create_finding(
            finding_id="tls_cert_expired",
            title="TLS Certificate Has Expired",
            category=CATEGORY_TLS,
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            summary=f"The TLS certificate expired {abs(days_remaining)} days ago.",
            evidence={
                "days_remaining": days_remaining,
                "expires_at": tls_cert.get("expires_at")
            },
            impact="Clients will encounter certificate expiration warnings and may block access to the website.",
            recommendation="Renew and deploy an active certificate immediately.",
            affected_component="TLS Certificate"
        ))
    # Certificate expiring soon (<= 30 days remaining)
    elif days_remaining is not None and 0 <= days_remaining <= 30:
        findings.append(create_finding(
            finding_id="tls_cert_expiring_soon",
            title="TLS Certificate Expires Soon",
            category=CATEGORY_TLS,
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            summary=f"The TLS certificate will expire in {days_remaining} days.",
            evidence={
                "days_remaining": days_remaining,
                "expires_at": tls_cert.get("expires_at")
            },
            impact="Failure to renew in time will cause browser security warnings and service outages once the certificate expires.",
            recommendation="Initiate certificate renewal and configure automated certificate renewal (e.g., Let's Encrypt / ACME).",
            affected_component="TLS Certificate"
        ))
    elif valid and days_remaining is not None and days_remaining > 30:
        findings.append(create_finding(
            finding_id="tls_cert_valid",
            title="Valid TLS Certificate",
            category=CATEGORY_TLS,
            severity=SEVERITY_INFORMATIONAL,
            confidence=CONFIDENCE_HIGH,
            summary=f"The TLS certificate is valid with {days_remaining} days remaining.",
            evidence={
                "issuer": tls_cert.get("issuer"),
                "days_remaining": days_remaining,
                "tls_version": tls_cert.get("tls_version"),
                "cipher": tls_cert.get("cipher")
            },
            impact="Encrypted connections are validated by a recognized Certificate Authority.",
            recommendation="Maintain automated renewal to prevent future expiration.",
            affected_component="TLS Certificate"
        ))

    return findings


def evaluate_security_headers(website_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate HTTP security headers presence and baseline values."""
    findings = []
    headers = website_data.get("security_headers", {})
    protocol = website_data.get("protocol", "").upper()
    is_https = protocol == "HTTPS" or website_data.get("final_url", "").lower().startswith("https://")

    # 1. HSTS (Strict-Transport-Security)
    hsts = headers.get("hsts", {})
    if is_https:
        if not hsts.get("present", False):
            findings.append(create_finding(
                finding_id="header_missing_hsts",
                title="HTTP Strict Transport Security (HSTS) Missing",
                category=CATEGORY_HEADERS,
                severity=SEVERITY_MEDIUM,
                confidence=CONFIDENCE_HIGH,
                summary="The HTTPS response does not include the Strict-Transport-Security header.",
                evidence={"header": "Strict-Transport-Security", "present": False},
                impact="Browsers may attempt initial connections over unencrypted HTTP, leaving visitors vulnerable to man-in-the-middle attacks.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                affected_component="HTTP Response Headers",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"]
            ))
        else:
            val = str(hsts.get("value") or "").lower()
            match = re.search(r"max-age\s*=\s*(\d+)", val)
            if match:
                max_age = int(match.group(1))
                if max_age < 300:
                    findings.append(create_finding(
                        finding_id="header_invalid_hsts",
                        title="HSTS Max-Age Is Ineffectively Short",
                        category=CATEGORY_HEADERS,
                        severity=SEVERITY_MEDIUM,
                        confidence=CONFIDENCE_HIGH,
                        summary=f"Strict-Transport-Security specifies max-age={max_age}, which is too short to provide effective protection.",
                        evidence={"header_value": hsts.get("value"), "parsed_max_age": max_age},
                        impact="Browsers will cease enforcing HTTPS almost immediately after visiting.",
                        recommendation="Set max-age to at least 31536000 (1 year) once HTTPS configuration is stable.",
                        affected_component="HTTP Response Headers"
                    ))

    # 2. Content-Security-Policy (CSP)
    csp = headers.get("csp", {})
    csp_present = csp.get("present", False)
    csp_value = str(csp.get("value") or "").strip()

    if not csp_present or not csp_value:
        findings.append(create_finding(
            finding_id="header_missing_csp",
            title="Content Security Policy (CSP) Missing",
            category=CATEGORY_HEADERS,
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            summary="The response lacks a Content-Security-Policy header.",
            evidence={"header": "Content-Security-Policy", "present": False},
            impact="Without CSP, the browser cannot restrict resource loading origins, significantly increasing vulnerability to Cross-Site Scripting (XSS) and data injection.",
            recommendation="Implement a Content Security Policy starting with restrictive defaults (e.g., default-src 'self').",
            affected_component="HTTP Response Headers",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]
        ))

    # 3. Framing Protections (X-Frame-Options vs CSP frame-ancestors overlap)
    xfo = headers.get("x_frame_options", {})
    xfo_present = xfo.get("present", False)
    has_frame_ancestors = "frame-ancestors" in csp_value.lower()

    if not xfo_present and not has_frame_ancestors:
        findings.append(create_finding(
            finding_id="header_missing_x_frame_options",
            title="Clickjacking Framing Protection Missing",
            category=CATEGORY_HEADERS,
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            summary="Neither X-Frame-Options nor CSP frame-ancestors is configured to prevent clickjacking.",
            evidence={"x_frame_options_present": False, "csp_frame_ancestors_present": False},
            impact="Malicious websites can embed this site inside an iframe to trick users into unintended actions (Clickjacking).",
            recommendation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or define the 'frame-ancestors' directive in Content-Security-Policy.",
            affected_component="HTTP Response Headers",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"]
        ))

    # 4. X-Content-Type-Options
    xcto = headers.get("x_content_type_options", {})
    if not xcto.get("present", False):
        findings.append(create_finding(
            finding_id="header_missing_x_content_type_options",
            title="X-Content-Type-Options Header Missing",
            category=CATEGORY_HEADERS,
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            summary="The response does not include the X-Content-Type-Options header.",
            evidence={"header": "X-Content-Type-Options", "present": False},
            impact="Browsers may perform MIME-type sniffing on responses, potentially interpreting user uploads or text files as executable scripts.",
            recommendation="Add 'X-Content-Type-Options: nosniff' to all responses.",
            affected_component="HTTP Response Headers",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
        ))
    elif str(xcto.get("value") or "").strip().lower() != "nosniff":
        findings.append(create_finding(
            finding_id="header_invalid_x_content_type_options",
            title="X-Content-Type-Options Has Non-Standard Value",
            category=CATEGORY_HEADERS,
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            summary="X-Content-Type-Options is present but is not set to 'nosniff'.",
            evidence={"value": xcto.get("value")},
            impact="MIME-sniffing protection will not be activated by browsers.",
            recommendation="Set header value strictly to 'nosniff'.",
            affected_component="HTTP Response Headers"
        ))

    # 5. Referrer-Policy
    ref = headers.get("referrer_policy", {})
    if not ref.get("present", False):
        findings.append(create_finding(
            finding_id="header_missing_referrer_policy",
            title="Referrer-Policy Header Missing",
            category=CATEGORY_HEADERS,
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            summary="The response does not explicitly specify a Referrer-Policy header.",
            evidence={"header": "Referrer-Policy", "present": False},
            impact="Browsers default to standard referrer behavior, which might leak URL path or query parameters to external sites during navigation.",
            recommendation="Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            affected_component="HTTP Response Headers",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"]
        ))

    # 6. Permissions-Policy (Informational)
    perm = headers.get("permissions_policy", {})
    if not perm.get("present", False):
        findings.append(create_finding(
            finding_id="header_missing_permissions_policy",
            title="Permissions-Policy Header Not Configured",
            category=CATEGORY_HEADERS,
            severity=SEVERITY_INFORMATIONAL,
            confidence=CONFIDENCE_HIGH,
            summary="Permissions-Policy header is omitted.",
            evidence={"header": "Permissions-Policy", "present": False},
            impact="Browser features (camera, microphone, geolocation) rely on default origin permissions rather than explicit restriction.",
            recommendation="Consider configuring Permissions-Policy to explicitly disable unnecessary hardware APIs.",
            affected_component="HTTP Response Headers"
        ))

    # 7. Cross-Origin Isolation headers (Informational)
    coop = headers.get("cross_origin_opener_policy", {})
    if not coop.get("present", False):
        findings.append(create_finding(
            finding_id="header_missing_coop",
            title="Cross-Origin-Opener-Policy (COOP) Not Set",
            category=CATEGORY_HEADERS,
            severity=SEVERITY_INFORMATIONAL,
            confidence=CONFIDENCE_HIGH,
            summary="Cross-Origin-Opener-Policy is not specified.",
            evidence={"header": "Cross-Origin-Opener-Policy", "present": False},
            impact="Top-level browsing context may share an event loop process with cross-origin documents.",
            recommendation="Consider setting 'Cross-Origin-Opener-Policy: same-origin' if cross-origin isolation is desired.",
            affected_component="HTTP Response Headers"
        ))

    return findings


def evaluate_cookie_security(cookie_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluate cookie attributes across all observed cookies.
    Groups identical issues across cookies to avoid artificial score inflation.
    CRITICAL: Never exposes cookie values!
    """
    findings = []
    cookie_details = cookie_data.get("cookie_details", [])

    if not cookie_details:
        return findings

    # Collect affected cookie names by category (never values)
    missing_secure = []
    missing_httponly = []
    missing_samesite = []
    samesite_none_insecure = []
    secure_prefix_violations = []
    host_prefix_violations = []

    for cookie in cookie_details:
        name = cookie.get("name", "unknown")
        is_secure = cookie.get("secure", False)
        is_httponly = cookie.get("httponly", False)
        samesite = cookie.get("samesite")
        path = cookie.get("path")
        domain_specified = cookie.get("domain_specified", False)

        if not is_secure:
            missing_secure.append(name)

        if not is_httponly:
            missing_httponly.append(name)

        if not samesite:
            missing_samesite.append(name)
        elif str(samesite).lower() == "none" and not is_secure:
            samesite_none_insecure.append(name)

        # Prefix rule checks
        if name.startswith("__Secure-") and not is_secure:
            secure_prefix_violations.append(name)

        if name.startswith("__Host-"):
            if not is_secure or path != "/" or domain_specified:
                host_prefix_violations.append(name)

    # 1. Grouped Missing Secure
    if missing_secure:
        findings.append(create_finding(
            finding_id="cookies_missing_secure",
            title="Cookies Without Secure Flag Detected",
            category=CATEGORY_COOKIES,
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            summary=f"{len(missing_secure)} cookie(s) lack the Secure attribute.",
            evidence={
                "affected_cookies": missing_secure[:10],
                "total_affected": len(missing_secure)
            },
            impact="Insecure cookies can be transmitted over unencrypted HTTP connections and intercepted by network eavesdroppers.",
            recommendation="Mark all sensitive cookies with the 'Secure' attribute to enforce transmission strictly over HTTPS.",
            affected_component="HTTP Cookies",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"]
        ))

    # 2. Grouped Missing HttpOnly
    if missing_httponly:
        findings.append(create_finding(
            finding_id="cookies_missing_httponly",
            title="Cookies Without HttpOnly Flag Detected",
            category=CATEGORY_COOKIES,
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            summary=f"{len(missing_httponly)} cookie(s) lack the HttpOnly attribute.",
            evidence={
                "affected_cookies": missing_httponly[:10],
                "total_affected": len(missing_httponly)
            },
            impact="Client-side JavaScript can read these cookies via document.cookie, making stored session tokens vulnerable to Cross-Site Scripting (XSS) theft.",
            recommendation="Set the 'HttpOnly' flag for all authentication and session identifiers.",
            affected_component="HTTP Cookies",
            references=["https://owasp.org/www-community/HttpOnly"]
        ))

    # 3. Grouped Missing SameSite
    if missing_samesite:
        findings.append(create_finding(
            finding_id="cookies_missing_samesite",
            title="Cookies Without Explicit SameSite Attribute",
            category=CATEGORY_COOKIES,
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            summary=f"{len(missing_samesite)} cookie(s) do not specify an explicit SameSite attribute.",
            evidence={
                "affected_cookies": missing_samesite[:10],
                "total_affected": len(missing_samesite)
            },
            impact="Modern browsers default to Lax, but older or non-standard clients may send these cookies with cross-site requests, increasing Cross-Site Request Forgery (CSRF) risk.",
            recommendation="Explicitly configure 'SameSite=Lax' or 'SameSite=Strict' on all state-managing cookies.",
            affected_component="HTTP Cookies",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"]
        ))

    # 4. SameSite=None without Secure
    if samesite_none_insecure:
        findings.append(create_finding(
            finding_id="cookie_samesite_none_insecure",
            title="SameSite=None Configured Without Secure Flag",
            category=CATEGORY_COOKIES,
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            summary=f"{len(samesite_none_insecure)} cookie(s) specify SameSite=None but lack the Secure flag.",
            evidence={
                "affected_cookies": samesite_none_insecure[:10],
                "total_affected": len(samesite_none_insecure)
            },
            impact="Modern browsers automatically reject cookies with SameSite=None that lack the Secure attribute, causing unexpected session or tracking failures.",
            recommendation="Always pair 'SameSite=None' with the 'Secure' attribute.",
            affected_component="HTTP Cookies"
        ))

    # 5. Prefix Violations
    if secure_prefix_violations:
        findings.append(create_finding(
            finding_id="cookie_secure_prefix_violation",
            title="__Secure- Cookie Prefix Requirement Violation",
            category=CATEGORY_COOKIES,
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            summary=f"{len(secure_prefix_violations)} cookie(s) use '__Secure-' prefix but omit the Secure attribute.",
            evidence={"affected_cookies": secure_prefix_violations},
            impact="Compliant browsers will reject cookies using the __Secure- prefix if they are not marked Secure and set over HTTPS.",
            recommendation="Ensure cookies using the __Secure- prefix are sent over HTTPS with the Secure attribute.",
            affected_component="HTTP Cookies"
        ))

    if host_prefix_violations:
        findings.append(create_finding(
            finding_id="cookie_host_prefix_violation",
            title="__Host- Cookie Prefix Requirement Violation",
            category=CATEGORY_COOKIES,
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            summary=f"{len(host_prefix_violations)} cookie(s) violate __Host- prefix requirements (requires Secure, Path=/, and no Domain).",
            evidence={"affected_cookies": host_prefix_violations},
            impact="Compliant browsers will reject cookies using the __Host- prefix that violate its strict scoping requirements.",
            recommendation="Configure __Host- cookies with Secure, Path=/, and do not specify a Domain attribute.",
            affected_component="HTTP Cookies"
        ))

    return findings


# ==============================================================================
# Public Findings Aggregator
# ==============================================================================

def generate_security_findings(
    website_data: Dict[str, Any],
    cookie_data: Optional[Dict[str, Any]] = None
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Generate normalized security findings and assessment limitations.

    Returns:
        (sorted_findings, assessment_limitations)
    """
    findings: List[Dict[str, Any]] = []
    limitations: List[Dict[str, Any]] = []

    # If website was not reachable, record limitation and return
    if not website_data.get("reachable", False):
        error_info = website_data.get("error", {})
        limitations.append({
            "code": error_info.get("code", "WEBSITE_UNREACHABLE"),
            "message": error_info.get("message", "Target website could not be reached."),
            "impact_on_assessment": "Assessment could not be conducted because target was unreachable."
        })
        return findings, limitations

    # Evaluate Transport and Redirects
    findings.extend(evaluate_transport_security(website_data))

    # Evaluate TLS Certificate
    tls_cert = website_data.get("tls_certificate")
    if website_data.get("secure_connection", False) and not tls_cert:
        limitations.append({
            "code": "TLS_INSPECTION_INCOMPLETE",
            "message": "TLS certificate details were unavailable for diagnostic inspection.",
            "impact_on_assessment": "Confidence in transport security is slightly reduced."
        })
    else:
        findings.extend(evaluate_tls_certificate(website_data))

    # Evaluate Security Headers
    findings.extend(evaluate_security_headers(website_data))

    # Evaluate Cookies
    if cookie_data:
        findings.extend(evaluate_cookie_security(cookie_data))

    # Deduplicate findings by stable 'id'
    unique_findings = {}
    for finding in findings:
        f_id = finding["id"]
        if f_id not in unique_findings:
            unique_findings[f_id] = finding

    # Deterministic sorting:
    # 1. Severity descending (Critical -> High -> Medium -> Low -> Informational)
    # 2. Category ascending
    # 3. Finding ID ascending
    sorted_findings = sorted(
        unique_findings.values(),
        key=lambda f: (
            -SEVERITY_ORDER.get(f["severity"], 0),
            f["category"],
            f["id"]
        )
    )

    return sorted_findings, limitations
