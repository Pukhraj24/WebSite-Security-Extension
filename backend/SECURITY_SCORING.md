# Website Security & Cookie Analyzer — Risk Scoring & Findings Methodology

**Methodology Version:** `1.0`  
**Status:** Implemented & Verified  
**Audience:** CSE Students, Web Developers, and Application Security Engineers

---

## 1. Purpose & Scope of the Scoring Engine

The **Risk Scoring Engine** and **Structured Security Findings System** evaluate the observable security configurations and cookie attributes of websites.

### What the Scanner CAN Detect:
- **Transport Security**: Use of plain HTTP vs. encrypted HTTPS, and redirection downgrades from HTTPS to HTTP.
- **TLS Certificate Status**: Certificate validity, expiration, not-yet-valid dates, untrusted/self-signed status, and impending expiration (<= 30 days).
- **Security Headers**: Presence, absence, and baseline values of key defensive headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Content-Type-Options` (MIME-sniffing protection)
  - `X-Frame-Options` and CSP `frame-ancestors` (Clickjacking defenses)
  - `Referrer-Policy` (Referrer leakage control)
  - `Permissions-Policy` (Browser hardware and API restrictions)
  - `Cross-Origin-Opener-Policy` (COOP)
- **Cookie Security Configurations**:
  - `Secure` flag (HTTPS-only transmission)
  - `HttpOnly` flag (protection against JavaScript `document.cookie` theft)
  - `SameSite` attribute (`Strict`, `Lax`, `None`)
  - Prefix compliance (`__Secure-` and `__Host-` prefixes)
  - Session vs. persistent cookie classification

### What the Scanner CANNOT Detect:
> [!IMPORTANT]
> **Heuristic Assessment Disclaimer:**  
> This system evaluates **observable configuration headers and network metadata only**. It is **not** a penetration test, dynamic application security test (DAST), vulnerability scanner, malware scanner, or phishing detector.  
> - A score of **0 (Low Risk)** does **not** guarantee that a website is "100% safe" or free of vulnerabilities (e.g., SQL injection, remote code execution, or business logic flaws).
> - A score of **100 (Critical Risk)** indicates severe configuration deficiencies (such as unencrypted transport or expired certificates); it does **not** mean the website is actively malicious.

---

## 2. Finding Categories and Severity Weights

### Controlled Finding Categories:
- `transport_security`: Protocol integrity and encryption.
- `tls_certificate`: Cryptographic certificate validity and trust.
- `security_headers`: Defensive HTTP response headers.
- `cookie_security`: Cookie transmission, scope, and script access controls.
- `redirects`: Redirection hops, downgrades, and loop protections.
- `assessment_limitations`: Observable constraints or incomplete scans.

### Severity-to-Weight Mapping:
Each finding is classified into one of five controlled severity levels:

| Severity Level | Base Weight | Description |
| :--- | :---: | :--- |
| **Critical** | `40` | Severe security flaws requiring immediate remediation (e.g., expired certificate, untrusted certificate, HTTPS-to-HTTP downgrade). |
| **High** | `20` | Major security omissions (e.g., unencrypted HTTP transport without HTTPS). |
| **Medium** | `8` | Important defensive controls absent (e.g., missing HSTS, missing CSP, cookies lacking `Secure`). |
| **Low** | `3` | Defense-in-depth gaps (e.g., missing `X-Content-Type-Options`, missing `Referrer-Policy`, cookies lacking `HttpOnly`). |
| **Informational**| `0` | Positive security indicators or optional hardening policies (e.g., valid TLS cert, `Permissions-Policy`). Adds zero risk points. |

---

## 3. Risk Score Formula & Scoring Bands

### Calculation Formula:
1. Findings are deduplicated by their stable `id`.
2. Each unique finding contributes its designated severity weight:
   $$\text{raw\_score} = \sum \text{SEVERITY\_WEIGHTS}[\text{finding.severity}]$$
3. The final numerical score is clamped between `0` and `100`:
   $$\text{risk\_score} = \min(100, \max(0, \text{raw\_score}))$$

### Risk Level Bands:
The numerical score maps to four heuristic bands:

| Score Range | Risk Level | Description |
| :---: | :---: | :--- |
| **0 – 19** | **Low** | Strong baseline configuration; minor hardening recommendations may apply. |
| **20 – 39** | **Moderate** | Standard security controls (e.g., missing HSTS or missing cookie flags) require attention. |
| **40 – 59** | **High** | Multiple major security controls are missing; higher exposure to common attacks. |
| **60 – 100**| **Critical** | Urgent security flaws observed (e.g., untrusted TLS certificate or severe downgrades). |

*Note on Unknown Assessment:* If a target is completely unreachable or blocked by safety policy, `risk_score` is `null` and `risk_level` is `"Unknown"`. Scores are never fabricated without evidence.

---

## 4. Assessment Confidence & Limitations

Confidence and Assessment Status are measured independently from the risk score:

- **Assessment Status**:
  - `"complete"`: All target checks (transport, TLS, headers, cookies) were performed.
  - `"partial"`: Target was reachable, but certain checks encountered limitations (e.g., TLS diagnostic connection was unavailable).
  - `"unknown"`: Target was unreachable or fatal connection error occurred.
- **Confidence Levels**:
  - `"High"`: Full evidence gathered across all analyzers without limitations.
  - `"Medium"`: Minor limitations encountered; confidence slightly reduced.
  - `"Low"`: Substantial portion of checks could not be verified.
  - `"Unknown"`: Insufficient evidence to produce a meaningful assessment.

---

## 5. Finding Catalog & Rule Definitions

| Finding ID | Default Severity | Category | Trigger Condition |
| :--- | :---: | :--- | :--- |
| `redirect_https_to_http_downgrade` | `critical` | `redirects` | Redirection hop moves from HTTPS to HTTP. |
| `tls_cert_verification_failed` | `critical` | `tls_certificate` | Certificate fails trust verification (e.g., self-signed). |
| `tls_cert_expired` | `critical` | `tls_certificate` | Certificate expiration date is in the past. |
| `transport_http_unencrypted` | `high` | `transport_security` | Final URL uses plain HTTP without TLS. |
| `tls_cert_expiring_soon` | `medium` | `tls_certificate` | Certificate expiration is within 30 days. |
| `header_missing_hsts` | `medium` | `security_headers` | HTTPS response lacks `Strict-Transport-Security`. |
| `header_invalid_hsts` | `medium` | `security_headers` | HSTS `max-age` is less than 300 seconds. |
| `header_missing_csp` | `medium` | `security_headers` | Response lacks `Content-Security-Policy`. |
| `cookie_samesite_none_insecure` | `medium` | `cookie_security` | Cookie specifies `SameSite=None` without `Secure`. |
| `cookie_secure_prefix_violation` | `medium` | `cookie_security` | Cookie name starts with `__Secure-` but lacks `Secure`. |
| `cookie_host_prefix_violation` | `medium` | `cookie_security` | Cookie name starts with `__Host-` but violates scoping rules. |
| `cookies_missing_secure` | `medium` | `cookie_security` | One or more cookies lack the `Secure` flag (grouped). |
| `header_missing_x_content_type_options`| `low` | `security_headers` | Response lacks `X-Content-Type-Options`. |
| `header_invalid_x_content_type_options`| `low` | `security_headers` | `X-Content-Type-Options` is not set to `nosniff`. |
| `header_missing_x_frame_options` | `low` | `security_headers` | Both `X-Frame-Options` and CSP `frame-ancestors` are missing. |
| `header_missing_referrer_policy` | `low` | `security_headers` | Response lacks `Referrer-Policy`. |
| `cookies_missing_httponly` | `low` | `cookie_security` | One or more cookies lack `HttpOnly` (grouped). |
| `cookies_missing_samesite` | `low` | `cookie_security` | One or more cookies lack `SameSite` attribute (grouped). |
| `redirect_chain_excessive` | `low` | `redirects` | Connection required more than 3 redirect hops. |
| `header_missing_permissions_policy` | `informational` | `security_headers` | `Permissions-Policy` header is not set. |
| `header_missing_coop` | `informational` | `security_headers` | `Cross-Origin-Opener-Policy` is not set. |
| `tls_cert_valid` | `informational` | `tls_certificate` | TLS certificate is valid (> 30 days remaining). |
| `transport_https_enforced` | `informational` | `transport_security` | Connection is encrypted and maintained over HTTPS. |

---

## 6. Cookie Grouping & Privacy Guarantee

### Value Non-Disclosure Rule:
**Under no circumstances are cookie values returned, logged, or included in findings.**  
Evidence only includes metadata:
```json
{
  "affected_cookies": ["session_id", "csrf_token"],
  "total_affected": 2
}
```

### Grouping Mechanism:
To avoid artificial score inflation (e.g., a website setting 10 cookies without `Secure` counting as 10 separate vulnerabilities), cookie issues are grouped into unified findings (`cookies_missing_secure`, `cookies_missing_httponly`, `cookies_missing_samesite`) that count as a single configuration risk.

---

## 7. How to Extend the Engine

### Adding a New Finding Rule:
1. Open [`backend/security_findings.py`](file:///c:/Users/LENOVO/Desktop/WebsiteSecurityExtension/backend/security_findings.py).
2. Add an evaluation check in the appropriate evaluator function (e.g., `evaluate_security_headers`).
3. Call `create_finding()` with a unique `finding_id`, `category`, and `severity`.
4. Add unit test coverage in [`backend/tests/test_security_findings.py`](file:///c:/Users/LENOVO/Desktop/WebsiteSecurityExtension/backend/tests/test_security_findings.py).

### Adjusting Scoring Weights:
1. Open [`backend/risk_scorer.py`](file:///c:/Users/LENOVO/Desktop/WebsiteSecurityExtension/backend/risk_scorer.py).
2. Modify the `SEVERITY_WEIGHTS` dictionary or the score band constants (`BAND_LOW_MAX`, etc.).
3. Update `METHODOLOGY_VERSION` (e.g., to `"1.1"`).
4. Run tests to confirm expected outcomes: `pytest -v backend/tests/test_risk_scorer.py`.

---

## 8. Running Automated Tests

Run the full test suite from the repository root:
```powershell
.\backend\venv\Scripts\python.exe -m pytest -v backend\tests
```
All 112 unit and integration tests run deterministically in < 1 second.
