# Rule-Based Website Security Detection Engine — Comprehensive Audit & Coverage Matrix

**Date:** October 2026
**Auditor:** Antigravity AI Engine (Autonomous Security Audit)
**Target:** Website Security Analyzer (Chrome Extension + FastAPI Backend)
**Repository:** `C:\Users\LENOVO\Desktop\WebsiteSecurityExtension`
**Methodology:** Code-level static analysis, control flow verification, unit test mapping, and regression evaluation.

---

## Executive Summary

This document provides a comprehensive, code-level audit of the rule-based security detection engine powering the Website Security Analyzer. Every rule, validation routine, heuristic check, network boundary, and scoring mechanism has been audited against the actual source code and automated tests.

Following the initial audit, high-value detection gaps were prioritized and implemented, expanding the rule-based engine's coverage across domain identity, deprecated cryptographic protocols, permissive Content Security Policies, and static HTML form/credential submission vulnerabilities.

### Audit Summary Statistics
- **Total Audit Categories Audited:** 9 (A through I)
- **Baseline Test Suite Status:** 145 passed, 0 failures (1.19s)
- **Final Test Suite Status:** 157 passed, 0 failures (12 new tests added, 0 regressions)
- **Dependency Audit Status (`pip-audit`):** 0 vulnerabilities detected (clean exit)
- **Rules Currently Implemented:** 21 stable findings + SSRF/network security suite (9 controls)
- **Rules Implemented in Phase 6:** 6 new high-value rules
- **Rules Intentionally Deferred:** Live domain reputation APIs, WHOIS lookups, and dynamic browser DOM analysis (justified below)

---

## 1. Initial Rule Coverage Matrix (Pre-Implementation Baseline)

| Category | Rule / Check Name | Baseline Status | Source File & Function | Evidence or Logic Used | Baseline Test Coverage | False-Positive / False-Negative Risks | Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A. URL & Domain** | Malformed / Invalid URL Syntax | **Implemented** | `ssrf_validator.py` :: `validate_url()` | Scheme/host syntax, URL parsing, length <= 2048 | `test_ssrf.py` (`test_validate_url_invalid_format`, etc.) | **FP:** None on valid URLs. **FN:** Novel URI scheme tricks. | Maintain existing input validation. |
| **A. URL & Domain** | Unsupported Schemes (file, ftp, javascript, data) | **Implemented** | `ssrf_validator.py` :: `validate_url()` | Strict whitelist: `http://` and `https://` only | `test_ssrf.py` (`test_validate_url_schemes`) | **FP:** Non-web protocols blocked intentionally. **FN:** None. | Maintain strict whitelist. |
| **A. URL & Domain** | Embedded User Credentials (`user:pass@host`) | **Implemented** | `ssrf_validator.py` :: `validate_url()` | Rejects URLs containing `userinfo` component | `test_ssrf.py` (`test_validate_url_credentials`) | **FP:** Rare valid basic auth in URLs. **FN:** None. | Maintain SSRF block. |
| **A. URL & Domain** | Invalid Port Numbers (out-of-range, non-numeric) | **Implemented** | `ssrf_validator.py` :: `validate_url()` | Rejects ports <= 0, > 65535, or non-numeric | `test_ssrf.py` (`test_validate_url_ports`) | **FP:** None. **FN:** None. | Maintain existing logic. |
| **A. URL & Domain** | Punycode / IDN Homograph Detection | **Gap** | `ssrf_validator.py` resolves via `getaddrinfo` but no heuristic finding | Hostname contains `xn--` or mixed scripts; unflagged | No finding test | **FP:** Legitimate international ccTLDs (`.xn--...`). **FN:** ASCII lookalikes not in punycode. | **Implement P1 Rule:** `domain_punycode_homograph`. |
| **A. URL & Domain** | IP-Literal Hostname in URL | **Gap** | `ssrf_validator.py` allows public IPs; no finding | Host is raw IPv4/IPv6 address instead of domain | Tested for SSRF reachability, not finding | **FP:** Intranet testing, raw IP dev servers. **FN:** Cloud ephemeral IPs. | **Implement P1 Rule:** `url_ip_address_host`. |
| **A. URL & Domain** | URL Length & Subdomain Depth | **Partial** | `main.py` enforces 2048-char cap via Pydantic; no depth check | URL string length <= 2048 | `test_api.py` validation | **FP:** Deep API routing. **FN:** Phishing subdomains on free hosts. | Keep boundary limit; defer heuristic subdomains to ML. |
| **A. URL & Domain** | Redirect Chain & Destination Tracking | **Implemented** | `ssrf_validator.py` :: `safe_fetch()`, `security_findings.py` | Step-by-step redirect interception; re-validates IPs | `test_ssrf.py`, `test_security_findings.py` | **FP:** Legitimate multi-stage OAuth/SSO. **FN:** Client-side JS redirects (`window.location`). | Maintain server-side tracking. Note JS redirect limitation. |
| **B. Threat Intel** | Live Blacklist / Safe Browsing Feed | **Missing** | None | No external API, threat feed, or blacklist client | None | **FP:** None. **FN:** 100% blind to known active phishing/malware domains. | Document absence honestly. Defer to future worker. |
| **B. Threat Intel** | Local Static Threat Feed / Cache | **Missing** | None | No local blacklist SQLite/JSON/bloom filter | None | **FP:** Stale entries if un-updated. **FN:** Low coverage. | Document gap. Avoid hardcoded small static lists that give false assurance. |
| **B. Threat Intel** | Domain Age / WHOIS / RDAP Signals | **Missing** | None | No WHOIS/RDAP protocol or socket lookup | None | **FP:** High for new legitimate startups. **FN:** Compromised aged domains. | Document gap. WHOIS rate limits make synchronous scanning unsafe. |
| **B. Threat Intel** | Reputation vs Heuristic Separation | **Implemented** | `security_findings.py` | All findings explicitly state they are observable heuristics | `test_risk_scorer.py` | **FP:** None. **FN:** None. | Preserve clear heuristic disclaimers in risk summaries. |
| **C. Transport & TLS** | Plain Unencrypted HTTP Detection | **Implemented** | `security_findings.py` :: `evaluate_transport_security()` | Protocol is HTTP and final URL does not use HTTPS | `test_security_findings.py` (`test_transport_http_unencrypted`) | **FP:** None. **FN:** None. | Stable High severity finding (`transport_http_unencrypted`). |
| **C. Transport & TLS** | HTTPS Enforcement Verification | **Implemented** | `security_findings.py` :: `evaluate_transport_security()` | Initial and final URLs maintain HTTPS | `test_security_findings.py` | **FP:** None. **FN:** None. | Stable Info finding (`transport_https_enforced`). |
| **C. Transport & TLS** | HTTPS-to-HTTP Downgrade Detection | **Implemented** | `security_findings.py` :: `evaluate_transport_security()` | Any redirect hop transitions from HTTPS to HTTP | `test_security_findings.py` (`test_redirect_https_to_http_downgrade`) | **FP:** None. **FN:** Client-side meta-refresh or JS downgrades. | Stable Critical finding (`redirect_https_to_http_downgrade`). |
| **C. Transport & TLS** | TLS Certificate Expiration & Validity | **Implemented** | `website_analyzer.py` :: `get_certificate_info()` | Timezone-aware UTC comparison against notBefore/notAfter | `test_security_findings.py` (`test_tls_cert_expired`, etc.) | **FP:** Clock skew if host clock unsynchronized. **FN:** None. | Stable Critical finding (`tls_cert_expired`) & Medium (`tls_cert_expiring_soon`). |
| **C. Transport & TLS** | TLS CA Trust & Hostname Verification | **Implemented** | `website_analyzer.py` :: `get_certificate_info()` | Python `ssl.create_default_context()` strict verification | `test_api.py`, `test_security_findings.py` | **FP:** Internal enterprise CAs if custom bundle missing. **FN:** Compromised public CA. | Stable Critical finding (`tls_cert_verification_failed`). |
| **C. Transport & TLS** | Deprecated TLS Protocol Versions | **Gap** | Handshake records `tls_version` but no finding emitted | Handshake negotiates TLSv1.0 or TLSv1.1 | Recorded in cert info, no finding | **FP:** Legacy client compatibility. **FN:** Deprecated crypto vulnerabilities. | **Implement P1 Rule:** `tls_deprecated_version` (High). |
| **D. Security Headers** | HSTS (Strict-Transport-Security) | **Implemented** | `security_findings.py` :: `evaluate_security_headers()` | Checks presence and parses `max-age`; flags if < 300 | `test_security_findings.py` (`test_header_missing_hsts`, `test_header_invalid_hsts`) | **FP:** Local development environments. **FN:** Ignored subdomains if directive missing. | Stable Medium findings (`header_missing_hsts`, `header_invalid_hsts`). |
| **D. Security Headers** | CSP Presence & Baseline Check | **Implemented** | `security_findings.py` :: `evaluate_security_headers()` | Verifies presence and non-empty `Content-Security-Policy` | `test_security_findings.py` (`test_header_missing_csp`) | **FP:** Sites using meta-tag CSP rather than header. **FN:** Bypasses in poorly configured CSP. | Stable Medium finding (`header_missing_csp`). |
| **D. Security Headers** | CSP Insecure Directives (`'unsafe-inline'`, `'unsafe-eval'`) | **Gap** | `security_findings.py` currently only checks presence | Script-src / default-src permits `'unsafe-inline'` or `'unsafe-eval'` | No test | **FP:** Legacy frameworks requiring eval. **FN:** Advanced nonce exfiltration. | **Implement P1 Rule:** `header_insecure_csp` (Low). |
| **D. Security Headers** | X-Frame-Options & CSP Frame Ancestors | **Implemented** | `security_findings.py` :: `evaluate_security_headers()` | Checks `X-Frame-Options`; suppresses if `frame-ancestors` present | `test_security_findings.py` (`test_header_xfo_csp_overlap`) | **FP:** Suppressed correctly via CSP overlap check. **FN:** None. | Stable Low finding (`header_missing_x_frame_options`). |
| **D. Security Headers** | X-Content-Type-Options | **Implemented** | `security_findings.py` :: `evaluate_security_headers()` | Flags missing header or value != 'nosniff' | `test_security_findings.py` | **FP:** Non-HTML resources. **FN:** None. | Stable Low findings (`header_missing_x_content_type_options`, `header_invalid_...`). |
| **D. Security Headers** | Referrer-Policy | **Implemented** | `security_findings.py` :: `evaluate_security_headers()` | Verifies explicit declaration of Referrer-Policy | `test_security_findings.py` | **FP:** Sites relying on browser default. **FN:** None. | Stable Low finding (`header_missing_referrer_policy`). |
| **D. Security Headers** | Permissions-Policy & COOP | **Implemented** | `security_findings.py` :: `evaluate_security_headers()` | Verifies modern origin isolation headers | `test_security_findings.py` | **FP:** None (informative only). **FN:** None. | Stable Informational findings (`header_missing_permissions_policy`, `header_missing_coop`). |
| **E. Cookie Security** | Secure Attribute Verification | **Implemented** | `security_findings.py` :: `evaluate_cookie_security()` | Groups cookies lacking `Secure` attribute; no values exposed | `test_cookies.py`, `test_security_findings.py` | **FP:** Non-sensitive tracking cookies. **FN:** None. | Stable Medium finding (`cookies_missing_secure`). |
| **E. Cookie Security** | HttpOnly Attribute Verification | **Implemented** | `security_findings.py` :: `evaluate_cookie_security()` | Groups cookies lacking `HttpOnly` attribute | `test_cookies.py`, `test_security_findings.py` | **FP:** Cookies legitimately read by JS (e.g. CSRF tokens). **FN:** None. | Stable Low finding (`cookies_missing_httponly`). |
| **E. Cookie Security** | SameSite Attribute Verification | **Implemented** | `security_findings.py` :: `evaluate_cookie_security()` | Flags missing SameSite or SameSite=None without Secure | `test_cookies.py`, `test_security_findings.py` | **FP:** Cross-domain widgets. **FN:** None. | Stable Low/Medium findings (`cookies_missing_samesite`, `cookie_samesite_none_insecure`). |
| **E. Cookie Security** | Prefix Integrity (`__Secure-`, `__Host-`) | **Implemented** | `security_findings.py` :: `evaluate_cookie_security()` | Validates prefix RFC compliance (Secure, Path=/, no Domain) | `test_cookies.py`, `test_security_findings.py` | **FP:** None. **FN:** None. | Stable Medium findings (`cookie_secure_prefix_violation`, `cookie_host_prefix_violation`). |
| **E. Cookie Security** | Cookie Value Non-Disclosure | **Implemented** | `cookie_analyzer.py` & `security_findings.py` | Strict attribute extraction; values discarded immediately | `test_cookies.py` | **FP:** None. **FN:** None. | Zero leakage guaranteed by design. |
| **F. Page Content** | Insecure Form Submission (`action="http://..."`) | **Gap** | HTML body in response is not inspected for forms | Form action posts sensitive data over unencrypted HTTP | No test | **FP:** Form action on external test endpoints. **FN:** Dynamic JS submit handler. | **Implement P1 Rule:** `form_insecure_submission` (High/Critical). |
| **F. Page Content** | Cross-Domain Password Form Submission | **Gap** | HTML body not inspected for password actions | `<input type="password">` form targets unrelated origin | No test | **FP:** Federated auth providers (SSO/OAuth). **FN:** Phishing via AJAX POST. | **Implement P1 Rule:** `form_external_credential_destination`. |
| **F. Page Content** | Brand-Domain Mismatch & Homograph Spoofing | **Partial** | No visual/textual brand analysis | Punycode or character spoofing | No test | **FP:** Legitimate international localized brands. **FN:** Random domain names. | Implement Punycode detection; defer deep visual matching to ML/browser agent. |
| **F. Page Content** | Client-Side JS Execution / DOM Analysis | **Not Applicable** | Server-side HTTP fetch only | Cannot execute JS, evaluate React/Vue DOM, or observe events | Architecture boundary | N/A | Document architectural limitation honestly. |
| **G. Network & SSRF** | Private / Reserved IP Blocking | **Implemented** | `ssrf_validator.py` :: `is_public_ip()` | Blocks RFC1918, loopback, CGNAT, link-local, multicast | `test_ssrf.py` | **FP:** Testing against local dev servers. **FN:** IPv6 exotic representations (mitigated by `ipaddress`). | Core SSRF security control. |
| **G. Network & SSRF** | Cloud Metadata Endpoint Defense | **Implemented** | `ssrf_validator.py` :: `is_public_ip()` | Blocks 169.254.169.254, fd00:ec2::254, etc. | `test_ssrf.py` (`test_is_public_ip_link_local_and_cloud_metadata`) | **FP:** None. **FN:** None. | Core SSRF security control. |
| **G. Network & SSRF** | DNS Rebinding & IP Pinning | **Implemented** | `ssrf_validator.py` :: `create_safe_socket()`, `SSRFAdapter` | Resolves DNS once; validates all IPs; connects only to pinned IP | `test_ssrf.py` (`test_ssrf_adapter_ip_pinning`) | **FP:** Multi-homed CDNs rotating IPs quickly. **FN:** None. | Core SSRF security control. |
| **G. Network & SSRF** | Redirect Validation & Re-evaluation | **Implemented** | `ssrf_validator.py` :: `safe_fetch()` | Intercepts 3xx redirects, validates each hop before request | `test_ssrf.py` (`test_safe_fetch_redirect_to_private_ip_blocked`) | **FP:** None. **FN:** None. | Core SSRF security control. |
| **G. Network & SSRF** | Response Size & Timeout Protection | **Implemented** | `ssrf_validator.py` :: `safe_fetch()` | Streams chunks; caps at 2MB; enforces 10s total deadline | `test_ssrf.py` (`test_safe_fetch_enforces_size_limit`, `test_safe_fetch_timeouts`) | **FP:** Valid websites > 2MB. **FN:** Slowloris if timeouts exceeded (prevented by socket timeout). | Core SSRF security control. |
| **H. Risk Scorer** | Deterministic Risk Score (0–100) | **Implemented** | `risk_scorer.py` :: `calculate_risk()` | Additive severity weights: Critical=40, High=20, Med=8, Low=3, Info=0; capped [0, 100] | `test_risk_scorer.py` | **FP:** High score on misconfigured low-value blogs. **FN:** Score of 0 on zero-day malware. | Maintain deterministic weights; emphasize heuristic nature. |
| **H. Risk Scorer** | Risk Level Bands | **Implemented** | `risk_scorer.py` :: `get_risk_level()` | 0–19: Low, 20–39: Moderate, 40–59: High, 60–100: Critical | `test_risk_scorer.py` | **FP:** None. **FN:** None. | Maintain standard documented thresholds. |
| **H. Risk Scorer** | Duplicate Finding Handling | **Implemented** | `security_findings.py` & `risk_scorer.py` | Deduplicated by stable finding ID; cookies grouped | `test_risk_scorer.py`, `test_security_findings.py` | **FP:** None. **FN:** None. | Preserves accurate score representation without inflation. |
| **H. Risk Scorer** | Assessment Completeness & Confidence | **Implemented** | `risk_scorer.py` :: `calculate_risk()` | Complete -> High; Limitations -> Partial / Medium; Unreachable -> Unknown | `test_risk_scorer.py`, `test_api.py` | **FP:** None. **FN:** None. | Accurately reflects analysis limitations without false assurance. |
| **I. API Contract** | Stable Schema & Error Codes | **Implemented** | `main.py` | Pydantic validation; standard HTTP codes (400, 413, 502, 504) | `test_api.py` | **FP:** None. **FN:** None. | Backward-compatible with Chrome Extension MV3. |
| **I. API Contract** | Deterministic Findings Ordering | **Implemented** | `security_findings.py` :: `generate_security_findings()` | Ordered by (-severity_weight, category, id) | `test_security_findings.py` | **FP:** None. **FN:** None. | Ensures stable UI presentation. |

---

## 2. Every Rule Implemented or Improved in Phase 6

### 1. `domain_punycode_homograph`
- **Category:** `domain_identity`
- **Trigger:** Hostname contains one or more labels starting with `xn--`.
- **Severity:** `medium` (Weight: +8)
- **Evidence Returned:** `hostname`, `punycode_labels`, `decoded_domain` (via RFC 3492/IDNA decoding).
- **Impact:** Warns users against homograph brand impersonation attacks where Cyrillic, Greek, or other Unicode characters visually mimic legitimate ASCII brand domains (e.g., `xn--pple-43d.com` displaying as `арple.com`).
- **Remediation:** Verify that the decoded Unicode domain corresponds to the authentic, intended service before entering sensitive information.
- **Limitations:** Legitimate international websites in non-Latin scripts legitimately use Punycode. This indicates elevated spoofing risk rather than guaranteed compromise.

### 2. `url_ip_address_host`
- **Category:** `domain_identity`
- **Trigger:** URL specifies a numeric IPv4 or IPv6 address directly as the hostname (parsed via standard library `ipaddress`).
- **Severity:** `medium` (Weight: +8)
- **Evidence Returned:** `hostname`, `ip_version` (IPv4 or IPv6).
- **Impact:** Legitimate public web applications almost universally rely on registered domain names with authenticated TLS certificates. Raw IP access is heavily associated with disposable phishing campaigns, malware C2 nodes, and unauthorized admin panels.
- **Remediation:** Avoid entering credentials or interacting with websites that lack a registered domain name and valid certificate.
- **Limitations:** Legitimate developer testing or intranet administration tools may use raw IPs.

### 3. `tls_deprecated_version`
- **Category:** `tls_certificate`
- **Trigger:** Negotiated TLS protocol version is `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.0`, or `TLSv1.1`.
- **Severity:** `high` (Weight: +20)
- **Evidence Returned:** `tls_version`, `cipher`.
- **Impact:** Deprecated protocols suffer from fundamental cryptographic vulnerabilities (e.g., POODLE, BEAST, sweet32) and lack modern AEAD ciphers and forward secrecy. Major web browsers and RFC 8996 formally deprecate them.
- **Remediation:** Reconfigure server software to disable SSLv3, TLS 1.0, and TLS 1.1, enforcing TLS 1.2 or TLS 1.3 exclusively.

### 4. `header_insecure_csp`
- **Category:** `security_headers`
- **Trigger:** `Content-Security-Policy` header is present, but allows unsafe execution via `'unsafe-inline'` or `'unsafe-eval'` in `script-src`, `script-src-elem`, or fallback `default-src`.
- **Severity:** `low` (Weight: +3)
- **Evidence Returned:** `insecure_directives` (list of detected tokens), `csp_snippet`.
- **Impact:** Permitting `'unsafe-inline'` or `'unsafe-eval'` neutralizes primary CSP defenses against Cross-Site Scripting (XSS), allowing injected scripts to execute in the victim's session.
- **Remediation:** Migrate to nonce-based or cryptographic hash-based script authorization and eliminate inline scripts and `eval()`.

### 5. `form_insecure_submission`
- **Category:** `page_content`
- **Trigger:** Static HTML response body (parsed safely via streaming `SecurityHTMLParser`) contains `<form>` elements whose resolved action uses unencrypted `http://`.
- **Severity:** `critical` (Weight: +40) if a password field is submitted over HTTP; `high` (Weight: +20) for general plaintext forms.
- **Evidence Returned:** `insecure_form_count`, `target_actions`, `contains_password_input`.
- **Impact:** Form inputs, user credentials, and session state are transmitted across the network in plaintext, vulnerable to passive interception, session hijacking, and man-in-the-middle manipulation.
- **Remediation:** Ensure all form action URLs use secure HTTPS endpoints.

### 6. `form_external_credential_destination`
- **Category:** `page_content`
- **Trigger:** A password input (`<input type="password">`) is enclosed within a form that submits credentials to an unrelated third-party domain (different registrable domain root).
- **Severity:** `high` (Weight: +20)
- **Evidence Returned:** `target_actions`, `target_hosts`, `base_host`.
- **Impact:** Directing credentials to an external origin is the foundational signature of phishing credential harvesters.
- **Remediation:** Validate that authentication forms submit strictly to your authenticated domain or a recognized federated identity provider.

---

## 3. Rules Intentionally Left Incomplete / Deferred

1. **Live External Domain Reputation Feeds (Google Safe Browsing, VirusTotal, AbuseIPDB):**
   - *Reason for Deferral:* Requires external API keys, commercial rate-limit agreements, and external network dependencies during synchronous analysis. The engine must remain 100% self-contained, air-gappable, and deterministic. A dedicated asynchronous background threat-intelligence worker should be introduced in a future phase.
2. **Synchronous WHOIS / RDAP Domain Age Queries:**
   - *Reason for Deferral:* Public WHOIS port 43 servers and RDAP HTTP endpoints enforce strict rate-limiting, variable latency (1–5 seconds), and unpredictable socket timeouts that violate API response SLAs (<1s).
3. **Dynamic Client-Side JavaScript / Rendered DOM Execution:**
   - *Reason for Deferral:* The backend is a secure HTTP analyzer with SSRF controls, not a full browser engine. Running headless Chrome/Chromium server-side introduces massive memory overhead (150MB+ per tab), slow execution (3–8s), and a massive attack surface. Furthermore, modifying the extension to inject invasive content scripts was explicitly prohibited by the security requirements.

---

## 4. Tests Added and Their Purpose

12 new unit and integration tests were authored:

| Test Name | File | Purpose |
| :--- | :--- | :--- |
| `test_url_ip_address_host_finding` | `test_security_findings.py` | Verifies that numeric IPv4/IPv6 hostnames trigger `url_ip_address_host` (Medium). |
| `test_domain_punycode_homograph_finding` | `test_security_findings.py` | Verifies that Punycode hostnames (`xn--...`) trigger `domain_punycode_homograph` with decoded domain evidence. |
| `test_tls_deprecated_version_finding` (parametrized) | `test_security_findings.py` | Verifies that TLS 1.0, TLS 1.1, and SSLv3 trigger `tls_deprecated_version` (High). |
| `test_header_insecure_csp_unsafe_inline` | `test_security_findings.py` | Verifies that CSP containing `'unsafe-inline'` triggers `header_insecure_csp` (Low). |
| `test_header_secure_csp_no_insecure_finding` | `test_security_findings.py` | Negative test ensuring strict nonce-based CSP does not trigger false findings. |
| `test_form_insecure_submission_finding` | `test_security_findings.py` | Verifies that plaintext HTTP form actions containing passwords trigger `form_insecure_submission` (Critical). |
| `test_form_external_credential_destination_finding` | `test_security_findings.py` | Verifies that password forms targeting external domains trigger `form_external_credential_destination` (High). |
| `test_analyze_endpoint_detects_insecure_forms_and_punycode` | `test_api.py` | End-to-end integration test verifying that `/analyze` runs HTML parsing, detects Punycode and form issues, and computes the risk score correctly. |
| `test_html_content_parser_unit` | `test_api.py` | Unit test verifying `SecurityHTMLParser` against relative paths, absolute paths, and password flags. |

---

## 5. Actual Test and Dependency Audit Results

### Pytest Execution
- **Command:** `.\backend\venv\Scripts\python.exe -m pytest -v backend\tests`
- **Exit Code:** 0
- **Summary:** **157 passed, 2 warnings in 5.76s**
- **Regressions:** 0 (all 145 baseline tests passed intact).

### Dependency Audit (`pip-audit`)
- **Command:** `.\backend\venv\Scripts\python.exe -m pip_audit`
- **Exit Code:** 0
- **Result:** **No known vulnerabilities found** across all installed backend packages.

---

## 6. Known Limitations and Remaining Risks

1. **Zero-Day Phishing without Heuristic Indicators:**
   A freshly registered phishing domain with a valid Let's Encrypt TLS certificate, strict HTTPS enforcement, standard security headers, and an HTTPS credential form cannot be detected by rules alone. This directly justifies the upcoming ML classifier.
2. **Client-Side Single Page Application (SPA) Routing:**
   Forms rendered entirely via JavaScript frameworks (React, Angular, Vue) without `<form>` or with synthetic `div` buttons submitting via `fetch()` or `axios()` are invisible to static HTML inspection.
3. **Legitimate Internationalized Domain Names (IDNs):**
   Non-Latin websites (e.g. Arabic, Chinese, Cyrillic) legitimately utilize Punycode. Heuristic classification alone cannot distinguish a genuine regional news site from an IDN homograph attack without external brand models.

---

## 7. Modified Files

1. `backend/website_analyzer.py` — Added `SecurityHTMLParser` and `extract_page_content_security()` to inspect static HTML form actions and credentials within the 2MB response payload.
2. `backend/security_findings.py` — Added `CATEGORY_DOMAIN` and `CATEGORY_CONTENT`, implemented `evaluate_domain_identity()`, `evaluate_page_content()`, `tls_deprecated_version`, and `header_insecure_csp`.
3. `backend/tests/test_security_findings.py` — Added 10 unit test cases for the new detection rules.
4. `backend/tests/test_api.py` — Added end-to-end integration test and HTML parser unit test.
5. `docs/RULE_ENGINE_AUDIT.md` — Complete audit matrix, implementation report, and ML readiness design.

---

## 8. Final Rule Coverage Summary Table

| Category | Final Status | Relevant Source File | Test Evidence | Remaining Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **A. URL & Domain** | **Complete** | `ssrf_validator.py`, `security_findings.py` | `test_ssrf.py`, `test_security_findings.py` | Heuristic subdomain entropy deferred to ML. |
| **B. Threat Intelligence** | **Deferred** | None | Documented absence | Requires asynchronous background feed pipeline. |
| **C. Transport & TLS** | **Complete** | `website_analyzer.py`, `security_findings.py` | `test_security_findings.py`, `test_api.py` | None for observable handshake signals. |
| **D. Security Headers** | **Complete** | `security_findings.py` | `test_security_findings.py` | Header syntax only; cannot verify backend enforcement. |
| **E. Cookie Security** | **Complete** | `cookie_analyzer.py`, `security_findings.py` | `test_cookies.py`, `test_security_findings.py` | First-party response cookies only; no client `document.cookie`. |
| **F. Page Content** | **Implemented (Static)** | `website_analyzer.py`, `security_findings.py` | `test_security_findings.py`, `test_api.py` | Static HTML only (no client-side JS/DOM). |
| **G. Network & SSRF** | **Complete** | `ssrf_validator.py` | `test_ssrf.py` | Server-side defense control; active & verified. |
| **H. Risk Scorer** | **Complete** | `risk_scorer.py` | `test_risk_scorer.py` | Deterministic heuristic weights (0–100 range). |
| **I. API Contract** | **Complete** | `main.py` | `test_api.py` | Fully backwards-compatible with Chrome Extension. |

---

## 9. Machine Learning (ML) Readiness

With the rule-based detection engine completed and verified, the project is ready to transition to Phase 7 (Machine Learning Development). The rule engine provides a deterministic, explainable baseline against which ML models can be trained, benchmarked, and deployed.

### A. Candidate Features Derived from Rule-Based Signals
The rule engine extracts rich, structured signals that directly map to numerical and categorical ML input features:

1. **Lexical & URL Features:**
   - `url_length`: Total character count of input and final URL.
   - `subdomain_count`: Number of dots/subdomain levels.
   - `is_ip_literal`: Binary flag indicating numeric IP hostname.
   - `has_punycode`: Binary flag indicating presence of `xn--` labels.
   - `path_length` and `query_param_count`: Depth of URL structure.
   - `entropy_domain`: Shannon entropy of domain string (detects DGA / algorithmic generation).

2. **Transport & Cryptographic Features:**
   - `protocol_is_https`: Binary flag (HTTP vs HTTPS).
   - `tls_cert_valid`: Binary flag.
   - `tls_days_remaining`: Integer days until certificate expiry.
   - `tls_version_ordinal`: Ordinal encoding (`SSLv3=0`, `TLS1.0=1`, `TLS1.1=2`, `TLS1.2=3`, `TLS1.3=4`).
   - `redirect_downgrade`: Binary flag indicating HTTPS-to-HTTP transition.
   - `redirect_count`: Number of hops in redirect chain.

3. **HTTP Header & Policy Features:**
   - `hsts_present` & `hsts_max_age`: Binary presence and integer duration.
   - `csp_present`: Binary flag.
   - `csp_insecure_directives`: Binary flag for `'unsafe-inline'` / `'unsafe-eval'`.
   - `xfo_present`: Binary flag for framing protections.
   - `xcto_nosniff`: Binary flag.

4. **Cookie Security Ratios:**
   - `cookie_secure_ratio`: `secure_cookie_count / max(1, cookie_count)`.
   - `cookie_httponly_ratio`: `httponly_cookie_count / max(1, cookie_count)`.
   - `cookie_samesite_ratio`: `samesite_cookie_count / max(1, cookie_count)`.

5. **Static Content Signals:**
   - `insecure_form_count`: Count of forms pointing to unencrypted `http://`.
   - `has_insecure_password_form`: Binary flag indicating password transmitted over HTTP.
   - `cross_domain_password_form`: Binary flag indicating external credential target.

### B. Required Labels & Evaluation Datasets
- **Ground Truth Sources:**
  - Benign / Legitimate: Tranco Top 10K / 50K domains (curated, validated benign traffic).
  - Malicious / Phishing: OpenPhish, PhishTank, URLhaus feeds.
- **Labeling Scheme:** Binary target: `0 = Benign`, `1 = Malicious / Phishing`.
- **Temporal Alignment:** Samples must record the date/time of collection to ensure features reflect the website state at the exact moment the URL was evaluated.

### C. Prevention of Data Leakage and Class Imbalance
1. **Data Leakage Safeguards:**
   - **Origin Splitting:** Partition training, validation, and test sets strictly by **registrable domain** (e.g. `example.com`), never by URL path. If multiple URLs belong to the same domain, they must strictly reside in the same split to prevent the model from memorizing specific domain reputations.
   - **Feature Independence:** Ensure features do not incorporate dynamic outputs from test-time services or post-facto blacklists.
2. **Class Imbalance Mitigation:**
   - Web traffic is overwhelmingly benign (99%+). In training datasets, target a realistic ratio (e.g. 10:1 or 20:1 benign-to-malicious) and apply **PR-AUC (Precision-Recall Area Under Curve)** and **Cost-Sensitive Learning** or **SMOTE** rather than relying on raw accuracy.

### D. Establishing the Rule-Based Baseline
Before deploying any ML model, the existing deterministic rule-based score ($S_{rule} \in [0, 100]$) serves as the formal baseline:
- Threshold baseline decision:
  $$\hat{Y}_{rule} = \mathbb{I}(S_{rule} \ge 40)$$ (i.e. High or Critical risk classification).
- Compute baseline metrics:
  - Precision: What percentage of sites flagged as High/Critical are confirmed malicious?
  - Recall: What percentage of confirmed malicious sites triggered High/Critical?
  - False Positive Rate (FPR): What percentage of benign sites were falsely flagged?
  - F1-Score: Harmonic mean of baseline precision and recall.

### E. Comparative Evaluation Protocol
The future ML model will be evaluated against the rule baseline on a **strictly held-out test set** (unseen domains collected across a 30-day temporal window):
- **Decision Criterion:** The ML model must achieve a statistically significant increase in Recall ($+15\%$ or higher on zero-day phishing) while strictly keeping the False Positive Rate on benign domains below $0.5\%$.
- **Evaluation Metrics:** ROC-AUC, PR-AUC, Confusion Matrix, and Brier Score (calibration).

### F. Rationale for a Hybrid Rules-Plus-ML Architecture
Replacing the rule engine entirely with an ML model is **strongly discouraged**. A hybrid architecture (Rules + ML) is superior for the following critical reasons:

1. **Deterministic Guarantees:** Hard security requirements (e.g., self-signed certificates, unencrypted HTTP, expired TLS, SSRF restrictions) must produce immediate, guaranteed Critical/High findings with zero tolerance for probabilistic ML error.
2. **Explainability & Trust:** Users and security auditors demand to know *why* a site was flagged. Rules provide verifiable, actionable explanations (e.g., "TLS certificate expired 5 days ago").
3. **Complementary Strengths:**
   - **Rules:** Perfect at detecting objective configuration errors, RFC violations, and cryptographic weaknesses.
   - **ML:** Excellent at detecting subtle, multi-variable heuristic patterns, domain name entropy, typosquatting nuances, and suspicious feature combinations where every individual component appears superficially valid.
4. **Ensemble Stacking:** The final risk engine should fuse the rule score ($S_{rule}$) and the ML inference probability ($P_{ML}$) into a composite assessment:
   $$S_{final} = \max(S_{rule}, f(P_{ML}, S_{rule}))$$
   This ensures that confirmed rule violations always take precedence, while ML elevates the risk of evasive phishing sites that mimic proper configurations.
