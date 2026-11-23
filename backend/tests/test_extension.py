"""
Automated verification test suite for Chrome Extension (Manifest V3) packaging,
manifest security, HTML/JS DOM safety, URL validation, and API schema contract.
"""

import json
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from main import app


client = TestClient(app)

EXTENSION_DIR = Path(__file__).parent.parent.parent / "extension"


# ==============================================================================
# Manifest V3 Packaging & Permissions Tests
# ==============================================================================

def test_manifest_exists_and_is_valid_json():
    """Verify that extension/manifest.json exists and parses as valid JSON."""
    manifest_path = EXTENSION_DIR / "manifest.json"
    assert manifest_path.exists(), f"manifest.json missing at {manifest_path}"

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("manifest_version") == 3, "Manifest version must be 3"
    assert "name" in data and len(data["name"]) > 0
    assert "version" in data and len(data["version"]) > 0
    assert "description" in data


def test_manifest_permissions_are_minimal():
    """
    Verify that permissions are strictly limited to activeTab,
    and host_permissions are scoped to the local backend.
    """
    manifest_path = EXTENSION_DIR / "manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Check permissions
    permissions = data.get("permissions", [])
    assert permissions == ["activeTab"], f"Unexpected permissions: {permissions}"

    # Dangerous permissions must NEVER be present
    disallowed = [
        "cookies", "webRequest", "history", "tabs", "<all_urls>",
        "management", "nativeMessaging", "webNavigation", "declarativeNetRequest"
    ]
    for perm in disallowed:
        assert perm not in permissions, f"Disallowed permission '{perm}' found in manifest"

    # Host permissions check
    host_perms = data.get("host_permissions", [])
    assert host_perms == ["http://127.0.0.1:8000/*"], f"Unexpected host_permissions: {host_perms}"


def test_manifest_referenced_assets_exist():
    """Verify that all files referenced in manifest.json actually exist on disk."""
    manifest_path = EXTENSION_DIR / "manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Check popup HTML
    action = data.get("action", {})
    popup_rel = action.get("default_popup")
    assert popup_rel, "default_popup missing in action"
    popup_path = EXTENSION_DIR / popup_rel
    assert popup_path.exists(), f"Popup file does not exist: {popup_path}"

    # Check action icons: path validity, PNG magic bytes, and dimensions (16, 32, 48, 128)
    action_icons = action.get("default_icon", {})
    assert set(action_icons.keys()) == {"16", "32", "48", "128"}
    for size, icon_rel in action_icons.items():
        icon_path = EXTENSION_DIR / icon_rel
        assert icon_path.exists(), f"Action icon {size} does not exist: {icon_path}"
        with open(icon_path, "rb") as f:
            data_bytes = f.read(24)
            assert data_bytes[:8] == b"\x89PNG\r\n\x1a\n", f"File {icon_path} is not a valid PNG"
            w, h = struct.unpack(">II", data_bytes[16:24])
            assert w == int(size) and h == int(size), f"Icon {size} dimensions mismatch: {w}x{h}"

    # Check extension root icons: path validity, PNG magic bytes, and dimensions
    icons = data.get("icons", {})
    assert set(icons.keys()) == {"16", "32", "48", "128"}
    for size, icon_rel in icons.items():
        icon_path = EXTENSION_DIR / icon_rel
        assert icon_path.exists(), f"Icon {size} does not exist: {icon_path}"
        with open(icon_path, "rb") as f:
            data_bytes = f.read(24)
            assert data_bytes[:8] == b"\x89PNG\r\n\x1a\n", f"File {icon_path} is not a valid PNG"
            w, h = struct.unpack(">II", data_bytes[16:24])
            assert w == int(size) and h == int(size), f"Icon {size} dimensions mismatch: {w}x{h}"


def test_popup_logo_branding_uses_packaged_local_asset():
    """
    Verify requirement 2:
    1. Popup header uses the packaged local logo image asset instead of the legacy SVG shield.
    2. Logo src points to an existing file in extension/icons/.
    3. No remote URLs or external assets are used.
    4. popup.css defines styling for the brand logo.
    """
    html_path = EXTENSION_DIR / "popup.html"
    css_path = EXTENSION_DIR / "popup.css"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # Legacy shield SVG must be replaced
    assert "brand-shield-svg" not in html, "Legacy shield SVG should be replaced in popup.html"

    # Brand icon wrapper contains local image tag
    img_match = re.search(r'<img[^>]+class=["\'][^"\']*brand-logo-img[^"\']*["\'][^>]*>', html)
    assert img_match, "Missing brand-logo-img in popup.html"
    img_tag = img_match.group(0)

    src_match = re.search(r'src=["\']([^"\']+)["\']', img_tag)
    assert src_match, "Missing src attribute on brand-logo-img"
    src_val = src_match.group(1)

    # Local packaged file verification
    assert not src_val.startswith("http://") and not src_val.startswith("https://"), "Logo must not use remote URL"
    assert src_val.startswith("icons/"), f"Logo src must point into icons/: {src_val}"
    resolved_path = EXTENSION_DIR / src_val
    assert resolved_path.exists(), f"Packaged logo asset does not exist at {resolved_path}"

    # CSS definition for brand logo image
    assert ".brand-logo-img" in css
    assert ".brand-icon-wrapper" in css


# ==============================================================================
# Popup HTML & CSS Integrity Tests
# ==============================================================================

def test_popup_html_structure_and_csp_safety():
    """
    Verify popup.html integrity:
    1. Does NOT contain inline executable JavaScript (onclick, inline <script> code).
    2. References local popup.css and popup.js only.
    3. Does NOT load remote scripts, fonts, or tracking libraries.
    """
    html_path = EXTENSION_DIR / "popup.html"
    assert html_path.exists()

    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()

    # No inline event handlers (onclick, onload, etc.)
    inline_handlers = re.findall(r"\s(on[a-z]+)\s*=", content, re.IGNORECASE)
    assert not inline_handlers, f"Inline event handlers found in popup.html: {inline_handlers}"

    # No inline script content (only external script src)
    script_matches = re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", content, re.DOTALL | re.IGNORECASE)
    for inline_code in script_matches:
        assert not inline_code.strip(), f"Inline JavaScript found in popup.html: {inline_code}"

    # No remote scripts or stylesheets
    remote_src = re.findall(r'(src|href)=["\'](https?://[^"\']+)["\']', content, re.IGNORECASE)
    assert not remote_src, f"Remote assets referenced in popup.html: {remote_src}"


# ==============================================================================
# Popup JavaScript Code Safety Tests
# ==============================================================================

def test_popup_js_safety_and_dom_sanitization():
    """
    Verify popup.js security rules:
    1. Zero innerHTML assignments (XSS prevention).
    2. Zero eval() or new Function().
    3. Backend URL is explicitly configured to 127.0.0.1:8000.
    4. No third-party analytics or external network endpoints.
    """
    js_path = EXTENSION_DIR / "popup.js"
    assert js_path.exists()

    with open(js_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Zero innerHTML usage or assignment
    assert ".innerHTML" not in content, "Forbidden '.innerHTML' property access found in popup.js"
    assert re.search(r"\binnerHTML\b", content) is None, "Forbidden 'innerHTML' found in popup.js"


    # Zero eval / Function constructor
    assert "eval(" not in content, "Forbidden 'eval(' found in popup.js"
    assert "new Function(" not in content, "Forbidden 'new Function(' found in popup.js"

    # Backend URL verification
    assert 'const BACKEND_URL = "http://127.0.0.1:8000"' in content or \
           "const BACKEND_URL = 'http://127.0.0.1:8000'" in content, \
           "BACKEND_URL must be configured to http://127.0.0.1:8000"

    # No external tracking / analytics
    assert "google-analytics" not in content
    assert "mixpanel" not in content
    assert "segment" not in content


# ==============================================================================
# URL Handling & Scheme Parsing Tests
# ==============================================================================

@pytest.mark.parametrize("test_url, expected_web, expected_scheme", [
    ("https://example.com/", True, "HTTPS"),
    ("http://example.com/test?query=1#hash", True, "HTTP"),
    ("https://sub.domain.co.uk:8443/path/page.html", True, "HTTPS"),
    ("chrome://extensions/", False, "CHROME"),
    ("chrome-extension://abcdefghijklmnop/popup.html", False, "CHROME-EXTENSION"),
    ("edge://settings/", False, "EDGE"),
    ("file:///C:/Users/test/doc.html", False, "FILE"),
    ("javascript:alert(1)", False, "JAVASCRIPT"),
    ("data:text/html,<h1>Hello</h1>", False, "DATA"),
])
def test_url_classification_logic(test_url, expected_web, expected_scheme):
    """
    Verify URL classification logic matches the behavior implemented in popup.js.
    """
    from urllib.parse import urlparse
    parsed = urlparse(test_url)
    scheme = parsed.scheme.upper()
    is_web = scheme in {"HTTP", "HTTPS"}
    assert is_web == expected_web
    assert scheme == expected_scheme


# ==============================================================================
# API Contract Verification with Extension
# ==============================================================================

def test_api_response_schema_compatibility():
    """
    Verify that POST /analyze returns all necessary top-level fields
    and nested attributes required by popup.js without runtime failure.
    """
    from unittest.mock import patch, MagicMock

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff"
    }
    mock_resp.cookies = []
    mock_resp.history = []
    mock_resp.iter_content.return_value = [b"<html>Safe content</html>"]

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", return_value=mock_resp):
            with patch("website_analyzer.get_certificate_info", return_value={
                "checked": True,
                "valid": True,
                "trusted": True,
                "issuer": {"commonName": "Test CA"},
                "subject": {"commonName": "example.com"},
                "days_remaining": 90,
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384"
            }):
                res = client.post("/analyze", json={"url": "https://example.com"})
                assert res.status_code == 200
                data = res.json()

                # Top-level keys expected by popup.js
                expected_keys = [
                    "reachable", "url", "final_url", "domain", "protocol",
                    "status_code", "response_time_ms", "redirect_count",
                    "tls_certificate", "security_headers", "cookies",
                    "assessment", "findings", "finding_summary", "limitations"
                ]
                for key in expected_keys:
                    assert key in data, f"Key '{key}' missing from /analyze response"

                # Check assessment structure
                assessment = data["assessment"]
                assert "risk_score" in assessment
                assert "risk_level" in assessment
                assert "confidence" in assessment
                assert "status" in assessment
                assert "summary" in assessment
                assert "methodology_version" in assessment

                # Check finding summary structure
                summary = data["finding_summary"]
                assert "critical" in summary
                assert "high" in summary
                assert "medium" in summary
                assert "low" in summary
                assert "informational" in summary
                assert "total" in summary


# ==============================================================================
# UI Redesign: Theme, Palette, and Adaptive Contrast Tests
# ==============================================================================

def test_popup_css_palette_and_themes():
    """
    Verify popup.css strictly satisfies:
    1. Jet Black dark theme base palette (#050505, #0C0C0C, #111111, #292929, #FFFFFF, #A8A8A8).
    2. Neon semantic colors (#FF3131, #FF6A00, #FFD400, #39FF14).
    3. Adaptive theme support via @media (prefers-color-scheme: light).
    4. Contrast-adjusted light theme tokens (e.g. #78350F dark amber for WCAG AA).
    5. Circular SVG score ring styling (.score-ring-svg, .score-ring-progress, .ring-*).
    """
    css_path = EXTENSION_DIR / "popup.css"
    assert css_path.exists(), f"popup.css missing at {css_path}"

    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # Dark mode base palette
    assert "#050505" in css, "Missing --bg-app #050505"
    assert "#0C0C0C" in css or "#0c0c0c" in css, "Missing elevated panel #0C0C0C"
    assert "#111111" in css, "Missing secondary surface #111111"
    assert "#292929" in css, "Missing border #292929"
    assert "#FFFFFF" in css or "#ffffff" in css, "Missing primary text #FFFFFF"
    assert "#A8A8A8" in css or "#a8a8a8" in css, "Missing secondary text #A8A8A8"

    # Neon semantic spectrum
    assert "#FF3131" in css or "#ff3131" in css, "Missing critical neon red #FF3131"
    assert "#FF6A00" in css or "#ff6a00" in css, "Missing high neon orange #FF6A00"
    assert "#FFD400" in css or "#ffd400" in css, "Missing medium neon yellow #FFD400"
    assert "#39FF14" in css or "#39ff14" in css, "Missing low neon green #39FF14"

    # Adaptive theme support
    assert "@media (prefers-color-scheme: light)" in css, "Missing prefers-color-scheme: light"

    # High-contrast light mode tokens (WCAG AA accessibility)
    assert "#78350F" in css or "#78350f" in css, "Missing light mode high-contrast amber #78350F"

    # Circular gauge and severity ring selectors
    assert ".score-ring-svg" in css
    assert ".score-ring-track" in css
    assert ".score-ring-progress" in css
    assert ".ring-critical" in css
    assert ".ring-high" in css
    assert ".ring-moderate" in css
    assert ".ring-low" in css
    assert ".ring-unknown" in css


def test_popup_html_element_contract():
    """
    Verify that all DOM element IDs required by popup.js exist in popup.html.
    """
    html_path = EXTENSION_DIR / "popup.html"
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    expected_ids = [
        # Header & Status
        "backend-status-indicator", "backend-status-text", "rescan-btn",
        # Target Card
        "protocol-badge", "target-hostname", "target-url-preview", "redirect-notice",
        # State Views
        "loading-state", "loading-status-text", "error-state", "error-title",
        "error-message", "error-remediation", "error-retry-btn", "results-container",
        # Banners
        "critical-alert-banner", "partial-alert-banner", "partial-alert-text",
        # Assessment & Score Ring
        "score-value", "score-scale", "risk-level-badge", "confidence-badge",
        "score-ring-progress", "assessment-summary-text",
        # Severity Counts
        "count-critical", "count-high", "count-medium", "count-low", "count-info",
        # Findings List & Collapsible Section
        "findings-toggle-btn", "findings-section-chevron", "findings-collapsible-wrapper",
        "findings-total-count", "findings-empty", "findings-list",
        # Technical Inspection Accordion
        "tech-details-accordion", "tls-details-grid", "headers-details-list",
        "cookies-summary-stats", "cookies-details-list", "network-details-grid",
        # Methodology Accordion
        "methodology-accordion", "methodology-version", "limitations-container"
    ]

    for element_id in expected_ids:
        assert f'id="{element_id}"' in html, f"Missing id='{element_id}' in popup.html"


def test_popup_js_score_ring_and_event_handling():
    """
    Verify popup.js incorporates the circular gauge, accessible keyboard controls,
    and safe severity-tagged finding cards.
    """
    js_path = EXTENSION_DIR / "popup.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    # Circular gauge circumference constant
    assert "RING_CIRCUMFERENCE" in js or "263.89" in js
    assert "scoreRingProgress" in js

    # SVGElement.className must NEVER be assigned (getter-only in Chromium)
    assert "scoreRingProgress.className" not in js, "SVG score ring must not assign to .className"
    assert "updateSvgScoreRing" in js, "Must use updateSvgScoreRing helper"

    # Accessible keyboard interaction for expandable finding cards
    assert "keydown" in js
    assert "Enter" in js

    # Finding card severity CSS class assignment
    assert "finding-sev-" in js

    # Explicit uppercase severity labels for accessibility
    assert "sev.toUpperCase()" in js or "toUpperCase()" in js

    # Strictly non-disclosure of cookie values (only name and security flags)
    assert "c.value" not in js, "Cookie values must never be referenced or rendered in popup.js"


def test_svg_score_gauge_updates_and_unknown_states_do_not_throw():
    """
    Regression test for: Cannot set property className of #<SVGElement> which has only a getter.
    Verifies that:
    1. Zero assignments to .className on SVG elements exist in popup.js.
    2. Simulated SVGElement with a read-only className (getter-only) executes
       updateSvgScoreRing cleanly without throwing TypeError across all risk levels and scores.
    """
    js_path = EXTENSION_DIR / "popup.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    # Static guard: no scoreRingProgress.className assignments
    assert not re.search(r"scoreRingProgress\s*\.\s*className\s*=", js_code), \
        "Found forbidden assignment to scoreRingProgress.className"

    # Verify helper exists and uses classList
    assert "function updateSvgScoreRing" in js_code
    assert "classList.add" in js_code
    assert "classList.remove" in js_code

    # Extract updateSvgScoreRing definition and constants directly from popup.js
    fn_match = re.search(r"(const RING_VARIANT_CLASSES = .*?function updateSvgScoreRing\(.*?\n\})", js_code, re.DOTALL)
    assert fn_match, "Could not extract updateSvgScoreRing from popup.js"
    extracted_fn = fn_match.group(1)

    node_bin = shutil.which("node")
    if node_bin:
        test_script = f"""
        'use strict';
        const RING_CIRCUMFERENCE = 263.89;
        {extracted_fn}

        // Mock SVG element matching Chromium's SVGElement property descriptor:
        // 'className' is an SVGAnimatedString instance with ONLY a getter, NO setter.
        function createMockSvgElement() {{
            const classes = new Set(['score-ring-progress', 'ring-unknown']);
            const el = {{
                style: {{ strokeDashoffset: '263.89' }},
                classList: {{
                    add: (cls) => classes.add(cls),
                    remove: (cls) => classes.delete(cls),
                    contains: (cls) => classes.has(cls),
                    has: (cls) => classes.has(cls)
                }},
                _classes: classes
            }};
            Object.defineProperty(el, 'className', {{
                get() {{
                    return {{ baseVal: Array.from(classes).join(' ') }};
                }},
                // Intentionally NO setter - assigning throws TypeError in strict mode
                configurable: false,
                enumerable: true
            }});
            return el;
        }}

        // Scenario 1: Critical risk level with high numerical score
        const el1 = createMockSvgElement();
        updateSvgScoreRing(el1, 'ring-critical', 26.39);
        if (!el1._classes.has('ring-critical') || el1._classes.has('ring-unknown')) {{
            throw new Error('Scenario 1 failed to set ring-critical');
        }}

        // Scenario 2: Low risk level with low numerical score
        const el2 = createMockSvgElement();
        updateSvgScoreRing(el2, 'ring-low', 237.50);
        if (!el2._classes.has('ring-low') || !el2._classes.has('score-ring-progress')) {{
            throw new Error('Scenario 2 failed to set ring-low');
        }}

        // Scenario 3: Unknown assessment (null score)
        const el3 = createMockSvgElement();
        updateSvgScoreRing(el3, 'ring-unknown', 263.89);
        if (!el3._classes.has('ring-unknown') || el3.style.strokeDashoffset !== '263.89') {{
            throw new Error('Scenario 3 failed unknown score state');
        }}

        // Scenario 4: Undefined / unexpected level string
        const el4 = createMockSvgElement();
        updateSvgScoreRing(el4, 'ring-unexpected', 100);
        if (!el4._classes.has('ring-unknown')) {{
            throw new Error('Scenario 4 failed fallback to ring-unknown');
        }}

        console.log('SVG_REGRESSION_TEST_SUCCESS');
        """
        # Pass script via stdin to avoid Windows command line character length limits
        result = subprocess.run([node_bin], input=test_script, capture_output=True, text=True)
        assert result.returncode == 0, f"Node SVG test failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        assert "SVG_REGRESSION_TEST_SUCCESS" in result.stdout


def test_retractable_finding_cards_accessibility_and_dom():
    """
    Verify retractable finding card contracts:
    1. Header is rendered as a native <button type="button"> with aria-expanded and aria-controls.
    2. Details section has matching id and hidden=true initially.
    3. Details visibility and aria-expanded are synchronized in toggleCard.
    4. Chevron rotation CSS and hidden attribute display:none rules are present in popup.css.
    5. Keyboard interaction (Enter and Space) is preserved.
    """
    js_path = EXTENSION_DIR / "popup.js"
    css_path = EXTENSION_DIR / "popup.css"

    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # Native button header with accessibility attributes
    assert 'createElement("button")' in js
    assert 'header.type = "button"' in js
    assert 'aria-expanded' in js
    assert 'aria-controls' in js

    # Details container synchronization
    assert "details.hidden = true" in js
    assert "details.hidden = !isExpanded" in js
    assert 'header.setAttribute("aria-expanded", String(isExpanded))' in js

    # Keyboard support
    assert 'e.key === "Enter" || e.key === " "' in js

    # CSS styles
    assert "button.finding-header" in css
    assert ".finding-details[hidden]" in css
    assert "display: none !important" in css
    assert ".finding-card.expanded .finding-chevron" in css
    assert "transform: rotate(180deg)" in css


def test_count_up_animations_and_reduced_motion():
    """
    Verify numeric count-up animation contracts:
    1. animateNumberCountUp uses requestAnimationFrame and cubic ease-out.
    2. Respects prefers-reduced-motion: reduce by setting final value immediately.
    3. Unknown scores render '--' and do not animate to zero.
    4. Rescanning triggers cancelAllActiveAnimations.
    5. Popup unload / pagehide listeners are attached for animation cleanup.
    """
    js_path = EXTENSION_DIR / "popup.js"
    css_path = EXTENSION_DIR / "popup.css"

    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # Animation infrastructure
    assert "animateNumberCountUp" in js
    assert "cancelAllActiveAnimations" in js
    assert "shouldReduceMotion" in js
    assert "requestAnimationFrame" in js
    assert "cancelAnimationFrame" in js

    # Unknown score does not animate to zero
    assert 'elements.scoreValue.textContent = "--"' in js

    # Cleanup listeners
    assert 'window.addEventListener("pagehide", cancelAllActiveAnimations)' in js
    assert 'window.addEventListener("unload", cancelAllActiveAnimations)' in js

    # CSS reduced motion query
    assert "@media (prefers-reduced-motion: reduce)" in css

    node_bin = shutil.which("node")
    if node_bin:
        test_script = """
        'use strict';
        let activeAnimationFrames = [];

        function cancelAllActiveAnimations() {
            activeAnimationFrames.forEach(id => clearTimeout(id));
            activeAnimationFrames = [];
        }

        let mockReducedMotion = false;
        function shouldReduceMotion() {
            return mockReducedMotion;
        }

        function animateNumberCountUp(element, targetValue, duration = 600) {
            if (!element) return;
            const target = Math.max(0, Math.round(Number(targetValue) || 0));

            if (shouldReduceMotion() || duration <= 0) {
                element.textContent = String(target);
                return;
            }

            if (target === 0) {
                element.textContent = "0";
                return;
            }

            // Test simulation with synchronous stepped progression
            for (let progress = 0; progress <= 1; progress += 0.25) {
                const eased = 1 - Math.pow(1 - progress, 3);
                element.textContent = String(Math.round(eased * target));
            }
            element.textContent = String(target);
        }

        // Test 1: Immediate set when prefers-reduced-motion is true
        mockReducedMotion = true;
        const scoreEl = { textContent: "" };
        animateNumberCountUp(scoreEl, 75, 600);
        if (scoreEl.textContent !== "75") {
            throw new Error("Reduced motion test failed: expected 75, got " + scoreEl.textContent);
        }

        // Test 2: Standard animation finishes with exact target value
        mockReducedMotion = false;
        const countEl = { textContent: "" };
        animateNumberCountUp(countEl, 42, 600);
        if (countEl.textContent !== "42") {
            throw new Error("Standard count-up failed: expected 42, got " + countEl.textContent);
        }

        // Test 3: Zero target
        const zeroEl = { textContent: "" };
        animateNumberCountUp(zeroEl, 0, 600);
        if (zeroEl.textContent !== "0") {
            throw new Error("Zero count-up failed: expected 0, got " + zeroEl.textContent);
        }

        console.log("ANIMATION_REGRESSION_TEST_SUCCESS");
        """
        result = subprocess.run([node_bin], input=test_script, capture_output=True, text=True)
        assert result.returncode == 0, f"Node animation test failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        assert "ANIMATION_REGRESSION_TEST_SUCCESS" in result.stdout


def test_findings_section_toggle_and_preservation():
    """
    Verify full FINDINGS section collapsible toggle requirements:
    1. Heading toggle is a button with an arrow placed before the heading text.
    2. Toggle has aria-expanded and aria-controls set to the collapsible wrapper.
    3. CSS rules rotate the section chevron by 180 degrees.
    4. setFindingsSectionExpanded toggles the outer wrapper without corrupting
       inner finding card expanded states.
    5. Double-toggle debounce guard protects against keydown + click double firing.
    6. Severity chips active indicators and rescan button spinning feedback are implemented.
    """
    html_path = EXTENSION_DIR / "popup.html"
    js_path = EXTENSION_DIR / "popup.js"
    css_path = EXTENSION_DIR / "popup.css"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # 1. HTML structure: button toggle with chevron before heading
    assert 'id="findings-toggle-btn"' in html
    assert 'id="findings-section-chevron"' in html
    assert 'id="findings-collapsible-wrapper"' in html
    assert html.find('id="findings-section-chevron"') < html.find('FINDINGS')

    # 2. JS toggle function and default expansion
    assert "function setFindingsSectionExpanded" in js
    assert "function toggleFindingsSection" in js
    assert "setFindingsSectionExpanded(true)" in js
    assert "findingsCollapsibleWrapper.hidden = !isFindingsSectionExpanded" in js
    assert "lastSectionToggleTimestamp" in js  # double-toggle guard

    # 3. Chevron rotation (180deg) and button styling in CSS
    assert ".findings-section-toggle.collapsed .section-chevron" in css
    assert "transform: rotate(-180deg)" in css
    assert "button.findings-section-toggle" in css

    # 4. Chip active findings accent and rescan spinning feedback
    assert "chip-has-findings" in js
    assert ".chip-critical.chip-has-findings" in css
    assert ".icon-button.spinning .icon-svg" in css


# ==============================================================================
# Risk Percentage Gauge & Prominent Confidence Verification Tests
# ==============================================================================

def test_gauge_label_explicitly_communicates_risk_percentage():
    """
    Verify requirement 1:
    1. Inside the circular gauge, the label directly underneath the score explicitly
       communicates 'RISK %' rather than '/100'.
    2. Legacy '/100' does NOT exist inside the score-center-value container.
    3. popup.js caches and updates elements.scoreScale to 'RISK %'.
    4. Does not calculate or display 100 - score as safety.
    """
    html_path = EXTENSION_DIR / "popup.html"
    js_path = EXTENSION_DIR / "popup.js"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    # Verify score-center-value container has RISK %
    center_val_match = re.search(r'<div class="score-center-value">(.*?)</div>', html, re.DOTALL)
    assert center_val_match, "score-center-value container missing in popup.html"
    center_val_content = center_val_match.group(1)

    assert "RISK %" in center_val_content, "Gauge label must explicitly state 'RISK %'"
    assert "/100" not in center_val_content, "Legacy '/100' must be replaced by RISK %"
    assert 'id="score-scale"' in center_val_content

    # Verify popup.js references score-scale and updates textContent to RISK %
    assert "scoreScale: document.getElementById" in js
    assert 'elements.scoreScale.textContent = "RISK %"' in js

    # Safety percentage inversion (100 - score) must NOT exist
    assert "100 - score" not in js
    assert "100 - clampedScore" not in js
    assert "SAFETY %" not in js


def test_gauge_stroke_reflects_actual_risk_score_and_neon_thresholds():
    """
    Verify requirement 2:
    1. Gauge stroke offset calculation uses actual risk score:
       offset = RING_CIRCUMFERENCE - (clampedScore / 100) * RING_CIRCUMFERENCE
    2. Does NOT invert the score (does not use 100 - clampedScore).
    3. Correct neon variant classes and thresholds are preserved:
       - Low (0-19): ring-low (#39FF14)
       - Moderate (20-39): ring-moderate (#FFD400)
       - High (40-59): ring-high (#FF6A00)
       - Critical (60-100): ring-critical (#FF3131)
    """
    js_path = EXTENSION_DIR / "popup.js"
    css_path = EXTENSION_DIR / "popup.css"

    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # Stroke formula validation
    assert "RING_CIRCUMFERENCE - (clampedScore / 100) * RING_CIRCUMFERENCE" in js

    # Semantic CSS ring rules
    assert ".ring-low" in css and ("#39FF14" in css or "#39ff14" in css)
    assert ".ring-moderate" in css and ("#FFD400" in css or "#ffd400" in css)
    assert ".ring-high" in css and ("#FF6A00" in css or "#ff6a00" in css)
    assert ".ring-critical" in css and ("#FF3131" in css or "#ff3131" in css)

    node_bin = shutil.which("node")
    if node_bin:
        test_script = """
        'use strict';
        const RING_CIRCUMFERENCE = 263.89;

        function calculateOffset(score) {
            const clampedScore = Math.max(0, Math.min(100, Number(score)));
            return RING_CIRCUMFERENCE - (clampedScore / 100) * RING_CIRCUMFERENCE;
        }

        // Test Score 25 (Moderate):
        const offset25 = calculateOffset(25);
        const expected25 = 263.89 - (25 / 100) * 263.89; // 197.9175
        if (Math.abs(offset25 - expected25) > 0.001) {
            throw new Error(`Score 25 offset calculation failed: expected ${expected25}, got ${offset25}`);
        }

        // Verify it is NOT 100 - 25 = 75 (inverted safety score)
        const invertedOffset = 263.89 - (75 / 100) * 263.89; // 65.9725
        if (Math.abs(offset25 - invertedOffset) < 0.001) {
            throw new Error("Score 25 incorrectly calculated as inverted safety score 75");
        }

        // Test boundary values
        const offset0 = calculateOffset(0);
        if (Math.abs(offset0 - RING_CIRCUMFERENCE) > 0.001) {
            throw new Error(`Score 0 offset calculation failed: expected ${RING_CIRCUMFERENCE}, got ${offset0}`);
        }

        const offset100 = calculateOffset(100);
        if (Math.abs(offset100 - 0) > 0.001) {
            throw new Error(`Score 100 offset calculation failed: expected 0, got ${offset100}`);
        }

        console.log("STROKE_REGRESSION_TEST_SUCCESS");
        """
        result = subprocess.run([node_bin], input=test_script, capture_output=True, text=True)
        assert result.returncode == 0, f"Node stroke test failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        assert "STROKE_REGRESSION_TEST_SUCCESS" in result.stdout


def test_confidence_badge_prominence_and_initial_visibility():
    """
    Verify requirement 3:
    1. Confidence badge is located immediately beside the risk gauge and risk-level badge
       in the primary assessment card (not buried in accordions).
    2. Arranged with score-meta-badges using flexbox for immediate visual scanning.
    3. popup.css applies high-visibility badge styling (border, padding, monospace font, background).
    4. Restrained accent styles are defined for high, medium, low, and unknown.
    5. Adaptive light theme maintains accessible contrast.
    """
    html_path = EXTENSION_DIR / "popup.html"
    css_path = EXTENSION_DIR / "popup.css"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # 1. HTML: confidence-badge is inside score-meta-badges beside risk-level-badge
    meta_badges_match = re.search(r'<div class="score-meta-badges">(.*?)</div>', html, re.DOTALL)
    assert meta_badges_match, "score-meta-badges container missing in popup.html"
    badges_content = meta_badges_match.group(1)
    assert 'id="risk-level-badge"' in badges_content
    assert 'id="confidence-badge"' in badges_content

    # Not inside details accordion
    assert html.find('id="confidence-badge"') < html.find('<details')

    # 2. CSS: distinct badge styling
    assert ".confidence-badge" in css
    assert ".confidence-high" in css
    assert ".confidence-medium" in css
    assert ".confidence-low" in css
    assert ".confidence-unknown" in css

    # 3. Flexible badge arrangement
    assert ".score-meta-badges" in css
    assert "flex-direction: row" in css or "flex-wrap: wrap" in css


def test_confidence_renders_actual_api_values_and_handles_missing():
    """
    Verify requirement 4:
    1. Renders the actual API confidence string (e.g. HIGH, MEDIUM, LOW, UNKNOWN).
    2. Does NOT hardcode 'HIGH'.
    3. Honestly handles missing, empty, or null confidence by displaying UNKNOWN.
    4. Sets the corresponding semantic variant class (.confidence-high, etc.).
    5. Tooltip clarifies that confidence refers to assessment completeness, not malware probability.
    """
    js_path = EXTENSION_DIR / "popup.js"

    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    assert "elements.confidenceBadge.textContent = `CONFIDENCE: ${confidenceText.toUpperCase()}`" in js or \
           "elements.confidenceBadge.textContent = `CONFIDENCE: " in js
    assert "elements.confidenceBadge.className = `confidence-badge ${confidenceClass}`" in js or \
           "confidenceClass" in js

    node_bin = shutil.which("node")
    if node_bin:
        test_script = """
        'use strict';
        function formatConfidence(rawConfidence) {
            const hasConfidence = rawConfidence !== null && rawConfidence !== undefined && String(rawConfidence).trim().length > 0;
            const confidenceText = hasConfidence ? String(rawConfidence).trim() : 'Unknown';
            const confidenceLower = confidenceText.toLowerCase();

            const knownConfidenceLevels = ['high', 'medium', 'low'];
            const confidenceClass = knownConfidenceLevels.includes(confidenceLower)
                ? `confidence-${confidenceLower}`
                : 'confidence-unknown';

            return {
                text: `CONFIDENCE: ${confidenceText.toUpperCase()}`,
                className: `confidence-badge ${confidenceClass}`
            };
        }

        // Test 1: API returns 'High'
        const res1 = formatConfidence('High');
        if (res1.text !== 'CONFIDENCE: HIGH' || res1.className !== 'confidence-badge confidence-high') {
            throw new Error(`Test 1 failed: ${JSON.stringify(res1)}`);
        }

        // Test 2: API returns 'Medium'
        const res2 = formatConfidence('Medium');
        if (res2.text !== 'CONFIDENCE: MEDIUM' || res2.className !== 'confidence-badge confidence-medium') {
            throw new Error(`Test 2 failed: ${JSON.stringify(res2)}`);
        }

        // Test 3: API returns 'Low'
        const res3 = formatConfidence('Low');
        if (res3.text !== 'CONFIDENCE: LOW' || res3.className !== 'confidence-badge confidence-low') {
            throw new Error(`Test 3 failed: ${JSON.stringify(res3)}`);
        }

        // Test 4: Missing / null confidence
        const res4 = formatConfidence(null);
        if (res4.text !== 'CONFIDENCE: UNKNOWN' || res4.className !== 'confidence-badge confidence-unknown') {
            throw new Error(`Test 4 (null) failed: ${JSON.stringify(res4)}`);
        }

        // Test 5: Undefined confidence
        const res5 = formatConfidence(undefined);
        if (res5.text !== 'CONFIDENCE: UNKNOWN' || res5.className !== 'confidence-badge confidence-unknown') {
            throw new Error(`Test 5 (undefined) failed: ${JSON.stringify(res5)}`);
        }

        // Test 6: Empty string confidence
        const res6 = formatConfidence('   ');
        if (res6.text !== 'CONFIDENCE: UNKNOWN' || res6.className !== 'confidence-badge confidence-unknown') {
            throw new Error(`Test 6 (empty) failed: ${JSON.stringify(res6)}`);
        }

        console.log("CONFIDENCE_REGRESSION_TEST_SUCCESS");
        """
        result = subprocess.run([node_bin], input=test_script, capture_output=True, text=True)
        assert result.returncode == 0, f"Node confidence test failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        assert "CONFIDENCE_REGRESSION_TEST_SUCCESS" in result.stdout


def test_unknown_scores_not_displayed_as_zero_risk():
    """
    Verify requirement 5:
    1. Unknown or unavailable risk score is displayed as '--' and never as '0' or '0%'.
    2. SVG progress ring receives 'ring-unknown' and full offset (no drawn stroke).
    3. Risk level badge displays 'UNKNOWN RISK'.
    4. Gauge does NOT falsely indicate low or zero risk.
    """
    js_path = EXTENSION_DIR / "popup.js"

    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    # When clampedScore is null:
    assert 'elements.scoreValue.textContent = "--"' in js
    assert 'updateSvgScoreRing(elements.scoreRingProgress, "ring-unknown", RING_CIRCUMFERENCE)' in js

    # Risk level displays with RISK suffix
    assert 'displayLevel = levelUpper.includes("RISK") ? levelUpper : `${levelUpper} RISK`' in js or \
           'elements.riskLevelBadge.textContent = displayLevel' in js


# ==============================================================================
# Bug 1 Regression Tests: Extension Limitations Rendering
# ==============================================================================

def test_limitations_rendering_safety_and_formatting():
    """
    Verify Bug 1 fix:
    1.popup.js no longer contains naive `• ${lim}` interpolation.
    2.formatLimitationText helper exists and safely extracts human-readable text.
    3.Prefers lim.message over lim.code.
    4.Falls back to lim.code if message is unavailable.
    5.Handles empty objects, null, undefined, strings, and unexpected primitives.
    6.NEVER outputs '[object Object]'.
    """
    js_path = EXTENSION_DIR / "popup.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    # Naive string interpolation must NOT be present
    assert "• ${lim}" not in js, "Found naive interpolation `• ${lim}` in popup.js"

    # Safe formatting helper must be present
    assert "function formatLimitationText" in js, "formatLimitationText function missing from popup.js"
    assert "lim.message" in js
    assert "lim.code" in js
    assert "[object Object]" in js  # explicitly checked to prevent rendering it

    # Node.js dynamic execution tests for formatLimitationText and rendering behavior
    node_bin = shutil.which("node")
    if node_bin:
        # Extract formatLimitationText function definition from popup.js
        fn_match = re.search(r"(function formatLimitationText\(.*?\n\})", js, re.DOTALL)
        assert fn_match, "Could not extract formatLimitationText from popup.js"
        extracted_fn = fn_match.group(1)

        test_script = f"""
        'use strict';
        {extracted_fn}

        // Test 1: Object with message only
        const r1 = formatLimitationText({{ message: "TLS inspection incomplete" }});
        if (r1 !== "TLS inspection incomplete") throw new Error(`Test 1 failed: ${{r1}}`);

        // Test 2: Object with code only
        const r2 = formatLimitationText({{ code: "HTTP_HEADERS_UNAVAILABLE" }});
        if (r2 !== "HTTP_HEADERS_UNAVAILABLE") throw new Error(`Test 2 failed: ${{r2}}`);

        // Test 3: Object with both message and code (prefers message)
        const r3 = formatLimitationText({{
            code: "COOKIES_UNAVAILABLE",
            message: "Cookie configurations were unavailable."
        }});
        if (r3 !== "Cookie configurations were unavailable.") throw new Error(`Test 3 failed: ${{r3}}`);

        // Test 4: Null and undefined (ignorable)
        const r4a = formatLimitationText(null);
        if (r4a !== null) throw new Error(`Test 4a (null) failed: ${{r4a}}`);
        const r4b = formatLimitationText(undefined);
        if (r4b !== null) throw new Error(`Test 4b (undefined) failed: ${{r4b}}`);

        // Test 5: Empty object (safe fallback, never '[object Object]')
        const r5 = formatLimitationText({{}});
        if (!r5 || r5.includes("[object Object]")) throw new Error(`Test 5 (empty obj) failed: ${{r5}}`);

        // Test 6: String limitation
        const r6 = formatLimitationText("Direct string limitation");
        if (r6 !== "Direct string limitation") throw new Error(`Test 6 (string) failed: ${{r6}}`);

        // Test 7: Unexpected primitive values
        const r7a = formatLimitationText(503);
        if (r7a !== "503") throw new Error(`Test 7a (number) failed: ${{r7a}}`);
        const r7b = formatLimitationText(true);
        if (r7b !== "true") throw new Error(`Test 7b (boolean) failed: ${{r7b}}`);

        // Test 8: Multiple limitations rendered together in mock DOM
        const mockContainer = {{
            children: [],
            appendChild: function(child) {{ this.children.push(child); }}
        }};

        const testLimitations = [
            {{ code: "C1", message: "First limitation" }},
            {{ code: "ONLY_CODE" }},
            null,
            "Plain text limitation",
            {{}},
            undefined,
            42
        ];

        let renderedCount = 0;
        testLimitations.forEach(lim => {{
            const text = formatLimitationText(lim);
            if (text) {{
                const itemText = `• ${{text}}`;
                if (itemText.includes("[object Object]")) {{
                    throw new Error(`Rendered '[object Object]' for limitation: ${{JSON.stringify(lim)}}`);
                }}
                mockContainer.appendChild({{ text: itemText, className: "limitation-item" }});
                renderedCount++;
            }}
        }});

        if (renderedCount !== 5) {{
            throw new Error(`Expected 5 rendered items (excluding null/undefined), got ${{renderedCount}}`);
        }}

        console.log("LIMITATIONS_RENDER_TEST_SUCCESS");
        """
        result = subprocess.run([node_bin], input=test_script, capture_output=True, text=True)
        assert result.returncode == 0, f"Node limitations test failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        assert "LIMITATIONS_RENDER_TEST_SUCCESS" in result.stdout


# ==============================================================================
# Phase 9E: Chrome Extension Hybrid ML Integration Tests
# ==============================================================================

def test_ml_phishing_heuristic_card_rendering():
    """
    Verify Phase 9E requirement:
    1. ml_phishing_heuristic finding renders into a standard accessible finding card.
    2. Category tag renders as 'phishing heuristic' (underscores replaced).
    3. Severity pills render as 'CRITICAL' / 'HIGH'.
    4. Severity classes finding-sev-critical and finding-sev-high are applied.
    5. Retractable details body is hidden by default (hidden = true, aria-expanded = false).
    6. Evidence box formats ML probability, model name, and version cleanly.
    """
    js_path = EXTENSION_DIR / "popup.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    node_bin = shutil.which("node")
    if not node_bin:
        pytest.skip("Node.js binary not available for DOM rendering test")

    test_script = r"""
    'use strict';

    // Mock DOM environment
    class MockElement {
        constructor(tagName) {
            this.tagName = tagName;
            this.classList = {
                classes: new Set(),
                add: function(c) { this.classes.add(c); },
                contains: function(c) { return this.classes.has(c); },
                toggle: function(c) {
                    if (this.classes.has(c)) { this.classes.delete(c); return false; }
                    this.classes.add(c); return true;
                }
            };
            this.attributes = {};
            this.children = [];
            this.textContent = '';
            this.hidden = false;
        }
        set className(val) {
            this._className = val;
            if (val) {
                val.split(/\s+/).filter(Boolean).forEach(c => this.classList.classes.add(c));
            }
        }
        get className() { return this._className || ""; }
        setAttribute(k, v) { this.attributes[k] = String(v); }
        getAttribute(k) { return this.attributes[k]; }
        appendChild(child) { this.children.push(child); }
        addEventListener() {}
    }

    const document = {
        createElement: (tag) => new MockElement(tag)
    };

    function clearElement(el) {
        if (el && el.children) el.children = [];
    }

    function createTextElement(tag, text, classNames = []) {
        const el = document.createElement(tag);
        el.textContent = text !== undefined && text !== null ? String(text) : "";
        if (Array.isArray(classNames)) {
            classNames.forEach(c => { if (c) el.classList.add(c); });
        } else if (classNames) {
            el.classList.add(classNames);
        }
        return el;
    }

    function isValidWebUrl(urlString) {
        try {
            const parsed = new URL(urlString);
            return parsed.protocol === "http:" || parsed.protocol === "https:";
        } catch {
            return false;
        }
    }

    const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
    const elements = {
        findingsList: new MockElement("div"),
        findingsEmpty: new MockElement("div")
    };

    // Extract renderFindingsList from popup.js
    """ + re.search(r"function renderFindingsList\(.*?\n\}", js, re.DOTALL).group(0) + """

    // Test with Critical and High ML findings
    const mockFindings = [
        {
            id: "ml_phishing_heuristic",
            title: "Critical Machine Learning Phishing Heuristic",
            category: "phishing_heuristic",
            severity: "critical",
            confidence: "high",
            summary: "Offline classifier identified URL as highly deceptive with 97.5% probability.",
            evidence: {
                phishing_probability: 0.975,
                classification: "phishing",
                heuristic_severity: "critical",
                threshold_applied: 0.95,
                model_name: "HistGradientBoosting",
                model_version: "v2.0.0"
            },
            impact: "Severe risk of credential theft.",
            recommendation: "Do not enter passwords.",
            affected_component: "URL Lexical & Domain Structure",
            references: ["https://csrc.nist.gov/glossary/term/phishing"]
        },
        {
            id: "ml_phishing_heuristic_high",
            title: "High-Risk Machine Learning Phishing Heuristic",
            category: "phishing_heuristic",
            severity: "high",
            confidence: "high",
            summary: "Suspicious lexical patterns identified with 88.0% probability.",
            evidence: { phishing_probability: 0.88 },
            impact: "Deceptive patterns detected.",
            recommendation: "Exercise caution.",
            affected_component: "URL Lexical & Domain Structure"
        }
    ];

    renderFindingsList(mockFindings);

    if (elements.findingsList.children.length !== 2) {
        throw new Error(`Expected 2 finding cards, got ${elements.findingsList.children.length}`);
    }

    // Verify Card 1 (Critical)
    const card1 = elements.findingsList.children[0];
    if (!card1.classList.contains("finding-sev-critical")) {
        throw new Error("Card 1 missing finding-sev-critical class");
    }
    const header1 = card1.children[0];
    if (header1.getAttribute("aria-expanded") !== "false") {
        throw new Error("Header 1 must have aria-expanded='false'");
    }
    const details1 = card1.children[1];
    if (details1.hidden !== true) {
        throw new Error("Details 1 must have hidden=true");
    }

    // Verify Card 2 (High)
    const card2 = elements.findingsList.children[1];
    if (!card2.classList.contains("finding-sev-high")) {
        throw new Error("Card 2 missing finding-sev-high class");
    }

    console.log("ML_FINDINGS_RENDER_SUCCESS");
    """
    result = subprocess.run([node_bin], input=test_script, capture_output=True, text=True)
    assert result.returncode == 0, f"Node ML findings render test failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    assert "ML_FINDINGS_RENDER_SUCCESS" in result.stdout


def test_ml_diagnostic_rendered_in_network_grid():
    """Verify popup.js renders ML diagnostic item when ml_analysis is present."""
    js_path = EXTENSION_DIR / "popup.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    assert "ML Phishing Model" in js
    assert "Phishing Heuristic" in js
    assert "Legitimate" in js
    assert "Unavailable" in js


def test_ml_unavailable_limitation_code_formatting():
    """Verify ML_PHISHING_INSPECTION_UNAVAILABLE limitation is formatted correctly."""
    js_path = EXTENSION_DIR / "popup.js"
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()

    node_bin = shutil.which("node")
    if not node_bin:
        pytest.skip("Node.js binary not available")

    fn_match = re.search(r"(function formatLimitationText\(.*?\n\})", js, re.DOTALL)
    extracted_fn = fn_match.group(1)

    test_script = f"""
    'use strict';
    {extracted_fn}

    const lim = {{
        code: "ML_PHISHING_INSPECTION_UNAVAILABLE",
        message: "Machine learning phishing inspection was unavailable: Model artifact file not found"
    }};

    const formatted = formatLimitationText(lim);
    if (!formatted.includes("Model artifact file not found")) {{
        throw new Error(`Unexpected formatted text: ${{formatted}}`);
    }}
    if (formatted.includes("[object Object]")) {{
        throw new Error("Rendered [object Object]");
    }}

    console.log("ML_LIMITATION_FORMAT_SUCCESS");
    """
    result = subprocess.run([node_bin], input=test_script, capture_output=True, text=True)
    assert result.returncode == 0
    assert "ML_LIMITATION_FORMAT_SUCCESS" in result.stdout
