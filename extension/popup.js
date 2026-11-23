/**
 * Website Security & Cookie Analyzer - Chrome Extension (Manifest V3)
 *
 * Interacts with the local FastAPI backend to inspect websites for transport security,
 * TLS certificates, HTTP security headers, and cookie configurations.
 *
 * Strict Security & Privacy Principles:
 * 1. Safe DOM: Zero raw HTML injections. All dynamic text uses textContent.
 * 2. Privacy: Zero cookie values displayed, logged, or stored.
 * 3. Minimal permissions: No tabs/history/cookies permissions requested.
 * 4. Resilient: Graceful handling of backend offline, timeouts, SSRF blocks, and partial results.
 */

"use strict";

// =============================================================================
// Configuration Constants
// =============================================================================

const BACKEND_URL = "http://127.0.0.1:8000";
const CLIENT_TIMEOUT_MS = 15000;
const RING_CIRCUMFERENCE = 263.89; // 2 * Math.PI * 42 for r=42 SVG circle

// Severity rankings for sorting
const SEVERITY_ORDER = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0
};

// =============================================================================
// State Management
// =============================================================================

let isAnalyzing = false;
let currentTabUrl = null;
let currentAbortController = null;

// =============================================================================
// DOM Elements Cache
// =============================================================================

const elements = {
  // Header
  backendStatusIndicator: document.getElementById("backend-status-indicator"),
  backendStatusText: document.getElementById("backend-status-text"),
  rescanBtn: document.getElementById("rescan-btn"),

  // Target Card
  protocolBadge: document.getElementById("protocol-badge"),
  targetHostname: document.getElementById("target-hostname"),
  targetUrlPreview: document.getElementById("target-url-preview"),
  redirectNotice: document.getElementById("redirect-notice"),

  // States
  loadingState: document.getElementById("loading-state"),
  loadingStatusText: document.getElementById("loading-status-text"),
  errorState: document.getElementById("error-state"),
  errorTitle: document.getElementById("error-title"),
  errorMessage: document.getElementById("error-message"),
  errorRemediation: document.getElementById("error-remediation"),
  errorRetryBtn: document.getElementById("error-retry-btn"),
  resultsContainer: document.getElementById("results-container"),

  // Banners
  criticalAlertBanner: document.getElementById("critical-alert-banner"),
  partialAlertBanner: document.getElementById("partial-alert-banner"),
  partialAlertText: document.getElementById("partial-alert-text"),

  // Assessment Card
  scoreValue: document.getElementById("score-value"),
  scoreScale: document.getElementById("score-scale"),
  riskLevelBadge: document.getElementById("risk-level-badge"),
  confidenceBadge: document.getElementById("confidence-badge"),
  scoreRingProgress: document.getElementById("score-ring-progress"),
  scoreMeter: document.getElementById("score-meter"),
  scoreMeterFill: document.getElementById("score-meter-fill"),
  assessmentSummaryText: document.getElementById("assessment-summary-text"),

  // Overview Counts
  countCritical: document.getElementById("count-critical"),
  countHigh: document.getElementById("count-high"),
  countMedium: document.getElementById("count-medium"),
  countLow: document.getElementById("count-low"),
  countInfo: document.getElementById("count-info"),

  // Findings
  findingsSection: document.querySelector(".findings-section"),
  findingsToggleBtn: document.getElementById("findings-toggle-btn"),
  findingsSectionChevron: document.getElementById("findings-section-chevron"),
  findingsCollapsibleWrapper: document.getElementById("findings-collapsible-wrapper"),
  findingsTotalCount: document.getElementById("findings-total-count"),
  findingsEmpty: document.getElementById("findings-empty"),
  findingsList: document.getElementById("findings-list"),

  // Tech Details
  tlsDetailsGrid: document.getElementById("tls-details-grid"),
  headersDetailsList: document.getElementById("headers-details-list"),
  cookiesSummaryStats: document.getElementById("cookies-summary-stats"),
  cookiesDetailsList: document.getElementById("cookies-details-list"),
  networkDetailsGrid: document.getElementById("network-details-grid"),

  // Limitations & Methodology
  methodologyVersion: document.getElementById("methodology-version"),
  limitationsContainer: document.getElementById("limitations-container")
};

// =============================================================================
// Helper Functions (DOM & Sanitization)
// =============================================================================

/**
 * Safely create a text element with classes.
 */
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

/**
 * Validate that a URL is a legitimate HTTP or HTTPS link before making it clickable.
 */
function isValidWebUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Clear all child nodes of a DOM element safely.
 */
function clearElement(element) {
  while (element && element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

/**
 * Safely update an SVG element's class list and stroke dashoffset.
 * In Chromium, SVGElement.className is an SVGAnimatedString with only a getter.
 * Directly assigning to .className throws TypeError in strict mode.
 * We safely manage classes using classList.remove and classList.add.
 */
const RING_VARIANT_CLASSES = ["ring-low", "ring-moderate", "ring-high", "ring-critical", "ring-unknown"];

function updateSvgScoreRing(svgCircleElement, targetVariantClass, offset) {
  if (!svgCircleElement || !svgCircleElement.classList) return;

  const numericOffset = typeof offset === "number" ? offset : parseFloat(offset);
  svgCircleElement.style.strokeDashoffset = !isNaN(numericOffset)
    ? numericOffset.toFixed(2)
    : String(RING_CIRCUMFERENCE);

  // Cleanly strip existing variant classes via classList
  RING_VARIANT_CLASSES.forEach(cls => svgCircleElement.classList.remove(cls));

  // Ensure base SVG class is present and add designated variant
  svgCircleElement.classList.add("score-ring-progress");
  if (targetVariantClass && RING_VARIANT_CLASSES.includes(targetVariantClass)) {
    svgCircleElement.classList.add(targetVariantClass);
  } else {
    svgCircleElement.classList.add("ring-unknown");
  }
}

// =============================================================================
// Count-Up Animation System
// =============================================================================

let activeAnimationFrames = [];

/**
 * Cancel any ongoing requestAnimationFrame count-up loops.
 */
function cancelAllActiveAnimations() {
  if (activeAnimationFrames.length > 0) {
    activeAnimationFrames.forEach(frameId => {
      if (typeof cancelAnimationFrame === "function") {
        cancelAnimationFrame(frameId);
      }
    });
    activeAnimationFrames = [];
  }
}

/**
 * Check if the user has requested reduced motion at OS or browser level.
 */
function shouldReduceMotion() {
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    try {
      return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Animate a numeric DOM text element smoothly from 0 to its target value.
 * Uses cubic ease-out over a short duration (500-700ms).
 * Strictly guarantees accurate final values and clean cancellation.
 */
function animateNumberCountUp(element, targetValue, duration = 650) {
  if (!element) return;
  const target = Math.max(0, Math.round(Number(targetValue) || 0));

  // If reduced motion is requested or target is already 0, set immediately
  if (shouldReduceMotion() || duration <= 0) {
    element.textContent = String(target);
    return;
  }

  if (target === 0) {
    element.textContent = "0";
    return;
  }

  const startTime = (typeof performance !== "undefined" && performance.now)
    ? performance.now()
    : Date.now();

  element.textContent = "0";

  function frame(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Cubic ease-out curve: 1 - (1 - progress)^3
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(eased * target);

    element.textContent = String(current);

    if (progress < 1) {
      if (typeof requestAnimationFrame === "function") {
        const id = requestAnimationFrame(frame);
        activeAnimationFrames.push(id);
      } else {
        element.textContent = String(target);
      }
    } else {
      element.textContent = String(target); // Guaranteed accurate final value
    }
  }

  if (typeof requestAnimationFrame === "function") {
    const id = requestAnimationFrame(frame);
    activeAnimationFrames.push(id);
  } else {
    element.textContent = String(target);
  }
}

// =============================================================================
// Findings Section Collapsible State
// =============================================================================

let isFindingsSectionExpanded = true;
let lastSectionToggleTimestamp = 0;

function setFindingsSectionExpanded(expanded) {
  isFindingsSectionExpanded = Boolean(expanded);
  if (elements.findingsToggleBtn) {
    elements.findingsToggleBtn.setAttribute("aria-expanded", String(isFindingsSectionExpanded));
    if (isFindingsSectionExpanded) {
      elements.findingsToggleBtn.classList.remove("collapsed");
    } else {
      elements.findingsToggleBtn.classList.add("collapsed");
    }
  }
  if (elements.findingsCollapsibleWrapper) {
    elements.findingsCollapsibleWrapper.hidden = !isFindingsSectionExpanded;
  }
}

function toggleFindingsSection() {
  const now = Date.now();
  if (now - lastSectionToggleTimestamp < 60) return; // Prevent double toggling from keydown + click
  lastSectionToggleTimestamp = now;
  setFindingsSectionExpanded(!isFindingsSectionExpanded);
}

// =============================================================================
// Backend Status Checker
// =============================================================================

async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${BACKEND_URL}/health`, {
      method: "GET",
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      setBackendStatus(true);
      return true;
    } else {
      setBackendStatus(false);
      return false;
    }
  } catch {
    setBackendStatus(false);
    return false;
  }
}

function setBackendStatus(isOnline) {
  if (isOnline) {
    elements.backendStatusIndicator.className = "status-indicator status-online";
    elements.backendStatusText.textContent = "Online";
    elements.backendStatusIndicator.title = "Local analyzer connected at 127.0.0.1:8000";
  } else {
    elements.backendStatusIndicator.className = "status-indicator status-offline";
    elements.backendStatusText.textContent = "Offline";
    elements.backendStatusIndicator.title = "Local analyzer not reachable at 127.0.0.1:8000";
  }
}

// =============================================================================
// Active Tab Detection & URL Validation
// =============================================================================

async function getActiveTabUrl() {
  if (!chrome.tabs || !chrome.tabs.query) {
    throw new Error("Chrome Tabs API is unavailable.");
  }

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs || tabs.length === 0 || !tabs[0].url) {
    return null;
  }

  return tabs[0].url;
}

function parseAndValidateUrl(rawUrl) {
  if (!rawUrl) {
    return {
      valid: false,
      isWebScheme: false,
      reason: "No active webpage detected."
    };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      valid: false,
      isWebScheme: false,
      reason: "Invalid or malformed URL."
    };
  }

  const isWebScheme = parsed.protocol === "http:" || parsed.protocol === "https:";
  return {
    valid: true,
    isWebScheme: isWebScheme,
    protocol: parsed.protocol.replace(":", "").toUpperCase(),
    hostname: parsed.hostname,
    fullUrl: rawUrl,
    displayPath: parsed.pathname + parsed.search
  };
}

// =============================================================================
// UI State Switchers
// =============================================================================

function showLoadingState(message = "Analyzing website security...") {
  cancelAllActiveAnimations();
  if (elements.rescanBtn) elements.rescanBtn.classList.add("spinning");
  elements.loadingState.classList.remove("hidden");
  elements.errorState.classList.add("hidden");
  elements.resultsContainer.classList.add("hidden");
  elements.loadingStatusText.textContent = message;
  elements.rescanBtn.disabled = true;
}

function showErrorState(title, message, remediation = null) {
  cancelAllActiveAnimations();
  if (elements.rescanBtn) elements.rescanBtn.classList.remove("spinning");
  elements.loadingState.classList.add("hidden");
  elements.errorState.classList.remove("hidden");
  elements.resultsContainer.classList.add("hidden");

  elements.errorTitle.textContent = title;
  elements.errorMessage.textContent = message;

  if (remediation) {
    elements.errorRemediation.textContent = remediation;
    elements.errorRemediation.classList.remove("hidden");
  } else {
    elements.errorRemediation.classList.add("hidden");
  }

  elements.rescanBtn.disabled = false;
}

function showResultsState() {
  elements.loadingState.classList.add("hidden");
  elements.errorState.classList.add("hidden");
  elements.resultsContainer.classList.remove("hidden");
  elements.rescanBtn.disabled = false;
}

// =============================================================================
// API Service & Core Scan Workflow
// =============================================================================

async function analyzeCurrentWebsite() {
  if (isAnalyzing) return;

  cancelAllActiveAnimations();

  if (currentAbortController) {
    currentAbortController.abort();
  }
  currentAbortController = new AbortController();

  isAnalyzing = true;
  showLoadingState("Detecting active tab URL...");

  try {
    const rawUrl = await getActiveTabUrl();
    const urlInfo = parseAndValidateUrl(rawUrl);

    if (!urlInfo.valid) {
      showErrorState(
        "No Active Website",
        urlInfo.reason || "Unable to determine the URL of the current tab.",
        "Please open a website in Chrome and try scanning again."
      );
      isAnalyzing = false;
      return;
    }

    // Update target banner
    updateTargetBanner(urlInfo);

    // Unsupported scheme check (e.g. chrome://, file://, data:)
    if (!urlInfo.isWebScheme) {
      showErrorState(
        "Unsupported URL Scheme",
        `Cannot analyze ${urlInfo.protocol || "internal"} URLs. Only standard HTTP and HTTPS websites are supported.`,
        "Navigate to a public website (e.g. https://example.com) to perform a security analysis."
      );
      isAnalyzing = false;
      return;
    }

    currentTabUrl = urlInfo.fullUrl;
    showLoadingState(`Sending ${urlInfo.hostname} to local analyzer...`);

    // Check backend health concurrently
    checkBackendHealth();

    // Call POST /analyze
    const analysisData = await executeApiAnalyze(currentTabUrl, currentAbortController.signal);
    renderAnalysisResults(analysisData);
    setBackendStatus(true);
    showResultsState();

  } catch (err) {
    handleScanError(err);
  } finally {
    isAnalyzing = false;
    elements.rescanBtn.disabled = false;
    if (elements.rescanBtn) elements.rescanBtn.classList.remove("spinning");
  }
}

async function executeApiAnalyze(targetUrl, signal) {
  const timeoutId = setTimeout(() => {
    if (currentAbortController) {
      currentAbortController.abort("CLIENT_TIMEOUT");
    }
  }, CLIENT_TIMEOUT_MS);

  let response;
  try {
    response = await fetch(`${BACKEND_URL}/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: targetUrl }),
      signal: signal
    });
  } catch (fetchErr) {
    clearTimeout(timeoutId);
    if (fetchErr.name === "AbortError") {
      throw new Error("CLIENT_TIMEOUT");
    }
    throw new Error("BACKEND_CONNECTION_FAILED");
  }

  clearTimeout(timeoutId);

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("INVALID_JSON_RESPONSE");
  }

  if (!response.ok) {
    const errorInfo = (data && data.error) || {};
    const errorCode = errorInfo.code || `HTTP_${response.status}`;
    const errorMessage = errorInfo.message || "The analyzer backend rejected or failed this request.";
    const err = new Error(errorMessage);
    err.code = errorCode;
    err.status = response.status;
    err.details = data;
    throw err;
  }

  return data;
}

function handleScanError(err) {
  setBackendStatus(false);

  if (err.message === "CLIENT_TIMEOUT" || err.code === "TIMEOUT") {
    showErrorState(
      "Request Timed Out",
      "The security analysis exceeded the timeout limit (15 seconds). The target website may be slow or unresponsive.",
      "Check your internet connection or click 'Retry Connection' to scan again."
    );
  } else if (err.message === "BACKEND_CONNECTION_FAILED") {
    showErrorState(
      "Local Analyzer Unavailable",
      "Could not connect to the backend API at http://127.0.0.1:8000.",
      "Start the FastAPI backend in PowerShell:\ncd backend\n.\\venv\\Scripts\\python.exe -m uvicorn main:app --reload"
    );
  } else if (err.code === "RESTRICTED_IP_ADDRESS" || err.code === "SSRF_BLOCKED") {
    showErrorState(
      "Restricted Target Blocked",
      "The URL resolves to a private, loopback, link-local, or cloud metadata address. Internal targets are blocked by SSRF protections.",
      "The security analyzer only permits external, public IP addresses."
    );
  } else if (err.code === "INVALID_URL") {
    showErrorState(
      "Invalid Target URL",
      err.message || "The requested URL contains embedded credentials, an invalid port, or unsupported formatting.",
      "Please provide a standard public HTTP or HTTPS web address."
    );
  } else if (err.code === "DNS_RESOLUTION_FAILED" || err.code === "WEBSITE_UNREACHABLE") {
    showErrorState(
      "Website Unreachable",
      "The target domain could not be resolved or the website refused the connection.",
      "Verify that the website domain exists and is accessible from your network."
    );
  } else if (err.code === "RESPONSE_TOO_LARGE") {
    showErrorState(
      "Response Limit Exceeded",
      "The target website sent a response exceeding the 2 MB streaming safety threshold.",
      "Large payloads are terminated to prevent memory exhaustion."
    );
  } else if (err.code === "REDIRECT_LOOP_DETECTED" || err.code === "REDIRECT_LIMIT_EXCEEDED") {
    showErrorState(
      "Redirect Error",
      err.message || "The website encountered an excessive redirect chain or circular redirect loop.",
      "Verify the website's redirect configuration."
    );
  } else {
    showErrorState(
      "Analysis Error",
      err.message || "An unexpected error occurred during website analysis.",
      "Verify the local backend is running cleanly without exceptions."
    );
  }
}

// =============================================================================
// Rendering Engine (Safe DOM)
// =============================================================================

function updateTargetBanner(urlInfo) {
  elements.targetHostname.textContent = urlInfo.hostname || "Unknown Host";
  elements.targetUrlPreview.textContent = urlInfo.fullUrl || "";

  if (urlInfo.protocol === "HTTPS") {
    elements.protocolBadge.textContent = "HTTPS";
    elements.protocolBadge.className = "protocol-badge protocol-https";
  } else if (urlInfo.protocol === "HTTP") {
    elements.protocolBadge.textContent = "HTTP";
    elements.protocolBadge.className = "protocol-badge protocol-http";
  } else {
    elements.protocolBadge.textContent = urlInfo.protocol || "...";
    elements.protocolBadge.className = "protocol-badge protocol-unknown";
  }
}

function renderAnalysisResults(data) {
  // Cancel previous animation frames if any were in flight
  cancelAllActiveAnimations();

  // 1. Redirect distinction
  if (data.final_url && data.url && data.final_url !== data.url) {
    elements.redirectNotice.textContent = `Redirected to: ${data.final_url}`;
    elements.redirectNotice.classList.remove("hidden");
  } else {
    elements.redirectNotice.classList.add("hidden");
  }

  // 2. Assessment card
  const assessment = data.assessment || {};
  const status = assessment.status || "unknown";
  const riskScore = assessment.risk_score;
  const riskLevel = assessment.risk_level || "Unknown";
  const confidence = assessment.confidence || "Unknown";
  const summary = assessment.summary || "No assessment summary available.";

  // Render Score & Circular SVG Gauge with count-up animation
  const levelLower = riskLevel.toLowerCase();
  const clampedScore = (riskScore !== null && riskScore !== undefined)
    ? Math.max(0, Math.min(100, Number(riskScore)))
    : null;

  if (clampedScore !== null) {
    animateNumberCountUp(elements.scoreValue, clampedScore, 650);
    if (elements.scoreRingProgress) {
      const offset = RING_CIRCUMFERENCE - (clampedScore / 100) * RING_CIRCUMFERENCE;
      updateSvgScoreRing(elements.scoreRingProgress, `ring-${levelLower}`, offset);
    }
  } else {
    elements.scoreValue.textContent = "--";
    if (elements.scoreRingProgress) {
      updateSvgScoreRing(elements.scoreRingProgress, "ring-unknown", RING_CIRCUMFERENCE);
    }
  }

  if (elements.scoreScale) {
    elements.scoreScale.textContent = "RISK %";
  }

  // Gracefully handle legacy meter if present
  if (elements.scoreMeter) {
    elements.scoreMeter.setAttribute("aria-valuenow", clampedScore !== null ? String(clampedScore) : "0");
  }
  if (elements.scoreMeterFill) {
    elements.scoreMeterFill.style.width = clampedScore !== null ? `${clampedScore}%` : "0%";
    elements.scoreMeterFill.className = `score-meter-fill meter-${levelLower}`;
  }

  // Risk Level Badge & Metadata
  const levelUpper = riskLevel.toUpperCase();
  const displayLevel = levelUpper.includes("RISK") ? levelUpper : `${levelUpper} RISK`;
  elements.riskLevelBadge.textContent = displayLevel;
  elements.riskLevelBadge.className = `risk-badge risk-${levelLower}`;

  // Update SVG gauge accessibility label
  if (elements.scoreRingProgress && elements.scoreRingProgress.parentElement) {
    const gaugeSvg = elements.scoreRingProgress.parentElement;
    if (clampedScore !== null) {
      gaugeSvg.setAttribute("aria-label", `Risk Assessment: ${clampedScore}% (${displayLevel})`);
    } else {
      gaugeSvg.setAttribute("aria-label", "Risk Assessment: Unknown Risk");
    }
  }

  // Confidence Badge (high-visibility, distinct styling, honest missing/unknown handling)
  const rawConfidence = assessment.confidence;
  const hasConfidence = rawConfidence !== null && rawConfidence !== undefined && String(rawConfidence).trim().length > 0;
  const confidenceText = hasConfidence ? String(rawConfidence).trim() : "Unknown";
  const confidenceLower = confidenceText.toLowerCase();

  const knownConfidenceLevels = ["high", "medium", "low"];
  const confidenceClass = knownConfidenceLevels.includes(confidenceLower)
    ? `confidence-${confidenceLower}`
    : "confidence-unknown";

  elements.confidenceBadge.textContent = `CONFIDENCE: ${confidenceText.toUpperCase()}`;
  elements.confidenceBadge.className = `confidence-badge ${confidenceClass}`;
  elements.confidenceBadge.setAttribute(
    "title",
    "Confidence in the heuristic security assessment based on completed checks and available data"
  );
  elements.assessmentSummaryText.textContent = summary;

  // 3. Findings & Critical Alerts
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const limitations = Array.isArray(data.limitations) ? data.limitations : [];

  // Default behavior: show findings section expanded after completed scan
  setFindingsSectionExpanded(true);

  // Check for critical findings
  const hasCritical = findings.some(f => (f.severity || "").toLowerCase() === "critical");
  if (hasCritical) {
    elements.criticalAlertBanner.classList.remove("hidden");
  } else {
    elements.criticalAlertBanner.classList.add("hidden");
  }

  // Check for partial assessment / limitations
  if (status === "partial" || limitations.length > 0) {
    elements.partialAlertBanner.classList.remove("hidden");
    if (limitations.length > 0) {
      elements.partialAlertText.textContent = `${limitations.length} check limitation(s) noted. See Technical Details below.`;
    } else {
      elements.partialAlertText.textContent = "Some checks were incomplete or limited.";
    }
  } else {
    elements.partialAlertBanner.classList.add("hidden");
  }

  // 4. Severity Summary Counts
  renderOverviewCounts(data.finding_summary, findings);

  // 5. Findings List
  renderFindingsList(findings);

  // 6. Technical Details Accordion
  renderTechnicalDetails(data);

  // 7. Methodology & Limitations
  renderMethodologyAndLimitations(assessment, limitations);
}

function renderOverviewCounts(backendSummary, findings) {
  // Derive counts safely from findings if backend summary is absent
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0
  };

  if (backendSummary && typeof backendSummary === "object") {
    counts.critical = Number(backendSummary.critical) || 0;
    counts.high = Number(backendSummary.high) || 0;
    counts.medium = Number(backendSummary.medium) || 0;
    counts.low = Number(backendSummary.low) || 0;
    counts.informational = Number(backendSummary.informational) || 0;
  } else {
    findings.forEach(f => {
      const sev = (f.severity || "").toLowerCase();
      if (counts[sev] !== undefined) {
        counts[sev]++;
      }
    });
  }

  animateNumberCountUp(elements.countCritical, counts.critical, 600);
  animateNumberCountUp(elements.countHigh, counts.high, 600);
  animateNumberCountUp(elements.countMedium, counts.medium, 600);
  animateNumberCountUp(elements.countLow, counts.low, 600);
  animateNumberCountUp(elements.countInfo, counts.informational, 600);

  const total = counts.critical + counts.high + counts.medium + counts.low + counts.informational;
  animateNumberCountUp(elements.findingsTotalCount, total, 600);

  // Restrained neon accent indication for chips with active findings
  const chipCrit = document.querySelector(".chip-critical");
  const chipHigh = document.querySelector(".chip-high");
  const chipMed = document.querySelector(".chip-medium");
  const chipLow = document.querySelector(".chip-low");
  const chipInfo = document.querySelector(".chip-info");

  if (chipCrit) chipCrit.classList.toggle("chip-has-findings", counts.critical > 0);
  if (chipHigh) chipHigh.classList.toggle("chip-has-findings", counts.high > 0);
  if (chipMed) chipMed.classList.toggle("chip-has-findings", counts.medium > 0);
  if (chipLow) chipLow.classList.toggle("chip-has-findings", counts.low > 0);
  if (chipInfo) chipInfo.classList.toggle("chip-has-findings", counts.informational > 0);
}

function renderFindingsList(findings) {
  clearElement(elements.findingsList);

  if (!findings || findings.length === 0) {
    elements.findingsEmpty.classList.remove("hidden");
    return;
  }
  elements.findingsEmpty.classList.add("hidden");

  // Sort findings by severity (Critical first)
  const sorted = [...findings].sort((a, b) => {
    const sevA = (a.severity || "").toLowerCase();
    const sevB = (b.severity || "").toLowerCase();
    const rankA = SEVERITY_ORDER[sevA] !== undefined ? SEVERITY_ORDER[sevA] : -1;
    const rankB = SEVERITY_ORDER[sevB] !== undefined ? SEVERITY_ORDER[sevB] : -1;
    return rankB - rankA;
  });

  sorted.forEach((finding, index) => {
    const sev = (finding.severity || "info").toLowerCase();
    const card = document.createElement("div");
    card.className = `finding-card finding-sev-${sev}`;

    const detailsId = `finding-details-${index}`;

    // Header Button (Real accessible button)
    const header = document.createElement("button");
    header.type = "button";
    header.className = "finding-header";
    header.setAttribute("aria-expanded", "false");
    header.setAttribute("aria-controls", detailsId);

    const titleGroup = document.createElement("div");
    titleGroup.className = "finding-title-group";

    const categoryTag = createTextElement(
      "span",
      (finding.category || "General").replace(/_/g, " "),
      "finding-category-tag"
    );
    const title = createTextElement(
      "h3",
      finding.title || "Security Finding",
      "finding-title"
    );
    titleGroup.appendChild(categoryTag);
    titleGroup.appendChild(title);

    const badges = document.createElement("div");
    badges.className = "finding-badges";

    const sevPill = createTextElement("span", sev.toUpperCase(), ["sev-pill", `sev-${sev}`]);
    const chevron = createTextElement("span", "▼", "finding-chevron");
    chevron.setAttribute("aria-hidden", "true");

    badges.appendChild(sevPill);
    badges.appendChild(chevron);

    header.appendChild(titleGroup);
    header.appendChild(badges);

    // Expandable Body Details (Hidden by default from layout and assistive tech)
    const details = document.createElement("div");
    details.id = detailsId;
    details.className = "finding-details";
    details.hidden = true;

    // Summary Block
    if (finding.summary) {
      const block = document.createElement("div");
      block.className = "detail-block";
      block.appendChild(createTextElement("span", "Summary", "detail-label"));
      block.appendChild(createTextElement("p", finding.summary, "detail-text"));
      details.appendChild(block);
    }

    // Affected Component
    if (finding.affected_component) {
      const block = document.createElement("div");
      block.className = "detail-block";
      block.appendChild(createTextElement("span", "Affected Component", "detail-label"));
      block.appendChild(createTextElement("p", finding.affected_component, "detail-text"));
      details.appendChild(block);
    }

    // Evidence
    if (finding.evidence && Object.keys(finding.evidence).length > 0) {
      const block = document.createElement("div");
      block.className = "detail-block";
      block.appendChild(createTextElement("span", "Evidence", "detail-label"));

      const evidenceBox = document.createElement("div");
      evidenceBox.className = "evidence-box";
      try {
        evidenceBox.textContent = JSON.stringify(finding.evidence, null, 2);
      } catch {
        evidenceBox.textContent = String(finding.evidence);
      }
      block.appendChild(evidenceBox);
      details.appendChild(block);
    }

    // Impact
    if (finding.impact) {
      const block = document.createElement("div");
      block.className = "detail-block";
      block.appendChild(createTextElement("span", "Impact", "detail-label"));
      block.appendChild(createTextElement("p", finding.impact, "detail-text"));
      details.appendChild(block);
    }

    // Recommendation
    if (finding.recommendation) {
      const block = document.createElement("div");
      block.className = "detail-block";
      block.appendChild(createTextElement("span", "Recommended Remediation", "detail-label"));
      block.appendChild(createTextElement("p", finding.recommendation, "detail-text"));
      details.appendChild(block);
    }

    // References (strictly validated)
    if (Array.isArray(finding.references) && finding.references.length > 0) {
      const block = document.createElement("div");
      block.className = "detail-block";
      block.appendChild(createTextElement("span", "References", "detail-label"));

      finding.references.forEach(refUrl => {
        if (isValidWebUrl(refUrl)) {
          const link = document.createElement("a");
          link.className = "reference-link";
          link.href = refUrl;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.textContent = refUrl;
          block.appendChild(link);
        }
      });
      details.appendChild(block);
    }

    // Retractable toggle interaction with double-toggle debounce guard
    let lastCardToggleTimestamp = 0;
    const toggleCard = () => {
      const now = Date.now();
      if (now - lastCardToggleTimestamp < 60) return; // Prevent double toggling from keydown + click
      lastCardToggleTimestamp = now;

      const isExpanded = card.classList.toggle("expanded");
      header.setAttribute("aria-expanded", String(isExpanded));
      details.hidden = !isExpanded;
    };

    header.addEventListener("click", toggleCard);
    header.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleCard();
      }
    });

    card.appendChild(header);
    card.appendChild(details);
    elements.findingsList.appendChild(card);
  });
}

function renderTechnicalDetails(data) {
  // 1. TLS Certificate
  clearElement(elements.tlsDetailsGrid);
  const tls = data.tls_certificate;
  if (tls && tls.checked) {
    appendTechItem(elements.tlsDetailsGrid, "Certificate Validity", tls.valid ? "Valid" : "Invalid");
    appendTechItem(elements.tlsDetailsGrid, "Trust Status", tls.trusted ? "Trusted CA" : "Untrusted / Self-signed");
    appendTechItem(elements.tlsDetailsGrid, "Protocol", tls.tls_version || "N/A");
    appendTechItem(elements.tlsDetailsGrid, "Cipher", tls.cipher || "N/A");

    if (tls.issuer && tls.issuer.commonName) {
      appendTechItem(elements.tlsDetailsGrid, "Issuer", tls.issuer.commonName);
    }
    if (tls.subject && tls.subject.commonName) {
      appendTechItem(elements.tlsDetailsGrid, "Subject", tls.subject.commonName);
    }
    if (tls.days_remaining !== undefined && tls.days_remaining !== null) {
      appendTechItem(elements.tlsDetailsGrid, "Days Remaining", `${tls.days_remaining} days`);
    }
    if (tls.expires_at) {
      appendTechItem(elements.tlsDetailsGrid, "Expires At", tls.expires_at);
    }
  } else {
    appendTechItem(elements.tlsDetailsGrid, "TLS Inspection", "Not available (HTTP or uninspected)");
  }

  // 2. HTTP Security Headers
  clearElement(elements.headersDetailsList);
  const headers = data.security_headers || {};
  const standardHeaders = [
    { key: "hsts", name: "Strict-Transport-Security (HSTS)" },
    { key: "csp", name: "Content-Security-Policy (CSP)" },
    { key: "x_frame_options", name: "X-Frame-Options (Clickjacking)" },
    { key: "x_content_type_options", name: "X-Content-Type-Options (MIME)" },
    { key: "referrer_policy", name: "Referrer-Policy" },
    { key: "permissions_policy", name: "Permissions-Policy" }
  ];

  standardHeaders.forEach(item => {
    const headerInfo = headers[item.key] || { present: false };
    const row = document.createElement("div");
    row.className = "header-check-item";

    const nameEl = createTextElement("span", item.name, "header-name");
    const statusEl = createTextElement(
      "span",
      headerInfo.present ? "✓ Present" : "✗ Missing",
      headerInfo.present ? "header-status-present" : "header-status-missing"
    );

    row.appendChild(nameEl);
    row.appendChild(statusEl);
    elements.headersDetailsList.appendChild(row);
  });

  // 3. Cookies Summary & Details (STRICTLY NON-DISCLOSURE OF VALUES)
  clearElement(elements.cookiesSummaryStats);
  clearElement(elements.cookiesDetailsList);

  const cookies = data.cookies || {};
  const totalCookies = cookies.cookie_count || 0;

  appendStatPill(elements.cookiesSummaryStats, `Total: ${totalCookies}`);
  appendStatPill(elements.cookiesSummaryStats, `Secure: ${cookies.secure_cookie_count || 0}`);
  appendStatPill(elements.cookiesSummaryStats, `HttpOnly: ${cookies.httponly_cookie_count || 0}`);
  appendStatPill(elements.cookiesSummaryStats, `SameSite: ${cookies.samesite_cookie_count || 0}`);

  const detailsList = Array.isArray(cookies.cookie_details) ? cookies.cookie_details : [];
  if (detailsList.length === 0) {
    elements.cookiesDetailsList.appendChild(
      createTextElement("p", "No Set-Cookie response headers observed.", "detail-text")
    );
  } else {
    detailsList.forEach(c => {
      const row = document.createElement("div");
      row.className = "cookie-row-card";

      const nameEl = createTextElement("div", c.name || "Unknown", "cookie-name");
      const flagsEl = document.createElement("div");
      flagsEl.className = "cookie-flags";

      const flags = [
        c.secure ? "Secure" : "No-Secure",
        c.httponly ? "HttpOnly" : "No-HttpOnly",
        c.samesite ? `SameSite=${c.samesite}` : "No-SameSite",
        c.type || "session"
      ];
      flagsEl.textContent = flags.join(" • ");

      row.appendChild(nameEl);
      row.appendChild(flagsEl);
      elements.cookiesDetailsList.appendChild(row);
    });
  }

  // 4. Network Details Grid
  clearElement(elements.networkDetailsGrid);
  appendTechItem(elements.networkDetailsGrid, "HTTP Status", String(data.status_code || "N/A"));
  appendTechItem(elements.networkDetailsGrid, "Response Time", `${data.response_time_ms || 0} ms`);
  appendTechItem(elements.networkDetailsGrid, "Redirect Hops", String(data.redirect_count || 0));
  appendTechItem(elements.networkDetailsGrid, "Protocol", data.protocol || "N/A");

  // 5. ML Phishing Model Diagnostic Status
  if (data.ml_analysis && typeof data.ml_analysis === "object") {
    const ml = data.ml_analysis;
    if (ml.available) {
      const probPct = ml.phishing_probability !== null && ml.phishing_probability !== undefined
        ? `${(Number(ml.phishing_probability) * 100).toFixed(1)}%`
        : "N/A";
      const statusText = ml.classification === "phishing"
        ? `Phishing Heuristic (${probPct})`
        : `Legitimate (${probPct})`;
      appendTechItem(elements.networkDetailsGrid, "ML Phishing Model", statusText);
    } else {
      appendTechItem(elements.networkDetailsGrid, "ML Phishing Model", "Unavailable");
    }
  }
}

function appendTechItem(container, key, value) {
  const item = document.createElement("div");
  item.className = "tech-item";
  item.appendChild(createTextElement("span", key, "tech-key"));
  item.appendChild(createTextElement("span", value, "tech-val"));
  container.appendChild(item);
}

function appendStatPill(container, text) {
  const pill = createTextElement("span", text, "stat-pill");
  container.appendChild(pill);
}

/**
 * Safely extract human-readable text from a scan limitation item.
 * Prefers lim.message, falls back to lim.code, then safe string representation.
 * Safely handles null, undefined, empty objects, and primitive values.
 * Never outputs '[object Object]'.
 *
 * @param {*} lim - Raw limitation item from API or assessment context
 * @returns {string|null} Formatted text or null if ignorable
 */
function formatLimitationText(lim) {
  if (lim === null || lim === undefined) {
    return null;
  }
  if (typeof lim === "object") {
    if (typeof lim.message === "string" && lim.message.trim().length > 0) {
      return lim.message.trim();
    }
    if (typeof lim.code === "string" && lim.code.trim().length > 0) {
      return lim.code.trim();
    }
    try {
      const str = String(lim);
      if (str && str !== "[object Object]" && str.trim().length > 0) {
        return str.trim();
      }
      const json = JSON.stringify(lim);
      if (json && json !== "{}") {
        return json;
      }
    } catch (_) {}
    return "Unspecified scan limitation";
  }
  if (typeof lim === "string") {
    const trimmed = lim.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  const str = String(lim).trim();
  return str.length > 0 ? str : null;
}

function renderMethodologyAndLimitations(assessment, limitations) {
  if (assessment && assessment.methodology_version) {
    elements.methodologyVersion.textContent = String(assessment.methodology_version);
  }

  clearElement(elements.limitationsContainer);
  const items = Array.isArray(limitations) ? limitations : [];
  const validTexts = [];

  for (let i = 0; i < items.length; i++) {
    const formatted = formatLimitationText(items[i]);
    if (formatted) {
      validTexts.push(formatted);
    }
  }

  if (validTexts.length > 0) {
    validTexts.forEach(text => {
      const item = createTextElement("div", `• ${text}`, "limitation-item");
      elements.limitationsContainer.appendChild(item);
    });
  } else {
    elements.limitationsContainer.appendChild(
      createTextElement("p", "No scan limitations recorded for this target.", "detail-text")
    );
  }
}

// =============================================================================
// Event Listeners & Lifecycle Setup
// =============================================================================

document.addEventListener("DOMContentLoaded", () => {
  // Findings section collapsible toggle button
  if (elements.findingsToggleBtn) {
    elements.findingsToggleBtn.addEventListener("click", () => {
      toggleFindingsSection();
    });
    elements.findingsToggleBtn.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleFindingsSection();
      }
    });
  }

  // Rescan / Refresh button
  elements.rescanBtn.addEventListener("click", () => {
    analyzeCurrentWebsite();
  });

  // Error Retry button
  elements.errorRetryBtn.addEventListener("click", () => {
    analyzeCurrentWebsite();
  });

  // Check initial backend health
  checkBackendHealth();

  // Initiate scan on popup open
  analyzeCurrentWebsite();

  // Cleanup active animations on unload / hide
  window.addEventListener("pagehide", cancelAllActiveAnimations);
  window.addEventListener("unload", cancelAllActiveAnimations);
});
