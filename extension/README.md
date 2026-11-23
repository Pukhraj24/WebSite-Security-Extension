# Website Security & Cookie Analyzer — Chrome Extension (Manifest V3)

A lightweight, privacy-preserving Chrome extension that inspects the active browser tab's website security configuration, TLS certificates, HTTP security headers, and cookie attributes via a locally running FastAPI analyzer.

Featuring a **Jet Black, White & Neon** design system with a high-contrast aesthetic, circular SVG risk gauge, and native **adaptive light and dark theme** support adhering to WCAG AA accessibility standards.

---

## 1. Prerequisites

- **Google Chrome** (version 88+ supporting Manifest V3) or any modern Chromium-based browser (Brave, Edge, Opera).
- **Python 3.13** with the project's virtual environment configured at `backend/venv`.
- Fast, local connection between the browser and `http://127.0.0.1:8000`.

---

## 2. Starting the Backend Server

The extension communicates with your local FastAPI backend. Start it before performing scans:

1. Open PowerShell and navigate to the `backend/` directory:
   ```powershell
   cd c:\Users\LENOVO\Desktop\WebsiteSecurityExtension\backend
   ```
2. Activate the virtual environment or run Uvicorn directly:
   ```powershell
   .\venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```
3. Keep this terminal window open while using the extension.

---

## 3. Verifying Backend Health

Verify that the local API is listening and responding:

- Open your browser or PowerShell and visit:
  ```
  http://127.0.0.1:8000/health
  ```
- Expected JSON response:
  ```json
  {"status": "healthy"}
  ```

---

## 4. Loading the Extension into Chrome

1. Open Google Chrome.
2. In the URL address bar, enter:
   ```
   chrome://extensions/
   ```
3. In the top-right corner of the Extensions page, toggle **Developer mode** to **ON**.
4. Click the **Load unpacked** button in the top-left toolbar.
5. In the folder picker dialog, select the exact `extension` directory:
   ```
   c:\Users\LENOVO\Desktop\WebsiteSecurityExtension\extension
   ```
6. The card **Website Security & Cookie Analyzer** will appear in your extension list with version `1.0.0`.

---

## 5. Pinning the Extension

1. Click the puzzle-piece **Extensions** icon in Chrome's top-right toolbar.
2. Find **Website Security & Cookie Analyzer**.
3. Click the **Pin** icon next to it so the extension logo remains visible in your browser bar.

---

## 6. How to Perform Scans and Test Scenarios

### Scenario A: Standard HTTPS Webpage (e.g., https://example.com)
1. Open a new tab and navigate to `https://example.com` (or any public site).
2. Click the extension's logo icon.
3. The popup opens, automatically queries the active tab's URL, displays the target hostname, and contacts `http://127.0.0.1:8000/analyze`.
4. The popup displays:
   - Target Hostname & Protocol (`HTTPS`).
   - Risk Score Gauge (e.g., `25 RISK %`) and Risk Level Badge (`MODERATE RISK`).
   - High-visibility Confidence Badge (e.g., `CONFIDENCE: HIGH`) and assessment summary.
   - Severity distribution chips (Critical, High, Medium, Low, Info).
   - Expandable security findings with impact and recommendations.
   - Technical inspection details (TLS certificate, Security Headers checklist, Cookies metadata, Network hops).

### Scenario B: Unsupported Browser Internal Page (e.g., chrome://extensions)
1. Navigate to `chrome://extensions` or `chrome://settings`.
2. Click the extension icon.
3. Expected Behavior: The popup detects the `chrome://` scheme and displays a clear notice:
   *"Cannot analyze internal browser URLs. Only standard HTTP and HTTPS websites are supported."*
   The backend is **not** queried.

### Scenario C: Backend Stopped / Connection Refused
1. Stop the backend server in PowerShell (`Ctrl + C`).
2. Open any website and click the extension icon.
3. Expected Behavior: The header status displays **Offline**, and an error card appears:
   *"Local Analyzer Unavailable: Could not connect to the backend API at http://127.0.0.1:8000."*
   Instructions to start Uvicorn and a **Retry Connection** button are provided.
4. Restart the backend and click **Retry Connection** — the scan will succeed without closing the popup.

### Scenario D: Blocked SSRF Target (e.g., 127.0.0.1 or Localhost)
1. If navigating to a private IP (e.g. `http://192.168.1.1` or `http://127.0.0.1:8080`):
2. Click the extension icon.
3. Expected Behavior: The backend rejects the request with HTTP 400 (`RESTRICTED_IP_ADDRESS`), and the extension displays:
   *"Restricted Target Blocked: The URL resolves to a private, loopback, link-local, or cloud metadata address. Internal targets are blocked by SSRF protections."*

---

## 7. Inspecting Extension Logs & Debugging

1. Right-click the extension icon in Chrome's toolbar and select **Inspect popup**.
2. Chrome DevTools will open for `popup.html`.
3. In the **Console** tab, view network requests and UI lifecycles.
4. In the **Network** tab, inspect the `POST http://127.0.0.1:8000/analyze` request payload and JSON response.

---

## 8. Reloading After Code Changes

If you modify `popup.html`, `popup.css`, or `popup.js`:
1. Open `chrome://extensions/`.
2. Locate the **Website Security & Cookie Analyzer** card.
3. Click the circular **Reload** arrow icon.
4. The popup updates immediately on next click.

---

## 9. Permissions & Privacy Justification

| Permission | Scope | Technical Justification |
| :--- | :--- | :--- |
| `activeTab` | Temporary active tab URL | Only queries the URL of the tab currently active when the user clicks the extension. Zero persistent access to other tabs. |
| `host_permissions` | `http://127.0.0.1:8000/*` | Strictly limits extension network communications to the local FastAPI analysis service. Cannot make network requests to any external third-party servers. |

### Strict Privacy Principles
- **No Cookie Interception**: The extension never reads your browser cookies and does not request `chrome.cookies`. All cookie findings are derived strictly from the backend's external HTTP inspection.
- **Zero Secret Exposure**: Cookie values, tokens, and session identifiers are never displayed, logged, or serialized.
- **Zero Telemetry**: No analytics libraries (Google Analytics, Mixpanel, etc.) or remote CDNs are loaded.
- **No Background Monitoring**: No background service worker or webNavigation listeners monitor your browsing. Analysis occurs exclusively upon user action.

---

## 10. Troubleshooting

### Issue: "Local Analyzer Unavailable" or CORS Error
- **Cause**: Backend is stopped or not running on port 8000.
- **Solution**: Confirm `.\venv\Scripts\python.exe -m uvicorn main:app --reload` is running. Backend CORS middleware is pre-configured with `allow_origin_regex=r"^chrome-extension://[a-z0-9]+$"` to permit unpacked Chrome extension origins.

### Issue: Chrome Blocks Local Network Access (Private Network Access)
- **Explanation**: In recent Chrome releases, requests from public webpages to `127.0.0.1` may be restricted. However, Chrome extension popups with `host_permissions: ["http://127.0.0.1:8000/*"]` have native browser permission to access local network addresses.

---

## 11. Known Limitations

1. **Heuristic Evaluation**: The risk score is an explainable heuristic based on observable configuration attributes (headers, TLS, cookies). It is not a malware scanner or full penetration test.
2. **Single-Page Scope**: Analyzes the specific URL provided, not the entire site hierarchy or client-side JavaScript execution.
3. **Local Backend Required**: The extension requires the companion Python backend running locally. It does not contact cloud services.
