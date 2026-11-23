import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, status, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from fastapi.middleware.cors import CORSMiddleware

from website_analyzer import analyze_website
from cookie_analyzer import analyze_cookies
from security_findings import generate_security_findings
from risk_scorer import calculate_risk, calculate_finding_summary
try:
    from ml_service import load_ml_model, get_model_status, predict_url_phishing
except ImportError:
    from backend.ml_service import load_ml_model, get_model_status, predict_url_phishing


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.
    Loads ML phishing model once at startup without blocking or failing on error.
    """
    load_ml_model()
    yield


app = FastAPI(
    title="Website Security API",
    description="Website security, cookie configuration, TLS analyzer, and risk scoring engine",
    version="1.2.0",
    lifespan=lifespan
)

# Enable CORS specifically for Chrome Extension origins (Manifest V3)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^chrome-extension://[a-z0-9]+$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)



class WebsiteRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="The HTTP or HTTPS website URL to analyze")


@app.exception_handler(Exception)
def global_exception_handler(request: Request, exc: Exception):
    """
    Catch unhandled exceptions to prevent stack trace leaks to API clients.
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "reachable": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An internal error occurred while processing the request."
            }
        }
    )


@app.get("/")
def home():
    return {
        "message": "Website Security API is running!"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.get("/health/ml")
def health_ml():
    return get_model_status()


@app.post("/analyze")
async def analyze_website_endpoint(website: WebsiteRequest):
    url = str(website.url).strip()

    # Perform website connectivity, redirect, TLS, and header analysis in threadpool
    website_data = await asyncio.to_thread(analyze_website, url)

    # Handle connection errors or security blocks
    if not website_data.get("reachable", False):
        error_info = website_data.get("error", {})
        error_code = error_info.get("code", "UNKNOWN_ERROR")

        if error_code in {
            "SSRF_BLOCKED",
            "INVALID_URL",
            "RESTRICTED_IP_ADDRESS",
            "REDIRECT_ERROR",
            "REDIRECT_LIMIT_EXCEEDED",
            "REDIRECT_LOOP_DETECTED"
        }:
            http_status = status.HTTP_400_BAD_REQUEST
        elif error_code == "TIMEOUT":
            http_status = status.HTTP_504_GATEWAY_TIMEOUT
        elif error_code in {"DNS_RESOLUTION_FAILED", "WEBSITE_UNREACHABLE", "CONNECTION_FAILED"}:
            http_status = status.HTTP_502_BAD_GATEWAY
        elif error_code == "RESPONSE_TOO_LARGE":
            http_status = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        else:
            http_status = status.HTTP_400_BAD_REQUEST

        return JSONResponse(status_code=http_status, content=website_data)

    # Perform cookie analysis on the HTTP response
    response = website_data.pop("response", None)
    cookie_data = {
        "cookie_count": 0,
        "secure_cookie_count": 0,
        "httponly_cookie_count": 0,
        "samesite_cookie_count": 0,
        "persistent_cookie_count": 0,
        "session_cookie_count": 0,
        "cookie_details": []
    }

    if response is not None:
        try:
            cookie_data = analyze_cookies(response)
        finally:
            # Guarantee HTTP connection is closed on all execution paths
            response.close()

    # Perform offline ML phishing inference safely and asynchronously
    try:
        ml_result = await predict_url_phishing(url)
    except Exception as ml_err:
        ml_result = {
            "available": False,
            "url": url,
            "error": f"ML prediction failed: {ml_err}"
        }

    # Generate structured security findings and assessment limitations
    findings, limitations = generate_security_findings(
        website_data,
        cookie_data,
        ml_result=ml_result
    )

    # Calculate risk score and summary metrics
    assessment_context = {
        "reachable": True,
        "limitations": limitations
    }
    assessment = calculate_risk(findings, assessment_context)
    finding_summary = calculate_finding_summary(findings)

    # Return unified, machine-readable analysis response
    response_payload = {
        **website_data,
        "cookies": cookie_data,
        "assessment": assessment,
        "findings": findings,
        "finding_summary": finding_summary,
        "limitations": limitations
    }

    # Expose backward-compatible ML analysis metadata
    if ml_result is not None:
        response_payload["ml_analysis"] = ml_result

    return response_payload