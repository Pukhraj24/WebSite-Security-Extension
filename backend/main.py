from fastapi import FastAPI, status, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from website_analyzer import analyze_website
from cookie_analyzer import analyze_cookies


app = FastAPI(
    title="Website Security API",
    description="Website security, cookie configuration, and TLS analyzer with SSRF protection",
    version="1.1.0"
)


class WebsiteRequest(BaseModel):
    url: str = Field(..., description="The HTTP or HTTPS website URL to analyze")


@app.exception_handler(Exception)
def global_exception_handler(request: Request, exc: Exception):
    """
    Catch any unhandled exceptions to prevent stack trace leaks to API clients.
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


@app.post("/analyze")
def analyze_website_endpoint(website: WebsiteRequest):
    url = str(website.url).strip()

    # Perform website and security header/TLS analysis
    website_data = analyze_website(url)

    # If the website was not reachable or was blocked by security policy:
    if not website_data.get("reachable", False):
        error_info = website_data.get("error", {})
        error_code = error_info.get("code", "UNKNOWN_ERROR")

        # Map security and reachability error codes to standard HTTP statuses
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

    # Retrieve response object for cookie analysis
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
            # Guarantee HTTP connection is closed on all code paths
            response.close()

    # Combine website metadata and cookie analysis
    return {
        **website_data,
        "cookies": cookie_data
    }