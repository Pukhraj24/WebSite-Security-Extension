"""
Unit tests for cookie security analysis, attribute detection, and value non-disclosure.
"""

from http.cookiejar import Cookie
import json
import pytest

from cookie_analyzer import analyze_cookies, normalize_samesite


class MockResponse:
    """Mock HTTP response with cookies for testing."""
    def __init__(self, cookies=None, history=None):
        self.cookies = cookies or []
        self.history = history or []


def make_test_cookie(
    name: str,
    value: str = "secret_val_12345",
    secure: bool = False,
    httponly: bool = False,
    samesite: str = None,
    domain: str = "example.com",
    path: str = "/",
    expires: float = None,
    domain_specified: bool = True,
    domain_initial_dot: bool = False,
    rest: dict = None
) -> Cookie:
    """Helper to construct standard Cookie objects."""
    cookie_rest = dict(rest or {})
    if httponly:
        cookie_rest["httponly"] = None
    if samesite:
        cookie_rest["samesite"] = samesite

    return Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=domain_specified,
        domain_initial_dot=domain_initial_dot,
        path=path,
        path_specified=True,
        secure=secure,
        expires=expires,
        discard=expires is None,
        comment=None,
        comment_url=None,
        rest=cookie_rest
    )


def test_normalize_samesite():
    """Verify SameSite normalization handles various casings and values."""
    assert normalize_samesite("lax") == "Lax"
    assert normalize_samesite("LAX") == "Lax"
    assert normalize_samesite("strict") == "Strict"
    assert normalize_samesite("STRICT") == "Strict"
    assert normalize_samesite("none") == "None"
    assert normalize_samesite("NONE") == "None"
    assert normalize_samesite(None) is None
    assert normalize_samesite("") is None


def test_cookie_value_non_disclosure():
    """
    CRITICAL SECURITY TEST:
    Verify that actual cookie values are NEVER exposed in the analyzer output.
    """
    secret_value = "super_confidential_session_token_xyz987"
    cookie = make_test_cookie(
        name="session_id",
        value=secret_value,
        secure=True,
        httponly=True,
        samesite="Strict"
    )

    response = MockResponse(cookies=[cookie])
    result = analyze_cookies(response)

    # Convert complete result structure to string
    result_str = json.dumps(result)

    # The secret value must not appear ANYWHERE in the returned data
    assert secret_value not in result_str
    assert result["cookie_count"] == 1
    assert result["cookie_details"][0]["name"] == "session_id"
    assert result["cookie_details"][0]["secure"] is True
    assert result["cookie_details"][0]["httponly"] is True
    assert result["cookie_details"][0]["samesite"] == "Strict"


def test_insecure_cookie_observations():
    """Verify observations generated for insecure or misconfigured cookies."""
    cookie = make_test_cookie(
        name="tracking_id",
        secure=False,
        httponly=False,
        samesite=None
    )

    response = MockResponse(cookies=[cookie])
    result = analyze_cookies(response)
    details = result["cookie_details"][0]

    obs = " ".join(details["observations"])
    assert "not marked Secure" in obs
    assert "not marked HttpOnly" in obs
    assert "SameSite attribute is not explicitly configured" in obs


def test_samesite_none_without_secure():
    """Verify observation when SameSite=None is used without Secure."""
    cookie = make_test_cookie(
        name="cross_site_cookie",
        secure=False,
        httponly=True,
        samesite="None"
    )

    response = MockResponse(cookies=[cookie])
    result = analyze_cookies(response)
    details = result["cookie_details"][0]

    obs = " ".join(details["observations"])
    assert "requires the Secure attribute" in obs


def test_prefix_security_rules():
    """Verify __Secure- and __Host- prefix validation."""
    # __Secure- without secure
    c1 = make_test_cookie(name="__Secure-token", secure=False)
    # __Host- without secure and non-root path
    c2 = make_test_cookie(name="__Host-id", secure=False, path="/api")

    response = MockResponse(cookies=[c1, c2])
    result = analyze_cookies(response)

    c1_obs = " ".join(result["cookie_details"][0]["observations"])
    assert "__Secure-" in c1_obs and "Secure attribute" in c1_obs

    c2_obs = " ".join(result["cookie_details"][1]["observations"])
    assert "__Host-" in c2_obs and "Path is not '/'" in c2_obs
