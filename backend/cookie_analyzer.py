from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def convert_expiration_timestamp(timestamp: Optional[float]) -> Optional[str]:
    """
    Convert Unix timestamp into timezone-aware ISO 8601 format string.
    """
    if timestamp is None:
        return None

    try:
        return datetime.fromtimestamp(
            timestamp,
            timezone.utc
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def normalize_samesite(samesite_raw: Any) -> Optional[str]:
    """
    Normalize SameSite string into standard capitalized form (Strict, Lax, None).
    """
    if not samesite_raw:
        return None

    s = str(samesite_raw).strip().lower()
    if s == "strict":
        return "Strict"
    elif s == "lax":
        return "Lax"
    elif s == "none":
        return "None"
    return str(samesite_raw).strip()


def analyze_cookies(response) -> Dict[str, Any]:
    """
    Analyze cookies from HTTP response and redirect chain.

    CRITICAL SECURITY REQUIREMENT:
    Under no circumstances are raw cookie values extracted or returned.
    Only security-relevant metadata (name, attributes, flags, expiration) is inspected.
    """
    # Collect cookies across redirect history and the final response
    all_cookies = []

    if hasattr(response, "history") and response.history:
        for redirect in response.history:
            if hasattr(redirect, "cookies"):
                all_cookies.extend(list(redirect.cookies))

    if hasattr(response, "cookies") and response.cookies:
        all_cookies.extend(list(response.cookies))

    # Deduplicate cookies by (name, domain, path)
    unique_cookies = {}
    for cookie in all_cookies:
        key = (
            cookie.name,
            cookie.domain,
            cookie.path
        )
        unique_cookies[key] = cookie

    cookies = list(unique_cookies.values())
    cookie_count = len(cookies)

    secure_cookie_count = 0
    httponly_cookie_count = 0
    samesite_cookie_count = 0
    persistent_cookie_count = 0
    session_cookie_count = 0

    cookie_details: List[Dict[str, Any]] = []

    for cookie in cookies:
        # Check HttpOnly (nonstandard attribute in standard cookiejar)
        httponly = cookie.has_nonstandard_attr("HttpOnly")
        if not httponly and hasattr(cookie, "_rest"):
            # Case-insensitive fallback for non-standard attribute dict
            for attr in cookie._rest.keys():
                if attr.lower() == "httponly":
                    httponly = True
                    break

        # Check SameSite
        samesite_raw = cookie.get_nonstandard_attr("SameSite")
        if not samesite_raw and hasattr(cookie, "_rest"):
            for attr, val in cookie._rest.items():
                if attr.lower() == "samesite":
                    samesite_raw = val
                    break

        samesite = normalize_samesite(samesite_raw)

        # Expiration and Max-Age
        expires = cookie.expires
        expires_at = convert_expiration_timestamp(expires)

        max_age = cookie.get_nonstandard_attr("Max-Age")
        if not max_age and hasattr(cookie, "_rest"):
            for attr, val in cookie._rest.items():
                if attr.lower() == "max-age":
                    max_age = val
                    break

        # Classify cookie persistence
        if expires is not None or max_age is not None:
            cookie_type = "persistent"
            persistent_cookie_count += 1
        else:
            cookie_type = "session"
            session_cookie_count += 1

        if cookie.secure:
            secure_cookie_count += 1

        if httponly:
            httponly_cookie_count += 1

        if samesite:
            samesite_cookie_count += 1

        # Security Observations
        observations = []

        if not cookie.secure:
            observations.append("Cookie is not marked Secure.")

        if not httponly:
            observations.append("Cookie is not marked HttpOnly.")

        if not samesite:
            observations.append("SameSite attribute is not explicitly configured.")
        elif samesite == "None" and not cookie.secure:
            observations.append("SameSite=None requires the Secure attribute in modern browsers.")

        # Check prefix-based security standards (__Secure- and __Host-)
        if cookie.name.startswith("__Secure-") and not cookie.secure:
            observations.append("Cookie name begins with '__Secure-' but lacks the Secure attribute.")

        if cookie.name.startswith("__Host-"):
            if not cookie.secure:
                observations.append("Cookie name begins with '__Host-' but lacks the Secure attribute.")
            if cookie.path != "/":
                observations.append("Cookie name begins with '__Host-' but Path is not '/'.")
            if cookie.domain_specified:
                observations.append("Cookie name begins with '__Host-' but specifies a Domain attribute.")

        # Append strictly metadata — NEVER the cookie's secret value!
        cookie_details.append({
            "name": cookie.name,
            "secure": bool(cookie.secure),
            "httponly": bool(httponly),
            "samesite": samesite,
            "domain": cookie.domain,
            "path": cookie.path,
            "domain_specified": bool(cookie.domain_specified),
            "domain_initial_dot": bool(cookie.domain_initial_dot),
            "expires": expires_at,
            "max_age": max_age,
            "type": cookie_type,
            "observations": observations
        })

    return {
        "cookie_count": cookie_count,
        "secure_cookie_count": secure_cookie_count,
        "httponly_cookie_count": httponly_cookie_count,
        "samesite_cookie_count": samesite_cookie_count,
        "persistent_cookie_count": persistent_cookie_count,
        "session_cookie_count": session_cookie_count,
        "cookie_details": cookie_details
    }