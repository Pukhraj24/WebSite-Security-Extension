from datetime import datetime, timezone


def convert_expiration_timestamp(timestamp):
    """
    Convert Unix timestamp into ISO format.
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


def analyze_cookies(response):

    # --------------------------------------------------
    # Collect cookies from redirect responses + final
    # response.
    # --------------------------------------------------

    all_cookies = []

    for redirect in response.history:
        all_cookies.extend(
            list(redirect.cookies)
        )

    all_cookies.extend(
        list(response.cookies)
    )

    # --------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------

    unique_cookies = {}

    for cookie in all_cookies:

        key = (
            cookie.name,
            cookie.domain,
            cookie.path
        )

        unique_cookies[key] = cookie

    cookies = list(
        unique_cookies.values()
    )

    cookie_count = len(cookies)

    # --------------------------------------------------
    # Counters
    # --------------------------------------------------

    secure_cookie_count = 0

    httponly_cookie_count = 0

    samesite_cookie_count = 0

    persistent_cookie_count = 0

    session_cookie_count = 0

    # --------------------------------------------------
    # Individual cookie details
    # --------------------------------------------------

    cookie_details = []

    for cookie in cookies:

        # HttpOnly
        httponly = cookie.has_nonstandard_attr(
            "HttpOnly"
        )

        # SameSite
        samesite = cookie.get_nonstandard_attr(
            "SameSite"
        )

        if samesite:
            samesite = str(samesite)

        # Expiration
        expires = cookie.expires

        expires_at = convert_expiration_timestamp(
            expires
        )

        # Max-Age
        max_age = cookie.get_nonstandard_attr(
            "Max-Age"
        )

        # Determine cookie type
        if expires is not None or max_age is not None:

            cookie_type = "persistent"

            persistent_cookie_count += 1

        else:

            cookie_type = "session"

            session_cookie_count += 1

        # Secure count
        if cookie.secure:

            secure_cookie_count += 1

        # HttpOnly count
        if httponly:

            httponly_cookie_count += 1

        # SameSite count
        if samesite:

            samesite_cookie_count += 1

        # --------------------------------------------------
        # Observations
        # --------------------------------------------------

        observations = []

        if not cookie.secure:

            observations.append(
                "Cookie is not marked Secure."
            )

        if not httponly:

            observations.append(
                "Cookie is not marked HttpOnly."
            )

        if not samesite:

            observations.append(
                "SameSite is not explicitly configured."
            )

        if (
            samesite
            and str(samesite).lower() == "none"
            and not cookie.secure
        ):

            observations.append(
                "SameSite=None normally requires Secure."
            )

        # --------------------------------------------------
        # Save cookie details
        # --------------------------------------------------

        cookie_details.append({

            # We intentionally DO NOT return
            # the cookie value.
            "name": cookie.name,

            "secure": cookie.secure,

            "httponly": httponly,

            "samesite": samesite,

            "domain": cookie.domain,

            "path": cookie.path,

            "domain_specified": cookie.domain_specified,

            "domain_initial_dot": (
                cookie.domain_initial_dot
            ),

            "expires": expires_at,

            "max_age": max_age,

            "type": cookie_type,

            "observations": observations
        })

    # --------------------------------------------------
    # Return cookie analysis
    # --------------------------------------------------

    return {

        "cookie_count": cookie_count,

        "secure_cookie_count": (
            secure_cookie_count
        ),

        "httponly_cookie_count": (
            httponly_cookie_count
        ),

        "samesite_cookie_count": (
            samesite_cookie_count
        ),

        "persistent_cookie_count": (
            persistent_cookie_count
        ),

        "session_cookie_count": (
            session_cookie_count
        ),

        "cookie_details": cookie_details
    }