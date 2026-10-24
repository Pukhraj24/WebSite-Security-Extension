from urllib.parse import urlparse
import requests
import ssl
import socket

from datetime import datetime, timezone


# Security headers that we want to inspect
SECURITY_HEADERS = {
    "hsts": "Strict-Transport-Security",
    "csp": "Content-Security-Policy",
    "x_content_type_options": "X-Content-Type-Options",
    "x_frame_options": "X-Frame-Options",
    "referrer_policy": "Referrer-Policy",
    "permissions_policy": "Permissions-Policy",
    "cross_origin_opener_policy": "Cross-Origin-Opener-Policy",
    "cross_origin_resource_policy": "Cross-Origin-Resource-Policy",
    "cross_origin_embedder_policy": "Cross-Origin-Embedder-Policy"
}


def parse_certificate_time(value):
    """
    Convert certificate date into a timezone-aware datetime.
    """

    if not value:
        return None

    return datetime.strptime(
        value,
        "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)


def parse_certificate_part(part):
    """
    Convert certificate subject/issuer information
    into a simple dictionary.
    """

    result = {}

    for rdn in part:

        for key, value in rdn:
            result[key] = value

    return result


def get_certificate_info(hostname, port):
    """
    Inspect the TLS certificate of a website.
    """

    try:

        # Normal certificate verification
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_sock:

                certificate = secure_sock.getpeercert()

                not_before = parse_certificate_time(
                    certificate.get("notBefore")
                )

                not_after = parse_certificate_time(
                    certificate.get("notAfter")
                )

                current_time = datetime.now(timezone.utc)

                valid = False

                days_remaining = None

                if not_before and not_after:

                    valid = (
                        not_before
                        <= current_time
                        <= not_after
                    )

                    days_remaining = (
                        not_after - current_time
                    ).days

                issuer = parse_certificate_part(
                    certificate.get("issuer", ())
                )

                subject = parse_certificate_part(
                    certificate.get("subject", ())
                )

                cipher_info = secure_sock.cipher()

                cipher = None

                if cipher_info:
                    cipher = cipher_info[0]

                return {
                    "checked": True,
                    "valid": valid,
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": (
                        not_before.isoformat()
                        if not_before
                        else None
                    ),
                    "expires_at": (
                        not_after.isoformat()
                        if not_after
                        else None
                    ),
                    "days_remaining": days_remaining,
                    "tls_version": secure_sock.version(),
                    "cipher": cipher
                }

    except ssl.SSLCertVerificationError as error:

        # The certificate failed normal verification.
        # We make a second diagnostic connection without
        # trusting the certificate, only to inspect it.

        try:

            context = ssl.SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            )

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port),
                timeout=5
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=hostname
                ) as secure_sock:

                    certificate = secure_sock.getpeercert()

                    return {
                        "checked": True,
                        "valid": False,
                        "verification_error": str(error),
                        "issuer": {},
                        "subject": {},
                        "valid_from": None,
                        "expires_at": None,
                        "days_remaining": None,
                        "tls_version": secure_sock.version(),
                        "cipher": (
                            secure_sock.cipher()[0]
                            if secure_sock.cipher()
                            else None
                        )
                    }

        except Exception as diagnostic_error:

            return {
                "checked": True,
                "valid": False,
                "verification_error": str(error),
                "error": str(diagnostic_error)
            }

    except Exception as error:

        return {
            "checked": False,
            "valid": False,
            "error": str(error)
        }


def analyze_website(url):

    # Parse URL
    parsed_url = urlparse(url)

    protocol = parsed_url.scheme.lower()

    hostname = parsed_url.hostname

    domain = parsed_url.netloc

    # Make sure we have a valid web protocol
    if protocol not in {"http", "https"}:

        return {
            "url": url,
            "reachable": False,
            "error": "Only HTTP and HTTPS URLs are supported."
        }

    if not hostname:

        return {
            "url": url,
            "reachable": False,
            "error": "Could not determine website hostname."
        }

    # Determine port
    if parsed_url.port:
        port = parsed_url.port

    elif protocol == "https":
        port = 443

    else:
        port = 80

    secure_connection = protocol == "https"

    # Try to connect to the website
    start_time = datetime.now(timezone.utc)

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            stream=True,
            headers={
                "User-Agent": (
                    "WebsiteSecurityAnalyzer/1.0"
                )
            }
        )

    except requests.exceptions.SSLError as error:

        certificate_info = None

        if secure_connection:
            certificate_info = get_certificate_info(
                hostname,
                port
            )

        return {
            "url": url,
            "reachable": False,
            "error": "TLS connection could not be established.",
            "tls_certificate": certificate_info
        }

    except requests.exceptions.RequestException as error:

        return {
            "url": url,
            "reachable": False,
            "error": "Could not connect to the website.",
            "details": str(error)
        }

    end_time = datetime.now(timezone.utc)

    response_time_ms = (
        end_time - start_time
    ).total_seconds() * 1000

    # HTTP information
    status_code = response.status_code

    final_url = str(response.url)

    content_type = response.headers.get(
        "Content-Type"
    )

    # Redirect information
    redirect_chain = []

    for redirect in response.history:

        redirect_chain.append({
            "status_code": redirect.status_code,
            "url": str(redirect.url),
            "location": redirect.headers.get(
                "Location"
            )
        })

    # Security headers
    security_headers = {}

    for key, header_name in SECURITY_HEADERS.items():

        value = response.headers.get(
            header_name
        )

        security_headers[key] = {
            "present": value is not None,
            "value": value
        }

    # TLS certificate
    certificate_info = None

    if secure_connection:

        certificate_info = get_certificate_info(
            hostname,
            port
        )

    return {
        "url": url,

        "reachable": True,

        "domain": domain,

        "hostname": hostname,

        "protocol": protocol.upper(),

        "secure_connection": secure_connection,

        "status_code": status_code,

        "final_url": final_url,

        "redirect_count": len(response.history),

        "redirect_chain": redirect_chain,

        "response_time_ms": round(
            response_time_ms,
            2
        ),

        "content_type": content_type,

        "tls_certificate": certificate_info,

        "security_headers": security_headers,

        # Used internally by cookie_analyzer.py
        "response": response
    }