from urllib.parse import urlparse
import requests
import ssl
import socket
import os
import tempfile
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from ssrf_validator import (
    safe_fetch,
    create_safe_socket,
    SSRFSecurityError,
    validate_url
)


# Security headers to inspect on the target website
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


def parse_certificate_time(value: Optional[str]) -> Optional[datetime]:
    """
    Convert certificate date string into a timezone-aware UTC datetime.
    """
    if not value:
        return None

    try:
        return datetime.strptime(
            value,
            "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def parse_certificate_part(part) -> Dict[str, str]:
    """
    Convert certificate subject/issuer RDN tuples into a clean dictionary.
    """
    result = {}
    if not part:
        return result

    for rdn in part:
        for key, value in rdn:
            result[key] = value

    return result


def decode_der_certificate(der_bytes: bytes) -> Dict[str, Any]:
    """
    Safely decode binary DER certificate data into a dictionary structure
    without needing external heavyweight dependencies.
    """
    if not der_bytes:
        return {}

    try:
        pem = ssl.DER_cert_to_PEM_cert(der_bytes)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(pem)

            if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
                return ssl._ssl._test_decode_cert(path)
        finally:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
    except Exception:
        pass

    return {}


def get_certificate_info(hostname: str, port: int) -> Dict[str, Any]:
    """
    Inspect the TLS certificate of a website using SSRF-safe connections.
    
    Adheres to strict security rules:
    - Never opens an unvalidated socket (SSRF protection enforced).
    - Never treats an untrusted certificate as valid.
    - Decodes diagnostic details for untrusted certs without bypassing trust rules.
    """
    try:
        # 1. Establish an SSRF-safe socket to the pinned public IP
        sock, pinned_ip = create_safe_socket(hostname, port, timeout=5.0)

        # 2. Strict certificate verification
        context = ssl.create_default_context()

        with sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()

                not_before = parse_certificate_time(cert.get("notBefore"))
                not_after = parse_certificate_time(cert.get("notAfter"))
                current_time = datetime.now(timezone.utc)

                valid = False
                days_remaining = None

                if not_before and not_after:
                    valid = not_before <= current_time <= not_after
                    days_remaining = (not_after - current_time).days

                issuer = parse_certificate_part(cert.get("issuer", ()))
                subject = parse_certificate_part(cert.get("subject", ()))

                cipher_info = secure_sock.cipher()
                cipher = cipher_info[0] if cipher_info else None

                return {
                    "checked": True,
                    "valid": valid,
                    "trusted": True,
                    "verification_error": None,
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": not_before.isoformat() if not_before else None,
                    "expires_at": not_after.isoformat() if not_after else None,
                    "days_remaining": days_remaining,
                    "tls_version": secure_sock.version(),
                    "cipher": cipher
                }

    except ssl.SSLCertVerificationError as error:
        # The certificate failed standard trust verification.
        # Open an SSRF-safe diagnostic connection (NEVER unrestricted) to extract details.
        try:
            diag_sock, pinned_ip = create_safe_socket(hostname, port, timeout=5.0)
            diag_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            diag_context.check_hostname = False
            diag_context.verify_mode = ssl.CERT_NONE

            with diag_sock:
                with diag_context.wrap_socket(diag_sock, server_hostname=hostname) as diag_secure_sock:
                    der = diag_secure_sock.getpeercert(binary_form=True)
                    decoded = decode_der_certificate(der) if der else {}

                    not_before = parse_certificate_time(decoded.get("notBefore"))
                    not_after = parse_certificate_time(decoded.get("notAfter"))
                    current_time = datetime.now(timezone.utc)

                    days_remaining = None
                    if not_before and not_after:
                        days_remaining = (not_after - current_time).days

                    issuer = parse_certificate_part(decoded.get("issuer", ()))
                    subject = parse_certificate_part(decoded.get("subject", ()))

                    cipher_info = diag_secure_sock.cipher()
                    cipher = cipher_info[0] if cipher_info else None

                    return {
                        "checked": True,
                        "valid": False,  # Untrusted certificates are NEVER valid
                        "trusted": False,
                        "verification_error": str(error),
                        "issuer": issuer,
                        "subject": subject,
                        "valid_from": not_before.isoformat() if not_before else None,
                        "expires_at": not_after.isoformat() if not_after else None,
                        "days_remaining": days_remaining,
                        "tls_version": diag_secure_sock.version(),
                        "cipher": cipher
                    }
        except Exception as diag_err:
            return {
                "checked": True,
                "valid": False,
                "trusted": False,
                "verification_error": str(error),
                "error": f"Failed to retrieve diagnostic certificate: {diag_err}"
            }

    except SSRFSecurityError as ssrf_err:
        return {
            "checked": False,
            "valid": False,
            "trusted": False,
            "error": ssrf_err.message
        }

    except Exception as error:
        return {
            "checked": False,
            "valid": False,
            "trusted": False,
            "error": "Failed to establish TLS connection."
        }


def analyze_website(url: str) -> Dict[str, Any]:
    """
    Analyze website connectivity, redirects, security headers, and TLS certificates
    with SSRF protection, size caps, and safe error handling.
    """
    # Pre-validate URL and extract basic components
    try:
        url_info = validate_url(url)
    except SSRFSecurityError as err:
        return {
            "url": url,
            "reachable": False,
            "error": {
                "code": err.code,
                "message": err.message
            }
        }

    hostname = url_info["hostname"]
    protocol = url_info["scheme"].upper()
    port = url_info["port"]
    domain = url_info["netloc"]
    secure_connection = url_info["scheme"] == "https"

    # Safely fetch the website with full SSRF and size controls
    try:
        response, redirect_chain, final_url, response_time_ms = safe_fetch(
            url,
            max_redirects=5,
            total_timeout=10.0,
            connect_timeout=3.0,
            read_timeout=5.0,
            max_bytes=2 * 1024 * 1024  # 2 MB limit
        )
    except SSRFSecurityError as err:
        return {
            "url": url,
            "reachable": False,
            "error": {
                "code": err.code,
                "message": err.message
            }
        }
    except requests.exceptions.SSLError:
        # TLS handshake or certificate failed during HTTP fetch
        cert_info = None
        if secure_connection:
            cert_info = get_certificate_info(hostname, port)

        return {
            "url": url,
            "reachable": False,
            "error": {
                "code": "TLS_ERROR",
                "message": "TLS connection could not be established."
            },
            "tls_certificate": cert_info
        }
    except requests.exceptions.RequestException:
        return {
            "url": url,
            "reachable": False,
            "error": {
                "code": "WEBSITE_UNREACHABLE",
                "message": "Could not connect to the website."
            }
        }
    except Exception:
        return {
            "url": url,
            "reachable": False,
            "error": {
                "code": "CONNECTION_FAILED",
                "message": "An unexpected error occurred while reaching the website."
            }
        }

    # Extract HTTP status and response details
    status_code = response.status_code
    content_type = response.headers.get("Content-Type")

    # Security headers extraction (both presence and value)
    security_headers = {}
    for key, header_name in SECURITY_HEADERS.items():
        value = response.headers.get(header_name)
        security_headers[key] = {
            "present": value is not None,
            "value": value
        }

    # TLS certificate analysis (only if initial or final scheme is HTTPS)
    certificate_info = None
    final_is_https = final_url.lower().startswith("https://")
    if secure_connection or final_is_https:
        target_hostname = urlparse(final_url).hostname or hostname
        target_port = urlparse(final_url).port or 443
        certificate_info = get_certificate_info(target_hostname, target_port)

    return {
        "url": url,
        "reachable": True,
        "domain": domain,
        "hostname": hostname,
        "protocol": protocol,
        "secure_connection": secure_connection,
        "status_code": status_code,
        "final_url": final_url,
        "redirect_count": len(redirect_chain),
        "redirect_chain": redirect_chain,
        "response_time_ms": response_time_ms,
        "content_type": content_type,
        "tls_certificate": certificate_info,
        "security_headers": security_headers,
        # Response object passed for cookie analysis; must be closed by caller
        "response": response
    }