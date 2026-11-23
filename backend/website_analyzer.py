from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser
import requests
import ssl
import socket
import os
import tempfile
import ipaddress
import tldextract
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

try:
    from ssrf_validator import (
        safe_fetch,
        create_safe_socket,
        SSRFSecurityError,
        validate_url
    )
except ImportError:
    from backend.ssrf_validator import (
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


class SecurityHTMLParser(HTMLParser):
    """
    Lightweight, streaming HTML parser to extract security signals from forms
    and input elements without external dependencies.
    """
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.in_form = False
        self.current_form: Optional[Dict[str, Any]] = None
        self.forms: List[Dict[str, Any]] = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()

        if tag_lower == "form":
            self.in_form = True
            action = attrs_dict.get("action", "").strip()
            resolved_action = urljoin(self.base_url, action) if action else self.base_url
            method = attrs_dict.get("method", "GET").upper()
            self.current_form = {
                "action": action,
                "resolved_action": resolved_action,
                "method": method,
                "has_password": False
            }
        elif tag_lower == "input":
            input_type = attrs_dict.get("type", "text").lower()
            if input_type == "password":
                if self.in_form and self.current_form is not None:
                    self.current_form["has_password"] = True

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self.in_form:
            self.in_form = False
            if self.current_form:
                self.forms.append(self.current_form)
                self.current_form = None

    def close(self):
        super().close()
        if self.in_form and self.current_form:
            self.forms.append(self.current_form)
            self.in_form = False
            self.current_form = None


# Offline TLD extractor using bundled Public Suffix List snapshot.
# suffix_list_urls=() guarantees zero network calls or download attempts.
_OFFLINE_TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True
)


def get_registrable_domain(hostname: Optional[str]) -> Optional[str]:
    """
    Safely extract the registrable domain (eTLD+1) for a hostname using an offline
    Public Suffix List extractor.

    Correctly handles:
    - Standard domains (example.com -> example.com)
    - Multipart public suffixes (bank.co.uk -> bank.co.uk, phish.co.uk -> phish.co.uk)
    - Second-level country domains (example.com.au, example.gov.uk)
    - Private domains (user.github.io -> user.github.io)
    - Subdomains (auth.example.com -> example.com, login.bank.co.uk -> bank.co.uk)
    - IP addresses and localhost without throwing exceptions
    - Malformed hosts, case normalization, and trailing dots
    - Never makes network calls (offline PSL snapshot only)
    """
    if not hostname:
        return None

    clean_host = hostname.strip().rstrip(".").lower()
    if not clean_host:
        return None

    # Check for IPv4 or IPv6 literals
    raw_ip = clean_host[1:-1] if clean_host.startswith("[") and clean_host.endswith("]") else clean_host
    try:
        ip = ipaddress.ip_address(raw_ip)
        return str(ip)
    except ValueError:
        pass

    try:
        extracted = _OFFLINE_TLD_EXTRACTOR(clean_host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain:
            return extracted.domain
        if extracted.suffix:
            return extracted.suffix
    except Exception:
        pass

    return clean_host


def extract_page_content_security(html_text: str, base_url: str) -> Dict[str, Any]:
    """
    Safely extract static HTML security signals (e.g. form destinations, password inputs)
    without running a browser engine or executing scripts.
    """
    if not html_text:
        return {
            "total_forms": 0,
            "insecure_forms": [],
            "cross_domain_password_forms": []
        }

    parser = SecurityHTMLParser(base_url)
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        pass

    base_parsed = urlparse(base_url)
    base_host = (base_parsed.hostname or "").lower()
    base_root = get_registrable_domain(base_host)

    insecure_forms = []
    cross_domain_password_forms = []

    for f in parser.forms:
        resolved = f.get("resolved_action", "")
        resolved_lower = resolved.lower()
        has_pwd = f.get("has_password", False)

        # Insecure form: submits over unencrypted HTTP
        if resolved_lower.startswith("http://"):
            insecure_forms.append({
                "action": resolved,
                "method": f.get("method", "GET"),
                "has_password": has_pwd
            })

        # Cross-domain password submission: password form submitting to an unrelated domain
        if has_pwd and resolved_lower.startswith(("http://", "https://")):
            target_host = (urlparse(resolved).hostname or "").lower()
            if target_host and base_host and target_host != base_host:
                target_root = get_registrable_domain(target_host)

                # Flag as cross-domain if root domains differ, or if either could not be extracted safely
                if not base_root or not target_root or base_root != target_root:
                    form_entry = {
                        "action": resolved,
                        "target_host": target_host,
                        "base_host": base_host,
                    }
                    cross_domain_password_forms.append(form_entry)

    return {
        "total_forms": len(parser.forms),
        "insecure_forms": insecure_forms,
        "cross_domain_password_forms": cross_domain_password_forms
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
                raw_cert = secure_sock.getpeercert()
                cert: Dict[str, Any] = raw_cert if isinstance(raw_cert, dict) else {}

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
        # TLS handshake or certificate failed during HTTP fetch.
        # Run diagnostic inspection to determine the exact certificate issue.
        cert_info = None
        if secure_connection:
            cert_info = get_certificate_info(hostname, port)
            if cert_info and cert_info.get("checked"):
                # Target host is reachable; certificate trust failed.
                # Return reachable=True partial analysis so findings and risk score are produced.
                return {
                    "url": url,
                    "reachable": True,
                    "domain": domain,
                    "hostname": hostname,
                    "protocol": protocol,
                    "secure_connection": True,
                    "status_code": None,
                    "final_url": url,
                    "redirect_count": 0,
                    "redirect_chain": [],
                    "response_time_ms": None,
                    "content_type": None,
                    "tls_certificate": cert_info,
                    "security_headers": {},
                    "response": None,
                    "connection_warning": "TLS handshake failed; certificate was inspected diagnostically."
                }

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

    # Extract page content security signals (forms, credential actions)
    page_content = None
    if content_type and any(t in content_type.lower() for t in ("text/html", "application/xhtml")):
        try:
            page_content = extract_page_content_security(response.text, final_url)
        except Exception:
            page_content = None

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
        "page_content": page_content,
        "tls_certificate": certificate_info,
        "security_headers": security_headers,
        # Response object passed for cookie analysis; must be closed by caller
        "response": response
    }