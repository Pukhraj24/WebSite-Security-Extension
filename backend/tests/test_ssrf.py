"""
Unit tests for SSRF validation, IP filtering, URL parsing, and safe fetching.
"""

import socket
from unittest.mock import patch, MagicMock
import pytest

from ssrf_validator import (
    is_safe_ip,
    validate_url,
    resolve_and_validate_hostname,
    safe_fetch,
    InvalidURLError,
    PrivateIPAddressError,
    DNSResolutionError,
    RedirectSecurityError,
    ResponseSizeLimitError,
    RequestTimeoutError
)


# ==============================================================================
# 1. IP Range & Safety Validation Tests
# ==============================================================================

@pytest.mark.parametrize("ip_str, expected_reason_keyword", [
    ("127.0.0.1", "Loopback"),
    ("127.0.0.2", "Loopback"),
    ("127.255.255.255", "Loopback"),
    ("::1", "Loopback"),
    ("10.0.0.1", "Private"),
    ("10.255.255.254", "Private"),
    ("172.16.0.1", "Private"),
    ("172.31.255.254", "Private"),
    ("192.168.0.1", "Private"),
    ("192.168.1.254", "Private"),
    ("fc00::1", "Private"),
    ("fd12:3456:789a:1::1", "Private"),
    ("169.254.0.1", "Link-local"),
    ("169.254.169.254", "Link-local"),  # AWS / Cloud metadata service
    ("fe80::1", "Link-local"),
    ("100.64.0.1", "Carrier-Grade NAT"),
    ("100.127.255.254", "Carrier-Grade NAT"),
    ("224.0.0.1", "Multicast"),
    ("ff02::1", "Multicast"),
    ("0.0.0.0", "Unspecified"),
    ("::", "Unspecified"),
    ("255.255.255.255", "Broadcast"),
    ("192.0.2.1", "Documentation"),
    ("198.51.100.1", "Documentation"),
    ("203.0.113.1", "Documentation"),
    ("198.18.0.1", "Documentation/Benchmark"),
    ("240.0.0.1", "Reserved"),
])
def test_blocked_ip_ranges(ip_str, expected_reason_keyword):
    """Verify that every restricted IP address range is blocked."""
    safe, reason = is_safe_ip(ip_str)
    assert not safe
    assert expected_reason_keyword.lower() in reason.lower()


@pytest.mark.parametrize("mapped_ipv6", [
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:192.168.1.1",
    "::ffff:169.254.169.254",
])
def test_ipv4_mapped_ipv6_blocked(mapped_ipv6):
    """Verify that IPv4-mapped IPv6 addresses targeting private/loopback IPs are blocked."""
    safe, reason = is_safe_ip(mapped_ipv6)
    assert not safe


@pytest.mark.parametrize("public_ip", [
    "93.184.215.14",     # example.com
    "8.8.8.8",            # Google DNS
    "1.1.1.1",            # Cloudflare DNS
    "151.101.1.69",       # Fastly
    "2606:2800:220:1:248:1893:25c8:1946", # example.com IPv6
])
def test_allowed_public_ips(public_ip):
    """Verify that legitimate public IP addresses are recognized as safe."""
    safe, reason = is_safe_ip(public_ip)
    assert safe
    assert "safe" in reason.lower()


def test_invalid_ip_format():
    """Verify that malformed IP strings are rejected."""
    safe, reason = is_safe_ip("999.999.999.999")
    assert not safe
    assert "invalid" in reason.lower()


# ==============================================================================
# 2. URL Scheme & Formatting Validation Tests
# ==============================================================================

def test_valid_http_and_https_urls():
    """Verify that standard HTTP and HTTPS URLs are parsed properly."""
    res_https = validate_url("https://example.com/test?query=1")
    assert res_https["scheme"] == "https"
    assert res_https["hostname"] == "example.com"
    assert res_https["port"] == 443

    res_http = validate_url("http://example.org:8080/path")
    assert res_http["scheme"] == "http"
    assert res_http["hostname"] == "example.org"
    assert res_http["port"] == 8080


@pytest.mark.parametrize("bad_scheme_url", [
    "file:///etc/passwd",
    "ftp://ftp.example.com/file.txt",
    "gopher://127.0.0.1:70/",
    "dict://dict.org",
    "ldap://127.0.0.1/",
    "javascript:alert(1)",
    "data:text/html,<html></html>",
])
def test_unsupported_schemes_rejected(bad_scheme_url):
    """Verify that non-HTTP/HTTPS protocols are rejected."""
    with pytest.raises(InvalidURLError) as exc:
        validate_url(bad_scheme_url)
    assert "unsupported url scheme" in str(exc.value).lower()


@pytest.mark.parametrize("credential_url", [
    "http://user:password@example.com/",
    "https://admin:secret@127.0.0.1/",
    "http://user@example.com/",
])
def test_embedded_credentials_rejected(credential_url):
    """Verify that URLs containing embedded credentials are blocked."""
    with pytest.raises(InvalidURLError) as exc:
        validate_url(credential_url)
    assert "embedded credentials" in str(exc.value).lower()


@pytest.mark.parametrize("invalid_port_url", [
    "http://example.com:0",
    "http://example.com:65536",
    "http://example.com:99999",
    "http://example.com:-80",
])
def test_invalid_ports_rejected(invalid_port_url):
    """Verify that ports outside 1-65535 are rejected."""
    with pytest.raises(InvalidURLError):
        validate_url(invalid_port_url)


# ==============================================================================
# 3. DNS Resolution & Mixed Answers Tests
# ==============================================================================

def test_resolve_localhost_rejected():
    """Verify that localhost resolving to 127.0.0.1 or ::1 is rejected."""
    with pytest.raises(PrivateIPAddressError):
        resolve_and_validate_hostname("localhost", 80)


def test_mixed_public_private_dns_rejected():
    """
    Verify that if a DNS answer contains BOTH public and private IPs,
    the connection is rejected (defense against mixed DNS answers).
    """
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ]

    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(PrivateIPAddressError) as exc:
            resolve_and_validate_hostname("rebind.example.com", 80)
        assert "unsafe address" in str(exc.value).lower()


def test_dns_resolution_failure():
    """Verify that gaierror raises DNSResolutionError."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        with pytest.raises(DNSResolutionError) as exc:
            resolve_and_validate_hostname("nonexistent.invalid", 80)
        assert "dns resolution failed" in str(exc.value).lower()


# ==============================================================================
# 4. Redirect Protection Tests
# ==============================================================================

def test_redirect_to_private_ip_blocked():
    """Verify that a redirect pointing to an internal IP is blocked."""
    mock_resp_1 = MagicMock()
    mock_resp_1.status_code = 302
    mock_resp_1.headers = {"Location": "http://192.168.1.1/admin"}

    def mock_dns(host, port=80):
        if host == "example.com":
            return ["93.184.215.14"]
        return resolve_and_validate_hostname(host, port)

    with patch("ssrf_validator.resolve_and_validate_hostname", side_effect=mock_dns):
        with patch("requests.Session.get", return_value=mock_resp_1):
            with pytest.raises(PrivateIPAddressError):
                safe_fetch("https://example.com/redirect")


def test_redirect_to_cloud_metadata_blocked():
    """Verify that a redirect pointing to 169.254.169.254 is blocked."""
    mock_resp_1 = MagicMock()
    mock_resp_1.status_code = 302
    mock_resp_1.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    def mock_dns(host, port=80):
        if host == "example.com":
            return ["93.184.215.14"]
        return resolve_and_validate_hostname(host, port)

    with patch("ssrf_validator.resolve_and_validate_hostname", side_effect=mock_dns):
        with patch("requests.Session.get", return_value=mock_resp_1):
            with pytest.raises(PrivateIPAddressError):
                safe_fetch("https://example.com/redirect")


def test_redirect_loop_detected():
    """Verify that redirect cycles (A -> B -> A) are blocked."""
    mock_resp_a = MagicMock()
    mock_resp_a.status_code = 302
    mock_resp_a.headers = {"Location": "https://example.com/b"}

    mock_resp_b = MagicMock()
    mock_resp_b.status_code = 302
    mock_resp_b.headers = {"Location": "https://example.com/a"}

    call_count = 0
    def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return mock_resp_a if call_count == 1 else mock_resp_b

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", side_effect=mock_get):
            with pytest.raises(RedirectSecurityError) as exc:
                safe_fetch("https://example.com/a")
            assert "redirect loop" in str(exc.value).lower()


def test_redirect_limit_exceeded():
    """Verify that exceeding the max redirect limit is blocked."""
    def mock_get(url, *args, **kwargs):
        hop = int(url.split("/")[-1])
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"Location": f"https://example.com/hop/{hop + 1}"}
        return resp

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", side_effect=mock_get):
            with pytest.raises(RedirectSecurityError) as exc:
                safe_fetch("https://example.com/hop/1", max_redirects=3)
            assert "redirect limit exceeded" in str(exc.value).lower()


# ==============================================================================
# 5. Response Size Limit Tests
# ==============================================================================

def test_oversized_content_length_rejected():
    """Verify that responses with Content-Length larger than max_bytes are rejected."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Length": str(10 * 1024 * 1024)}  # 10 MB

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", return_value=mock_resp):
            with pytest.raises(ResponseSizeLimitError) as exc:
                safe_fetch("https://example.com", max_bytes=1024 * 1024)
            assert "content-length" in str(exc.value).lower()


def test_oversized_chunked_response_rejected():
    """Verify that streamed chunked responses exceeding max_bytes are stopped."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}  # No Content-Length (e.g. chunked transfer)
    mock_resp.iter_content.return_value = [b"A" * 1024] * 20  # 20 KB total

    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", return_value=mock_resp):
            with pytest.raises(ResponseSizeLimitError) as exc:
                safe_fetch("https://example.com", max_bytes=10 * 1024)  # 10 KB limit
            assert "exceeded limit" in str(exc.value).lower()


# ==============================================================================
# 6. Timeout Tests
# ==============================================================================

def test_request_timeout_handling():
    """Verify that network timeouts raise RequestTimeoutError."""
    import requests
    with patch("ssrf_validator.resolve_and_validate_hostname", return_value=["93.184.215.14"]):
        with patch("requests.Session.get", side_effect=requests.exceptions.Timeout("Read timed out")):
            with pytest.raises(RequestTimeoutError):
                safe_fetch("https://example.com")


def test_ssrf_session_ignores_environment_proxies():
    """Verify that SSRF session ignores environment proxies to prevent bypass."""
    import os
    from ssrf_validator import create_ssrf_session

    with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:8888", "HTTPS_PROXY": "http://127.0.0.1:8888"}):
        session = create_ssrf_session()
        assert session.trust_env is False
