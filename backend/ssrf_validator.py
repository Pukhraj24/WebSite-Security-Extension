"""
SSRF (Server-Side Request Forgery) Validator & Secure HTTP Fetcher.

This module enforces strict security boundaries on all outgoing network connections:
1. URL scheme validation (only HTTP and HTTPS permitted).
2. Embedded credential rejection (user:pass@host forbidden).
3. Hostname DNS resolution and comprehensive IP range verification (blocking
   loopback, private networks, carrier-grade NAT, link-local, cloud metadata,
   multicast, unspecified, broadcast, and IPv4-mapped IPv6).
4. Mixed DNS answer rejection (if any returned IP is unsafe, connection is denied).
5. DNS rebinding prevention via IP-pinned socket connections.
6. Safe redirect handling with cycle detection, redirect limits, and per-hop SSRF validation.
7. Streaming response size limits (preventing memory exhaustion/bombs).
8. Strict connection, read, and total request deadline timeouts.
"""

import ipaddress
import socket
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any

import requests
from requests.adapters import HTTPAdapter
import urllib3
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.poolmanager import PoolManager
from urllib3.util import connection


# ==============================================================================
# Security Exceptions
# ==============================================================================

class SSRFSecurityError(Exception):
    """Base exception for all SSRF and network security violations."""
    def __init__(self, message: str, code: str = "SSRF_BLOCKED"):
        super().__init__(message)
        self.code = code
        self.message = message


class InvalidURLError(SSRFSecurityError):
    """Raised when the URL format, scheme, or components are invalid or forbidden."""
    def __init__(self, message: str):
        super().__init__(message, code="INVALID_URL")


class PrivateIPAddressError(SSRFSecurityError):
    """Raised when an IP address resolves to a private, loopback, or restricted range."""
    def __init__(self, message: str):
        super().__init__(message, code="RESTRICTED_IP_ADDRESS")


class DNSResolutionError(SSRFSecurityError):
    """Raised when hostname resolution fails completely."""
    def __init__(self, message: str):
        super().__init__(message, code="DNS_RESOLUTION_FAILED")


class RedirectSecurityError(SSRFSecurityError):
    """Raised when redirects violate policy (loops, limits, or unsafe destinations)."""
    def __init__(self, message: str, code: str = "REDIRECT_ERROR"):
        super().__init__(message, code=code)


class ResponseSizeLimitError(SSRFSecurityError):
    """Raised when response body exceeds maximum allowed size."""
    def __init__(self, message: str):
        super().__init__(message, code="RESPONSE_TOO_LARGE")


class RequestTimeoutError(SSRFSecurityError):
    """Raised when network operations exceed connection or deadline timeouts."""
    def __init__(self, message: str):
        super().__init__(message, code="TIMEOUT")


# ==============================================================================
# IP Address Safety Verification
# ==============================================================================

# RFC 6598 Carrier-Grade NAT
CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")

# Documentation / Benchmarking ranges
TEST_NET_1 = ipaddress.ip_network("192.0.2.0/24")
TEST_NET_2 = ipaddress.ip_network("198.51.100.0/24")
TEST_NET_3 = ipaddress.ip_network("203.0.113.0/24")
BENCHMARK_NET = ipaddress.ip_network("198.18.0.0/15")
RESERVED_NET = ipaddress.ip_network("240.0.0.0/4")

# IPv6 Documentation / Discard
IPV6_DOC = ipaddress.ip_network("2001:db8::/32")
IPV6_DISCARD = ipaddress.ip_network("100::/64")


def is_safe_ip(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluate whether an IP address (IPv4 or IPv6) is a safe public address.

    Blocks:
    - Loopback (127.0.0.0/8, ::1)
    - Private RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Link-local and cloud metadata (169.254.0.0/16, fe80::/10)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Unspecified / Broadcast (0.0.0.0, 255.255.255.255, ::)
    - Carrier-grade NAT (100.64.0.0/10)
    - IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    - Reserved and documentation networks
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    # Check specific categories first to produce precise diagnostic messages
    if ip.is_unspecified:
        return False, f"Unspecified address ({ip}) is forbidden"

    if ip.is_loopback:
        return False, f"Loopback address ({ip}) is forbidden"

    if ip.is_link_local:
        return False, f"Link-local / Cloud metadata address ({ip}) is forbidden"

    if ip.is_multicast:
        return False, f"Multicast address ({ip}) is forbidden"

    # Specific IPv4 checks
    if isinstance(ip, ipaddress.IPv4Address):
        if ip == ipaddress.IPv4Address("255.255.255.255"):
            return False, "Broadcast address (255.255.255.255) is forbidden"

        if (
            ip in TEST_NET_1
            or ip in TEST_NET_2
            or ip in TEST_NET_3
            or ip in BENCHMARK_NET
        ):
            return False, f"Documentation/Benchmark address ({ip}) is forbidden"

        if ip in RESERVED_NET:
            return False, f"Reserved address ({ip}) is forbidden"

        if ip in CARRIER_GRADE_NAT:
            return False, f"Carrier-Grade NAT address ({ip}) is forbidden"

    # Specific IPv6 checks
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in IPV6_DOC or ip in IPV6_DISCARD:
            return False, f"Documentation/Discard IPv6 address ({ip}) is forbidden"

    if ip.is_reserved:
        return False, f"Reserved address ({ip}) is forbidden"

    if ip.is_private:
        return False, f"Private network address ({ip}) is forbidden"

    return True, "Safe public IP"


# ==============================================================================
# URL Parsing & Hostname Validation
# ==============================================================================

def validate_url(url: str) -> Dict[str, Any]:
    """
    Parse and validate a URL against scheme, credential, and structure rules.
    """
    if not url or not isinstance(url, str):
        raise InvalidURLError("URL must be a non-empty string.")

    url = url.strip()

    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception as e:
        raise InvalidURLError(f"Failed to parse URL: {e}")

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidURLError(
            f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."
        )

    # Reject embedded credentials (user:pass@host)
    if parsed.username or parsed.password:
        raise InvalidURLError(
            "URLs containing embedded credentials (username/password) are forbidden."
        )

    hostname = parsed.hostname
    if not hostname:
        raise InvalidURLError("URL does not contain a valid hostname.")

    # Determine port
    try:
        port = parsed.port
    except ValueError:
        raise InvalidURLError("URL contains an invalid port number.")

    if port is None:
        port = 443 if scheme == "https" else 80
    elif not (1 <= port <= 65535):
        raise InvalidURLError(f"Port {port} is out of valid range (1-65535).")

    return {
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "netloc": parsed.netloc,
        "original_url": url
    }


def resolve_and_validate_hostname(hostname: str, port: int = 80) -> List[str]:
    """
    Resolve a hostname via DNS and verify that EVERY resolved IP address is safe.

    If ANY resolved IP is in a forbidden range (e.g. mixed public/private answers),
    the entire resolution is rejected with PrivateIPAddressError.
    """
    hostname = hostname.strip().rstrip(".")

    # If hostname is a raw IP literal:
    try:
        ipaddress.ip_address(hostname)
        is_safe, reason = is_safe_ip(hostname)
        if not is_safe:
            raise PrivateIPAddressError(
                f"Direct IP access to '{hostname}' is restricted: {reason}"
            )
        return [hostname]
    except ValueError:
        pass  # Hostname is a domain name, proceed to DNS resolution

    try:
        # Resolve both IPv4 and IPv6 addresses
        addr_info = socket.getaddrinfo(
            hostname,
            port,
            proto=socket.IPPROTO_TCP,
            type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise DNSResolutionError(f"DNS resolution failed for '{hostname}': {e}")
    except Exception as e:
        raise DNSResolutionError(f"Unexpected error resolving '{hostname}': {e}")

    if not addr_info:
        raise DNSResolutionError(f"No DNS records returned for '{hostname}'")

    # Extract all distinct resolved IP addresses
    resolved_ips: List[str] = []
    seen = set()
    for item in addr_info:
        sockaddr = item[4]
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            resolved_ips.append(ip)

    # Validate EVERY resolved address
    for ip in resolved_ips:
        is_safe, reason = is_safe_ip(ip)
        if not is_safe:
            raise PrivateIPAddressError(
                f"Domain '{hostname}' resolved to unsafe address '{ip}': {reason}"
            )

    return resolved_ips


# ==============================================================================
# Safe Socket Creation (For TLS diagnostics & direct connections)
# ==============================================================================

def create_safe_socket(
    hostname: str,
    port: int,
    timeout: float = 5.0
) -> Tuple[socket.socket, str]:
    """
    Create a connected TCP socket to a validated public IP for hostname.
    Ensures that TLS inspection or direct connections never bypass SSRF rules.
    """
    validated_ips = resolve_and_validate_hostname(hostname, port)
    pinned_ip = validated_ips[0]

    sock = connection.create_connection(
        (pinned_ip, port),
        timeout=timeout
    )
    return sock, pinned_ip


# ==============================================================================
# IP-Pinned Urllib3 & Requests Transport Adapters (Anti-DNS-Rebinding)
# ==============================================================================

class SSRFHTTPConnection(HTTPConnection):
    """
    urllib3 HTTP connection that resolves DNS, validates all IPs, and connects
    directly to the pinned IP to eliminate DNS rebinding (TOCTOU) risks.
    """
    def _new_conn(self) -> socket.socket:
        host = self._dns_host
        port = self.port

        validated_ips = resolve_and_validate_hostname(host, port)
        pinned_ip = validated_ips[0]

        try:
            sock = connection.create_connection(
                (pinned_ip, port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
            return sock
        except socket.gaierror as e:
            raise NameResolutionError(self.host, self, e) from e
        except TimeoutError as e:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out (connect timeout={self.timeout})"
            ) from e
        except OSError as e:
            raise NewConnectionError(
                self, f"Failed to establish a new connection to {self.host}: {e}"
            ) from e


class SSRFHTTPSConnection(HTTPSConnection):
    """
    urllib3 HTTPS connection that connects socket directly to the pinned IP
    while preserving original hostname in TLS SNI and certificate verification.
    """
    def _new_conn(self) -> socket.socket:
        host = self._dns_host
        port = self.port

        validated_ips = resolve_and_validate_hostname(host, port)
        pinned_ip = validated_ips[0]

        try:
            sock = connection.create_connection(
                (pinned_ip, port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
            return sock
        except socket.gaierror as e:
            raise NameResolutionError(self.host, self, e) from e
        except TimeoutError as e:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out (connect timeout={self.timeout})"
            ) from e
        except OSError as e:
            raise NewConnectionError(
                self, f"Failed to establish a new connection to {self.host}: {e}"
            ) from e


class SSRFConnectionPool(HTTPConnectionPool):
    ConnectionCls = SSRFHTTPConnection


class SSRFHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = SSRFHTTPSConnection


class SSRFAdapter(HTTPAdapter):
    """
    Custom Requests HTTPAdapter that uses SSRFConnectionPool for anti-rebinding.
    """
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs
        )
        self.poolmanager.pool_classes_by_scheme = {
            "http": SSRFConnectionPool,
            "https": SSRFHTTPSConnectionPool,
        }


def create_ssrf_session() -> requests.Session:
    """Create a configured requests.Session with SSRF protection mounted."""
    session = requests.Session()
    adapter = SSRFAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ==============================================================================
# Safe HTTP Fetcher
# ==============================================================================

def safe_fetch(
    url: str,
    max_redirects: int = 5,
    total_timeout: float = 10.0,
    connect_timeout: float = 3.0,
    read_timeout: float = 5.0,
    max_bytes: int = 2 * 1024 * 1024  # 2 MB limit
) -> Tuple[requests.Response, List[Dict[str, Any]], str, float]:
    """
    Safely fetch a URL with comprehensive security controls:
    - Pre-validates URL scheme and credentials.
    - Resolves and verifies all IPs against SSRF restrictions.
    - Follows redirects manually with SSRF checks on every hop.
    - Prevents redirect cycles and limits redirect count.
    - Enforces streaming response size limits (even on chunked or missing Content-Length).
    - Enforces connection timeout, read timeout, and total deadline.
    - Always closes intermediate and failed responses to prevent socket leaks.

    Returns:
        (final_response, redirect_chain, final_url, elapsed_time_ms)
    """
    start_time = time.monotonic()
    deadline = start_time + total_timeout

    # Validate initial URL and destination IP
    validated_url_info = validate_url(url)
    resolve_and_validate_hostname(
        validated_url_info["hostname"],
        validated_url_info["port"]
    )
    current_url = validated_url_info["original_url"]

    redirect_chain: List[Dict[str, Any]] = []
    visited_urls = {current_url}
    redirect_count = 0

    session = create_ssrf_session()

    try:
        while True:
            # Check deadline before each request
            time_left = deadline - time.monotonic()
            if time_left <= 0:
                raise RequestTimeoutError("Total request deadline exceeded.")

            hop_timeout = (
                min(connect_timeout, max(0.5, time_left)),
                min(read_timeout, max(0.5, time_left))
            )

            response: Optional[requests.Response] = None
            try:
                response = session.get(
                    current_url,
                    timeout=hop_timeout,
                    allow_redirects=False,
                    stream=True,
                    headers={
                        "User-Agent": "WebsiteSecurityAnalyzer/1.0"
                    }
                )
            except requests.exceptions.Timeout as e:
                raise RequestTimeoutError(f"Request to '{current_url}' timed out: {e}")
            except requests.exceptions.SSLError:
                # Re-raise SSL errors so caller can perform TLS diagnostics
                raise
            except requests.exceptions.RequestException as e:
                # Check if underlying cause was an SSRFSecurityError
                curr = e
                while curr:
                    if isinstance(curr, SSRFSecurityError):
                        raise curr
                    curr = getattr(curr, "__cause__", None) or getattr(curr, "__context__", None)
                raise

            status = response.status_code

            # Handle 3xx Redirects
            if 300 <= status < 400 and "Location" in response.headers:
                location = response.headers["Location"].strip()
                response.close()

                redirect_count += 1
                if redirect_count > max_redirects:
                    raise RedirectSecurityError(
                        f"Redirect limit exceeded (maximum {max_redirects} redirects permitted).",
                        code="REDIRECT_LIMIT_EXCEEDED"
                    )

                next_url = urllib.parse.urljoin(current_url, location)

                # Validate next URL and resolve its IP BEFORE making any connection
                next_info = validate_url(next_url)
                resolve_and_validate_hostname(
                    next_info["hostname"],
                    next_info["port"]
                )

                if next_url in visited_urls:
                    raise RedirectSecurityError(
                        f"Redirect loop detected: '{next_url}' was visited previously.",
                        code="REDIRECT_LOOP_DETECTED"
                    )

                visited_urls.add(next_url)
                redirect_chain.append({
                    "status_code": status,
                    "url": current_url,
                    "location": location
                })
                current_url = next_url
                continue

            # Final response reached: enforce response size limit
            content_length_header = response.headers.get("Content-Length")
            if content_length_header and content_length_header.isdigit():
                content_length = int(content_length_header)
                if content_length > max_bytes:
                    response.close()
                    raise ResponseSizeLimitError(
                        f"Content-Length ({content_length} bytes) exceeds limit of {max_bytes} bytes."
                    )

            # Read content in chunks to enforce size limit even with chunked transfer
            bytes_read = 0
            chunks = []
            try:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    bytes_read += len(chunk)
                    if bytes_read > max_bytes:
                        response.close()
                        raise ResponseSizeLimitError(
                            f"Streamed response body exceeded limit of {max_bytes} bytes."
                        )
                    chunks.append(chunk)
            except Exception:
                response.close()
                raise

            # Cache the read body so caller can inspect response.text / response.content safely
            response._content = b"".join(chunks)

            elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
            return response, redirect_chain, current_url, elapsed_ms

    finally:
        session.close()
