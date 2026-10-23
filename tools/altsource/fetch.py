"""SSRF-safe HTTPS download for third-party IPAs (route 3).

``fetch`` only speaks HTTPS to hosts whose every resolved address is public. It connects to the
vetted address itself (no second DNS lookup), sends SNI and ``Host`` for the original hostname,
verifies the certificate for that hostname and checks that the peer address is the vetted one.
Redirects are validated again on every hop, credentials never cross hosts, and the body is
streamed to disk under a byte cap. Errors are ``FetchError`` with a stable ``rule`` id; messages
never contain the URL, the host or its addresses.
"""

from __future__ import annotations

import dataclasses
import hashlib
import http.client
import ipaddress
import os
import re
import socket
import ssl
import tempfile
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urljoin, urlsplit

CHUNK = 1 << 20
MAX_URL_LENGTH = 8192
USER_AGENT = "altsource-fetch"
REDIRECT_STATUSES = frozenset((301, 302, 303, 307, 308))
# headers that carry credentials; dropped once a redirect leaves the original origin
SENSITIVE_HEADERS = frozenset(("authorization", "cookie", "proxy-authorization"))
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

# Networks that are never fetched from, in addition to what ``ipaddress`` reports as non-global.
BLOCKED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",
    "fec0::/10", "ff00::/8",
))


class FetchError(Exception):
    """Download refused or failed. ``rule`` is a stable id safe to print."""

    def __init__(self, rule: str, message: str = ""):
        super().__init__(message or rule)
        self.rule = rule


@dataclasses.dataclass
class FetchResult:
    size: int
    sha256: str
    redirects: int


# -- validation ------------------------------------------------------------------------------------

def address_allowed(address: Any) -> bool:
    """True only for globally routable unicast addresses (IPv4-mapped IPv6 is always refused)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None:
            return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or not ip.is_global):
        return False
    return not any(ip.version == net.version and ip in net for net in BLOCKED_NETWORKS)


@dataclasses.dataclass(frozen=True)
class _Target:
    url: str
    host: str
    port: int
    path: str

    @property
    def origin(self) -> Tuple[str, int]:
        return (self.host, self.port)


def parse_url(url: str) -> _Target:
    """Validate ``url``: absolute https, no userinfo, ASCII host name or global IP literal."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise FetchError("url-invalid", "URL is empty or too long")
    if not url.isascii() or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url):
        raise FetchError("url-invalid", "URL contains whitespace, control or non-ASCII characters")
    if "\\" in url:  # parsers disagree on backslashes (WHATWG reads them as "/")
        raise FetchError("url-invalid", "URL contains a backslash")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise FetchError("url-invalid", "URL cannot be parsed") from None
    if parts.scheme.lower() != "https":
        raise FetchError("url-scheme", "only https URLs are fetched")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise FetchError("url-userinfo", "URLs with credentials are refused")
    host = (parts.hostname or "").lower()
    if not host:
        raise FetchError("url-host", "URL has no host")
    try:
        literal: Optional[Any] = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is None and (not _HOST_RE.match(host) or host.replace(".", "").isdigit()):
        raise FetchError("url-host", "URL host is not a valid DNS name")
    if port == 0:
        raise FetchError("url-invalid", "URL port is invalid")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    clean = parts._replace(fragment="").geturl()
    return _Target(url=clean, host=host, port=port or 443, path=path)


def resolve(host: str, port: int) -> List[str]:
    """Every address ``host`` resolves to; refuses the host if any address is not public."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        raise FetchError("resolve-failed", "host name cannot be resolved") from None
    addresses: List[str] = []
    for family, _, _, _, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise FetchError("private-address", "host resolves to a non-IP address")
        address = str(sockaddr[0]).split("%", 1)[0]
        if not address_allowed(address):
            raise FetchError("private-address", "host resolves to a non-public address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise FetchError("resolve-failed", "host name has no addresses")
    return addresses


def _same_ip(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a.split("%", 1)[0]) == ipaddress.ip_address(b.split("%", 1)[0])
    except ValueError:
        return False


# -- connection ------------------------------------------------------------------------------------

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection to a fixed, vetted IP; SNI, certificate check and Host use ``host``."""

    def __init__(self, host: str, port: int, ip: str, *, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self.vetted_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self.vetted_ip, self.port), self.timeout)
        try:
            peer = sock.getpeername()[0]
            if not _same_ip(str(peer), self.vetted_ip) or not address_allowed(str(peer).split("%", 1)[0]):
                raise FetchError("peer-mismatch", "connected peer is not the vetted address")
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def open_connection(host: str, port: int, ip: str, timeout: float) -> Any:
    """The connection used for one request (replaced in tests)."""
    return PinnedHTTPSConnection(host, port, ip, timeout=timeout, context=tls_context())


# -- download --------------------------------------------------------------------------------------

def _request_headers(target: _Target, extra: Mapping[str, str], cross_origin: bool) -> Dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"}
    for name, value in extra.items():
        if not _HEADER_NAME_RE.match(str(name)) or any(c in str(value) for c in "\r\n\x00"):
            raise FetchError("header-invalid", "request header is invalid")
        if name.lower() in ("host", "content-length", "transfer-encoding", "connection", "accept-encoding"):
            raise FetchError("header-invalid", "request header cannot be overridden")
        if cross_origin and name.lower() in SENSITIVE_HEADERS:
            continue
        headers[str(name)] = str(value)
    return headers


def _get(target: _Target, headers: Mapping[str, str], timeout: float) -> Tuple[Any, Any]:
    """Send GET to ``target`` over a vetted address; returns (connection, response)."""
    addresses = resolve(target.host, target.port)
    for ip in addresses:
        conn = open_connection(target.host, target.port, ip, timeout)
        try:
            conn.request("GET", target.path, headers=dict(headers))
            return conn, conn.getresponse()
        except FetchError:
            conn.close()
            raise
        except ssl.SSLError:  # includes certificate verification errors; do not try other addresses
            conn.close()
            raise FetchError("tls-error", "TLS handshake or certificate verification failed") from None
        except socket.timeout:
            conn.close()
            raise FetchError("timeout", "connection timed out") from None
        except (OSError, http.client.HTTPException):
            conn.close()
    raise FetchError("connect-failed", "no vetted address accepted the connection")


def _normalize_sha256(value: Optional[str]) -> Optional[str]:
    if value is None or value == "":
        return None
    text = str(value).strip().lower()
    if text.startswith("sha256:"):
        text = text[len("sha256:"):]
    if not _SHA256_RE.match(text):
        raise FetchError("sha256-invalid", "expected sha256 must be 64 hex digits")
    return text


def _stream(response: Any, dest: str, max_bytes: int, deadline: Optional[float],
            expected: Optional[str]) -> Tuple[int, str]:
    length = response.getheader("Content-Length")
    if length is not None:
        try:
            declared = int(length)
        except ValueError:
            raise FetchError("http-error", "invalid Content-Length") from None
        if declared < 0:
            raise FetchError("http-error", "invalid Content-Length")
        if declared > max_bytes:
            raise FetchError("too-large", "response exceeds the byte limit")
    encoding = (response.getheader("Content-Encoding") or "identity").strip().lower()
    if encoding != "identity":
        raise FetchError("content-encoding", "encoded responses are refused")
    directory = os.path.dirname(os.path.abspath(dest))
    fd, tmp = tempfile.mkstemp(prefix=".fetch-", suffix=".part", dir=directory)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as fh:
            while True:
                if deadline is not None and time.monotonic() > deadline:
                    raise FetchError("timeout", "download took too long")
                try:
                    chunk = response.read(CHUNK)
                except socket.timeout:
                    raise FetchError("timeout", "download stalled") from None
                except (OSError, http.client.HTTPException):
                    raise FetchError("http-error", "download interrupted") from None
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise FetchError("too-large", "response exceeds the byte limit")
                digest.update(chunk)
                fh.write(chunk)
        if length is not None and size != int(length):
            raise FetchError("http-error", "response is shorter than its Content-Length")
        if expected is not None and digest.hexdigest() != expected:
            raise FetchError("sha256-mismatch", "downloaded bytes do not match the expected sha256")
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return size, digest.hexdigest()


def fetch(url: str, dest: str, *, max_bytes: int = 2_000_000_000, timeout: float = 60,
          max_redirects: int = 5, sha256: Optional[str] = None, headers: Optional[Mapping[str, str]] = None,
          deadline: Optional[float] = None) -> FetchResult:
    """Download ``url`` to ``dest``; ``dest`` is only written when every check passed.

    ``timeout`` bounds each socket operation, ``deadline`` (seconds) optionally bounds the whole
    download, ``sha256`` (hex, optionally ``sha256:``-prefixed) must match the downloaded bytes.
    """
    expected = _normalize_sha256(sha256)
    extra = dict(headers or {})
    target = parse_url(url)
    origin = target.origin
    cross_origin = False
    end = time.monotonic() + deadline if deadline is not None else None
    for hop in range(max_redirects + 1):
        conn, response = _get(target, _request_headers(target, extra, cross_origin), timeout)
        try:
            status = int(response.status)
            if status in REDIRECT_STATUSES:
                location = response.getheader("Location")
                if not location:
                    raise FetchError("redirect-invalid", "redirect without Location")
                if hop == max_redirects:
                    raise FetchError("too-many-redirects", "too many redirects")
                target = parse_url(urljoin(target.url, location.strip()))
                cross_origin = cross_origin or target.origin != origin
                continue
            if status != 200:
                raise FetchError("http-%d" % status if 100 <= status <= 599 else "http-error",
                                 "unexpected HTTP status")
            size, digest = _stream(response, dest, max_bytes, end, expected)
        finally:
            conn.close()
        return FetchResult(size=size, sha256=digest, redirects=hop)
    raise FetchError("too-many-redirects", "too many redirects")  # pragma: no cover
