"""SSRF-safe fetch: URL and address vetting, pinned connections, redirects, caps. No network."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
import unittest
from unittest import mock

from altsource import fetch as fetchmod
from altsource.fetch import FetchError

HOST = "files.example.com"
OTHER = "cdn.example.net"
PUBLIC = "1.1.1.1"
PUBLIC2 = "8.8.8.8"
PUBLIC6 = "2606:4700:4700::1111"
BODY = b"IPA bytes " * 1000


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", fail_after=None):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body
        self.pos = 0
        self.fail_after = fail_after

    def getheader(self, name, default=None):
        return self.headers.get(name.lower(), default)

    def read(self, n):
        if self.fail_after is not None and self.pos >= self.fail_after:
            raise socket.timeout("stalled")
        chunk = self.body[self.pos:self.pos + min(n, 4096)]
        self.pos += len(chunk)
        return chunk


class FakeConnection:
    def __init__(self, net, host, port, ip, timeout):
        self.net = net
        self.host, self.port, self.ip, self.timeout = host, port, ip, timeout
        self.closed = False

    def request(self, method, path, headers):
        self.net.requests.append({"host": self.host, "port": self.port, "ip": self.ip, "method": method,
                                  "path": path, "headers": dict(headers)})
        error = self.net.connect_errors.get(self.ip)
        if error is not None:
            raise error
        self.path = path

    def getresponse(self):
        route = self.net.routes[(self.host, self.path)]
        return route() if callable(route) else route

    def close(self):
        self.closed = True


class FakeNet:
    """Resolver and connection factory standing in for DNS and HTTPS."""

    def __init__(self, dns=None, routes=None):
        self.dns = {HOST: [PUBLIC], OTHER: [PUBLIC2]}
        self.dns.update(dns or {})
        self.routes = routes or {}
        self.requests = []
        self.lookups = []
        self.connect_errors = {}

    def getaddrinfo(self, host, port, *args, **kwargs):
        self.lookups.append(host)
        try:
            ipaddress.ip_address(host)
            return self._infos([host], port)
        except ValueError:
            pass
        if host not in self.dns:
            raise socket.gaierror(socket.EAI_NONAME, "unknown")
        return self._infos(self.dns[host], port)

    @staticmethod
    def _infos(addresses, port):
        out = []
        for ip in addresses:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
            out.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
        return out

    def open_connection(self, host, port, ip, timeout):
        return FakeConnection(self, host, port, ip, timeout)


def ok(body=BODY, **headers):
    headers.setdefault("Content-Length", str(len(body)))
    return FakeResponse(200, headers, body)


def redirect(location, status=302):
    return FakeResponse(status, {"Location": location})


class FetchCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.dest = os.path.join(self.dir, "out.ipa")
        self.net = FakeNet(routes={(HOST, "/a.ipa"): ok})  # a fresh response per request
        patches = [mock.patch.object(fetchmod.socket, "getaddrinfo", self.net.getaddrinfo),
                   mock.patch.object(fetchmod, "open_connection", self.net.open_connection)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def fetch(self, url="https://%s/a.ipa" % HOST, **kwargs):
        return fetchmod.fetch(url, self.dest, **kwargs)

    def assertRejected(self, rule, url="https://%s/a.ipa" % HOST, **kwargs):
        with self.assertRaises(FetchError) as ctx:
            self.fetch(url, **kwargs)
        self.assertEqual(ctx.exception.rule, rule)
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(os.listdir(self.dir), [])  # no partial downloads left behind
        for secret in (HOST, OTHER, PUBLIC, "10.0.0.1", "leaky-host-0"):
            self.assertNotIn(secret, str(ctx.exception))
        return ctx.exception


class SuccessTests(FetchCase):
    def test_download(self):
        result = self.fetch()
        with open(self.dest, "rb") as fh:
            self.assertEqual(fh.read(), BODY)
        self.assertEqual(result.size, len(BODY))
        self.assertEqual(result.sha256, hashlib.sha256(BODY).hexdigest())
        self.assertEqual(result.redirects, 0)
        (req,) = self.net.requests
        self.assertEqual((req["host"], req["port"], req["ip"], req["method"], req["path"]),
                         (HOST, 443, PUBLIC, "GET", "/a.ipa"))
        self.assertEqual(req["headers"]["Accept-Encoding"], "identity")
        self.assertNotIn("Host", req["headers"])  # http.client sends the hostname itself

    def test_query_port_and_fragment(self):
        self.net.routes[(HOST, "/a.ipa?x=1")] = ok()
        self.fetch("https://%s:8443/a.ipa?x=1#frag" % HOST)
        self.assertEqual((self.net.requests[0]["port"], self.net.requests[0]["path"]), (8443, "/a.ipa?x=1"))

    def test_sha256_forms(self):
        digest = hashlib.sha256(BODY).hexdigest()
        for value in (digest, digest.upper(), "sha256:" + digest):
            self.fetch(sha256=value)

    def test_sha256_mismatch_keeps_previous_file(self):
        with open(self.dest, "wb") as fh:
            fh.write(b"previous")
        with self.assertRaises(FetchError) as ctx:
            self.fetch(sha256="0" * 64)
        self.assertEqual(ctx.exception.rule, "sha256-mismatch")
        with open(self.dest, "rb") as fh:
            self.assertEqual(fh.read(), b"previous")
        self.assertEqual(os.listdir(self.dir), ["out.ipa"])

    def test_ipv6_and_second_address(self):
        self.net.dns[HOST] = [PUBLIC, PUBLIC6]
        self.net.connect_errors[PUBLIC] = ConnectionRefusedError()
        self.fetch()
        self.assertEqual([r["ip"] for r in self.net.requests], [PUBLIC, PUBLIC6])

    def test_custom_headers(self):
        self.fetch(headers={"Authorization": "token x", "Accept": "application/octet-stream"})
        headers = self.net.requests[0]["headers"]
        self.assertEqual(headers["Authorization"], "token x")
        self.assertEqual(headers["Accept"], "application/octet-stream")


class UrlTests(FetchCase):
    def test_rejected_urls_make_no_lookup(self):
        cases = {
            "url-scheme": ["http://%s/a.ipa" % HOST, "ftp://%s/a.ipa" % HOST, "file:///etc/passwd", "//%s/a" % HOST],
            "url-userinfo": ["https://user:pw@%s/a.ipa" % HOST, "https://user@%s/a.ipa" % HOST,
                             "https://%s@10.0.0.1/a" % HOST],
            "url-host": ["https:///a.ipa", "https://bad_host.example/a", "https://-x.example/a",
                         "https://%s./a" % HOST, "https://2130706433/a"],
            "url-invalid": ["", "https://%s/a b" % HOST, "https://%s/\u00e9" % HOST, "https://%s/a\n" % HOST,
                            "https://%s:99999/a" % HOST, "https://%s\\@x/a" % HOST, "https://%s:0/a" % HOST,
                            "https://%s/" % HOST + "a" * 9000],
        }
        for rule, urls in cases.items():
            for url in urls:
                with self.subTest(url=url[:60]):
                    self.assertRejected(rule, url)
        self.assertEqual(self.net.lookups, [])
        self.assertEqual(self.net.requests, [])

    def test_invalid_sha256_is_refused_before_any_request(self):
        self.assertRejected("sha256-invalid", sha256="abc")
        self.assertEqual(self.net.requests, [])


class AddressTests(FetchCase):
    BLOCKED = ["10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "100.127.255.254", "172.16.0.1",
               "192.168.1.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255", "192.0.2.1",
               "198.18.0.1", "::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "fec0::1",
               "::ffff:10.0.0.1", "::ffff:1.1.1.1", "64:ff9b::a00:1", "2002:a00:1::1", "2001:db8::1",
               "2001::1", "::10.0.0.1", "not an ip"]
    ALLOWED = [PUBLIC, PUBLIC2, "140.82.112.3", PUBLIC6, "2a00:1450:4001::200e"]

    def test_address_allowed(self):
        for address in self.BLOCKED:
            self.assertFalse(fetchmod.address_allowed(address), address)
        for address in self.ALLOWED:
            self.assertTrue(fetchmod.address_allowed(address), address)

    def test_private_resolution_is_refused_before_connecting(self):
        for addresses in (["10.0.0.1"], [PUBLIC, "127.0.0.1"], ["::ffff:10.0.0.1"], ["fe80::1%en0"]):
            with self.subTest(addresses=addresses):
                self.net.dns["leaky-host-0.example.invalid"] = addresses
                self.assertRejected("private-address", "https://leaky-host-0.example.invalid/a.ipa")
        self.assertEqual(self.net.requests, [])

    def test_ip_literals(self):
        for url in ("https://127.0.0.1/a", "https://[::1]/a", "https://169.254.169.254/latest/meta-data",
                    "https://[::ffff:7f00:1]/a"):
            with self.subTest(url=url):
                self.assertRejected("private-address", url)
        self.assertEqual(self.net.requests, [])

    def test_unresolvable(self):
        self.assertRejected("resolve-failed", "https://missing.example.org/a.ipa")


class RedirectTests(FetchCase):
    def test_redirect_chain_is_followed(self):
        self.net.routes[(HOST, "/start")] = redirect("/a.ipa", 301)
        result = self.fetch("https://%s/start" % HOST)
        self.assertEqual(result.redirects, 1)

    def test_redirect_to_private_address(self):
        self.net.dns["internal.example.org"] = ["192.168.1.10"]
        self.net.routes[(HOST, "/start")] = redirect("https://internal.example.org/a.ipa")
        self.assertRejected("private-address", "https://%s/start" % HOST)
        self.assertEqual(len(self.net.requests), 1)

    def test_redirect_to_http_or_userinfo(self):
        self.net.routes[(HOST, "/start")] = redirect("http://%s/a.ipa" % HOST)
        self.assertRejected("url-scheme", "https://%s/start" % HOST)
        self.net.routes[(HOST, "/start")] = redirect("https://u:p@%s/a.ipa" % OTHER)
        self.assertRejected("url-userinfo", "https://%s/start" % HOST)

    def test_authorization_never_crosses_hosts(self):
        self.net.routes[(HOST, "/start")] = redirect("/hop")
        self.net.routes[(HOST, "/hop")] = redirect("https://%s/x" % OTHER, 307)
        self.net.routes[(OTHER, "/x")] = redirect("https://%s/a.ipa" % HOST, 308)
        self.fetch("https://%s/start" % HOST, headers={"Authorization": "token x", "Cookie": "c=1", "X-Other": "y"})
        seen = [(r["host"], "Authorization" in r["headers"], "Cookie" in r["headers"], r["headers"].get("X-Other"))
                for r in self.net.requests]
        self.assertEqual(seen, [(HOST, True, True, "y"), (HOST, True, True, "y"), (OTHER, False, False, "y"),
                                (HOST, False, False, "y")])

    def test_port_change_is_another_origin(self):
        self.net.routes[(HOST, "/start")] = redirect("https://%s:8443/a.ipa" % HOST)
        self.fetch("https://%s/start" % HOST, headers={"Authorization": "token x"})
        self.assertNotIn("Authorization", self.net.requests[1]["headers"])

    def test_too_many_redirects(self):
        self.net.routes[(HOST, "/loop")] = redirect("/loop")
        self.assertRejected("too-many-redirects", "https://%s/loop" % HOST, max_redirects=2)
        self.assertEqual(len(self.net.requests), 3)

    def test_redirect_without_location(self):
        self.net.routes[(HOST, "/start")] = FakeResponse(302, {})
        self.assertRejected("redirect-invalid", "https://%s/start" % HOST)


class ResponseTests(FetchCase):
    def test_http_errors(self):
        for status in (404, 500, 204, 206):
            with self.subTest(status=status):
                self.net.routes[(HOST, "/a.ipa")] = FakeResponse(status, {}, b"error page")
                self.assertRejected("http-%d" % status)

    def test_declared_length_over_cap(self):
        response = ok()
        self.net.routes[(HOST, "/a.ipa")] = response
        self.assertRejected("too-large", max_bytes=100)
        self.assertEqual(response.pos, 0)  # refused before reading the body

    def test_streamed_body_over_cap(self):
        self.net.routes[(HOST, "/a.ipa")] = FakeResponse(200, {}, BODY)
        self.assertRejected("too-large", max_bytes=len(BODY) - 1)
        self.net.routes[(HOST, "/a.ipa")] = FakeResponse(200, {}, BODY)
        self.assertEqual(self.fetch(max_bytes=len(BODY)).size, len(BODY))

    def test_encoded_truncated_and_stalled_bodies(self):
        self.net.routes[(HOST, "/a.ipa")] = ok(**{"Content-Encoding": "gzip"})
        self.assertRejected("content-encoding")
        self.net.routes[(HOST, "/a.ipa")] = FakeResponse(200, {"Content-Length": str(len(BODY) + 1)}, BODY)
        self.assertRejected("http-error")
        self.net.routes[(HOST, "/a.ipa")] = FakeResponse(200, {}, BODY, fail_after=4096)
        self.assertRejected("timeout")
        self.net.routes[(HOST, "/a.ipa")] = ok()
        self.assertRejected("timeout", deadline=-1)

    def test_transport_errors(self):
        self.net.connect_errors[PUBLIC] = ssl.SSLCertVerificationError("bad certificate")
        self.assertRejected("tls-error")
        self.net.connect_errors[PUBLIC] = socket.timeout("slow")
        self.assertRejected("timeout")
        self.net.connect_errors[PUBLIC] = ConnectionRefusedError()
        self.assertRejected("connect-failed")

    def test_header_injection(self):
        self.assertRejected("header-invalid", headers={"X-A": "1\r\nHost: evil"})
        self.assertRejected("header-invalid", headers={"Host": "other.example"})
        self.assertRejected("header-invalid", headers={"Bad Name": "1"})


class FakeSocket:
    def __init__(self, peer):
        self.peer = peer
        self.closed = False

    def getpeername(self):
        return (self.peer, 443)

    def close(self):
        self.closed = True


class FakeContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True
    post_handshake_auth = None

    def __init__(self):
        self.wrapped = []

    def set_alpn_protocols(self, protocols):
        pass

    def wrap_socket(self, sock, server_hostname=None):
        self.wrapped.append((sock, server_hostname))
        return sock


class PinnedConnectionTests(unittest.TestCase):
    def test_connects_to_vetted_ip_with_sni_for_the_host(self):
        context = FakeContext()
        sock = FakeSocket(PUBLIC)
        conn = fetchmod.PinnedHTTPSConnection(HOST, 443, PUBLIC, timeout=5, context=context)
        with mock.patch.object(fetchmod.socket, "create_connection", return_value=sock) as create:
            conn.connect()
        create.assert_called_once_with((PUBLIC, 443), 5)
        self.assertEqual(context.wrapped, [(sock, HOST)])
        self.assertIs(conn.sock, sock)
        self.assertEqual(conn.host, HOST)  # used for the Host header

    def test_peer_mismatch(self):
        for peer in ("10.0.0.1", PUBLIC2):
            sock = FakeSocket(peer)
            context = FakeContext()
            conn = fetchmod.PinnedHTTPSConnection(HOST, 443, PUBLIC, timeout=5, context=context)
            with mock.patch.object(fetchmod.socket, "create_connection", return_value=sock):
                with self.assertRaises(FetchError) as ctx:
                    conn.connect()
            self.assertEqual(ctx.exception.rule, "peer-mismatch")
            self.assertTrue(sock.closed)
            self.assertEqual(context.wrapped, [])

    def test_tls_context_verifies(self):
        context = fetchmod.tls_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_default_factory_builds_a_pinned_connection(self):
        conn = fetchmod.open_connection(HOST, 443, PUBLIC, 7)
        self.assertIsInstance(conn, fetchmod.PinnedHTTPSConnection)
        self.assertEqual((conn.host, conn.port, conn.vetted_ip, conn.timeout), (HOST, 443, PUBLIC, 7))


if __name__ == "__main__":
    unittest.main()
