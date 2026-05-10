"""
Functional tests: real mitmproxy process + in-process mock HTTP server.

The proxy fixture starts mitmdump as a subprocess, an echo server as a thread,
and yields connection details. Tests use urllib with HTTP_PROXY set to talk
through the proxy exactly as an agent would.

Run with:  uv run pytest test_functional.py -v
"""

import datetime
import ipaddress
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = pathlib.Path(__file__).parent
MITMDUMP = str(pathlib.Path(sys.executable).parent / "mitmdump")


# ── Helpers ────────────────────────────────────────────────────────────────────

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EchoHandler(BaseHTTPRequestHandler):
    """Returns request path + headers as JSON so tests can inspect both."""

    def do_GET(self):
        body = json.dumps({
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class CookieHandler(BaseHTTPRequestHandler):
    """Returns a fixed set of Set-Cookie headers to test proxy cookie filtering."""

    COOKIES = ["csrftoken=abc123", "session=xyz789", "tracker=evil"]

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        for cookie in self.COOKIES:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _ForceProxyHandler(urllib.request.ProxyHandler):
    """ProxyHandler that ignores no_proxy — needed because the system no_proxy
    typically excludes 127.0.0.1/localhost, which is where our echo server runs."""

    def proxy_open(self, req, proxy, type):
        # Temporarily clear no_proxy so localhost requests go through the proxy
        saved = {k: os.environ.pop(k, None) for k in ("no_proxy", "NO_PROXY")}
        try:
            return super().proxy_open(req, proxy, type)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v


def agent_opener(proxy_url: str) -> urllib.request.OpenerDirector:
    """urllib opener that forces all HTTP through proxy_url regardless of no_proxy."""
    return urllib.request.build_opener(
        _ForceProxyHandler({"http": proxy_url})
    )


def _make_server_cert(tmp: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Generate a self-signed TLS certificate for the H2 test server."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp / "server.crt"
    key_path = tmp / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class H2EchoServer(threading.Thread):
    """TLS + HTTP/2 server that records request headers and echoes them as JSON.

    Uses the h2 library directly so that validate_inbound_headers (True by
    default) will raise ProtocolError—and ultimately send RST_STREAM—when it
    receives an uppercase header name, reproducing the real-world failure.
    """

    def __init__(self, host: str, port: int, certfile: str, keyfile: str):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self._received: dict[str, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        ctx.set_alpn_protocols(["h2"])
        self._ctx = ctx

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(10)
        self._sock.settimeout(1.0)

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                tls = self._ctx.wrap_socket(raw, server_side=True)
                threading.Thread(target=self._handle, args=(tls,), daemon=True).start()
            except ssl.SSLError:
                raw.close()

    def _handle(self, conn: ssl.SSLSocket) -> None:
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        h2c = h2.connection.H2Connection(config=cfg)
        h2c.initiate_connection()
        conn.sendall(h2c.data_to_send(65536))

        pending: dict[int, dict] = {}
        try:
            while True:
                try:
                    data = conn.recv(65536)
                except OSError:
                    return
                if not data:
                    return

                try:
                    events = h2c.receive_data(data)
                except h2.exceptions.ProtocolError:
                    # Upstream sent an invalid header (e.g. uppercase name).
                    # h2 has already queued a RST_STREAM/GOAWAY; flush and exit.
                    conn.sendall(h2c.data_to_send(65536))
                    return

                conn.sendall(h2c.data_to_send(65536))

                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        pending[ev.stream_id] = dict(ev.headers)
                        if ev.stream_ended is not None:
                            self._respond(h2c, ev.stream_id, pending.pop(ev.stream_id))
                    elif isinstance(ev, h2.events.DataReceived):
                        h2c.acknowledge_received_data(
                            ev.flow_controlled_length, ev.stream_id
                        )
                        if ev.stream_ended is not None and ev.stream_id in pending:
                            self._respond(h2c, ev.stream_id, pending.pop(ev.stream_id))
                    elif isinstance(ev, h2.events.StreamEnded):
                        if ev.stream_id in pending:
                            self._respond(h2c, ev.stream_id, pending.pop(ev.stream_id))
                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        return

                conn.sendall(h2c.data_to_send(65536))
        finally:
            conn.close()

    def _respond(self, h2c: h2.connection.H2Connection, sid: int, hdrs: dict) -> None:
        with self._lock:
            self._received = hdrs
        body = json.dumps(
            {"headers": {k: v for k, v in hdrs.items() if not k.startswith(":")}}
        ).encode()
        h2c.send_headers(
            sid,
            [
                (":status", "200"),
                ("content-type", "application/json"),
                ("content-length", str(len(body))),
            ],
        )
        h2c.send_data(sid, body, end_stream=True)

    @property
    def received_headers(self) -> dict[str, str]:
        with self._lock:
            return dict(self._received)

    def shutdown(self) -> None:
        self._stop.set()
        self._sock.close()


@contextmanager
def _h2_proxy_context(tmp: pathlib.Path, config_text: str):
    """Spin up a TLS h2 server and a mitmdump proxy; yield connection details."""
    server_port = free_port()
    proxy_port = free_port()
    management_port = free_port()

    cert_path, key_path = _make_server_cert(tmp)
    h2_server = H2EchoServer("127.0.0.1", server_port, str(cert_path), str(key_path))
    h2_server.start()

    config = tmp / "config.yaml"
    config.write_text(config_text + f"\nmanagement_port: {management_port}\n")

    proc = subprocess.Popen(
        [
            MITMDUMP,
            "-s", "addon.py",
            "--listen-port", str(proxy_port),
            "--set", f"confdir={tmp}",
            "--set", "ssl_insecure=true",   # accept our self-signed server cert
        ],
        cwd=HERE,
        env={**os.environ, "PROXY_CONFIG": str(config)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        proc.terminate()
        h2_server.shutdown()
        pytest.fail("Proxy did not start in time")

    mitm_ca = tmp / "mitmproxy-ca-cert.pem"
    deadline = time.time() + 5
    while not mitm_ca.exists() and time.time() < deadline:
        time.sleep(0.1)
    if not mitm_ca.exists():
        proc.terminate()
        h2_server.shutdown()
        pytest.fail("mitmproxy CA cert not found in confdir")

    try:
        yield {
            "h2_server": h2_server,
            "server_url": f"https://127.0.0.1:{server_port}",
            "proxy_url": f"http://127.0.0.1:{proxy_port}",
            "mitm_ca": str(mitm_ca),
        }
    finally:
        proc.terminate()
        proc.wait()
        h2_server.shutdown()


# ── Fixture factory ────────────────────────────────────────────────────────────

@contextmanager
def _proxy_context(tmp, handler_class, config_text):
    """Spin up an HTTP server and a mitmdump proxy; yield connection details."""
    server_port = free_port()
    server = HTTPServer(("127.0.0.1", server_port), handler_class)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    management_port = free_port()
    config = tmp / "config.yaml"
    config.write_text(config_text + f"\nmanagement_port: {management_port}\n")

    proxy_port = free_port()
    proc = subprocess.Popen(
        [MITMDUMP, "-s", "addon.py", "--listen-port", str(proxy_port),
         "--set", f"confdir={tmp}"],
        cwd=HERE,
        env={
            **os.environ,
            "PROXY_CONFIG": str(config),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.fail("Proxy did not start in time")

    try:
        yield {
            "opener": agent_opener(f"http://127.0.0.1:{proxy_port}"),
            "server_url": f"http://127.0.0.1:{server_port}",
        }
    finally:
        proc.terminate()
        proc.wait()
        server.shutdown()


@pytest.fixture(scope="module")
def proxy(tmp_path_factory):
    config_text = (
        "allowed_hosts:\n"
        "  - host: 127.0.0.1\n"
        "credentials:\n"
        "  - host: 127.0.0.1\n"
        "    header: X-Api-Key\n"
        "    fake_value: fake-key\n"
        "    real_value: real-key\n"
    )
    with _proxy_context(
        tmp_path_factory.mktemp("functional"),
        EchoHandler,
        config_text,
    ) as ctx:
        yield ctx


@pytest.fixture(scope="module")
def proxy_cookie(tmp_path_factory):
    with _proxy_context(
        tmp_path_factory.mktemp("functional_cookie"),
        CookieHandler,
        "allowed_hosts:\n"
        "  - host: 127.0.0.1\n"
        "    allow_response_cookies:\n"
        "      - csrftoken\n",
    ) as ctx:
        yield ctx


@pytest.fixture
def proxy_secrets(tmp_path):
    """Proxy fixture that loads real_value from a secrets_file."""
    secrets = tmp_path / "secrets.yaml"
    secrets.write_text("REAL_API_KEY: real-key\n")
    config_text = (
        f"secrets_file: {secrets}\n"
        "allowed_hosts:\n"
        "  - host: 127.0.0.1\n"
        "credentials:\n"
        "  - host: 127.0.0.1\n"
        "    header: X-Api-Key\n"
        "    fake_value: fake-key\n"
        '    real_value: "${REAL_API_KEY}"\n'
    )
    with _proxy_context(tmp_path, EchoHandler, config_text) as ctx:
        yield ctx


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_blocked_domain_returns_403(proxy):
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy["opener"].open("http://blocked.example.com/")
    assert exc.value.code == 403


def test_allowed_domain_reaches_server(proxy):
    resp = proxy["opener"].open(proxy["server_url"] + "/hello")
    data = json.loads(resp.read())
    assert data["path"] == "/hello"


def test_credential_swap(proxy):
    req = urllib.request.Request(
        proxy["server_url"] + "/api",
        headers={"X-Api-Key": "fake-key"},
    )
    data = json.loads(proxy["opener"].open(req).read())
    # Echo server must see the real key, never the fake one
    assert data["headers"].get("x-api-key") == "real-key"


def test_credential_swap_with_secrets_file(proxy_secrets):
    """Credential real_value resolved from a secrets_file at startup."""
    req = urllib.request.Request(
        proxy_secrets["server_url"] + "/api",
        headers={"X-Api-Key": "fake-key"},
    )
    data = json.loads(proxy_secrets["opener"].open(req).read())
    assert data["headers"].get("x-api-key") == "real-key"


# ── Cookie filtering tests ──────────────────────────────────────────────────────

def test_cookie_filtering_keeps_allowed(proxy_cookie):
    resp = proxy_cookie["opener"].open(proxy_cookie["server_url"] + "/")
    cookies = resp.info().get_all("set-cookie") or []
    cookie_names = [c.split("=")[0].strip() for c in cookies]
    assert "csrftoken" in cookie_names


def test_cookie_filtering_strips_others(proxy_cookie):
    resp = proxy_cookie["opener"].open(proxy_cookie["server_url"] + "/")
    cookies = resp.info().get_all("set-cookie") or []
    cookie_names = [c.split("=")[0].strip() for c in cookies]
    assert "session" not in cookie_names
    assert "tracker" not in cookie_names


# ── HTTP/2 cookie injection tests ───────────────────────────────────────────────

@pytest.fixture
def proxy_h2_inject(tmp_path):
    """Proxy that injects a Cookie header; upstream is a TLS HTTP/2 server."""
    config_text = (
        "allowed_hosts:\n"
        "  - host: 127.0.0.1\n"
        "credentials:\n"
        "  - host: 127.0.0.1\n"
        "    header: Cookie\n"
        "    real_value: session=real-session-value\n"
    )
    with _h2_proxy_context(tmp_path, config_text) as ctx:
        yield ctx


def test_h2_cookie_inject(proxy_h2_inject):
    """Cookie header injected via inject mode must reach an HTTP/2 upstream.

    Before the fix, the addon stored headers with the config-supplied name
    (e.g. 'Cookie' with uppercase C). mitmproxy's h2 layer only lowercases
    headers when the incoming request was HTTP/1.1; for HTTP/2 requests it
    passes the stored bytes unchanged. The upstream h2 server then raises
    ProtocolError on the uppercase name and sends RST_STREAM PROTOCOL_ERROR.

    The fix lowercases the header name at injection time, which is safe for
    HTTP/1.1 (case-insensitive) and correct for HTTP/2.
    """
    ctx = proxy_h2_inject

    ssl_ctx = ssl.create_default_context(cafile=ctx["mitm_ca"])
    with httpx.Client(
        http2=True,
        verify=ssl_ctx,
        proxy=httpx.Proxy(ctx["proxy_url"]),
    ) as client:
        resp = client.get(ctx["server_url"] + "/test")

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.http_version == "HTTP/2", (
        f"Expected HTTP/2 but got {resp.http_version!r}; "
        "the test only exercises the bug path when the agent uses HTTP/2"
    )
    data = resp.json()
    assert data["headers"].get("cookie") == "session=real-session-value", (
        f"Injected cookie not found; received headers: {data['headers']}"
    )
