"""
Functional tests: real mitmproxy process + in-process mock HTTP server.

The proxy fixture starts mitmdump as a subprocess, an echo server as a thread,
and yields connection details. Tests use urllib with HTTP_PROXY set to talk
through the proxy exactly as an agent would.

Run with:  uv run pytest test_functional.py -v
"""

import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

HERE = pathlib.Path(__file__).parent
MITMDUMP = str(pathlib.Path(sys.executable).parent / "mitmdump")


# ── Helpers ────────────────────────────────────────────────────────────────────

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EchoHandler(BaseHTTPRequestHandler):
    """Returns request path + headers (+ body, if any) as JSON so tests can
    inspect what actually reached the upstream server.

    `received` records every request that reaches this handler, across every
    fixture that uses it (the class is shared). Tests that need to prove a
    denied request never reached upstream diff its length across the action
    instead of asserting an absolute value, since other tests share it.
    """

    received = []

    def _echo(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length else b""
        EchoHandler.received.append({"method": self.command, "path": self.path})
        body = json.dumps({
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": raw_body.decode("utf-8", "replace"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._echo()

    def do_POST(self):
        self._echo()

    def do_PUT(self):
        self._echo()

    def do_PATCH(self):
        self._echo()

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


class RecordingHandler(EchoHandler):
    """EchoHandler that also records every request's headers on the server
    object, so tests can assert what actually reached the upstream."""

    def _echo(self):
        self.server.received.append({k.lower(): v for k, v in self.headers.items()})
        super()._echo()


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


class RawTcpServer:
    """Plain TCP listener that records every accepted connection and the bytes
    it receives, echoing them back. Lets tests prove whether the proxy opened
    an upstream connection or relayed non-HTTP bytes."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        self.received = b""
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    def _echo(self, conn):
        with conn:
            while data := conn.recv(4096):
                self.received += data
                conn.sendall(data)

    def close(self):
        self.sock.close()


def raw_connect(proxy_port: int, target: str) -> tuple[socket.socket, bytes]:
    """Send a CONNECT for target through the proxy; return the socket and the
    proxy's response head."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            break
        head += chunk
    return sock, head


def recv_all(sock: socket.socket, timeout: float = 1.0) -> bytes:
    """Read until EOF or timeout; a reset counts as EOF."""
    sock.settimeout(timeout)
    data = b""
    try:
        while chunk := sock.recv(4096):
            data += chunk
    except (TimeoutError, ConnectionError):
        pass
    return data


def agent_opener(proxy_url: str) -> urllib.request.OpenerDirector:
    """urllib opener that forces all HTTP through proxy_url regardless of no_proxy."""
    return urllib.request.build_opener(
        _ForceProxyHandler({"http": proxy_url})
    )


# ── Fixture factory ────────────────────────────────────────────────────────────

@contextmanager
def _proxy_context(tmp, handler_class, config_text, server_tls=None, extra_args=()):
    """Spin up an HTTP server and a mitmdump proxy; yield connection details.
    server_tls: optional (certfile, keyfile) to serve HTTPS instead of HTTP."""
    server_port = free_port()
    server = HTTPServer(("127.0.0.1", server_port), handler_class)
    server.received = []
    server.sni = []  # SNI of each TLS handshake the server saw (None: no SNI)
    if server_tls:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(*server_tls)
        tls.sni_callback = lambda _sock, name, _ctx: server.sni.append(name)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Short private dir: AF_UNIX paths are capped at ~104 bytes, which a
    # pytest tmp_path can exceed.
    management_socket = os.path.join(tempfile.mkdtemp(prefix="ap-"), "mgmt.sock")
    config = tmp / "config.yaml"
    config.write_text(config_text + f"\nmanagement_socket: {management_socket}\n")

    proxy_port = free_port()
    proc = subprocess.Popen(
        [MITMDUMP, "-s", "addon.py", "--listen-port", str(proxy_port),
         "--set", f"confdir={tmp}", *extra_args],
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
            "server": server,
            "server_port": server_port,
            "proxy_port": proxy_port,
            "ca_cert": tmp / "mitmproxy-ca-cert.pem",
            "management_socket": management_socket,
            "pid": proc.pid,
        }
    finally:
        proc.terminate()
        proc.wait()
        server.shutdown()
        shutil.rmtree(os.path.dirname(management_socket), ignore_errors=True)


@pytest.fixture(scope="module")
def proxy(tmp_path_factory):
    config_text = (
        "hosts:\n"
        "  - host: 127.0.0.1\n"
        "    credential:\n"
        "      header: X-Api-Key\n"
        "      fake_value: fake-key\n"
        "      real_value: real-key\n"
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
        "hosts:\n"
        "  - host: 127.0.0.1\n"
        "    allow_response_cookies:\n"
        "      - csrftoken\n",
    ) as ctx:
        yield ctx


RESTRICTED_CONFIG = (
    "hosts:\n"
    "  - host: 127.0.0.1\n"
    "    rules:\n"
    "      - methods: [GET, HEAD]\n"
    "        path: \"/pkg/[a-z0-9-]{1,64}\"\n"
    "        query:\n"
    "          version: \"[a-z0-9.]{1,32}\"\n"
)


@pytest.fixture(scope="module")
def proxy_restricted(tmp_path_factory):
    """Proxy where the echo host is restricted (rule-matched), not allowlisted."""
    with _proxy_context(
        tmp_path_factory.mktemp("functional_restricted"),
        EchoHandler,
        RESTRICTED_CONFIG,
    ) as ctx:
        yield ctx


@pytest.fixture
def proxy_restricted_fn(tmp_path):
    """Function-scoped variant for tests that mutate proxy state (temp allows)."""
    with _proxy_context(tmp_path, EchoHandler, RESTRICTED_CONFIG) as ctx:
        yield ctx


def mgmt_request(management_socket: str, method: str, path: str, **kwargs) -> httpx.Response:
    """Call the management API over its Unix socket, with retries because the
    API thread may start slightly after the proxy port opens."""
    transport = httpx.HTTPTransport(uds=management_socket)
    deadline = time.time() + 10
    with httpx.Client(transport=transport, base_url="http://agent-proxy", timeout=5) as client:
        while True:
            try:
                return client.request(method, path, **kwargs)
            except httpx.TransportError:
                if time.time() > deadline:
                    raise
                time.sleep(0.2)


def mgmt_post(management_socket: str, path: str, payload: dict) -> httpx.Response:
    """POST JSON to the management API (see mgmt_request)."""
    return mgmt_request(management_socket, "POST", path, json=payload).raise_for_status()


def mgmt_get(management_socket: str, path: str) -> httpx.Response:
    """GET from the management API (see mgmt_request)."""
    return mgmt_request(management_socket, "GET", path).raise_for_status()


@pytest.fixture
def proxy_secrets(tmp_path):
    """Proxy fixture that loads real_value from a secrets_file."""
    secrets = tmp_path / "secrets.yaml"
    secrets.write_text("REAL_API_KEY: real-key\n")
    config_text = (
        f"secrets_file: {secrets}\n"
        "hosts:\n"
        "  - host: 127.0.0.1\n"
        "    credential:\n"
        "      header: X-Api-Key\n"
        "      fake_value: fake-key\n"
        '      real_value: "${REAL_API_KEY}"\n'
    )
    with _proxy_context(tmp_path, EchoHandler, config_text) as ctx:
        yield ctx


# ── Scoped service preset (github/gitlab) fixtures ──────────────────────────────
#
# The `github`/`gitlab` presets used to grant blanket host access; they now
# compile an operator's `scope:` into registries.HostRules, same as any other
# restricted host. These fixtures prove that compiled rule set is what the
# running proxy actually enforces -- including credential brokering, which
# depends on AllowlistAddon (header scrubbing) and CredentialBrokerAddon
# (the swap) agreeing on which header survives.
#
# `gitlab` takes its host from the entry (self-hosted), so it can point at
# our local echo server and prove both the deny and the pass paths. `github`
# is hardcoded to api.github.com, which this sandbox cannot and should not
# dial out to -- its fixture is used only for assertions that must be denied
# before any upstream connection is attempted.

GITLAB_SCOPE_CONFIG = (
    "services:\n"
    "  - service: gitlab\n"
    "    host: 127.0.0.1\n"
    "    scope:\n"
    "      projects: [acme/webapp]\n"
    "    write: true\n"
    "    real_value: real-glpat-secret\n"
    "    fake_value: glpat-fake-token\n"
)

GITLAB_SCOPE_READONLY_CONFIG = (
    "services:\n"
    "  - service: gitlab\n"
    "    host: 127.0.0.1\n"
    "    scope:\n"
    "      projects: [acme/webapp]\n"
    "    real_value: real-glpat-secret\n"
    "    fake_value: glpat-fake-token\n"
)

GITHUB_SCOPE_CONFIG = (
    "services:\n"
    "  - service: github\n"
    "    scope:\n"
    "      repos: [acme/webapp]\n"
    "    real_value: real-ghp-secret\n"
    "    fake_value: ghp_fake0000000000000000000000000000\n"
)


@pytest.fixture(scope="module")
def proxy_gitlab_scoped(tmp_path_factory):
    """Real mitmdump enforcing a scoped `gitlab` service preset, `write: true`."""
    with _proxy_context(
        tmp_path_factory.mktemp("functional_gitlab_scoped"),
        EchoHandler,
        GITLAB_SCOPE_CONFIG,
    ) as ctx:
        yield ctx


@pytest.fixture(scope="module")
def proxy_gitlab_scoped_readonly(tmp_path_factory):
    """Same scope as proxy_gitlab_scoped, without `write:` -- proves the flag
    actually gates the write rules rather than them being on by default."""
    with _proxy_context(
        tmp_path_factory.mktemp("functional_gitlab_readonly"),
        EchoHandler,
        GITLAB_SCOPE_READONLY_CONFIG,
    ) as ctx:
        yield ctx


@pytest.fixture(scope="module")
def proxy_gitlab_scoped_plus_unrestricted(tmp_path_factory):
    """A scoped, credentialed `gitlab` service and an unrestricted hand-written
    entry on the same host: two entries, only one carrying the credential."""
    with _proxy_context(
        tmp_path_factory.mktemp("functional_gitlab_two_entries"),
        EchoHandler,
        GITLAB_SCOPE_READONLY_CONFIG + "hosts:\n  - 127.0.0.1\n",
    ) as ctx:
        yield ctx


@pytest.fixture(scope="module")
def proxy_github_scoped(tmp_path_factory):
    """Real mitmdump enforcing a scoped `github` service preset (no `graphql:`).

    api.github.com is unreachable (and shouldn't be dialed) from this
    sandbox, so this fixture only backs assertions that are denied before any
    upstream connection would be attempted.
    """
    with _proxy_context(
        tmp_path_factory.mktemp("functional_github_scoped"),
        EchoHandler,
        GITHUB_SCOPE_CONFIG,
    ) as ctx:
        yield ctx


SPOOF_SECRET = "Bearer REAL-SECRET-123"
SPOOF_CONFIG = (
    "hosts:\n"
    "  - host: example.org\n"
    "    credential:\n"
    "      header: Authorization\n"
    f"      real_value: {SPOOF_SECRET}\n"
)


@pytest.fixture
def proxy_spoof(tmp_path):
    """Only example.org is allowed (with an inject-mode credential); the local
    recording server is NOT allowed, so reaching it means a bypass."""
    with _proxy_context(tmp_path, RecordingHandler, SPOOF_CONFIG) as ctx:
        yield ctx


def _self_signed_cert(tmp) -> tuple:
    """Write a throwaway self-signed cert for 127.0.0.1; return (cert, key) paths."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / "server-cert.pem", tmp / "server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return cert_path, key_path


@pytest.fixture
def proxy_spoof_tls(tmp_path):
    """proxy_spoof with an HTTPS upstream; mitmproxy skips upstream cert
    verification since the server cert is self-signed."""
    with _proxy_context(
        tmp_path, RecordingHandler, SPOOF_CONFIG,
        server_tls=_self_signed_cert(tmp_path),
        extra_args=("--set", "ssl_insecure=true"),
    ) as ctx:
        yield ctx


def _recv_response(sock) -> bytes:
    """Read one HTTP/1.1 response (headers + Content-Length body)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def _status(response: bytes) -> int:
    return int(response.split(b" ", 2)[1])


def _raw_request(ctx, request: bytes) -> bytes:
    """Send one raw request to the proxy itself (absolute-form)."""
    with socket.create_connection(("127.0.0.1", ctx["proxy_port"]), timeout=10) as sock:
        sock.sendall(request)
        return _recv_response(sock)


def _connect_tunnel(ctx) -> socket.socket:
    """Open a CONNECT tunnel through the proxy to the local server."""
    sock = socket.create_connection(("127.0.0.1", ctx["proxy_port"]), timeout=10)
    target = f"127.0.0.1:{ctx['server_port']}"
    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    resp = _recv_response(sock)
    assert _status(resp) == 200, resp
    return sock


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_blocked_domain_returns_503(proxy):
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy["opener"].open("http://blocked.example.com/")
    assert exc.value.code == 503


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


# ── Restricted host (registry policy) tests ───────────────────────────────────

def test_restricted_matching_request_passes(proxy_restricted):
    resp = proxy_restricted["opener"].open(proxy_restricted["server_url"] + "/pkg/foo")
    data = json.loads(resp.read())
    assert data["path"] == "/pkg/foo"


def test_restricted_scrubs_unknown_headers(proxy_restricted):
    req = urllib.request.Request(
        proxy_restricted["server_url"] + "/pkg/foo",
        headers={"X-Exfil": "secret-data", "Accept": "application/json"},
    )
    data = json.loads(proxy_restricted["opener"].open(req).read())
    assert "x-exfil" not in data["headers"]
    assert data["headers"].get("accept") == "application/json"


def test_restricted_post_blocked_with_503(proxy_restricted):
    req = urllib.request.Request(
        proxy_restricted["server_url"] + "/pkg/foo", data=b"payload")
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_restricted["opener"].open(req)
    assert exc.value.code == 503
    assert b"not currently allowed by policy" in exc.value.read()


def test_restricted_disallowed_query_blocked(proxy_restricted):
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_restricted["opener"].open(
            proxy_restricted["server_url"] + "/pkg/foo?data=secret")
    assert exc.value.code == 503


def test_restricted_disallowed_path_blocked(proxy_restricted):
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_restricted["opener"].open(
            proxy_restricted["server_url"] + "/other/path")
    assert exc.value.code == 503


def test_temp_allow_lifts_restrictions(proxy_restricted_fn):
    url = proxy_restricted_fn["server_url"] + "/pkg/foo?data=secret"
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_restricted_fn["opener"].open(url)
    assert exc.value.code == 503

    mgmt_post(proxy_restricted_fn["management_socket"], "/allow/temp",
              {"host": "127.0.0.1", "duration_seconds": 60})

    resp = proxy_restricted_fn["opener"].open(url)
    assert json.loads(resp.read())["path"] == "/pkg/foo?data=secret"


# ── Scoped service preset tests (real mitmdump enforcing github/gitlab scoping) ─
#
# The service preset compiles an operator's scope into the same registries
# rule engine exercised above; these confirm that compiled result is what a
# real mitmdump process enforces, for the specific shapes the scoping feature
# introduced: an in-scope repo/project path, an out-of-scope one, a
# write-gated POST with a body, and the always-deny-by-default `/graphql`.

def test_scoped_in_scope_path_passes(proxy_gitlab_scoped):
    # The query glab issue list sends by default, so the query whitelist is
    # exercised through the real proxy as well as the path.
    path = ("/api/v4/projects/acme%2Fwebapp/issues?in=title%2Cdescription"
            "&order_by=created_at&page=1&per_page=30&sort=desc&state=opened")
    resp = proxy_gitlab_scoped["opener"].open(proxy_gitlab_scoped["server_url"] + path)
    data = json.loads(resp.read())
    assert data["path"] == path


def test_scoped_out_of_scope_path_503(proxy_gitlab_scoped):
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_gitlab_scoped["opener"].open(
            proxy_gitlab_scoped["server_url"] + "/api/v4/projects/other%2Fproject/issues")
    assert exc.value.code == 503
    assert b"not currently allowed by policy" in exc.value.read()

    denied = json.loads(mgmt_get(proxy_gitlab_scoped["management_socket"], "/denied").read())
    assert denied[-1]["type"] == "policy_violation"


def test_scoped_write_post_passes(proxy_gitlab_scoped):
    req = urllib.request.Request(
        proxy_gitlab_scoped["server_url"] + "/api/v4/projects/acme%2Fwebapp/issues",
        data=b'{"title": "bug"}',
        headers={"Content-Type": "application/json"},
    )
    data = json.loads(proxy_gitlab_scoped["opener"].open(req).read())
    assert data["body"] == '{"title": "bug"}'


def test_scoped_write_post_without_write_flag_503(proxy_gitlab_scoped_readonly):
    req = urllib.request.Request(
        proxy_gitlab_scoped_readonly["server_url"] + "/api/v4/projects/acme%2Fwebapp/issues",
        data=b'{"title": "bug"}',
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_gitlab_scoped_readonly["opener"].open(req)
    assert exc.value.code == 503
    assert b"not currently allowed by policy" in exc.value.read()


def test_scoped_graphql_blocked_without_flag(proxy_github_scoped):
    req = urllib.request.Request(
        "http://api.github.com/graphql",
        data=b'{"query": "{ viewer { login } }"}',
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_github_scoped["opener"].open(req)
    assert exc.value.code == 503
    assert b"not currently allowed by policy" in exc.value.read()


# ── Credential brokering under scoping (the subtle failure mode) ───────────────
#
# AllowlistAddon scrubs request headers not on a host's request_headers
# *before* CredentialBrokerAddon runs. If a scoped rule set's
# scope_template forgot to list its own credential header there (e.g.
# `private-token` for gitlab, `authorization` for github), the swap would
# never fire and every request would go upstream silently unauthenticated --
# a unit test stubbing either addon in isolation cannot catch that. These
# run both addons for real, back to back, through a real mitmdump.

def test_scoped_credential_reaches_upstream_on_in_scope_request(proxy_gitlab_scoped):
    """The fake token the client sends is swapped for the real one, and the
    real one is what the upstream server actually receives."""
    req = urllib.request.Request(
        proxy_gitlab_scoped["server_url"] + "/api/v4/projects/acme%2Fwebapp/issues",
        headers={"PRIVATE-TOKEN": "glpat-fake-token"},
    )
    data = json.loads(proxy_gitlab_scoped["opener"].open(req).read())
    assert data["headers"].get("private-token") == "real-glpat-secret"


def test_scoped_credential_reaches_upstream_on_current_user(proxy_gitlab_scoped_readonly):
    """glab verifies its token via GET /api/v4/user; that call must pass on a
    read-only scope and carry the real token, or `glab auth login` fails."""
    req = urllib.request.Request(
        proxy_gitlab_scoped_readonly["server_url"] + "/api/v4/user",
        headers={"PRIVATE-TOKEN": "glpat-fake-token"},
    )
    data = json.loads(proxy_gitlab_scoped_readonly["opener"].open(req).read())
    assert data["path"] == "/api/v4/user"
    assert data["headers"].get("private-token") == "real-glpat-secret"


def test_scoped_credential_never_reaches_upstream_on_denied_request(proxy_gitlab_scoped):
    """A request denied by policy must be stopped before CredentialBrokerAddon
    ever runs -- the real token must never reach upstream. EchoHandler.received
    is shared with other tests/fixtures, so this asserts on the delta across
    just this request rather than an absolute count."""
    before = len(EchoHandler.received)
    req = urllib.request.Request(
        proxy_gitlab_scoped["server_url"] + "/api/v4/projects/other%2Fproject/issues",
        headers={"PRIVATE-TOKEN": "glpat-fake-token"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_gitlab_scoped["opener"].open(req)
    assert exc.value.code == 503
    # The upstream echo server never saw this request at all -- the real
    # token (which only CredentialBrokerAddon, downstream of the deny, knows)
    # had no channel to leak through.
    assert len(EchoHandler.received) == before


def test_two_entries_one_host_credential_bound_to_scoped_entry(
        proxy_gitlab_scoped_plus_unrestricted):
    """In scope, the scoped entry permits and brokers the real token; out of
    scope, the unrestricted entry permits but the credential is withheld and
    the fake header stripped -- neither token reaches upstream."""
    ctx = proxy_gitlab_scoped_plus_unrestricted
    in_scope = urllib.request.Request(
        ctx["server_url"] + "/api/v4/projects/acme%2Fwebapp/issues",
        headers={"PRIVATE-TOKEN": "glpat-fake-token"},
    )
    data = json.loads(ctx["opener"].open(in_scope).read())
    assert data["headers"].get("private-token") == "real-glpat-secret"

    out_of_scope = urllib.request.Request(
        ctx["server_url"] + "/api/v4/projects/other%2Fproject/issues",
        headers={"PRIVATE-TOKEN": "glpat-fake-token"},
    )
    data = json.loads(ctx["opener"].open(out_of_scope).read())
    assert data["path"] == "/api/v4/projects/other%2Fproject/issues"
    assert "private-token" not in data["headers"]


# ── Spoofed Host header (policy host != real destination) ─────────────────────

SPOOFED_GET = b"GET /a HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n"


def _assert_blocked_and_not_leaked(ctx, resp):
    assert _status(resp) == 403, resp
    assert b"REAL-SECRET" not in resp
    # The real secret must never reach the server — nothing should at all
    assert all(SPOOF_SECRET not in h.values() for h in ctx["server"].received)
    assert ctx["server"].received == []


def test_spoofed_host_absolute_form_blocked(proxy_spoof):
    """Absolute-form request to the local server with Host: example.org must
    not be treated as a request to the allowed example.org."""
    resp = _raw_request(proxy_spoof, (
        f"GET http://127.0.0.1:{proxy_spoof['server_port']}/a HTTP/1.1\r\n"
        "Host: example.org\r\nConnection: close\r\n\r\n").encode())
    _assert_blocked_and_not_leaked(proxy_spoof, resp)


def test_spoofed_host_connect_http_blocked(proxy_spoof):
    """CONNECT to the local server, then a plaintext inner request with
    Host: example.org."""
    with _connect_tunnel(proxy_spoof) as sock:
        sock.sendall(SPOOFED_GET)
        resp = _recv_response(sock)
    _assert_blocked_and_not_leaked(proxy_spoof, resp)


def test_spoofed_host_connect_tls_blocked(proxy_spoof_tls):
    """CONNECT to the local HTTPS server, TLS with SNI example.org, then an
    inner request with Host: example.org."""
    tls = ssl.create_default_context(cafile=str(proxy_spoof_tls["ca_cert"]))
    with _connect_tunnel(proxy_spoof_tls) as raw:
        with tls.wrap_socket(raw, server_hostname="example.org") as sock:
            sock.sendall(SPOOFED_GET)
            resp = _recv_response(sock)
    _assert_blocked_and_not_leaked(proxy_spoof_tls, resp)


@pytest.fixture
def proxy_allowed_tls(tmp_path):
    """The local HTTPS server is itself allowed, with an inject-mode
    credential, so only the SNI can point the request elsewhere."""
    with _proxy_context(
        tmp_path, RecordingHandler,
        "hosts:\n"
        "  - host: 127.0.0.1\n"
        "    credential:\n"
        "      header: Authorization\n"
        f"      real_value: {SPOOF_SECRET}\n",
        server_tls=_self_signed_cert(tmp_path),
        extra_args=("--set", "ssl_insecure=true"),
    ) as ctx:
        yield ctx


def test_spoofed_sni_blocked(proxy_allowed_tls):
    """CONNECT to the allowed destination with a matching Host header, but TLS
    SNI other.example: mitmproxy would pass that SNI upstream, so a front
    that routes by SNI could deliver the credential to another backend."""
    ctx = proxy_allowed_tls
    tls = ssl.create_default_context(cafile=str(ctx["ca_cert"]))
    with _connect_tunnel(ctx) as raw:
        with tls.wrap_socket(raw, server_hostname="other.example") as sock:
            sock.sendall((
                f"GET /a HTTP/1.1\r\nHost: 127.0.0.1:{ctx['server_port']}\r\n"
                "Connection: close\r\n\r\n").encode())
            resp = _recv_response(sock)
    assert ctx["server"].sni == []
    _assert_blocked_and_not_leaked(ctx, resp)


def test_connect_tls_without_sni_reaches_server(proxy_allowed_tls):
    """An IP-literal destination carries no SNI; that must keep working."""
    ctx = proxy_allowed_tls
    tls = ssl.create_default_context(cafile=str(ctx["ca_cert"]))
    with _connect_tunnel(ctx) as raw:
        with tls.wrap_socket(raw, server_hostname="127.0.0.1") as sock:
            sock.sendall((
                f"GET /a HTTP/1.1\r\nHost: 127.0.0.1:{ctx['server_port']}\r\n"
                "Connection: close\r\n\r\n").encode())
            resp = _recv_response(sock)
    assert _status(resp) == 200, resp
    assert ctx["server"].received[0]["authorization"] == SPOOF_SECRET


def _h2_get(sock, authority: str, path: str) -> tuple[int, bytes]:
    """Send one HTTP/2 GET over an established h2 TLS socket; return
    (status, body)."""
    import h2.connection
    import h2.events

    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    conn.send_headers(1, [(":method", "GET"), (":scheme", "https"),
                          (":authority", authority), (":path", path)],
                      end_stream=True)
    sock.sendall(conn.data_to_send())
    status, body = None, b""
    while True:
        data = sock.recv(65536)
        if not data:
            break
        for event in conn.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                status = int(dict(event.headers)[b":status"])
            elif isinstance(event, h2.events.DataReceived):
                body += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, 1)
            elif isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                return status, body
        sock.sendall(conn.data_to_send())
    return status, body


def test_spoofed_authority_http2_blocked(proxy_spoof_tls):
    """CONNECT to the local HTTPS server, then an HTTP/2 request whose
    :authority is example.org."""
    tls = ssl.create_default_context(cafile=str(proxy_spoof_tls["ca_cert"]))
    tls.set_alpn_protocols(["h2"])
    with _connect_tunnel(proxy_spoof_tls) as raw:
        with tls.wrap_socket(raw, server_hostname="example.org") as sock:
            assert sock.selected_alpn_protocol() == "h2"
            status, body = _h2_get(sock, "example.org", "/a")
    assert status == 403, body
    assert SPOOF_SECRET.encode() not in body
    assert proxy_spoof_tls["server"].received == []


def test_mismatched_host_blocked_even_if_destination_allowed(proxy):
    """127.0.0.1 is allowed here, but Host names another host: fail closed
    rather than forward a request the upstream may route by Host."""
    resp = _raw_request(proxy, (
        f"GET {proxy['server_url']}/a HTTP/1.1\r\n"
        "Host: example.org\r\nConnection: close\r\n\r\n").encode())
    assert _status(resp) == 403, resp


def test_matching_host_via_connect_reaches_server(proxy):
    """A non-spoofed CONNECT + inner request still works, with credential swap."""
    with _connect_tunnel(proxy) as sock:
        sock.sendall((
            f"GET /tunnel HTTP/1.1\r\nHost: 127.0.0.1:{proxy['server_port']}\r\n"
            "X-Api-Key: fake-key\r\nConnection: close\r\n\r\n").encode())
        resp = _recv_response(sock)
    assert _status(resp) == 200, resp
    data = json.loads(resp.partition(b"\r\n\r\n")[2])
    assert data["path"] == "/tunnel"
    assert data["headers"]["x-api-key"] == "real-key"


# ── Management API exposure ──────────────────────────────────────────────────
#
# The API can change the proxy's own policy, so it must be unreachable from
# the sandbox (Lima forwards host.lima.internal to the host's loopback) and
# from browsers: it listens only on a private Unix socket, never on TCP.

def _listening_tcp_ports(pid: int) -> set[int]:
    """TCP ports process `pid` is listening on (Linux /proc)."""
    inodes = set()
    for fd in pathlib.Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[len("socket:["):-1])
    ports = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        with open(table) as f:
            next(f)
            for line in f:
                fields = line.split()
                if fields[3] == "0A" and fields[9] in inodes:  # 0A: LISTEN
                    ports.add(int(fields[1].rsplit(":", 1)[1], 16))
    return ports


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
def test_management_api_not_listening_on_tcp(proxy):
    mgmt_get(proxy["management_socket"], "/allowlist")  # wait until it's up
    proxy_port = int(proxy["opener"].handlers[0].proxies["http"].rsplit(":", 1)[1])
    assert _listening_tcp_ports(proxy["pid"]) == {proxy_port}


def test_management_socket_is_private(proxy):
    sock = proxy["management_socket"]
    mgmt_get(sock, "/allowlist")
    assert os.stat(sock).st_mode & 0o777 == 0o600
    assert os.stat(os.path.dirname(sock)).st_mode & 0o777 == 0o700


def test_management_rejects_non_json_post(proxy):
    """A cross-site form or no-preflight fetch can only send text/plain,
    form-encoded or multipart bodies; none of them may change policy."""
    r = mgmt_request(proxy["management_socket"], "POST", "/allow/permanent",
                     content=b'{"host": "attacker.example"}',
                     headers={"Content-Type": "text/plain"})
    assert r.status_code == 415
    assert r.json()["ok"] is False
    allowlist = mgmt_get(proxy["management_socket"], "/allowlist").json()
    assert "attacker.example" not in allowlist["permanent"]


# ── CONNECT tunnel policy tests ────────────────────────────────────────────────

@pytest.fixture
def raw_server():
    server = RawTcpServer()
    yield server
    server.close()


# A CONNECT to a disallowed host still opens the tunnel: clients don't show
# the body of a refused CONNECT, so the denial is answered on the request
# inside it, where the agent can read "pending human approval". Lazy
# connections keep that from reaching upstream (or DNS) before policy runs.

def _get(host: str) -> bytes:
    return f"GET /x HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()


def test_connect_to_disallowed_host_denied_inside_tunnel(proxy, raw_server):
    # "localhost" is not on the allowlist (only 127.0.0.1 is), but resolves
    # to the raw server — so any upstream connect would show up as an accept.
    target = f"localhost:{raw_server.port}"
    sock, head = raw_connect(proxy["proxy_port"], target)
    with sock:
        assert head.startswith(b"HTTP/1.1 200")
        sock.sendall(_get(target))
        resp = _recv_response(sock)
    assert _status(resp) == 503, resp
    assert b"pending human approval" in resp
    time.sleep(0.5)
    assert raw_server.accepted == 0
    denied = mgmt_get(proxy["management_socket"], "/denied").json()
    assert any(e["host"] == "localhost" and e["type"] == "pending_approval" for e in denied)


def test_connect_tls_to_disallowed_host_denied_inside_tunnel(proxy, raw_server):
    target = f"localhost:{raw_server.port}"
    tls = ssl.create_default_context(cafile=str(proxy["ca_cert"]))
    sock, head = raw_connect(proxy["proxy_port"], target)
    assert head.startswith(b"HTTP/1.1 200")
    with tls.wrap_socket(sock, server_hostname="localhost") as tls_sock:
        tls_sock.sendall(_get(target))
        resp = _recv_response(tls_sock)
    assert _status(resp) == 503, resp
    assert b"pending human approval" in resp
    time.sleep(0.5)
    assert raw_server.accepted == 0


def test_connect_to_unresolvable_host_denied_without_dns(proxy):
    # An eager connection would fail the CONNECT with a DNS error (502)
    # before policy ran; lazily, the denial is the only answer.
    target = "nonexistent.invalid:443"
    tls = ssl.create_default_context(cafile=str(proxy["ca_cert"]))
    sock, head = raw_connect(proxy["proxy_port"], target)
    assert head.startswith(b"HTTP/1.1 200")
    with tls.wrap_socket(sock, server_hostname="nonexistent.invalid") as tls_sock:
        tls_sock.sendall(_get("nonexistent.invalid"))
        resp = _recv_response(tls_sock)
    assert _status(resp) == 503, resp
    assert b"pending human approval" in resp


def test_raw_bytes_after_connect_not_relayed(proxy, raw_server):
    sock, head = raw_connect(proxy["proxy_port"], f"127.0.0.1:{raw_server.port}")
    with sock:
        # Allowed host: the tunnel itself is established...
        assert head.startswith(b"HTTP/1.1 200")
        # ...but non-HTTP, non-TLS bytes must not be forwarded as raw TCP
        sock.sendall(b"SSH-2.0-exfil secret-data\r\n")
        reply = recv_all(sock)
    time.sleep(0.5)
    assert b"secret-data" not in reply
    assert raw_server.received == b""
    assert raw_server.accepted == 0


@pytest.fixture
def proxy_unsafe_set(tmp_path):
    """The proxy fixture's config, launched asking for mitmproxy's unsafe
    defaults explicitly; the addon must override both."""
    with _proxy_context(
        tmp_path, EchoHandler, "hosts:\n  - host: 127.0.0.1\n",
        extra_args=("--set", "rawtcp=true", "--set", "connection_strategy=eager"),
    ) as ctx:
        yield ctx


def test_set_rawtcp_overridden(proxy_unsafe_set, raw_server):
    sock, head = raw_connect(proxy_unsafe_set["proxy_port"], f"127.0.0.1:{raw_server.port}")
    with sock:
        assert head.startswith(b"HTTP/1.1 200")
        sock.sendall(b"SSH-2.0-exfil secret-data\r\n")
        reply = recv_all(sock)
    time.sleep(0.5)
    assert b"secret-data" not in reply
    assert raw_server.received == b""


def test_set_eager_connection_strategy_overridden(proxy_unsafe_set, raw_server):
    target = f"localhost:{raw_server.port}"
    sock, head = raw_connect(proxy_unsafe_set["proxy_port"], target)
    with sock:
        assert head.startswith(b"HTTP/1.1 200")
        sock.sendall(_get(target))
        resp = _recv_response(sock)
    assert _status(resp) == 503, resp
    time.sleep(0.5)
    assert raw_server.accepted == 0
