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
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

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
            "management_url": f"http://127.0.0.1:{management_port}",
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


RESTRICTED_CONFIG = (
    "restricted_hosts:\n"
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


def mgmt_post(management_url: str, path: str, payload: dict):
    """POST to the management API directly (bypassing the proxy), with retries
    because the Flask thread may start slightly after the proxy port opens."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        management_url + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    deadline = time.time() + 10
    while True:
        try:
            return opener.open(req)
        except (urllib.error.URLError, ConnectionError):
            if time.time() > deadline:
                raise
            time.sleep(0.2)


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


def test_restricted_post_blocked_with_403(proxy_restricted):
    req = urllib.request.Request(
        proxy_restricted["server_url"] + "/pkg/foo", data=b"payload")
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_restricted["opener"].open(req)
    assert exc.value.code == 403
    assert b"policy violation" in exc.value.read()


def test_restricted_disallowed_query_blocked(proxy_restricted):
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_restricted["opener"].open(
            proxy_restricted["server_url"] + "/pkg/foo?data=secret")
    assert exc.value.code == 403


def test_restricted_disallowed_path_blocked(proxy_restricted):
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_restricted["opener"].open(
            proxy_restricted["server_url"] + "/other/path")
    assert exc.value.code == 403


def test_temp_allow_lifts_restrictions(proxy_restricted_fn):
    url = proxy_restricted_fn["server_url"] + "/pkg/foo?data=secret"
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_restricted_fn["opener"].open(url)
    assert exc.value.code == 403

    mgmt_post(proxy_restricted_fn["management_url"], "/allow/temp",
              {"host": "127.0.0.1", "duration_seconds": 60})

    resp = proxy_restricted_fn["opener"].open(url)
    assert json.loads(resp.read())["path"] == "/pkg/foo?data=secret"
