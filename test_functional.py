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


# ── Fixture ────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def proxy(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("functional")

    # Echo server in a background thread
    server_port = free_port()
    server = HTTPServer(("127.0.0.1", server_port), EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Minimal allowlist: only the echo server host
    config = tmp / "config.yaml"
    config.write_text("allowed_hosts:\n  - 127.0.0.1\n")

    creds = json.dumps([{
        "host": "127.0.0.1",
        "header": "X-Api-Key",
        "fake_value": "fake-key",
        "real_value": "real-key",
    }])

    proxy_port = free_port()
    proc = subprocess.Popen(
        [MITMDUMP, "-s", "addon.py", "--listen-port", str(proxy_port),
         "--set", f"confdir={tmp}"],
        cwd=HERE,
        env={
            **os.environ,
            "PROXY_CONFIG": str(config),
            "PROXY_CREDENTIALS": creds,
            "PROXY_MGMT_PORT": str(free_port()),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait up to 10 s for proxy to bind
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

    yield {
        "opener": agent_opener(f"http://127.0.0.1:{proxy_port}"),
        "server_url": f"http://127.0.0.1:{server_port}",
    }

    proc.terminate()
    proc.wait()
    server.shutdown()


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
