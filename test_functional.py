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
        "hosts:\n"
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


def mgmt_get(management_url: str, path: str):
    """GET from the management API directly (bypassing the proxy), with the
    same retry-until-up behaviour as mgmt_post."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(management_url + path)
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
        "hosts:\n"
        "  - host: 127.0.0.1\n"
        "credentials:\n"
        "  - host: 127.0.0.1\n"
        "    header: X-Api-Key\n"
        "    fake_value: fake-key\n"
        '    real_value: "${REAL_API_KEY}"\n'
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


# ── Scoped service preset tests (real mitmdump enforcing github/gitlab scoping) ─
#
# The service preset compiles an operator's scope into the same registries
# rule engine exercised above; these confirm that compiled result is what a
# real mitmdump process enforces, for the specific shapes the scoping feature
# introduced: an in-scope repo/project path, an out-of-scope one, a
# write-gated POST with a body, and the always-deny-by-default `/graphql`.

def test_scoped_in_scope_path_passes(proxy_gitlab_scoped):
    resp = proxy_gitlab_scoped["opener"].open(
        proxy_gitlab_scoped["server_url"] + "/api/v4/projects/acme%2Fwebapp/issues")
    data = json.loads(resp.read())
    assert data["path"] == "/api/v4/projects/acme%2Fwebapp/issues"


def test_scoped_out_of_scope_path_403(proxy_gitlab_scoped):
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_gitlab_scoped["opener"].open(
            proxy_gitlab_scoped["server_url"] + "/api/v4/projects/other%2Fproject/issues")
    assert exc.value.code == 403
    assert b"policy violation" in exc.value.read()

    denied = json.loads(mgmt_get(proxy_gitlab_scoped["management_url"], "/denied").read())
    assert denied[-1]["type"] == "policy_violation"


def test_scoped_write_post_passes(proxy_gitlab_scoped):
    req = urllib.request.Request(
        proxy_gitlab_scoped["server_url"] + "/api/v4/projects/acme%2Fwebapp/issues",
        data=b'{"title": "bug"}',
        headers={"Content-Type": "application/json"},
    )
    data = json.loads(proxy_gitlab_scoped["opener"].open(req).read())
    assert data["body"] == '{"title": "bug"}'


def test_scoped_write_post_without_write_flag_403(proxy_gitlab_scoped_readonly):
    req = urllib.request.Request(
        proxy_gitlab_scoped_readonly["server_url"] + "/api/v4/projects/acme%2Fwebapp/issues",
        data=b'{"title": "bug"}',
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_gitlab_scoped_readonly["opener"].open(req)
    assert exc.value.code == 403
    assert b"policy violation" in exc.value.read()


def test_scoped_graphql_blocked_without_flag(proxy_github_scoped):
    req = urllib.request.Request(
        "http://api.github.com/graphql",
        data=b'{"query": "{ viewer { login } }"}',
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        proxy_github_scoped["opener"].open(req)
    assert exc.value.code == 403
    assert b"policy violation" in exc.value.read()


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
    assert exc.value.code == 403
    # The upstream echo server never saw this request at all -- the real
    # token (which only CredentialBrokerAddon, downstream of the deny, knows)
    # had no channel to leak through.
    assert len(EchoHandler.received) == before
