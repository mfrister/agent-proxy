"""
mitmproxy Sandbox Proxy

Run headless:  mitmdump -s addon.py
Run with UI:   mitmweb -s addon.py

Environment variables:
  PROXY_CONFIG   path to config YAML (default: config.yaml)

Config YAML format:

  secrets_file: /path/to/secrets.yaml   # optional; separate file with secret values

  management_port: 8082                  # management API port (default: 8082)

  credentials:
    - host: api.example.com
      header: Authorization
      fake_value: "Bearer sk-fake"       # swap mode: agent sends fake, proxy swaps real
      real_value: "${MY_API_KEY}"        # ${KEY} references a key in secrets_file
    - host: internal.example.com
      header: Cookie
      real_value: "session=abc123"       # inject mode: omit fake_value

  # Claude subscription mode — keeps the real session token out of the sandbox.
  # The agent uses the fake_value below; the proxy swaps it for the live token
  # obtained via the OAuth login flow at http://localhost:<management_port>/claude/login
  #
  #   credentials:
  #     - host: api.anthropic.com
  #       header: Authorization
  #       fake_value: "Bearer sk-ant-proxy00-placeholder"
  #       real_value: "!claude-subscription"   # resolved dynamically
  #
  #   claude_subscription:
  #     token_file: /home/user/.config/agent-proxy/claude_tokens.json
  #     # oauth_auth_url / oauth_token_url / client_id / scopes are optional overrides

  allowed_hosts:
    - api.anthropic.com                  # plain string: all cookies pass through
    - host: platform.claude.com
      allow_response_cookies: []         # no cookies allowed (all stripped)
    - host: internal.example.com
      allow_response_cookies:
        - csrftoken                      # only csrftoken passes through

Secrets file format (simple flat key/value map):

  MY_API_KEY: "Bearer sk-real-key-here"
  OTHER_SECRET: "some-value"
"""

import collections
import json
import logging
import os
import re
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from flask import Flask, jsonify, redirect, request as flask_request
from mitmproxy import http
from mitmproxy.http import HTTPFlow

from claude_auth import ClaudeAuthError, ClaudeAuthManager


# ── Shared state ──────────────────────────────────────────────────────────────

@dataclass
class HostConfig:
    allow_response_cookies: list[str] | None = None
    # None means no restriction; a list (even empty) enables filtering


@dataclass
class ProxyState:
    allowlist: set            # permanent allowed hosts
    allowlist_path: str       # path to config YAML, used by SIGHUP reload
    credentials: list         # [{host, header, fake_value, real_value}]
    temp_allows: dict         # host -> expires_at (epoch seconds)
    temp_lock: threading.Lock
    deny_log: collections.deque  # maxlen=1000, entries: {timestamp,host,url,method}
    deny_lock: threading.Lock
    host_config: dict         # host -> HostConfig
    management_port: int = 8082
    claude_auth: Optional[ClaudeAuthManager] = None


# ── Config loaders ─────────────────────────────────────────────────────────────

def _expand_secrets(obj, secrets: dict):
    """Recursively expand ${KEY} references in string values using the secrets map."""
    if isinstance(obj, str):
        def replace(m):
            key = m.group(1)
            if key not in secrets:
                raise KeyError(f"Secret key not found in secrets_file: ${{{key}}}")
            return str(secrets[key])
        return re.sub(r'\$\{([^}]+)\}', replace, obj)
    if isinstance(obj, dict):
        return {k: _expand_secrets(v, secrets) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_secrets(item, secrets) for item in obj]
    return obj


def load_config(path: str) -> dict:
    """Load config YAML and expand any ${KEY} references from the secrets_file."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

    secrets = {}
    secrets_path = data.get("secrets_file")
    if secrets_path:
        with open(secrets_path) as f:
            secrets = yaml.safe_load(f) or {}

    return _expand_secrets(data, secrets)


def load_allowlist(path: str) -> set:
    """Load allowed hosts from config YAML."""
    data = load_config(path)
    result = []
    for item in data.get("allowed_hosts", []):
        if isinstance(item, str):
            result.append(item)
        else:
            result.append(item["host"])
    return set(result)


def load_host_config(path: str) -> dict:
    """Load per-host config (cookie rules) from config YAML."""
    data = load_config(path)
    result = {}
    for item in data.get("allowed_hosts", []):
        if not isinstance(item, str):
            host = item["host"]
            result[host] = HostConfig(
                allow_response_cookies=item.get("allow_response_cookies")
            )
    return result


def load_credentials(path: str) -> list:
    """Load credential mappings from config YAML."""
    data = load_config(path)
    return data.get("credentials", [])


def load_management_port(path: str) -> int:
    """Load management API port from config YAML."""
    data = load_config(path)
    return int(data.get("management_port", 8082))


def load_claude_auth(path: str) -> Optional[ClaudeAuthManager]:
    """
    Return a ClaudeAuthManager if ``claude_subscription`` is present in the
    config, otherwise None.

    Config section (all keys except ``token_file`` are optional):

      claude_subscription:
        token_file: /home/user/.config/agent-proxy/claude_tokens.json
        oauth_auth_url: https://claude.ai/oauth/authorize
        oauth_token_url: https://console.anthropic.com/v1/oauth/token
        client_id: 9d1c250a-e61b-48f7-9a12-c6ac30e5d9a6
        scopes: "openid email profile"
    """
    data = load_config(path)
    cfg = data.get("claude_subscription")
    if not cfg:
        return None

    from claude_auth import DEFAULT_AUTH_URL, DEFAULT_CLIENT_ID, DEFAULT_SCOPES, DEFAULT_TOKEN_URL

    return ClaudeAuthManager(
        token_file=Path(cfg["token_file"]),
        auth_url=cfg.get("oauth_auth_url", DEFAULT_AUTH_URL),
        token_url=cfg.get("oauth_token_url", DEFAULT_TOKEN_URL),
        client_id=cfg.get("client_id", DEFAULT_CLIENT_ID),
        scopes=cfg.get("scopes", DEFAULT_SCOPES),
    )


# ── Addons ─────────────────────────────────────────────────────────────────────

class AllowlistAddon:
    """
    Checks every request against the permanent allowlist and active temporary
    allows. Denied requests receive a 403 response and are logged.
    Also starts the management API when mitmproxy is running.
    """

    def __init__(self, state: ProxyState):
        self.state = state

    def running(self):
        """Start the management API in a background thread."""
        threading.Thread(
            target=lambda: create_app(self.state).run(
                host="127.0.0.1", port=self.state.management_port, use_reloader=False
            ),
            daemon=True,
        ).start()

    def request(self, flow: HTTPFlow):
        host = flow.request.pretty_host
        s = self.state

        if host in s.allowlist:
            return

        with s.temp_lock:
            exp = s.temp_allows.get(host)
            if exp and time.time() < exp:
                return

        flow.response = http.Response.make(
            403, f"Blocked: {host}", {"Content-Type": "text/plain"}
        )
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": host,
            "url": flow.request.pretty_url,
            "method": flow.request.method,
        }
        with s.deny_lock:
            s.deny_log.append(entry)


class CredentialBrokerAddon:
    """
    For configured hosts, handles two credential modes:

    Swap mode (fake_value present): replaces the agent's placeholder value with
    the real credential. Blocks if an unexpected non-empty value is seen (prompt
    injection / agent misbehavior).

    Inject mode (no fake_value): unconditionally sets the header to real_value,
    regardless of what the agent sent. Useful for cookies or other credentials
    the agent should never need to supply itself.

    Real credentials are never logged.
    """

    def __init__(self, state: ProxyState):
        self.state = state

    def _resolve_real_value(self, raw_real: str, host: str, header: str, flow: HTTPFlow) -> Optional[str]:
        """
        Resolve ``real_value`` to a concrete string.

        ``"!claude-subscription"`` is a dynamic resolver: calls
        ``ClaudeAuthManager.get_header_value()`` and returns the live token.
        Returns ``None`` and sets a 403 response on ``flow`` when resolution
        fails so the caller can abort immediately.
        """
        if raw_real != "!claude-subscription":
            return raw_real

        if self.state.claude_auth is None:
            flow.response = http.Response.make(
                503,
                "claude_subscription not configured in proxy config",
                {"Content-Type": "text/plain"},
            )
            print(json.dumps({
                "event": "claude_subscription_error",
                "host": host,
                "header": header,
                "reason": "not_configured",
            }))
            return None

        value = self.state.claude_auth.get_header_value()
        if value is None:
            flow.response = http.Response.make(
                503,
                "Claude subscription: not logged in — visit /claude/login on the management API",
                {"Content-Type": "text/plain"},
            )
            print(json.dumps({
                "event": "claude_subscription_error",
                "host": host,
                "header": header,
                "reason": "not_logged_in",
            }))
            return None

        return value

    def request(self, flow: HTTPFlow):
        # Skip flows already denied by AllowlistAddon
        if flow.response is not None:
            return

        host = flow.request.pretty_host
        for cred in self.state.credentials:
            if cred["host"] != host:
                continue
            header = cred["header"]
            raw_real = cred["real_value"]
            fake = cred.get("fake_value")

            if fake is None:
                # Inject mode: resolve and set the header unconditionally
                real = self._resolve_real_value(raw_real, host, header, flow)
                if real is None:
                    return
                flow.request.headers[header] = real
                print(json.dumps({
                    "event": "credential_injected",
                    "host": host,
                    "header": header,
                    "mode": "inject",
                }))
            else:
                current = flow.request.headers.get(header, "")
                if current == fake:
                    real = self._resolve_real_value(raw_real, host, header, flow)
                    if real is None:
                        return
                    flow.request.headers[header] = real
                    print(json.dumps({
                        "event": "credential_injected",
                        "host": host,
                        "header": header,
                        "mode": "swap",
                    }))
                elif current:
                    # Non-empty value that isn't the expected fake — block and alert
                    flow.response = http.Response.make(
                        403,
                        f"Credential mismatch on {host}: unexpected value in {header}",
                        {"Content-Type": "text/plain"},
                    )
                    # Log fake (confirms expected identity) but never real value
                    print(json.dumps({
                        "event": "credential_mismatch",
                        "host": host,
                        "header": header,
                        "expected_fake": fake,
                    }))

    def response(self, flow: HTTPFlow):
        host = flow.request.pretty_host
        cfg = self.state.host_config.get(host)
        if cfg is None or cfg.allow_response_cookies is None:
            return
        allowed = set(cfg.allow_response_cookies)
        kept = [
            v for v in flow.response.headers.get_all("set-cookie")
            if v.split("=")[0].strip() in allowed
        ]
        flow.response.headers.pop("set-cookie", None)
        for v in kept:
            flow.response.headers.add("set-cookie", v)


class LoggingAddon:
    """Structured JSON logging of all allowed outbound requests."""

    def __init__(self, state: ProxyState):
        self.state = state
        # Headers that carry credentials — excluded from logs
        self._sensitive = {cred["header"].lower() for cred in state.credentials}

    def request(self, flow: HTTPFlow):
        # Skip flows already denied upstream
        if flow.response is not None:
            return
        print(json.dumps({
            "event": "request",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": flow.request.method,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
        }))


# ── Management API ─────────────────────────────────────────────────────────────

def create_app(state: ProxyState) -> Flask:
    app = Flask(__name__)
    # Silence werkzeug request logs and Flask startup banner
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    import flask.cli
    flask.cli.show_server_banner = lambda *_a, **_kw: None

    @app.get("/denied")
    def get_denied():
        with state.deny_lock:
            return jsonify(list(state.deny_log))

    @app.get("/allowlist")
    def get_allowlist_view():
        now = time.time()
        with state.temp_lock:
            active_temps = {
                h: exp for h, exp in state.temp_allows.items() if now < exp
            }
        return jsonify({
            "permanent": sorted(state.allowlist),
            "temporary": active_temps,
        })

    @app.post("/allow/temp")
    def temp_allow():
        body = flask_request.get_json(force=True)
        host = body["host"]
        duration = float(body.get("duration_seconds", 300))
        with state.temp_lock:
            state.temp_allows[host] = time.time() + duration
        return jsonify({"ok": True})

    @app.post("/allow/permanent")
    def permanent_allow():
        host = flask_request.get_json(force=True)["host"]
        try:
            with open(state.allowlist_path) as f:
                data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            data = {}
        hosts = data.get("allowed_hosts", [])
        host_names = [h if isinstance(h, str) else h["host"] for h in hosts]
        if host not in host_names:
            hosts.append({"host": host})
            data["allowed_hosts"] = hosts
            with open(state.allowlist_path, "w") as f:
                yaml.safe_dump(data, f)
        state.allowlist = load_allowlist(state.allowlist_path)
        state.host_config = load_host_config(state.allowlist_path)
        return jsonify({"ok": True})

    # ── Claude subscription auth endpoints ──────────────────────────────────────
    #
    # Login flow (operator visits from a browser on the host, never from sandbox):
    #
    #   GET  /claude/login     → 302 redirect to Claude's OAuth authorization page
    #   GET  /claude/callback  → exchanges the code; returns success page
    #   GET  /claude/status    → JSON with token state / expiry
    #   POST /claude/logout    → revokes stored tokens

    def _require_claude_auth():
        """Return (claude_auth, None) or (None, error_response)."""
        if state.claude_auth is None:
            return None, (
                jsonify({"error": "claude_subscription not configured in proxy config"}),
                404,
            )
        return state.claude_auth, None

    @app.get("/claude/login")
    def claude_login():
        """
        Redirect the operator's browser to Claude's OAuth authorization page.

        Optional query parameter ``redirect_uri`` overrides the default
        callback URL (useful when the proxy is reachable on a non-localhost
        address).
        """
        auth, err = _require_claude_auth()
        if err:
            return err

        default_callback = (
            flask_request.url_root.rstrip("/") + "/claude/callback"
        )
        redirect_uri = flask_request.args.get("redirect_uri", default_callback)
        login_url = auth.start_login(redirect_uri)
        return redirect(login_url, code=302)

    @app.get("/claude/callback")
    def claude_callback():
        """
        OAuth callback — Claude redirects here after successful login.

        Exchanges the authorization code for tokens and stores them.  On
        success renders a plain-text page the operator can close.
        """
        auth, err = _require_claude_auth()
        if err:
            return err

        code = flask_request.args.get("code", "")
        state_param = flask_request.args.get("state", "")
        error = flask_request.args.get("error", "")

        if error:
            return f"OAuth error from Claude: {error}", 400

        if not code:
            return "Missing 'code' parameter in callback", 400

        try:
            auth.complete_login(code, state_param)
        except ClaudeAuthError as exc:
            return f"Login failed: {exc}", 400

        return (
            "<html><body><h2>Claude login successful.</h2>"
            "<p>You can close this tab. The proxy will now swap the fake token "
            "for your real session token on every request to api.anthropic.com.</p>"
            "</body></html>"
        )

    @app.get("/claude/status")
    def claude_status():
        """Return current token state: logged_in, expiry, refresh_token presence."""
        auth, err = _require_claude_auth()
        if err:
            return err
        return jsonify(auth.status())

    @app.post("/claude/logout")
    def claude_logout():
        """Clear stored tokens from memory and disk."""
        auth, err = _require_claude_auth()
        if err:
            return err
        auth.logout()
        return jsonify({"ok": True})

    return app


# ── SIGHUP reload ──────────────────────────────────────────────────────────────

def setup_sighup(state: ProxyState):
    def handler(signum, frame):
        state.allowlist = load_allowlist(state.allowlist_path)
        state.host_config = load_host_config(state.allowlist_path)
        state.credentials = load_credentials(state.allowlist_path)
        print(json.dumps({
            "event": "sighup_reload",
            "host_count": len(state.allowlist),
            "credential_count": len(state.credentials),
        }))
    signal.signal(signal.SIGHUP, handler)


# ── mitmproxy entry point ──────────────────────────────────────────────────────

_config_path = os.environ.get("PROXY_CONFIG", "config.yaml")

state = ProxyState(
    allowlist=load_allowlist(_config_path),
    allowlist_path=_config_path,
    credentials=load_credentials(_config_path),
    temp_allows={},
    temp_lock=threading.Lock(),
    deny_log=collections.deque(maxlen=1000),
    deny_lock=threading.Lock(),
    host_config=load_host_config(_config_path),
    management_port=load_management_port(_config_path),
    claude_auth=load_claude_auth(_config_path),
)

setup_sighup(state)

addons = [
    AllowlistAddon(state),
    CredentialBrokerAddon(state),
    LoggingAddon(state),
]
