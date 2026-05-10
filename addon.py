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

import yaml
from flask import Flask, jsonify, request as flask_request
from mitmproxy import http
from mitmproxy.http import HTTPFlow


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
    creds = data.get("credentials", [])
    # YAML block literals (|) and folded scalars (>) add a trailing newline.
    # Strip all credential values so that LF/CR never reach HTTP/2 header fields,
    # where they are forbidden (RFC 9113 § 8.2.1) and cause PROTOCOL_ERROR.
    for cred in creds:
        for key in ("real_value", "fake_value"):
            if key in cred and isinstance(cred[key], str):
                cred[key] = cred[key].strip()
    return creds


def load_management_port(path: str) -> int:
    """Load management API port from config YAML."""
    data = load_config(path)
    return int(data.get("management_port", 8082))


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

    def request(self, flow: HTTPFlow):
        # Skip flows already denied by AllowlistAddon
        if flow.response is not None:
            return

        host = flow.request.pretty_host
        for cred in self.state.credentials:
            if cred["host"] != host:
                continue
            header = cred["header"]
            real = cred["real_value"]
            fake = cred.get("fake_value")

            if fake is None:
                # Inject mode: set the header unconditionally.
                # Lowercase the name: HTTP/2 forbids uppercase header names, and
                # the mitmproxy h2 layer only normalises case when the incoming
                # request was HTTP/1.1; if the agent already spoke HTTP/2 the
                # header is forwarded as stored, so we must store it lowercase.
                flow.request.headers[header.lower()] = real
                print(json.dumps({
                    "event": "credential_injected",
                    "host": host,
                    "header": header,
                    "mode": "inject",
                }))
            else:
                current = flow.request.headers.get(header, "")
                if current == fake:
                    flow.request.headers[header.lower()] = real
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
)

setup_sighup(state)

addons = [
    AllowlistAddon(state),
    CredentialBrokerAddon(state),
    LoggingAddon(state),
]
