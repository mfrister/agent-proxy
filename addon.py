"""
mitmproxy Sandbox Proxy

Run headless:  mitmdump -s addon.py
Run with UI:   mitmweb -s addon.py

Environment variables:
  PROXY_CONFIG        path to allowlist config YAML (default: config.yaml)
  PROXY_CREDENTIALS   JSON array of credential mappings (default: [])
  PROXY_MGMT_PORT     management API port (default: 8081)

Credential mapping format:
  [{"host": "api.example.com", "header": "Authorization",
    "fake_value": "Bearer sk-fake", "real_value": "Bearer sk-real"}]
"""

import collections
import json
import logging
import os
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
class ProxyState:
    allowlist: set            # permanent allowed hosts
    allowlist_path: str       # path to config YAML, used by SIGHUP reload
    credentials: list         # [{host, header, fake_value, real_value}]
    temp_allows: dict         # host -> expires_at (epoch seconds)
    temp_lock: threading.Lock
    deny_log: collections.deque  # maxlen=1000, entries: {timestamp,host,url,method}
    deny_lock: threading.Lock


# ── Config loaders ─────────────────────────────────────────────────────────────

def load_allowlist(path: str) -> set:
    """Load allowed hosts from YAML. Returns empty set if file is missing."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return set(data.get("allowed_hosts", []))
    except FileNotFoundError:
        return set()


def load_credentials() -> list:
    """Parse credential mappings from PROXY_CREDENTIALS env var (JSON array)."""
    raw = os.environ.get("PROXY_CREDENTIALS", "[]")
    return json.loads(raw)


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
        port = int(os.environ.get("PROXY_MGMT_PORT", "8082"))
        threading.Thread(
            target=lambda: create_app(self.state).run(
                host="127.0.0.1", port=port, use_reloader=False
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
    For configured hosts, swaps the fake credential value for the real one.
    If an unexpected (non-fake, non-empty) value is seen, the request is
    blocked — this indicates prompt injection or agent misbehavior.
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
            fake = cred["fake_value"]
            real = cred["real_value"]

            current = flow.request.headers.get(header, "")
            if current == fake:
                flow.request.headers[header] = real
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
        duration = float(body["duration_seconds"])
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
        if host not in hosts:
            hosts.append(host)
            data["allowed_hosts"] = hosts
            with open(state.allowlist_path, "w") as f:
                yaml.safe_dump(data, f)
        state.allowlist = load_allowlist(state.allowlist_path)
        return jsonify({"ok": True})

    return app


# ── SIGHUP reload ──────────────────────────────────────────────────────────────

def setup_sighup(state: ProxyState):
    def handler(signum, frame):
        state.allowlist = load_allowlist(state.allowlist_path)
        print(json.dumps({
            "event": "sighup_reload",
            "host_count": len(state.allowlist),
        }))
    signal.signal(signal.SIGHUP, handler)


# ── mitmproxy entry point ──────────────────────────────────────────────────────

_config_path = os.environ.get("PROXY_CONFIG", "config.yaml")

state = ProxyState(
    allowlist=load_allowlist(_config_path),
    allowlist_path=_config_path,
    credentials=load_credentials(),
    temp_allows={},
    temp_lock=threading.Lock(),
    deny_log=collections.deque(maxlen=1000),
    deny_lock=threading.Lock(),
)

setup_sighup(state)

addons = [
    AllowlistAddon(state),
    CredentialBrokerAddon(state),
    LoggingAddon(state),
]
