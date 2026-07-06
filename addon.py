"""
mitmproxy Sandbox Proxy

Run headless:  mitmdump -s addon.py
Run with UI:   mitmweb -s addon.py

Environment variables:
  PROXY_CONFIG   path to config YAML (default: config.yaml)

See config.py for the config and secrets file formats.
"""

import asyncio
import functools
import json
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone

from mitmproxy import http
from mitmproxy.http import HTTPFlow

import registries
from config import Config, ProxyState
from management_api import create_app


# ── Happy eyeballs ───────────────────────────────────────────────────────────────

def happy_eyeballs_supported(version: tuple = None) -> bool:
    """asyncio's happy-eyeballs implementation (asyncio.staggered) crashes
    under the eager task factory mitmproxy sets, on Pythons predating the
    cpython#124309 rewrite (fixed in 3.12.8 / 3.13.1)."""
    v = version or sys.version_info
    return v[:3] >= (3, 12, 8) and v[:3] != (3, 13, 0)


def enable_happy_eyeballs(delay: float) -> None:
    """Race IPv6/IPv4 upstream connects (RFC 8305 happy eyeballs).

    mitmproxy opens upstream connections with a bare asyncio.open_connection
    (mitmproxy/proxy/server.py), which tries resolved addresses one at a
    time: when a host publishes an AAAA record but its IPv6 path blackholes,
    the connect stalls for the full OS timeout before IPv4 is ever tried.
    Injecting happy_eyeballs_delay makes asyncio race the address families.
    Remove once https://github.com/mitmproxy/mitmproxy/issues/8088 ships.
    """
    original = asyncio.open_connection

    @functools.wraps(original)
    def open_connection(host=None, port=None, **kwargs):
        # Only meaningful for host-based connects, not pre-made sockets
        if host is not None and kwargs.get("sock") is None:
            kwargs.setdefault("happy_eyeballs_delay", delay)
        return original(host, port, **kwargs)

    asyncio.open_connection = open_connection


# ── Addons ─────────────────────────────────────────────────────────────────────

class AllowlistAddon:
    """
    Checks every request against the permanent allowlist and active temporary
    allows. Denied requests receive a 503 response and are logged.
    """

    def __init__(self, state: ProxyState):
        self.state = state

    def request(self, flow: HTTPFlow):
        host = flow.request.pretty_host
        s = self.state

        if host in s.allowlist:
            return

        with s.temp_lock:
            exp = s.temp_allows.get(host)
            if exp and time.time() < exp:
                return

        host_rules = s.restricted.get(host)
        if host_rules is not None:
            self._apply_registry_policy(flow, host_rules)
            return

        flow.response = http.Response.make(
            503,
            f"Request to {host} is pending human approval. Retry the request after approval is granted.",
            {"Content-Type": "text/plain", "Retry-After": "5"},
        )
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": host,
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "type": "pending_approval",
        }
        with s.deny_lock:
            s.deny_log.append(entry)

    def _apply_registry_policy(self, flow: HTTPFlow, host_rules):
        host = flow.request.pretty_host
        verdict = registries.evaluate(
            host_rules,
            method=flow.request.method,
            path_with_query=flow.request.path,
            headers=flow.request.headers,
            has_body=bool(flow.request.raw_content),
        )

        if isinstance(verdict, registries.Violation):
            flow.response = http.Response.make(
                403,
                f"Blocked by registry policy '{host_rules.source}': {verdict.reason}. "
                "This is a policy violation, not a pending approval — it will not "
                "be granted by waiting.",
                {"Content-Type": "text/plain"},
            )
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "host": host,
                # Attacker-influenced; truncate so the deny log stays bounded
                "url": flow.request.pretty_url[:512],
                "method": flow.request.method,
                "type": "policy_violation",
                "reason": verdict.reason,
            }
            with self.state.deny_lock:
                self.state.deny_log.append(entry)
            print(json.dumps({
                "event": "registry_policy_violation",
                "host": host,
                "method": flow.request.method,
                "path": flow.request.path[:512],
                "reason": verdict.reason,
                "policy": host_rules.source,
            }))
            return

        for name in verdict.drop_headers:
            del flow.request.headers[name]
        for name, cap in verdict.clamp_headers:
            flow.request.headers[name] = flow.request.headers[name][:cap]
        if verdict.drop_headers or verdict.clamp_headers:
            # Names only — scrubbed values may contain credentials
            print(json.dumps({
                "event": "registry_headers_scrubbed",
                "host": host,
                "dropped": sorted(verdict.drop_headers),
                "clamped": sorted(name for name, _ in verdict.clamp_headers),
            }))
        flow.metadata["registry"] = host_rules.source


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
            if cred.host != host:
                continue

            if cred.fake_value is None:
                # Inject mode: set the header unconditionally
                flow.request.headers[cred.header] = cred.real_value
                print(json.dumps({
                    "event": "credential_injected",
                    "host": host,
                    "header": cred.header,
                    "mode": "inject",
                }))
            else:
                current = flow.request.headers.get(cred.header, "")
                if current == cred.fake_value:
                    flow.request.headers[cred.header] = cred.real_value
                    print(json.dumps({
                        "event": "credential_injected",
                        "host": host,
                        "header": cred.header,
                        "mode": "swap",
                    }))
                elif current:
                    # Non-empty value that isn't the expected fake — block and alert
                    flow.response = http.Response.make(
                        403,
                        f"Credential mismatch on {host}: unexpected value in {cred.header}",
                        {"Content-Type": "text/plain"},
                    )
                    # Log fake (confirms expected identity) but never real value
                    print(json.dumps({
                        "event": "credential_mismatch",
                        "host": host,
                        "header": cred.header,
                        "expected_fake": cred.fake_value,
                    }))


class ResponseCookieFilterAddon:
    """Filters Set-Cookie response headers according to each host's config."""

    def __init__(self, state: ProxyState):
        self.state = state

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
        self._sensitive = {cred.header.lower() for cred in state.credentials}

    def request(self, flow: HTTPFlow):
        # Skip flows already denied upstream
        if flow.response is not None:
            return
        entry = {
            "event": "request",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": flow.request.method,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
        }
        registry = flow.metadata.get("registry")
        if registry:
            entry["registry"] = registry
        print(json.dumps(entry))


class ManagementApiAddon:
    """Starts the management API in a background thread once mitmproxy is running."""

    def __init__(self, state: ProxyState):
        self.state = state

    def running(self):
        threading.Thread(
            target=lambda: create_app(self.state).run(
                host="127.0.0.1", port=self.state.management_port, use_reloader=False
            ),
            daemon=True,
        ).start()


# ── SIGHUP reload ──────────────────────────────────────────────────────────────

def setup_sighup(state: ProxyState):
    def handler(signum, frame):
        state.reload()
        print(json.dumps({
            "event": "sighup_reload",
            "host_count": len(state.allowlist),
            "credential_count": len(state.credentials),
            "restricted_count": len(state.restricted),
        }))
    signal.signal(signal.SIGHUP, handler)


# ── mitmproxy entry point ──────────────────────────────────────────────────────

class SandboxProxy:
    """
    Entry-point addon. Builds the proxy state from PROXY_CONFIG when mitmproxy
    loads the script — importing this module has no side effects. A config
    error raised here is logged by mitmproxy's script loader and terminates
    mitmdump at startup (via its ErrorCheck addon).
    """

    def load(self, loader):
        config_path = os.environ.get("PROXY_CONFIG", "config.yaml")
        config = Config.load(config_path)
        state = ProxyState(config_path=config_path, management_port=config.management_port)
        state.apply(config)
        setup_sighup(state)
        self.state = state
        self.addons = [
            AllowlistAddon(state),
            CredentialBrokerAddon(state),
            ResponseCookieFilterAddon(state),
            LoggingAddon(state),
            ManagementApiAddon(state),
        ]

        # uv enforces requires-python (>=3.12.8,!=3.13.0); this guard covers
        # runs outside uv, where a broken interpreter would make every connect hang.
        delay = config.happy_eyeballs_delay
        if delay and not happy_eyeballs_supported():
            print(json.dumps({
                "event": "happy_eyeballs_unsupported",
                "python": ".".join(map(str, sys.version_info[:3])),
                "message": (
                    "this Python's asyncio happy-eyeballs crashes under mitmproxy's "
                    "eager task factory (fixed in 3.12.8/3.13.1); falling back to "
                    "sequential connects — IPv6-blackholed hosts will stall"
                ),
            }))
        elif delay:
            enable_happy_eyeballs(delay)
            print(json.dumps({
                "event": "happy_eyeballs_enabled",
                "delay_seconds": delay,
            }))


addons = [SandboxProxy()]
