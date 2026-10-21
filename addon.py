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
from config import Config, HostConfig, HostEntry, ProxyState
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
    Checks every request against the host's `hosts:` entries and any active
    temporary allow. Denied requests receive a 503 response and are logged.

    A host may carry several entries (hand-written and service-generated).
    Entries whose swap-mode credential the request presents (the header
    carries that credential's fake_value) are evaluated first, so a client
    asking for authenticated access isn't shadowed by an earlier
    unauthenticated entry; then the rest, in config order, followed by the
    entries of any temporarily enabled (otherwise dormant) service, with a
    live temporary allow appended as a final unrestricted entry. The first entry
    that permits the request wins: an unrestricted entry always permits, a
    restricted one when registries.evaluate allows the request. Only the
    winning entry's header scrubbing is applied, and the entry is stamped on
    flow.metadata["host_entry"] for CredentialBrokerAddon and
    ResponseCookieFilterAddon, and the full list considered on
    flow.metadata["host_entries"]. A denial reports the first entry that rejected
    the request, and names any disabled service that would have permitted it.
    """

    def __init__(self, state: ProxyState):
        self.state = state

    def request(self, flow: HTTPFlow):
        host = flow.request.pretty_host
        s = self.state

        entries = list(s.hosts.get(host, ()))
        with s.temp_lock:
            now = time.time()
            active = {key for key, exp in s.temp_services.items() if now < exp}
            for key in active:
                entries.extend(s.dormant_services.get(key, {}).get(host, ()))
            exp = s.temp_allows.get(host)
            if exp and now < exp:
                # Temp-allow grants access, not a cookie policy: keep whatever
                # the host's configured entries filter.
                entries.append(HostEntry(
                    host_config=entries[0].host_config if entries else HostConfig(),
                ))

        if not entries:
            self._deny_pending(flow)
            return
        flow.metadata["host_entries"] = entries

        headers = flow.request.headers
        presented = [
            e for e in entries
            if e.credential is not None and e.credential.fake_value is not None
            and headers.get(e.credential.header) == e.credential.fake_value
        ]
        rest = [e for e in entries if not any(e is p for p in presented)]

        rejection = None  # (entry, Violation) of the first entry to reject
        for entry in presented + rest:
            if entry.rules is None:
                flow.metadata["host_entry"] = entry
                return
            verdict = self._evaluate(entry, flow)
            if isinstance(verdict, registries.Allowed):
                self._apply_scrubbing(flow, verdict)
                flow.metadata["host_entry"] = entry
                flow.metadata["registry"] = entry.rules.source
                return
            if rejection is None:
                rejection = (entry, verdict)

        self._deny_violation(flow, *rejection)

    @staticmethod
    def _evaluate(entry: HostEntry, flow: HTTPFlow):
        return registries.evaluate(
            entry.rules,
            method=flow.request.method,
            path_with_query=flow.request.path,
            headers=flow.request.headers,
            # raw_content is the buffered body mitmproxy actually forwards;
            # the client-supplied Content-Length header can lie.
            body_len=len(flow.request.raw_content or b""),
            content_type=flow.request.headers.get("content-type"),
        )

    def _permits(self, entry: HostEntry, flow: HTTPFlow) -> bool:
        return entry.rules is None or isinstance(self._evaluate(entry, flow), registries.Allowed)

    def _disabled_services(self, flow: HTTPFlow) -> list:
        """Disabled services (not temporarily enabled either) that would
        permit this request."""
        s = self.state
        host = flow.request.pretty_host
        with s.temp_lock:
            now = time.time()
            active = {key for key, exp in s.temp_services.items() if now < exp}
        return [
            key for key, dormant in s.dormant_services.items()
            if key not in active
            and any(self._permits(e, flow) for e in dormant.get(host, ()))
        ]

    def _log_denial(self, flow: HTTPFlow, entry: dict) -> None:
        # Name the disabled services that would have permitted the request,
        # so the operator can enable one instead of opening the whole host.
        disabled = self._disabled_services(flow)
        if disabled:
            entry["disabled_services"] = [
                {"service": name, **({"host": h} if h else {})} for name, h in disabled
            ]
        with self.state.deny_lock:
            self.state.deny_log.append(entry)

    def _deny_pending(self, flow: HTTPFlow):
        host = flow.request.pretty_host
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
        self._log_denial(flow, entry)

    def _deny_violation(self, flow: HTTPFlow, host_entry: HostEntry, verdict):
        host = flow.request.pretty_host
        source = host_entry.rules.source
        flow.response = http.Response.make(
            503,
            f"Request to {host} is not currently allowed by policy "
            f"'{source}': {verdict.reason}. Request is pending "
            "human approval. Retry the request after approval is granted.",
            {"Content-Type": "text/plain", "Retry-After": "5"},
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
        self._log_denial(flow, entry)
        print(json.dumps({
            "event": "registry_policy_violation",
            "host": host,
            "method": flow.request.method,
            "path": flow.request.path[:512],
            "reason": verdict.reason,
            "policy": source,
        }))

    def _apply_scrubbing(self, flow: HTTPFlow, verdict):
        for name in verdict.drop_headers:
            del flow.request.headers[name]
        for name, cap in verdict.clamp_headers:
            flow.request.headers[name] = flow.request.headers[name][:cap]
        if verdict.drop_headers or verdict.clamp_headers:
            # Names only — scrubbed values may contain credentials
            print(json.dumps({
                "event": "registry_headers_scrubbed",
                "host": flow.request.pretty_host,
                "dropped": sorted(verdict.drop_headers),
                "clamped": sorted(name for name, _ in verdict.clamp_headers),
            }))


class CredentialBrokerAddon:
    """
    Brokers the credential of the host entry that permitted the request
    (flow.metadata["host_entry"], stamped by AllowlistAddon), in one of two
    modes:

    Swap mode (fake_value present): replaces the agent's placeholder value with
    the real credential. Blocks if an unexpected non-empty value is seen (prompt
    injection / agent misbehavior).

    Inject mode (no fake_value): unconditionally sets the header to real_value,
    regardless of what the agent sent. Useful for cookies or other credentials
    the agent should never need to supply itself.

    A credential declared on some other entry for the host is withheld: its
    header is stripped rather than forwarded, since an unrestricted entry does
    no header scrubbing of its own and would otherwise pass the fake token (or
    anything else the client put there) upstream.

    Real credentials are never logged.
    """

    def __init__(self, state: ProxyState):
        self.state = state

    def request(self, flow: HTTPFlow):
        # Skip flows already denied by AllowlistAddon
        if flow.response is not None:
            return

        host = flow.request.pretty_host
        host_entry = flow.metadata.get("host_entry")
        cred = host_entry.credential if host_entry is not None else None
        self._strip_withheld(flow, cred)
        if cred is None:
            return

        if cred.fake_value is None:
            # Inject mode: set the header unconditionally
            flow.request.headers[cred.header] = cred.real_value
            print(json.dumps({
                "event": "credential_injected",
                "host": host,
                "header": cred.header,
                "mode": "inject",
            }))
            return

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

    def _strip_withheld(self, flow: HTTPFlow, cred):
        """Drop headers carrying a credential of another entry for this host."""
        host = flow.request.pretty_host
        keep = cred.header.lower() if cred is not None else None
        # The entries AllowlistAddon considered, temporarily enabled services
        # included; state.hosts when it didn't stamp them.
        entries = flow.metadata.get("host_entries", self.state.hosts.get(host, ()))
        withheld = {
            e.credential.header for e in entries
            if e.credential is not None and e.credential.header.lower() != keep
        }
        stripped = sorted(h for h in withheld if h in flow.request.headers)
        for name in stripped:
            del flow.request.headers[name]
        if stripped:
            # Names only — the stripped value is the client's (fake) token
            print(json.dumps({
                "event": "credential_withheld",
                "host": host,
                "headers": stripped,
                "message": (
                    f"{host}: request permitted by an entry without this "
                    f"credential; stripped {stripped} instead of brokering"
                ),
            }))


class ResponseCookieFilterAddon:
    """Filters Set-Cookie response headers according to the config of the
    host entry that permitted the request (see AllowlistAddon)."""

    def __init__(self, state: ProxyState):
        self.state = state

    def response(self, flow: HTTPFlow):
        host_entry = flow.metadata.get("host_entry")
        if host_entry is None or host_entry.host_config.allow_response_cookies is None:
            return
        allowed = set(host_entry.host_config.allow_response_cookies)
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
        restricted_count = sum(
            1 for entries in state.hosts.values() for e in entries if e.rules is not None
        )
        print(json.dumps({
            "event": "sighup_reload",
            "host_count": len(state.hosts),
            "credential_count": len(state.credentials),
            "restricted_count": restricted_count,
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
