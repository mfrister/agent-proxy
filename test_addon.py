"""
Tests for the mitmproxy sandbox proxy addons.

Run with:  pytest test_addon.py -v
"""

import collections
import json
import os
import signal
import threading
import time
from unittest.mock import MagicMock

import pytest
import yaml


# ── Test helpers ───────────────────────────────────────────────────────────────

def make_state(**overrides):
    """Return a ProxyState with sensible defaults, merged with any overrides."""
    from addon import ProxyState

    defaults = dict(
        allowlist={"allowed.com"},
        allowlist_path="config.yaml",
        credentials=[],
        temp_allows={},
        temp_lock=threading.Lock(),
        deny_log=collections.deque(maxlen=1000),
        deny_lock=threading.Lock(),
    )
    defaults.update(overrides)
    return ProxyState(**defaults)


def make_flow(host, method="GET", path="/", headers=None):
    """Return a mock HTTPFlow with the given request properties."""
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.request.pretty_url = f"http://{host}{path}"
    flow.request.method = method
    flow.request.path = path
    flow.request.headers = dict(headers or {})
    flow.response = None
    return flow


# Credential fixture used across multiple test classes
CRED = {
    "host": "api.example.com",
    "header": "Authorization",
    "fake_value": "Bearer sk-fake",
    "real_value": "Bearer sk-real",
}


# ── AllowlistAddon ─────────────────────────────────────────────────────────────

class TestAllowlistAddon:
    def test_allowed_host_passes(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist={"good.com"}))
        flow = make_flow("good.com")
        addon.request(flow)
        assert flow.response is None

    def test_blocked_host_gets_403(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set()))
        flow = make_flow("evil.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_host_logged(self):
        from addon import AllowlistAddon
        state = make_state(allowlist=set())
        addon = AllowlistAddon(state)
        flow = make_flow("evil.com", method="POST", path="/steal")
        addon.request(flow)
        assert len(state.deny_log) == 1
        entry = state.deny_log[0]
        assert entry["host"] == "evil.com"
        assert entry["method"] == "POST"
        assert "timestamp" in entry

    def test_temp_allow_within_ttl_passes(self):
        from addon import AllowlistAddon
        state = make_state(
            allowlist=set(),
            temp_allows={"temp.com": time.time() + 60},
        )
        addon = AllowlistAddon(state)
        flow = make_flow("temp.com")
        addon.request(flow)
        assert flow.response is None

    def test_temp_allow_expired_blocks(self):
        from addon import AllowlistAddon
        state = make_state(
            allowlist=set(),
            temp_allows={"temp.com": time.time() - 1},
        )
        addon = AllowlistAddon(state)
        flow = make_flow("temp.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_multiple_denials_all_logged(self):
        from addon import AllowlistAddon
        state = make_state(allowlist=set())
        addon = AllowlistAddon(state)
        for host in ["a.com", "b.com", "c.com"]:
            addon.request(make_flow(host))
        assert len(state.deny_log) == 3


# ── CredentialBrokerAddon ──────────────────────────────────────────────────────

class TestCredentialBrokerAddon:
    def test_fake_swapped_for_real(self):
        from addon import CredentialBrokerAddon
        addon = CredentialBrokerAddon(make_state(credentials=[CRED]))
        flow = make_flow("api.example.com", headers={"Authorization": "Bearer sk-fake"})
        addon.request(flow)
        assert flow.request.headers["Authorization"] == "Bearer sk-real"
        assert flow.response is None

    def test_no_header_passes_through(self):
        from addon import CredentialBrokerAddon
        addon = CredentialBrokerAddon(make_state(credentials=[CRED]))
        flow = make_flow("api.example.com", headers={})
        addon.request(flow)
        assert flow.response is None

    def test_unexpected_value_blocks(self):
        from addon import CredentialBrokerAddon
        addon = CredentialBrokerAddon(make_state(credentials=[CRED]))
        flow = make_flow("api.example.com", headers={"Authorization": "Bearer injected"})
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_non_matching_host_unchanged(self):
        from addon import CredentialBrokerAddon
        addon = CredentialBrokerAddon(make_state(credentials=[CRED]))
        flow = make_flow("other.com", headers={"Authorization": "Bearer anything"})
        addon.request(flow)
        assert flow.response is None

    def test_real_value_not_in_log(self, capsys):
        from addon import CredentialBrokerAddon
        addon = CredentialBrokerAddon(make_state(credentials=[CRED]))
        flow = make_flow("api.example.com", headers={"Authorization": "Bearer injected"})
        addon.request(flow)
        captured = capsys.readouterr().out
        assert "sk-real" not in captured

    def test_skips_already_denied_flow(self):
        from addon import CredentialBrokerAddon
        from mitmproxy import http
        addon = CredentialBrokerAddon(make_state(credentials=[CRED]))
        flow = make_flow("api.example.com", headers={"Authorization": "Bearer injected"})
        # Simulate AllowlistAddon already set a 403
        flow.response = http.Response.make(403, "Blocked")
        addon.request(flow)
        # Should not overwrite the existing response
        assert flow.response.status_code == 403
        assert b"Blocked" in flow.response.content


# ── LoggingAddon ───────────────────────────────────────────────────────────────

class TestLoggingAddon:
    def test_logs_allowed_request(self, capsys):
        from addon import LoggingAddon
        addon = LoggingAddon(make_state())
        flow = make_flow("allowed.com", method="GET", path="/data")
        addon.request(flow)
        out = capsys.readouterr().out
        entry = json.loads(out.strip())
        assert entry["event"] == "request"
        assert entry["host"] == "allowed.com"
        assert entry["method"] == "GET"
        assert entry["path"] == "/data"

    def test_skips_denied_flow(self, capsys):
        from addon import LoggingAddon
        from mitmproxy import http
        addon = LoggingAddon(make_state())
        flow = make_flow("evil.com")
        flow.response = http.Response.make(403, "Blocked")
        addon.request(flow)
        assert capsys.readouterr().out == ""


# ── SIGHUP reload ──────────────────────────────────────────────────────────────

class TestSighupReload:
    def test_sighup_reloads_allowlist(self, tmp_path):
        from addon import load_allowlist, setup_sighup

        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts:\n  - original.com\n")

        state = make_state(
            allowlist={"original.com"},
            allowlist_path=str(config),
        )
        setup_sighup(state)

        # Update config on disk then signal
        config.write_text("allowed_hosts:\n  - original.com\n  - new.com\n")
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.05)

        assert "new.com" in state.allowlist
        assert "original.com" in state.allowlist


# ── Management API ─────────────────────────────────────────────────────────────

@pytest.fixture
def mgmt(tmp_path):
    """Flask test client wired to a fresh ProxyState with a temp config file."""
    from addon import create_app

    config = tmp_path / "config.yaml"
    config.write_text("allowed_hosts:\n  - existing.com\n")

    state = make_state(
        allowlist={"existing.com"},
        allowlist_path=str(config),
    )
    app = create_app(state)
    app.config["TESTING"] = True
    with app.test_client() as client:
        client._state = state
        yield client


class TestManagementAPI:
    def test_get_denied_empty(self, mgmt):
        r = mgmt.get("/denied")
        assert r.status_code == 200
        assert r.get_json() == []

    def test_get_denied_with_entries(self, mgmt):
        state = mgmt._state
        with state.deny_lock:
            state.deny_log.append({
                "timestamp": "2024-01-01T00:00:00+00:00",
                "host": "evil.com",
                "url": "http://evil.com/",
                "method": "GET",
            })
        data = mgmt.get("/denied").get_json()
        assert len(data) == 1
        assert data[0]["host"] == "evil.com"

    def test_get_allowlist_permanent(self, mgmt):
        data = mgmt.get("/allowlist").get_json()
        assert "existing.com" in data["permanent"]
        assert data["temporary"] == {}

    def test_get_allowlist_active_temp_included(self, mgmt):
        state = mgmt._state
        with state.temp_lock:
            state.temp_allows["live.com"] = time.time() + 60
            state.temp_allows["dead.com"] = time.time() - 1  # expired
        data = mgmt.get("/allowlist").get_json()
        assert "live.com" in data["temporary"]
        assert "dead.com" not in data["temporary"]

    def test_post_allow_temp(self, mgmt):
        r = mgmt.post("/allow/temp", json={"host": "temp.com", "duration_seconds": 60})
        assert r.get_json()["ok"] is True
        state = mgmt._state
        with state.temp_lock:
            assert "temp.com" in state.temp_allows
            assert state.temp_allows["temp.com"] > time.time()

    def test_post_allow_permanent_updates_state(self, mgmt):
        r = mgmt.post("/allow/permanent", json={"host": "new.com"})
        assert r.get_json()["ok"] is True
        assert "new.com" in mgmt._state.allowlist

    def test_post_allow_permanent_writes_file(self, mgmt, tmp_path):
        mgmt.post("/allow/permanent", json={"host": "written.com"})
        config_path = mgmt._state.allowlist_path
        with open(config_path) as f:
            data = yaml.safe_load(f)
        assert "written.com" in data["allowed_hosts"]

    def test_post_allow_permanent_idempotent(self, mgmt):
        mgmt.post("/allow/permanent", json={"host": "existing.com"})
        mgmt.post("/allow/permanent", json={"host": "existing.com"})
        with open(mgmt._state.allowlist_path) as f:
            data = yaml.safe_load(f)
        assert data["allowed_hosts"].count("existing.com") == 1
