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
        host_config={},
        management_port=8082,
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


# ── load_config ────────────────────────────────────────────────────────────────

class TestLoadConfig:
    def test_missing_file_returns_empty(self, tmp_path):
        from addon import load_config
        result = load_config(str(tmp_path / "nonexistent.yaml"))
        assert result == {}

    def test_basic_config_loaded(self, tmp_path):
        from addon import load_config
        config = tmp_path / "config.yaml"
        config.write_text(
            "management_port: 9000\n"
            "allowed_hosts:\n"
            "  - host: example.com\n"
        )
        result = load_config(str(config))
        assert result["management_port"] == 9000
        assert result["allowed_hosts"][0]["host"] == "example.com"

    def test_secrets_expanded(self, tmp_path):
        from addon import load_config
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("MY_KEY: real-value\n")
        config = tmp_path / "config.yaml"
        config.write_text(
            f"secrets_file: {secrets}\n"
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    fake_value: fake\n"
            "    real_value: \"${MY_KEY}\"\n"
        )
        result = load_config(str(config))
        assert result["credentials"][0]["real_value"] == "real-value"

    def test_missing_secret_key_raises(self, tmp_path):
        from addon import load_config
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("OTHER_KEY: something\n")
        config = tmp_path / "config.yaml"
        config.write_text(
            f"secrets_file: {secrets}\n"
            "credentials:\n"
            "  - host: api.example.com\n"
            "    real_value: \"${MISSING_KEY}\"\n"
        )
        with pytest.raises(KeyError, match="MISSING_KEY"):
            load_config(str(config))

    def test_missing_secrets_file_raises(self, tmp_path):
        from addon import load_config
        config = tmp_path / "config.yaml"
        config.write_text(
            "secrets_file: /nonexistent/secrets.yaml\n"
            "allowed_hosts: []\n"
        )
        with pytest.raises(FileNotFoundError):
            load_config(str(config))

    def test_no_secrets_file_plain_values_unchanged(self, tmp_path):
        from addon import load_config
        config = tmp_path / "config.yaml"
        config.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    real_value: plain-value\n"
        )
        result = load_config(str(config))
        assert result["credentials"][0]["real_value"] == "plain-value"

    def test_multiple_secrets_expanded(self, tmp_path):
        from addon import load_config
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("KEY_A: value-a\nKEY_B: value-b\n")
        config = tmp_path / "config.yaml"
        config.write_text(
            f"secrets_file: {secrets}\n"
            "credentials:\n"
            "  - host: a.com\n"
            "    real_value: \"${KEY_A}\"\n"
            "  - host: b.com\n"
            "    real_value: \"${KEY_B}\"\n"
        )
        result = load_config(str(config))
        assert result["credentials"][0]["real_value"] == "value-a"
        assert result["credentials"][1]["real_value"] == "value-b"

    def test_load_credentials_from_config(self, tmp_path):
        from addon import load_credentials
        config = tmp_path / "config.yaml"
        config.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    fake_value: fake\n"
            "    real_value: real\n"
        )
        creds = load_credentials(str(config))
        assert len(creds) == 1
        assert creds[0]["real_value"] == "real"

    def test_load_credentials_empty_when_absent(self, tmp_path):
        from addon import load_credentials
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts:\n  - host: example.com\n")
        assert load_credentials(str(config)) == []

    def test_load_management_port_from_config(self, tmp_path):
        from addon import load_management_port
        config = tmp_path / "config.yaml"
        config.write_text("management_port: 9999\n")
        assert load_management_port(str(config)) == 9999

    def test_load_management_port_default(self, tmp_path):
        from addon import load_management_port
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts: []\n")
        assert load_management_port(str(config)) == 8082


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
    def test_fake_swapped_for_real(self, capsys):
        from addon import CredentialBrokerAddon
        addon = CredentialBrokerAddon(make_state(credentials=[CRED]))
        flow = make_flow("api.example.com", headers={"Authorization": "Bearer sk-fake"})
        addon.request(flow)
        assert flow.request.headers["Authorization"] == "Bearer sk-real"
        assert flow.response is None
        entry = json.loads(capsys.readouterr().out)
        assert entry["event"] == "credential_injected"
        assert entry["mode"] == "swap"
        assert entry["header"] == "Authorization"
        assert entry["host"] == "api.example.com"

    def test_no_header_passes_through(self, capsys):
        from addon import CredentialBrokerAddon
        addon = CredentialBrokerAddon(make_state(credentials=[CRED]))
        flow = make_flow("api.example.com", headers={})
        addon.request(flow)
        assert flow.response is None
        assert capsys.readouterr().out == ""

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

    def test_inject_mode_sets_header_when_absent(self, capsys):
        from addon import CredentialBrokerAddon
        inject_cred = {"host": "api.example.com", "header": "Cookie", "real_value": "session=abc123"}
        addon = CredentialBrokerAddon(make_state(credentials=[inject_cred]))
        flow = make_flow("api.example.com", headers={})
        addon.request(flow)
        assert flow.request.headers["Cookie"] == "session=abc123"
        assert flow.response is None
        entry = json.loads(capsys.readouterr().out)
        assert entry["event"] == "credential_injected"
        assert entry["mode"] == "inject"

    def test_inject_mode_overwrites_existing_header(self, capsys):
        from addon import CredentialBrokerAddon
        inject_cred = {"host": "api.example.com", "header": "Cookie", "real_value": "session=abc123"}
        addon = CredentialBrokerAddon(make_state(credentials=[inject_cred]))
        flow = make_flow("api.example.com", headers={"Cookie": "old=value"})
        addon.request(flow)
        assert flow.request.headers["Cookie"] == "session=abc123"
        assert flow.response is None
        entry = json.loads(capsys.readouterr().out)
        assert entry["event"] == "credential_injected"
        assert entry["mode"] == "inject"

    def test_inject_mode_does_not_affect_other_hosts(self):
        from addon import CredentialBrokerAddon
        inject_cred = {"host": "api.example.com", "header": "Cookie", "real_value": "session=abc123"}
        addon = CredentialBrokerAddon(make_state(credentials=[inject_cred]))
        flow = make_flow("other.com", headers={})
        addon.request(flow)
        assert "Cookie" not in flow.request.headers
        assert flow.response is None


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
        config.write_text("allowed_hosts:\n  - host: original.com\n")

        state = make_state(
            allowlist={"original.com"},
            allowlist_path=str(config),
        )
        setup_sighup(state)

        config.write_text("allowed_hosts:\n  - host: original.com\n  - host: new.com\n")
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.05)

        assert "new.com" in state.allowlist
        assert "original.com" in state.allowlist

    def test_sighup_reloads_credentials(self, tmp_path):
        from addon import setup_sighup

        config = tmp_path / "config.yaml"
        config.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    real_value: old-value\n"
        )

        state = make_state(
            credentials=[{"host": "api.example.com", "header": "Authorization", "real_value": "old-value"}],
            allowlist_path=str(config),
        )
        setup_sighup(state)

        config.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    real_value: new-value\n"
        )
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.05)

        assert state.credentials[0]["real_value"] == "new-value"


# ── Management API ─────────────────────────────────────────────────────────────

@pytest.fixture
def mgmt(tmp_path):
    """Flask test client wired to a fresh ProxyState with a temp config file."""
    from addon import create_app

    config = tmp_path / "config.yaml"
    config.write_text("allowed_hosts:\n  - host: existing.com\n")

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
        host_names = [
            h if isinstance(h, str) else h["host"]
            for h in data["allowed_hosts"]
        ]
        assert "written.com" in host_names

    def test_post_allow_permanent_idempotent(self, mgmt):
        mgmt.post("/allow/permanent", json={"host": "existing.com"})
        mgmt.post("/allow/permanent", json={"host": "existing.com"})
        with open(mgmt._state.allowlist_path) as f:
            data = yaml.safe_load(f)
        host_names = [
            h if isinstance(h, str) else h["host"]
            for h in data["allowed_hosts"]
        ]
        assert host_names.count("existing.com") == 1

    def test_post_allow_permanent_writes_dict_format(self, mgmt):
        mgmt.post("/allow/permanent", json={"host": "newdict.com"})
        with open(mgmt._state.allowlist_path) as f:
            data = yaml.safe_load(f)
        hosts = data["allowed_hosts"]
        assert any(
            (isinstance(h, dict) and h["host"] == "newdict.com") for h in hosts
        )


# ── Cookie allowlist (response side) ──────────────────────────────────────────

def make_response_flow(host, set_cookie_headers=None):
    """Return a mock HTTPFlow with response Set-Cookie headers."""
    from unittest.mock import MagicMock
    flow = MagicMock()
    flow.request.pretty_host = host
    cookies = list(set_cookie_headers or [])

    # Simulate mitmproxy Headers.get_all / pop / add
    stored = list(cookies)

    def get_all(name):
        if name.lower() == "set-cookie":
            return list(stored)
        return []

    def pop(name, default=None):
        if name.lower() == "set-cookie":
            stored.clear()

    def add(name, value):
        if name.lower() == "set-cookie":
            stored.append(value)

    flow.response.headers.get_all = get_all
    flow.response.headers.pop = pop
    flow.response.headers.add = add
    flow.response._stored = stored
    return flow


class TestCookieAllowlist:
    def test_host_absent_passes_all_cookies(self):
        from addon import CredentialBrokerAddon
        state = make_state(host_config={})
        addon = CredentialBrokerAddon(state)
        flow = make_response_flow("other.com", ["session=abc", "tracker=xyz"])
        addon.response(flow)
        assert flow.response._stored == ["session=abc", "tracker=xyz"]

    def test_host_config_none_restriction_passes_all(self):
        from addon import CredentialBrokerAddon, HostConfig
        state = make_state(host_config={"example.com": HostConfig(allow_response_cookies=None)})
        addon = CredentialBrokerAddon(state)
        flow = make_response_flow("example.com", ["session=abc", "tracker=xyz"])
        addon.response(flow)
        assert flow.response._stored == ["session=abc", "tracker=xyz"]

    def test_empty_allowlist_strips_all_cookies(self):
        from addon import CredentialBrokerAddon, HostConfig
        state = make_state(host_config={"example.com": HostConfig(allow_response_cookies=[])})
        addon = CredentialBrokerAddon(state)
        flow = make_response_flow("example.com", ["session=abc", "tracker=xyz"])
        addon.response(flow)
        assert flow.response._stored == []

    def test_allowlist_keeps_only_named_cookie(self):
        from addon import CredentialBrokerAddon, HostConfig
        state = make_state(host_config={"example.com": HostConfig(allow_response_cookies=["csrftoken"])})
        addon = CredentialBrokerAddon(state)
        flow = make_response_flow("example.com", ["csrftoken=abc123", "session=xyz"])
        addon.response(flow)
        assert flow.response._stored == ["csrftoken=abc123"]

    def test_multiple_set_cookie_headers_filtered(self):
        from addon import CredentialBrokerAddon, HostConfig
        state = make_state(host_config={"example.com": HostConfig(allow_response_cookies=["csrftoken", "lang"])})
        addon = CredentialBrokerAddon(state)
        flow = make_response_flow(
            "example.com",
            ["csrftoken=abc", "session=xyz", "lang=en", "tracker=1"],
        )
        addon.response(flow)
        assert set(flow.response._stored) == {"csrftoken=abc", "lang=en"}


# ── ClaudeAuthManager ──────────────────────────────────────────────────────────

class TestClaudeAuthManager:
    """Unit tests for claude_auth.ClaudeAuthManager."""

    def _manager(self, tmp_path, **kwargs):
        from claude_auth import ClaudeAuthManager
        return ClaudeAuthManager(
            token_file=tmp_path / "tokens.json",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token",
            client_id="test-client",
            scopes="openid",
            **kwargs,
        )

    def test_status_not_logged_in(self, tmp_path):
        mgr = self._manager(tmp_path)
        assert mgr.status() == {"logged_in": False}

    def test_get_header_value_returns_none_when_not_logged_in(self, tmp_path):
        mgr = self._manager(tmp_path)
        assert mgr.get_header_value() is None

    def test_start_login_returns_url_with_pkce_params(self, tmp_path):
        import urllib.parse
        mgr = self._manager(tmp_path)
        url = mgr.start_login("http://localhost:8082/claude/callback")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        assert parsed.netloc == "auth.example.com"
        assert params["response_type"] == ["code"]
        assert params["code_challenge_method"] == ["S256"]
        assert params["redirect_uri"] == ["http://localhost:8082/claude/callback"]
        assert "code_challenge" in params
        assert "state" in params

    def test_complete_login_state_mismatch_raises(self, tmp_path):
        from claude_auth import ClaudeAuthError
        mgr = self._manager(tmp_path)
        mgr.start_login("http://localhost:8082/claude/callback")
        with pytest.raises(ClaudeAuthError, match="State mismatch"):
            mgr.complete_login("some-code", "wrong-state")

    def test_complete_login_without_start_raises(self, tmp_path):
        from claude_auth import ClaudeAuthError
        mgr = self._manager(tmp_path)
        with pytest.raises(ClaudeAuthError):
            mgr.complete_login("code", "state")

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _mock_post(status=200, json_body=None, text=None):
        """Return a context manager that patches httpx.post with a fake response."""
        from unittest.mock import MagicMock, patch
        mock_resp = MagicMock()
        mock_resp.status_code = status
        mock_resp.json.return_value = json_body or {}
        mock_resp.text = text or ""
        return patch("httpx.post", return_value=mock_resp)

    @staticmethod
    def _get_state(url):
        import urllib.parse
        return urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]

    # ── tests ──────────────────────────────────────────────────────────────────

    def test_complete_login_stores_tokens(self, tmp_path):
        mgr = self._manager(tmp_path)
        url = mgr.start_login("http://localhost:8082/claude/callback")
        state_val = self._get_state(url)

        with self._mock_post(json_body={
            "access_token": "real-access-token",
            "refresh_token": "real-refresh-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }):
            mgr.complete_login("auth-code", state_val)

        assert mgr.status()["logged_in"] is True
        assert mgr.status()["has_refresh_token"] is True
        assert mgr.get_header_value() == "Bearer real-access-token"

    def test_tokens_persisted_to_disk(self, tmp_path):
        from claude_auth import ClaudeAuthManager
        mgr = self._manager(tmp_path)
        url = mgr.start_login("http://localhost:8082/claude/callback")
        state_val = self._get_state(url)

        with self._mock_post(json_body={
            "access_token": "persisted-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }):
            mgr.complete_login("code", state_val)

        # New manager loads from disk
        mgr2 = ClaudeAuthManager(
            token_file=tmp_path / "tokens.json",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token",
            client_id="test-client",
        )
        assert mgr2.get_header_value() == "Bearer persisted-token"

    def test_token_file_permissions_are_0600(self, tmp_path):
        import stat
        mgr = self._manager(tmp_path)
        url = mgr.start_login("http://localhost:8082/claude/callback")
        state_val = self._get_state(url)

        with self._mock_post(json_body={
            "access_token": "tok", "expires_in": 3600, "token_type": "Bearer"
        }):
            mgr.complete_login("code", state_val)
        mode = stat.S_IMODE((tmp_path / "tokens.json").stat().st_mode)
        assert mode == 0o600

    def test_get_header_value_triggers_refresh_when_near_expiry(self, tmp_path):
        mgr = self._manager(tmp_path)
        # Inject near-expired tokens directly
        mgr._tokens = {
            "access_token": "old-token",
            "refresh_token": "refresh-tok",
            "expires_at": time.time() + 30,  # within 60s buffer
            "token_type": "Bearer",
        }

        with self._mock_post(json_body={
            "access_token": "new-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }):
            result = mgr.get_header_value()
        assert result == "Bearer new-token"

    def test_refresh_failure_keeps_stale_token(self, tmp_path):
        mgr = self._manager(tmp_path)
        mgr._tokens = {
            "access_token": "stale-token",
            "refresh_token": "refresh-tok",
            "expires_at": time.time() + 30,
            "token_type": "Bearer",
        }

        with self._mock_post(status=500, text="server error"):
            result = mgr.get_header_value()

        # Should not raise; returns stale token
        assert result == "Bearer stale-token"

    def test_logout_clears_tokens_and_file(self, tmp_path):
        mgr = self._manager(tmp_path)
        url = mgr.start_login("http://localhost:8082/claude/callback")
        state_val = self._get_state(url)

        with self._mock_post(json_body={
            "access_token": "tok", "expires_in": 3600, "token_type": "Bearer"
        }):
            mgr.complete_login("code", state_val)
        assert (tmp_path / "tokens.json").exists()

        mgr.logout()
        assert not (tmp_path / "tokens.json").exists()
        assert mgr.status() == {"logged_in": False}
        assert mgr.get_header_value() is None

    def test_http_error_on_token_exchange_raises(self, tmp_path):
        from claude_auth import ClaudeAuthError
        mgr = self._manager(tmp_path)
        url = mgr.start_login("http://localhost:8082/claude/callback")
        state_val = self._get_state(url)

        with self._mock_post(status=401, text="Unauthorized"):
            with pytest.raises(ClaudeAuthError, match="Token exchange failed"):
                mgr.complete_login("bad-code", state_val)


# ── CredentialBrokerAddon — !claude-subscription ───────────────────────────────

class TestClaudeSubscriptionCredential:
    """Tests for the !claude-subscription dynamic resolver in CredentialBrokerAddon."""

    CRED_SUB = {
        "host": "api.anthropic.com",
        "header": "Authorization",
        "fake_value": "Bearer sk-ant-proxy00-placeholder",
        "real_value": "!claude-subscription",
    }

    def _make_auth(self, tmp_path, token="Bearer real-session-token"):
        """Return a ClaudeAuthManager pre-loaded with a valid token."""
        from claude_auth import ClaudeAuthManager
        mgr = ClaudeAuthManager(token_file=tmp_path / "tokens.json")
        if token is not None:
            mgr._tokens = {
                "access_token": token.removeprefix("Bearer "),
                "token_type": "Bearer",
                "expires_at": time.time() + 3600,
                "refresh_token": None,
            }
        return mgr

    def test_fake_swapped_for_real_subscription_token(self, tmp_path, capsys):
        from addon import CredentialBrokerAddon
        mgr = self._make_auth(tmp_path)
        state = make_state(credentials=[self.CRED_SUB], claude_auth=mgr)
        addon = CredentialBrokerAddon(state)
        flow = make_flow(
            "api.anthropic.com",
            headers={"Authorization": "Bearer sk-ant-proxy00-placeholder"},
        )
        addon.request(flow)
        assert flow.request.headers["Authorization"] == "Bearer real-session-token"
        assert flow.response is None
        entry = json.loads(capsys.readouterr().out)
        assert entry["event"] == "credential_injected"
        assert entry["mode"] == "swap"

    def test_returns_503_when_not_logged_in(self, tmp_path):
        from addon import CredentialBrokerAddon
        mgr = self._make_auth(tmp_path, token=None)
        state = make_state(credentials=[self.CRED_SUB], claude_auth=mgr)
        addon = CredentialBrokerAddon(state)
        flow = make_flow(
            "api.anthropic.com",
            headers={"Authorization": "Bearer sk-ant-proxy00-placeholder"},
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 503

    def test_returns_503_when_claude_auth_not_configured(self):
        from addon import CredentialBrokerAddon
        state = make_state(credentials=[self.CRED_SUB], claude_auth=None)
        addon = CredentialBrokerAddon(state)
        flow = make_flow(
            "api.anthropic.com",
            headers={"Authorization": "Bearer sk-ant-proxy00-placeholder"},
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 503

    def test_inject_mode_also_resolves_subscription(self, tmp_path, capsys):
        """Inject mode (no fake_value) should also work with !claude-subscription."""
        from addon import CredentialBrokerAddon
        inject_cred = {
            "host": "api.anthropic.com",
            "header": "Authorization",
            "real_value": "!claude-subscription",
        }
        mgr = self._make_auth(tmp_path)
        state = make_state(credentials=[inject_cred], claude_auth=mgr)
        addon = CredentialBrokerAddon(state)
        flow = make_flow("api.anthropic.com", headers={})
        addon.request(flow)
        assert flow.request.headers["Authorization"] == "Bearer real-session-token"
        assert flow.response is None
        entry = json.loads(capsys.readouterr().out)
        assert entry["mode"] == "inject"

    def test_unexpected_value_still_blocked(self, tmp_path):
        """Credential mismatch detection still works with !claude-subscription."""
        from addon import CredentialBrokerAddon
        mgr = self._make_auth(tmp_path)
        state = make_state(credentials=[self.CRED_SUB], claude_auth=mgr)
        addon = CredentialBrokerAddon(state)
        flow = make_flow(
            "api.anthropic.com",
            headers={"Authorization": "Bearer sk-ant-injected-by-agent"},
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403


# ── Management API — Claude endpoints ─────────────────────────────────────────

@pytest.fixture
def mgmt_claude(tmp_path):
    """Flask test client wired to ProxyState with a live ClaudeAuthManager."""
    from addon import create_app
    from claude_auth import ClaudeAuthManager

    config = tmp_path / "config.yaml"
    config.write_text("allowed_hosts:\n  - host: api.anthropic.com\n")

    mgr = ClaudeAuthManager(
        token_file=tmp_path / "tokens.json",
        auth_url="https://auth.example.com/oauth/authorize",
        token_url="https://auth.example.com/oauth/token",
        client_id="test-client",
    )

    state = make_state(allowlist={"api.anthropic.com"}, allowlist_path=str(config), claude_auth=mgr)
    app = create_app(state)
    app.config["TESTING"] = True
    with app.test_client() as client:
        client._state = state
        client._mgr = mgr
        yield client


class TestClaudeManagementAPI:
    def test_status_not_configured_returns_404(self, mgmt):
        """When claude_auth is None the endpoints return 404."""
        r = mgmt.get("/claude/status")
        assert r.status_code == 404
        assert "not configured" in r.get_json()["error"]

    def test_status_not_logged_in(self, mgmt_claude):
        r = mgmt_claude.get("/claude/status")
        assert r.status_code == 200
        assert r.get_json() == {"logged_in": False}

    def test_login_redirects_to_auth_url(self, mgmt_claude):
        r = mgmt_claude.get("/claude/login", follow_redirects=False)
        assert r.status_code == 302
        location = r.headers["Location"]
        assert "auth.example.com/oauth/authorize" in location
        assert "code_challenge" in location
        assert "state" in location

    def test_login_redirect_contains_callback_uri(self, mgmt_claude):
        import urllib.parse
        r = mgmt_claude.get(
            "/claude/login?redirect_uri=http://host:8082/claude/callback",
            follow_redirects=False,
        )
        location = r.headers["Location"]
        params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        assert params["redirect_uri"] == ["http://host:8082/claude/callback"]

    def test_callback_state_mismatch_returns_400(self, mgmt_claude):
        mgmt_claude.get("/claude/login", follow_redirects=False)  # initialise state
        r = mgmt_claude.get("/claude/callback?code=abc&state=wrong-state")
        assert r.status_code == 400
        assert "State mismatch" in r.data.decode()

    def test_callback_missing_code_returns_400(self, mgmt_claude):
        r = mgmt_claude.get("/claude/callback?state=whatever")
        assert r.status_code == 400

    def test_callback_oauth_error_param_returns_400(self, mgmt_claude):
        r = mgmt_claude.get("/claude/callback?error=access_denied")
        assert r.status_code == 400
        assert "access_denied" in r.data.decode()

    def test_full_login_callback_flow(self, mgmt_claude):
        from unittest.mock import MagicMock, patch
        import urllib.parse

        # Step 1: initiate login
        r = mgmt_claude.get("/claude/login", follow_redirects=False)
        location = r.headers["Location"]
        params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        state_val = params["state"][0]

        # Step 2: mock token endpoint response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "live-token",
            "refresh_token": "refresh-tok",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

        # Step 3: simulate OAuth callback
        with patch("httpx.post", return_value=mock_resp):
            r = mgmt_claude.get(f"/claude/callback?code=mycode&state={state_val}")
        assert r.status_code == 200
        assert b"successful" in r.data

        # Step 4: status reflects logged-in state
        status = mgmt_claude.get("/claude/status").get_json()
        assert status["logged_in"] is True
        assert status["has_refresh_token"] is True

    def test_logout_clears_state(self, mgmt_claude):
        from unittest.mock import MagicMock, patch
        import urllib.parse

        r = mgmt_claude.get("/claude/login", follow_redirects=False)
        state_val = urllib.parse.parse_qs(
            urllib.parse.urlparse(r.headers["Location"]).query
        )["state"][0]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "tok", "expires_in": 3600, "token_type": "Bearer"
        }
        with patch("httpx.post", return_value=mock_resp):
            mgmt_claude.get(f"/claude/callback?code=c&state={state_val}")
        assert mgmt_claude.get("/claude/status").get_json()["logged_in"] is True

        r = mgmt_claude.post("/claude/logout")
        assert r.get_json()["ok"] is True
        assert mgmt_claude.get("/claude/status").get_json()["logged_in"] is False

    def test_logout_not_configured_returns_404(self, mgmt):
        r = mgmt.post("/claude/logout")
        assert r.status_code == 404

    def test_login_not_configured_returns_404(self, mgmt):
        r = mgmt.get("/claude/login", follow_redirects=False)
        assert r.status_code == 404
