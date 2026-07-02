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


def make_flow(host, method="GET", path="/", headers=None, body=b""):
    """Return a mock HTTPFlow with the given request properties."""
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.request.pretty_url = f"http://{host}{path}"
    flow.request.method = method
    flow.request.path = path
    flow.request.headers = dict(headers or {})
    flow.request.raw_content = body
    flow.response = None
    flow.metadata = {}
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


# ── Happy eyeballs ─────────────────────────────────────────────────────────────

class TestHappyEyeballs:
    def test_load_delay_default(self, tmp_path):
        from addon import load_happy_eyeballs_delay
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts: []\n")
        assert load_happy_eyeballs_delay(str(config)) == 0.25

    def test_load_delay_custom(self, tmp_path):
        from addon import load_happy_eyeballs_delay
        config = tmp_path / "config.yaml"
        config.write_text("happy_eyeballs_delay: 0.1\n")
        assert load_happy_eyeballs_delay(str(config)) == 0.1

    def test_load_delay_disabled(self, tmp_path):
        from addon import load_happy_eyeballs_delay
        config = tmp_path / "config.yaml"
        for value in ("0", "false", "null"):
            config.write_text(f"happy_eyeballs_delay: {value}\n")
            assert load_happy_eyeballs_delay(str(config)) == 0

    def test_supported_version_ranges(self):
        from addon import happy_eyeballs_supported

        assert not happy_eyeballs_supported((3, 12, 3))
        assert not happy_eyeballs_supported((3, 13, 0))
        assert happy_eyeballs_supported((3, 12, 8))
        assert happy_eyeballs_supported((3, 13, 1))
        assert happy_eyeballs_supported((3, 14, 0))

    def test_current_interpreter_supported(self):
        # requires-python guarantees this; a failure here means the venv
        # interpreter predates the cpython#124309 fix
        from addon import happy_eyeballs_supported

        assert happy_eyeballs_supported()

    @pytest.fixture
    def recorded_open_connection(self):
        """Replace asyncio.open_connection with a recorder, restore after."""
        import asyncio

        calls = []
        original = asyncio.open_connection
        asyncio.open_connection = (
            lambda host=None, port=None, **kw: calls.append((host, port, kw))
        )
        yield calls
        asyncio.open_connection = original

    def test_patch_injects_delay(self, recorded_open_connection):
        import asyncio
        from addon import enable_happy_eyeballs

        enable_happy_eyeballs(0.25)
        asyncio.open_connection("example.com", 443, local_addr=None)
        host, port, kwargs = recorded_open_connection[0]
        assert (host, port) == ("example.com", 443)
        assert kwargs["happy_eyeballs_delay"] == 0.25
        assert kwargs["local_addr"] is None

    def test_patch_keeps_explicit_delay(self, recorded_open_connection):
        import asyncio
        from addon import enable_happy_eyeballs

        enable_happy_eyeballs(0.25)
        asyncio.open_connection("example.com", 443, happy_eyeballs_delay=1.0)
        _, _, kwargs = recorded_open_connection[0]
        assert kwargs["happy_eyeballs_delay"] == 1.0

    def test_patch_skips_sock_connects(self, recorded_open_connection):
        import asyncio
        from addon import enable_happy_eyeballs

        enable_happy_eyeballs(0.25)
        asyncio.open_connection(sock=object())
        _, _, kwargs = recorded_open_connection[0]
        assert "happy_eyeballs_delay" not in kwargs


# ── AllowlistAddon ─────────────────────────────────────────────────────────────

class TestAllowlistAddon:
    def test_allowed_host_passes(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist={"good.com"}))
        flow = make_flow("good.com")
        addon.request(flow)
        assert flow.response is None

    def test_blocked_host_gets_503(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set()))
        flow = make_flow("evil.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 503
        assert b"pending human approval" in flow.response.content
        assert flow.response.headers.get("Retry-After") == "5"

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
        assert flow.response.status_code == 503

    def test_multiple_denials_all_logged(self):
        from addon import AllowlistAddon
        state = make_state(allowlist=set())
        addon = AllowlistAddon(state)
        for host in ["a.com", "b.com", "c.com"]:
            addon.request(make_flow(host))
        assert len(state.deny_log) == 3

    def test_denial_entry_typed_pending_approval(self):
        from addon import AllowlistAddon
        state = make_state(allowlist=set())
        AllowlistAddon(state).request(make_flow("evil.com"))
        assert state.deny_log[0]["type"] == "pending_approval"


# ── Registry policy (restricted hosts) ─────────────────────────────────────────

def make_restricted(**spec_overrides):
    """Compiled rules for a simple restricted test host."""
    import registries
    spec = {
        "rules": [
            {"methods": ["GET", "HEAD"], "path": "/pkg/[a-z0-9-]{1,64}",
             "query": {"version": "[a-z0-9.]{1,32}"}},
        ],
    }
    spec.update(spec_overrides)
    return {"registry.example.com": registries.compile_host_rules(spec, source="testpreset")}


class TestRegistryPolicy:
    def test_matching_request_passes(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set(), restricted=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo")
        addon.request(flow)
        assert flow.response is None
        assert flow.metadata["registry"] == "testpreset"

    def test_allowed_query_param_passes(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set(), restricted=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo?version=1.2.3")
        addon.request(flow)
        assert flow.response is None

    def test_violation_gets_403_without_retry_after(self, capsys):
        from addon import AllowlistAddon
        state = make_state(allowlist=set(), restricted=make_restricted())
        addon = AllowlistAddon(state)
        flow = make_flow("registry.example.com", method="POST", path="/pkg/foo")
        addon.request(flow)
        assert flow.response.status_code == 403
        assert b"policy violation" in flow.response.content
        assert "Retry-After" not in flow.response.headers
        entry = state.deny_log[0]
        assert entry["type"] == "policy_violation"
        assert "POST" in entry["reason"]
        event = json.loads(capsys.readouterr().out)
        assert event["event"] == "registry_policy_violation"
        assert event["policy"] == "testpreset"

    def test_disallowed_query_param_blocked(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set(), restricted=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo?data=secret")
        addon.request(flow)
        assert flow.response.status_code == 403

    def test_body_on_get_blocked(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set(), restricted=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo", body=b"exfil")
        addon.request(flow)
        assert flow.response.status_code == 403

    def test_allowlist_beats_restricted(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(
            allowlist={"registry.example.com"}, restricted=make_restricted()))
        flow = make_flow("registry.example.com", method="POST", path="/anything")
        addon.request(flow)
        assert flow.response is None

    def test_temp_allow_beats_restricted(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(
            allowlist=set(),
            temp_allows={"registry.example.com": time.time() + 60},
            restricted=make_restricted(),
        ))
        flow = make_flow("registry.example.com", method="POST", path="/anything")
        addon.request(flow)
        assert flow.response is None

    def test_unlisted_host_still_gets_503(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set(), restricted=make_restricted()))
        flow = make_flow("other.com")
        addon.request(flow)
        assert flow.response.status_code == 503

    def test_headers_scrubbed_names_logged_values_not(self, capsys):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set(), restricted=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo", headers={
            "Accept": "*/*",
            "X-Exfil": "top-secret-value",
            "Cookie": "session=abc",
        })
        addon.request(flow)
        assert flow.response is None
        assert "X-Exfil" not in flow.request.headers
        assert "Cookie" not in flow.request.headers
        assert flow.request.headers["Accept"] == "*/*"
        out = capsys.readouterr().out
        event = json.loads(out)
        assert event["event"] == "registry_headers_scrubbed"
        assert "X-Exfil" in event["dropped"]
        assert "top-secret-value" not in out

    def test_overlong_header_clamped(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(allowlist=set(), restricted=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo",
                         headers={"User-Agent": "u" * 600})
        addon.request(flow)
        assert flow.response is None
        assert len(flow.request.headers["User-Agent"]) == 512

    def test_declared_header_survives(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(
            allowlist=set(),
            restricted=make_restricted(request_headers=["authorization"]),
        ))
        flow = make_flow("registry.example.com", path="/pkg/foo",
                         headers={"Authorization": "Bearer tok"})
        addon.request(flow)
        assert flow.request.headers["Authorization"] == "Bearer tok"


# ── load_restricted_hosts ──────────────────────────────────────────────────────

class TestLoadRestrictedHosts:
    def test_preset_expansion(self, tmp_path):
        from addon import load_restricted_hosts
        config = tmp_path / "config.yaml"
        config.write_text("allowed_registries: [go, npm]\n")
        result = load_restricted_hosts(str(config))
        assert result["proxy.golang.org"].source == "go"
        assert result["sum.golang.org"].source == "go"
        assert result["registry.npmjs.org"].source == "npm"

    def test_unknown_preset_raises(self, tmp_path):
        from addon import load_restricted_hosts
        config = tmp_path / "config.yaml"
        config.write_text("allowed_registries: [nonexistent]\n")
        with pytest.raises(ValueError, match="nonexistent"):
            load_restricted_hosts(str(config))

    def test_custom_restricted_host(self, tmp_path):
        from addon import load_restricted_hosts
        config = tmp_path / "config.yaml"
        config.write_text(
            "restricted_hosts:\n"
            "  - host: artifacts.example.com\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/repo/[a-z]{1,10}\"\n"
        )
        result = load_restricted_hosts(str(config))
        assert result["artifacts.example.com"].source == "config"

    def test_custom_entry_replaces_preset(self, tmp_path):
        from addon import load_restricted_hosts
        config = tmp_path / "config.yaml"
        config.write_text(
            "allowed_registries: [npm]\n"
            "restricted_hosts:\n"
            "  - host: registry.npmjs.org\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/only-this\"\n"
        )
        result = load_restricted_hosts(str(config))
        assert result["registry.npmjs.org"].source == "config"
        assert len(result["registry.npmjs.org"].rules) == 1

    def test_overlap_with_allowlist_warns(self, tmp_path, capsys):
        from addon import load_restricted_hosts
        config = tmp_path / "config.yaml"
        config.write_text(
            "allowed_registries: [npm]\n"
            "allowed_hosts:\n"
            "  - host: registry.npmjs.org\n"
        )
        load_restricted_hosts(str(config))
        event = json.loads(capsys.readouterr().out)
        assert event["event"] == "config_warning"
        assert "registry.npmjs.org" in event["message"]

    def test_host_config_strips_cookies_for_restricted(self, tmp_path):
        from addon import load_host_config
        config = tmp_path / "config.yaml"
        config.write_text(
            "allowed_registries: [npm]\n"
            "restricted_hosts:\n"
            "  - host: artifacts.example.com\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/x\"\n"
            "    allow_response_cookies: [csrftoken]\n"
        )
        result = load_host_config(str(config))
        assert result["registry.npmjs.org"].allow_response_cookies == []
        assert result["artifacts.example.com"].allow_response_cookies == ["csrftoken"]


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
        # Simulate AllowlistAddon already set a 503
        flow.response = http.Response.make(503, "pending human approval")
        addon.request(flow)
        # Should not overwrite the existing response
        assert flow.response.status_code == 503
        assert b"pending human approval" in flow.response.content

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
        flow.response = http.Response.make(503, "pending human approval")
        addon.request(flow)
        assert capsys.readouterr().out == ""

    def test_registry_field_included_when_set(self, capsys):
        from addon import LoggingAddon
        addon = LoggingAddon(make_state())
        flow = make_flow("proxy.golang.org", path="/golang.org/x/text/@latest")
        flow.metadata["registry"] = "go"
        addon.request(flow)
        entry = json.loads(capsys.readouterr().out.strip())
        assert entry["registry"] == "go"


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

    def test_sighup_reloads_restricted(self, tmp_path):
        from addon import setup_sighup

        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts: []\n")

        state = make_state(allowlist=set(), allowlist_path=str(config))
        setup_sighup(state)
        assert state.restricted == {}

        config.write_text("allowed_registries: [go]\n")
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.05)

        assert "proxy.golang.org" in state.restricted


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
        assert data["restricted"] == {}

    def test_get_allowlist_restricted_grouped_by_source(self, mgmt):
        mgmt._state.restricted = make_restricted()
        data = mgmt.get("/allowlist").get_json()
        assert data["restricted"] == {"testpreset": ["registry.example.com"]}

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
