"""
Tests for config loading and validation (config.py).

Run with:  pytest test_config.py -v
"""

import json

import pytest

from config import Credential
from conftest import make_state


# ── Config.load ────────────────────────────────────────────────────────────────

class TestConfigLoad:
    def test_missing_file_empty_config_with_warning(self, tmp_path, capsys):
        from config import Config
        cfg = Config.load(str(tmp_path / "nonexistent.yaml"))
        assert cfg.allowlist == set()
        assert cfg.credentials == []
        assert cfg.restricted == {}
        assert cfg.management_port == 8082
        event = json.loads(capsys.readouterr().out)
        assert event["event"] == "config_warning"
        assert "not found" in event["message"]

    def test_basic_config_loaded(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "management_port: 9000\n"
            "allowed_hosts:\n"
            "  - host: example.com\n"
        )
        cfg = Config.load(str(config))
        assert cfg.management_port == 9000
        assert "example.com" in cfg.allowlist

    def test_secrets_expanded(self, tmp_path):
        from config import Config
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
        cfg = Config.load(str(config))
        assert cfg.credentials[0].real_value == "real-value"

    def test_missing_secret_key_raises(self, tmp_path):
        from config import Config
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("OTHER_KEY: something\n")
        config = tmp_path / "config.yaml"
        config.write_text(
            f"secrets_file: {secrets}\n"
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    real_value: \"${MISSING_KEY}\"\n"
        )
        with pytest.raises(KeyError, match="MISSING_KEY"):
            Config.load(str(config))

    def test_missing_secrets_file_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "secrets_file: /nonexistent/secrets.yaml\n"
            "allowed_hosts: []\n"
        )
        with pytest.raises(FileNotFoundError):
            Config.load(str(config))

    def test_no_secrets_file_plain_values_unchanged(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    real_value: plain-value\n"
        )
        cfg = Config.load(str(config))
        assert cfg.credentials[0].real_value == "plain-value"

    def test_multiple_secrets_expanded(self, tmp_path):
        from config import Config
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("KEY_A: value-a\nKEY_B: value-b\n")
        config = tmp_path / "config.yaml"
        config.write_text(
            f"secrets_file: {secrets}\n"
            "credentials:\n"
            "  - host: a.com\n"
            "    header: Authorization\n"
            "    real_value: \"${KEY_A}\"\n"
            "  - host: b.com\n"
            "    header: Authorization\n"
            "    real_value: \"${KEY_B}\"\n"
        )
        cfg = Config.load(str(config))
        assert cfg.credentials[0].real_value == "value-a"
        assert cfg.credentials[1].real_value == "value-b"

    def test_credentials_from_config(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    fake_value: fake\n"
            "    real_value: real\n"
        )
        cfg = Config.load(str(config))
        assert cfg.credentials == [Credential(
            host="api.example.com", header="Authorization",
            fake_value="fake", real_value="real",
        )]

    def test_credentials_empty_when_absent(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts:\n  - host: example.com\n")
        assert Config.load(str(config)).credentials == []

    def test_credential_missing_key_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    real_value: real\n"
        )
        with pytest.raises(ValueError, match="header"):
            Config.load(str(config))

    def test_management_port_from_config(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("management_port: 9999\n")
        assert Config.load(str(config)).management_port == 9999

    def test_management_port_default(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts: []\n")
        assert Config.load(str(config)).management_port == 8082

    def test_null_sections_treated_as_empty(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "allowed_hosts:\n"
            "restricted_hosts:\n"
            "credentials:\n"
            "services:\n"
        )
        cfg = Config.load(str(config))
        assert cfg.allowlist == set()
        assert cfg.restricted == {}
        assert cfg.credentials == []

    def test_scalar_allowed_hosts_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts: example.com\n")
        with pytest.raises(ValueError, match="allowed_hosts"):
            Config.load(str(config))

    def test_allowed_hosts_entry_without_host_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "allowed_hosts:\n"
            "  - allow_response_cookies: []\n"
        )
        with pytest.raises(ValueError, match="allowed_hosts"):
            Config.load(str(config))

    def test_failed_reload_keeps_old_state(self, tmp_path):
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts: not-a-list\n")
        state = make_state(allowlist={"old.com"}, config_path=str(config))
        with pytest.raises(ValueError):
            state.reload()
        assert state.allowlist == {"old.com"}


# ── Happy eyeballs delay (config loading) ───────────────────────────────────────

class TestHappyEyeballsDelay:
    def test_load_delay_default(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts: []\n")
        assert Config.load(str(config)).happy_eyeballs_delay == 0.25

    def test_load_delay_custom(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("happy_eyeballs_delay: 0.1\n")
        assert Config.load(str(config)).happy_eyeballs_delay == 0.1

    def test_load_delay_disabled(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        for value in ("0", "false", "null"):
            config.write_text(f"happy_eyeballs_delay: {value}\n")
            assert Config.load(str(config)).happy_eyeballs_delay == 0


# ── Config.load: restricted hosts ──────────────────────────────────────────────

class TestLoadRestrictedHosts:
    def test_preset_expansion(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("services: [go, npm]\n")
        result = Config.load(str(config)).restricted
        assert result["proxy.golang.org"].source == "go"
        assert result["sum.golang.org"].source == "go"
        assert result["registry.npmjs.org"].source == "npm"

    def test_unknown_preset_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("services: [nonexistent]\n")
        with pytest.raises(ValueError, match="nonexistent"):
            Config.load(str(config))

    def test_old_allowed_registries_key_rejected(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("allowed_registries: [go]\n")
        with pytest.raises(ValueError, match="renamed to services"):
            Config.load(str(config))

    def test_bare_string_restricted_host_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("restricted_hosts:\n  - artifacts.example.com\n")
        with pytest.raises(ValueError, match="restricted_hosts\\[0\\]"):
            Config.load(str(config))

    def test_restricted_host_missing_rules_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("restricted_hosts:\n  - host: artifacts.example.com\n")
        with pytest.raises(ValueError, match="'rules'"):
            Config.load(str(config))

    def test_custom_restricted_host(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "restricted_hosts:\n"
            "  - host: artifacts.example.com\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/repo/[a-z]{1,10}\"\n"
        )
        result = Config.load(str(config)).restricted
        assert result["artifacts.example.com"].source == "config"

    def test_custom_entry_replaces_preset(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "services: [npm]\n"
            "restricted_hosts:\n"
            "  - host: registry.npmjs.org\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/only-this\"\n"
        )
        result = Config.load(str(config)).restricted
        assert result["registry.npmjs.org"].source == "config"
        assert len(result["registry.npmjs.org"].rules) == 1

    def test_overlap_with_allowlist_warns(self, tmp_path, capsys):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "services: [npm]\n"
            "allowed_hosts:\n"
            "  - host: registry.npmjs.org\n"
        )
        Config.load(str(config))
        event = json.loads(capsys.readouterr().out)
        assert event["event"] == "config_warning"
        assert "registry.npmjs.org" in event["message"]

    def test_host_config_strips_cookies_for_restricted(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "services: [npm]\n"
            "restricted_hosts:\n"
            "  - host: artifacts.example.com\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/x\"\n"
            "    allow_response_cookies: [csrftoken]\n"
        )
        result = Config.load(str(config)).host_config
        assert result["registry.npmjs.org"].allow_response_cookies == []
        assert result["artifacts.example.com"].allow_response_cookies == ["csrftoken"]
