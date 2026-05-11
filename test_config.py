"""
Tests for config loading (ConfigLoader, Config, HostConfig).

Run with:  pytest test_config.py -v
"""

import pytest

from config import ConfigLoader


# ── ConfigLoader ───────────────────────────────────────────────────────────────

class TestLoadConfig:
    def test_missing_file_returns_empty(self, tmp_path):
        config = ConfigLoader(str(tmp_path / "nonexistent.yaml")).load()
        assert config.allowlist == set()
        assert config.credentials == []
        assert config.management_port == 8082

    def test_basic_config_loaded(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            "management_port: 9000\n"
            "allowed_hosts:\n"
            "  - host: example.com\n"
        )
        config = ConfigLoader(str(path)).load()
        assert config.management_port == 9000
        assert "example.com" in config.allowlist

    def test_secrets_expanded(self, tmp_path):
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("MY_KEY: real-value\n")
        path = tmp_path / "config.yaml"
        path.write_text(
            f"secrets_file: {secrets}\n"
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    fake_value: fake\n"
            "    real_value: \"${MY_KEY}\"\n"
        )
        config = ConfigLoader(str(path)).load()
        assert config.credentials[0]["real_value"] == "real-value"

    def test_missing_secret_key_raises(self, tmp_path):
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("OTHER_KEY: something\n")
        path = tmp_path / "config.yaml"
        path.write_text(
            f"secrets_file: {secrets}\n"
            "credentials:\n"
            "  - host: api.example.com\n"
            "    real_value: \"${MISSING_KEY}\"\n"
        )
        with pytest.raises(KeyError, match="MISSING_KEY"):
            ConfigLoader(str(path)).load()

    def test_missing_secrets_file_raises(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            "secrets_file: /nonexistent/secrets.yaml\n"
            "allowed_hosts: []\n"
        )
        with pytest.raises(FileNotFoundError):
            ConfigLoader(str(path)).load()

    def test_no_secrets_file_plain_values_unchanged(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    real_value: plain-value\n"
        )
        config = ConfigLoader(str(path)).load()
        assert config.credentials[0]["real_value"] == "plain-value"

    def test_multiple_secrets_expanded(self, tmp_path):
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("KEY_A: value-a\nKEY_B: value-b\n")
        path = tmp_path / "config.yaml"
        path.write_text(
            f"secrets_file: {secrets}\n"
            "credentials:\n"
            "  - host: a.com\n"
            "    real_value: \"${KEY_A}\"\n"
            "  - host: b.com\n"
            "    real_value: \"${KEY_B}\"\n"
        )
        config = ConfigLoader(str(path)).load()
        assert config.credentials[0]["real_value"] == "value-a"
        assert config.credentials[1]["real_value"] == "value-b"

    def test_load_credentials_from_config(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    fake_value: fake\n"
            "    real_value: real\n"
        )
        creds = ConfigLoader(str(path)).load().credentials
        assert len(creds) == 1
        assert creds[0]["real_value"] == "real"

    def test_load_credentials_strips_yaml_block_literal_newline(self, tmp_path):
        # YAML block literals (|) and folded scalars (>) append a trailing \n.
        # That \n is forbidden in HTTP/2 header values (RFC 9113 § 8.2.1) and
        # causes PROTOCOL_ERROR on strict servers (e.g. Cloudflare).  The loader
        # must strip it so that injected values are always whitespace-free.
        path = tmp_path / "config.yaml"
        path.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: cookie\n"
            "    real_value: |\n"
            "      session=abc123; other=xyz\n"
        )
        creds = ConfigLoader(str(path)).load().credentials
        assert creds[0]["real_value"] == "session=abc123; other=xyz"

    def test_load_credentials_strips_fake_value_whitespace(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            "credentials:\n"
            "  - host: api.example.com\n"
            "    header: Authorization\n"
            "    fake_value: |\n"
            "      Bearer fake-token\n"
            "    real_value: |\n"
            "      Bearer real-token\n"
        )
        creds = ConfigLoader(str(path)).load().credentials
        assert creds[0]["fake_value"] == "Bearer fake-token"
        assert creds[0]["real_value"] == "Bearer real-token"

    def test_load_credentials_empty_when_absent(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("allowed_hosts:\n  - host: example.com\n")
        assert ConfigLoader(str(path)).load().credentials == []

    def test_load_management_port_from_config(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("management_port: 9999\n")
        assert ConfigLoader(str(path)).load().management_port == 9999

    def test_load_management_port_default(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("allowed_hosts: []\n")
        assert ConfigLoader(str(path)).load().management_port == 8082
