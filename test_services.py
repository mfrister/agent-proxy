"""
Tests for service presets (services.py) and their expansion into config
primitives (the `services` section of Config.from_data).

Run with:  pytest test_services.py -v
"""

import pytest

import registries
import services
from config import Config, Credential


# ── Preset catalog ─────────────────────────────────────────────────────────────

class TestCatalog:
    def test_wraps_all_registry_presets(self):
        for name, hosts in registries.PRESETS.items():
            preset = services.SERVICE_PRESETS[name]
            assert preset.hosts == hosts
            assert preset.credential is None
            assert preset.param_host is False

    def test_github_preset(self):
        preset = services.SERVICE_PRESETS["github"]
        assert preset.hosts == {"api.github.com": None}
        assert preset.credential.header == "Authorization"
        assert preset.credential.on_host == "api.github.com"
        assert preset.credential.wrap("ghp_x") == "token ghp_x"

    def test_gitlab_preset(self):
        preset = services.SERVICE_PRESETS["gitlab"]
        assert preset.param_host is True
        assert preset.hosts == {}
        assert preset.credential.header == "PRIVATE-TOKEN"
        assert preset.credential.on_host is None
        assert preset.credential.wrap("glpat-x") == "glpat-x"

    def test_fake_prefixes_fit_fake_length(self):
        for name, preset in services.SERVICE_PRESETS.items():
            cred = preset.credential
            if cred is not None:
                assert len(cred.fake_prefix) < cred.fake_length, name
                assert "{token}" in cred.value_template, name


# ── Expansion via Config.from_data ─────────────────────────────────────────────

class TestExpansion:
    def test_github_credential_and_allowlist(self):
        cfg = Config.from_data({"services": [
            {"service": "github", "fake_value": "ghp_fake", "real_value": "ghp_real"},
        ]})
        assert cfg.credentials == [Credential(
            host="api.github.com", header="Authorization",
            fake_value="token ghp_fake", real_value="token ghp_real",
            preset="github",
        )]
        assert "api.github.com" in cfg.allowlist
        assert cfg.restricted == {}

    def test_gitlab_with_host(self):
        cfg = Config.from_data({"services": [
            {"service": "gitlab", "host": "gitlab.example.com",
             "fake_value": "glpat-fake", "real_value": "glpat-real"},
        ]})
        assert cfg.credentials == [Credential(
            host="gitlab.example.com", header="PRIVATE-TOKEN",
            fake_value="glpat-fake", real_value="glpat-real",
            preset="gitlab",
        )]
        assert "gitlab.example.com" in cfg.allowlist

    def test_registry_service_bare_string(self):
        cfg = Config.from_data({"services": ["npm"]})
        assert cfg.restricted["registry.npmjs.org"].source == "npm"
        assert cfg.credentials == []
        assert cfg.allowlist == set()
        assert cfg.host_config["registry.npmjs.org"].allow_response_cookies == []

    def test_allow_host_false_brokers_without_allowlisting(self):
        cfg = Config.from_data({"services": [
            {"service": "github", "fake_value": "ghp_fake",
             "real_value": "ghp_real", "allow_host": False},
        ]})
        assert cfg.credentials[0].host == "api.github.com"
        assert "api.github.com" not in cfg.allowlist

    def test_gitlab_without_host_raises(self):
        with pytest.raises(ValueError, match="requires a 'host'"):
            Config.from_data({"services": [
                {"service": "gitlab", "fake_value": "f", "real_value": "r"},
            ]})

    def test_host_on_fixed_host_service_raises(self):
        with pytest.raises(ValueError, match="does not take a 'host'"):
            Config.from_data({"services": [
                {"service": "github", "host": "evil.example.com",
                 "fake_value": "f", "real_value": "r"},
            ]})

    def test_unknown_service_raises(self):
        with pytest.raises(ValueError, match="nonexistent"):
            Config.from_data({"services": ["nonexistent"]})

    def test_missing_token_raises(self):
        with pytest.raises(ValueError, match="real_value"):
            Config.from_data({"services": [
                {"service": "github", "fake_value": "ghp_fake"},
            ]})
        with pytest.raises(ValueError, match="fake_value"):
            Config.from_data({"services": [
                {"service": "github", "real_value": "ghp_real"},
            ]})

    def test_token_on_registry_service_raises(self):
        with pytest.raises(ValueError, match="takes no credential"):
            Config.from_data({"services": [
                {"service": "npm", "real_value": "secret"},
            ]})

    def test_entry_without_service_key_raises(self):
        with pytest.raises(ValueError, match="services\\[0\\]"):
            Config.from_data({"services": [{"host": "example.com"}]})

    def test_secret_reference_expanded_through_template(self, tmp_path):
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("GITHUB_TOKEN: ghp_real\n")
        cfg = Config.from_data({
            "secrets_file": str(secrets),
            "services": [
                {"service": "github", "fake_value": "ghp_fake",
                 "real_value": "${GITHUB_TOKEN}"},
            ],
        })
        assert cfg.credentials[0].real_value == "token ghp_real"

    def test_credential_header_wired_into_restricted_rules(self):
        # A hypothetical combined preset: credential on a restricted host must
        # have its header added to that host's request_headers, or scrubbing
        # would strip it before the broker runs.
        combined = services.ServicePreset(
            hosts=dict(registries.PRESETS["npm"]),
            credential=services.CredentialSpec(
                header="Authorization", value_template="Bearer {token}",
                on_host="registry.npmjs.org",
            ),
        )
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(services.SERVICE_PRESETS, "npm-auth", combined)
            cfg = Config.from_data({"services": [
                {"service": "npm-auth", "fake_value": "f", "real_value": "r"},
            ]})
        rules = cfg.restricted["registry.npmjs.org"]
        assert "authorization" in rules.request_headers
        # The catalog's own npm preset is untouched (frozen dataclass replaced,
        # not mutated).
        assert "authorization" not in registries.PRESETS["npm"]["registry.npmjs.org"].request_headers
