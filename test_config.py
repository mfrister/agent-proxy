"""
Tests for config loading and validation (config.py).

Run with:  pytest test_config.py -v
"""

import json

import pytest

import registries
from config import Credential
from conftest import make_state


# ── Config.load ────────────────────────────────────────────────────────────────

class TestConfigLoad:
    def test_missing_file_empty_config_with_warning(self, tmp_path, capsys):
        from config import Config
        cfg = Config.load(str(tmp_path / "nonexistent.yaml"))
        assert cfg.hosts == {}
        assert cfg.credentials == []
        assert cfg.management_port == 8082
        event = json.loads(capsys.readouterr().out)
        assert event["event"] == "config_warning"
        assert "not found" in event["message"]

    def test_basic_config_loaded(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "management_port: 9000\n"
            "hosts:\n"
            "  - host: example.com\n"
        )
        cfg = Config.load(str(config))
        assert cfg.management_port == 9000
        assert "example.com" in cfg.hosts
        assert cfg.hosts["example.com"] is None

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
            "hosts: []\n"
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
        config.write_text("hosts:\n  - host: example.com\n")
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
        config.write_text("hosts: []\n")
        assert Config.load(str(config)).management_port == 8082

    def test_null_sections_treated_as_empty(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "hosts:\n"
            "credentials:\n"
            "services:\n"
        )
        cfg = Config.load(str(config))
        assert cfg.hosts == {}
        assert cfg.credentials == []

    def test_scalar_hosts_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("hosts: example.com\n")
        with pytest.raises(ValueError, match="hosts"):
            Config.load(str(config))

    def test_hosts_entry_without_host_raises(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "hosts:\n"
            "  - allow_response_cookies: []\n"
        )
        with pytest.raises(ValueError, match="hosts"):
            Config.load(str(config))

    def test_old_allowed_hosts_key_rejected(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("allowed_hosts:\n  - example.com\n")
        with pytest.raises(ValueError, match="merged into hosts"):
            Config.load(str(config))

    def test_old_restricted_hosts_key_rejected(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "restricted_hosts:\n"
            "  - host: artifacts.example.com\n"
            "    rules: []\n"
        )
        with pytest.raises(ValueError, match="merged into hosts"):
            Config.load(str(config))

    def test_failed_reload_keeps_old_state(self, tmp_path):
        config = tmp_path / "config.yaml"
        config.write_text("hosts: not-a-list\n")
        state = make_state(hosts={"old.com": None}, config_path=str(config))
        with pytest.raises(ValueError):
            state.reload()
        assert state.hosts == {"old.com": None}


# ── Happy eyeballs delay (config loading) ───────────────────────────────────────

class TestHappyEyeballsDelay:
    def test_load_delay_default(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("hosts: []\n")
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


# ── Config.load: hosts (unrestricted + restricted) ─────────────────────────────

class TestLoadHosts:
    def test_preset_expansion(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("services: [go, npm]\n")
        result = Config.load(str(config)).hosts
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

    def test_host_without_rules_is_unrestricted(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text("hosts:\n  - host: artifacts.example.com\n")
        result = Config.load(str(config)).hosts
        assert result["artifacts.example.com"] is None

    def test_custom_restricted_host(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "hosts:\n"
            "  - host: artifacts.example.com\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/repo/[a-z]{1,10}\"\n"
        )
        result = Config.load(str(config)).hosts
        assert result["artifacts.example.com"].source == "config"

    def test_custom_entry_replaces_preset(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "services: [npm]\n"
            "hosts:\n"
            "  - host: registry.npmjs.org\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/only-this\"\n"
        )
        result = Config.load(str(config)).hosts
        assert result["registry.npmjs.org"].source == "config"
        assert len(result["registry.npmjs.org"].rules) == 1

    def test_hosts_entry_overrides_preset_with_no_warning(self, tmp_path, capsys):
        # A hand-written `hosts:` entry for a host a service preset also
        # restricts replaces the preset's rules entirely (unrestricted, here)
        # -- and since one dict entry per host makes the old both-sections
        # overlap state unconstructible, no config_warning is emitted either.
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "services: [npm]\n"
            "hosts:\n"
            "  - registry.npmjs.org\n"
        )
        cfg = Config.load(str(config))
        assert cfg.hosts["registry.npmjs.org"] is None
        assert capsys.readouterr().out == ""

    def test_host_config_strips_cookies_for_restricted(self, tmp_path):
        from config import Config
        config = tmp_path / "config.yaml"
        config.write_text(
            "services: [npm]\n"
            "hosts:\n"
            "  - host: artifacts.example.com\n"
            "    rules:\n"
            "      - methods: [GET]\n"
            "        path: \"/x\"\n"
            "    allow_response_cookies: [csrftoken]\n"
        )
        result = Config.load(str(config)).host_config
        assert result["registry.npmjs.org"].allow_response_cookies == []
        assert result["artifacts.example.com"].allow_response_cookies == ["csrftoken"]


# ── Scoped service expansion (github/gitlab: scope, unrestricted, flags) ───────
#
# This is the security property step 5 exists to close: a scopable service
# preset (scope_params non-empty) must be scoped or explicitly opted out, and
# the compiled rules must actually restrict the rule engine, not just the
# ServicePreset descriptor (that's test_services.py's job).

GITHUB_CRED = {"fake_value": "ghp_fake", "real_value": "ghp_real"}


class TestScopedServiceExpansion:
    def test_scoped_entry_compiles_host_rules(self):
        from config import Config
        cfg = Config.from_data({"services": [
            {"service": "github", "scope": {"repos": ["myorg/myrepo"]}, **GITHUB_CRED},
        ]})
        rules = cfg.hosts["api.github.com"]
        assert isinstance(rules, registries.HostRules)
        assert rules.source == "github"

    def test_missing_scope_and_no_opt_out_raises(self):
        from config import Config
        with pytest.raises(ValueError, match=r"github.*repos.*orgs|github.*orgs.*repos"):
            Config.from_data({"services": [
                {"service": "github", **GITHUB_CRED},
            ]})

    def test_scope_and_unrestricted_together_raises(self):
        from config import Config
        with pytest.raises(ValueError, match="mutually exclusive"):
            Config.from_data({"services": [
                {"service": "github", "scope": {"repos": ["myorg/myrepo"]},
                 "unrestricted": True, **GITHUB_CRED},
            ]})

    def test_unrestricted_true_logs_and_grants(self, capsys):
        from config import Config
        cfg = Config.from_data({"services": [
            {"service": "github", "unrestricted": True, **GITHUB_CRED},
        ]})
        assert cfg.hosts["api.github.com"] is None
        events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        [event] = [e for e in events if e["event"] == "service_unrestricted"]
        assert event["service"] == "github"
        assert event["host"] == "api.github.com"

    def test_unknown_flag_key_raises(self):
        from config import Config
        with pytest.raises(ValueError, match="wrtie"):
            Config.from_data({"services": [
                {"service": "github", "scope": {"repos": ["myorg/myrepo"]},
                 "wrtie": True, **GITHUB_CRED},
            ]})

    def test_unscoped_flag_emits_warning(self, capsys):
        from config import Config
        Config.from_data({"services": [
            {"service": "github", "scope": {"repos": ["myorg/myrepo"]},
             "graphql": True, **GITHUB_CRED},
        ]})
        events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        [event] = [e for e in events if e["event"] == "service_flag_unscoped"]
        assert event["service"] == "github"
        assert event["flag"] == "graphql"

    def test_declared_scoped_flag_does_not_warn(self, capsys):
        # "write" is a declared flag but not unscoped=True -- no warning.
        from config import Config
        Config.from_data({"services": [
            {"service": "github", "scope": {"repos": ["myorg/myrepo"]},
             "write": True, **GITHUB_CRED},
        ]})
        events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert not [e for e in events if e["event"] == "service_flag_unscoped"]

    def test_malformed_host_raises(self):
        # host_param.pattern is enforced now that the host flows into a
        # compiled HostRules key and the credential-broker host, not just
        # stashed unvalidated in an isinstance(str) check.
        from config import Config
        for bad_host in ("gitlab.example.com/evil", "gitlab example.com",
                          "gitlab.example.com\nX-Injected: 1"):
            with pytest.raises(ValueError, match="gitlab"):
                Config.from_data({"services": [
                    {"service": "gitlab", "host": bad_host,
                     "scope": {"projects": ["team/backend"]},
                     "fake_value": "glpat-fake", "real_value": "glpat-real"},
                ]})

    def test_scoped_github_allows_in_scope_denies_out_of_scope(self):
        from config import Config
        cfg = Config.from_data({"services": [
            {"service": "github", "scope": {"repos": ["myorg/myrepo"]}, **GITHUB_CRED},
        ]})
        rules = cfg.hosts["api.github.com"]
        allowed = registries.evaluate(
            rules, method="GET", path_with_query="/repos/myorg/myrepo",
            headers={}, body_len=0,
        )
        denied = registries.evaluate(
            rules, method="GET", path_with_query="/repos/otherorg/x",
            headers={}, body_len=0,
        )
        assert isinstance(allowed, registries.Allowed)
        assert isinstance(denied, registries.Violation)

    def test_credential_header_survives_scoping(self):
        # Without this, AllowlistAddon's header scrubbing strips Authorization
        # before CredentialBrokerAddon ever sees the request -- a silent 401,
        # not a policy_violation, so it's easy to miss in testing.
        from config import Config
        cfg = Config.from_data({"services": [
            {"service": "github", "scope": {"repos": ["myorg/myrepo"]}, **GITHUB_CRED},
        ]})
        assert "authorization" in cfg.hosts["api.github.com"].request_headers

    def test_scope_round_trips_regex_metacharacters_literally(self):
        # '.' in a repo name is a legal GH_REPO character and a regex
        # metacharacter; Config.from_data's full path (YAML -> build_scope ->
        # scope_template -> compile_host_rules) must still treat it as
        # literal, not just literal_alternation in isolation.
        from config import Config
        cfg = Config.from_data({"services": [
            {"service": "github", "scope": {"repos": ["myorg/a.b"]}, **GITHUB_CRED},
        ]})
        rules = cfg.hosts["api.github.com"]
        literal = registries.evaluate(
            rules, method="GET", path_with_query="/repos/myorg/a.b",
            headers={}, body_len=0,
        )
        wildcarded = registries.evaluate(
            rules, method="GET", path_with_query="/repos/myorg/axb",
            headers={}, body_len=0,
        )
        assert isinstance(literal, registries.Allowed)
        assert isinstance(wildcarded, registries.Violation)

    def test_hosts_entry_restricts_host_preset_left_unrestricted(self):
        # The reverse (and security-relevant) direction of
        # test_hosts_entry_overrides_preset_with_no_warning: a hand-written
        # `hosts:` entry with `rules:` claws back a host a service preset
        # left unrestricted. This is the plan's documented raw-rules escape
        # hatch, and it did not actually work before 4ab01ae (old addon.py
        # checked `allowlist` before `restricted`, so an unrestricted host
        # could never be reclaimed).
        from config import Config
        cfg = Config.from_data({
            "services": [
                {"service": "github", "unrestricted": True, **GITHUB_CRED},
            ],
            "hosts": [
                {"host": "api.github.com", "rules": [
                    {"methods": ["GET"], "path": "/repos/myorg/myrepo"},
                ]},
            ],
        })
        rules = cfg.hosts["api.github.com"]
        assert isinstance(rules, registries.HostRules)
        assert rules.source == "config"
