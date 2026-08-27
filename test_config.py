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

class TestRedactKnownSecrets:
    # Belt-and-braces backstop for Finding 1: _expand_secret_fields (tested
    # above via TestConfigLoad/TestScopedServiceExpansion) is the real fix --
    # this only pins that Config.from_data still scrubs a live secret value
    # out of any ValueError it raises, as a safety net against some future
    # field growing a ${KEY} use that isn't real_value/fake_value.
    def test_redacts_known_secret_value(self):
        from config import _redact_known_secrets
        msg = _redact_known_secrets(
            "'host' 'AKIA-super-secret' does not match the required pattern",
            {"AWS_KEY": "AKIA-super-secret"},
        )
        assert "AKIA-super-secret" not in msg
        assert "[REDACTED]" in msg

    def test_leaves_ordinary_messages_unaffected(self):
        from config import _redact_known_secrets
        msg = "services[0] (github): unknown key(s) wrtie; available flags: ['write']"
        assert _redact_known_secrets(msg, {"AWS_KEY": "AKIA-super-secret"}) == msg

    def test_from_data_scrubs_secret_that_reaches_a_validation_error(self, tmp_path, monkeypatch):
        # Simulate a future field that (mistakenly) still gets whole-value
        # secret expansion and then fails a pattern check, by monkeypatching
        # _host_entries to raise a ValueError containing an expanded secret
        # -- exactly the shape Finding 1 produced before the real fix.
        import config as config_module
        from config import Config

        real_secret = "AKIA-super-secret-value"

        def _boom(data, section="hosts"):
            raise ValueError(f"hosts[0]: {real_secret!r} does not match the required pattern")

        monkeypatch.setattr(config_module, "_host_entries", _boom)

        secrets = tmp_path / "secrets.yaml"
        secrets.write_text(f"AWS_KEY: {real_secret}\n")
        with pytest.raises(ValueError) as exc_info:
            Config.from_data({"secrets_file": str(secrets), "hosts": []})
        assert real_secret not in str(exc_info.value)


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

    def test_secret_in_host_field_not_expanded_and_not_leaked(self, tmp_path):
        # Finding 4: ${KEY} expansion used to run over the *entire* config
        # dict before validation, so a secret placed somewhere other than
        # real_value/fake_value (here: a gitlab service's `host`) would be
        # substituted in, then echoed back verbatim in the ValueError raised
        # when host_param.pattern rejects it (a '/' isn't a legal hostname
        # character). Expansion is now scoped to real_value/fake_value only,
        # so the ${KEY} reference reaches validation unexpanded and the
        # secret never appears in the error message.
        from config import Config
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("AWS_SECRET_KEY: AKIA_super_secret_value/withslash\n")
        with pytest.raises(ValueError) as exc_info:
            Config.from_data({
                "secrets_file": str(secrets),
                "services": [
                    {"service": "gitlab", "host": "${AWS_SECRET_KEY}",
                     "unrestricted": True, "fake_value": "glpat-fake",
                     "real_value": "glpat-real"},
                ],
            })
        message = str(exc_info.value)
        assert "AKIA_super_secret_value" not in message
        assert "${AWS_SECRET_KEY}" in message

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

    def test_secret_in_scope_value_not_expanded_and_not_leaked(self, tmp_path):
        # Finding 1: a ${KEY} reference placed in a `scope:` value (instead
        # of real_value/fake_value, its only documented use) used to be
        # expanded to the real secret by the old whole-document
        # _expand_secrets before the scope pattern check ran, so the
        # resulting "does not match the required pattern" ValueError carried
        # the secret verbatim -- and management_api.py returns ValueError
        # text straight to the HTTP caller. Expansion is now scoped to
        # real_value/fake_value only, so the raw, unexpanded ${KEY} text
        # reaches build_scope's pattern check and the secret never appears
        # in the error.
        from config import Config
        secrets = tmp_path / "secrets.yaml"
        secrets.write_text("AWS_SECRET_KEY: AKIA-super-secret-other-service-key\n")
        with pytest.raises(ValueError) as exc_info:
            Config.from_data({
                "secrets_file": str(secrets),
                "services": [
                    {"service": "github", "scope": {"repos": ["${AWS_SECRET_KEY}"]},
                     **GITHUB_CRED},
                ],
            })
        message = str(exc_info.value)
        assert "AKIA-super-secret-other-service-key" not in message
        assert "${AWS_SECRET_KEY}" in message

    @pytest.mark.parametrize("bad_value", ["no", "false", "0", "", 1, 0])
    def test_unrestricted_non_bool_rejected(self, bad_value):
        # Finding 2: bool("no") is True in Python, so a hand-quoted
        # `unrestricted: "no"` in YAML (or a JSON string/int from an API
        # caller) used to grant exactly the blanket access the operator was
        # declining. Only an actual bool is accepted now.
        from config import Config
        with pytest.raises(ValueError, match="unrestricted"):
            Config.from_data({"services": [
                {"service": "github", "unrestricted": bad_value, **GITHUB_CRED},
            ]})

    def test_unrestricted_true_still_works(self):
        from config import Config
        cfg = Config.from_data({"services": [
            {"service": "github", "unrestricted": True, **GITHUB_CRED},
        ]})
        assert cfg.hosts["api.github.com"] is None

    def test_unrestricted_false_still_requires_scope(self):
        from config import Config
        with pytest.raises(ValueError, match="must be scoped"):
            Config.from_data({"services": [
                {"service": "github", "unrestricted": False, **GITHUB_CRED},
            ]})

    @pytest.mark.parametrize("bad_value", ["no", "false", "0", "", 1, 0])
    def test_scope_flag_non_bool_rejected(self, bad_value):
        from config import Config
        with pytest.raises(ValueError, match="write"):
            Config.from_data({"services": [
                {"service": "github", "scope": {"repos": ["myorg/myrepo"]},
                 "write": bad_value, **GITHUB_CRED},
            ]})

    def test_scope_flag_true_still_works(self):
        from config import Config
        cfg = Config.from_data({"services": [
            {"service": "github", "scope": {"repos": ["myorg/myrepo"]},
             "write": True, **GITHUB_CRED},
        ]})
        rules = cfg.hosts["api.github.com"]
        allowed = registries.evaluate(
            rules, method="POST", path_with_query="/repos/myorg/myrepo/issues",
            headers={"content-type": "application/json"}, body_len=10,
            content_type="application/json",
        )
        assert isinstance(allowed, registries.Allowed)

    @pytest.mark.parametrize("bad_value", ["no", "false", "0", "", 1, 0])
    def test_allow_host_non_bool_rejected(self, bad_value):
        from config import Config
        with pytest.raises(ValueError, match="allow_host"):
            Config.from_data({"services": [
                {"service": "github", "unrestricted": True, "allow_host": bad_value,
                 **GITHUB_CRED},
            ]})

    def test_allow_host_false_still_works(self):
        from config import Config
        cfg = Config.from_data({"services": [
            {"service": "github", "unrestricted": True, "allow_host": False,
             **GITHUB_CRED},
        ]})
        assert "api.github.com" not in cfg.hosts

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

    def test_hosts_entry_over_scoped_service_keeps_credential_header(self, capsys):
        # Finding 3: a hand-written `hosts:` entry for a host a *scoped*
        # (not unrestricted) service preset also touches replaces the
        # preset's compiled rules wholesale, including the request_headers
        # merge that keeps `authorization` alive through AllowlistAddon's
        # header scrubbing. Without re-wiring it, CredentialBrokerAddon
        # (which runs after AllowlistAddon) never sees the header to swap
        # in the real token, and the request goes upstream unauthenticated
        # -- silently, since that looks like an ordinary 200, not a
        # policy_violation or a pending approval. The existing override test
        # above uses `unrestricted: true`, which never reaches this branch
        # (preset.hosts is empty for github, so there's no compiled
        # request_headers to lose in the first place).
        from config import Config
        cfg = Config.from_data({
            "services": [
                {"service": "github", "scope": {"repos": ["myorg/myrepo"]}, **GITHUB_CRED},
            ],
            "hosts": [
                {"host": "api.github.com", "rules": [
                    {"methods": ["GET"], "path": "/repos/myorg/myrepo/releases"},
                ]},
            ],
        })
        rules = cfg.hosts["api.github.com"]
        assert isinstance(rules, registries.HostRules)
        assert rules.source == "config"
        assert "authorization" in rules.request_headers

        events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        [event] = [e for e in events if e["event"] == "hosts_entry_rewires_credential_header"]
        assert event["host"] == "api.github.com"
        assert event["headers"] == ["authorization"]

    def test_hosts_entry_over_hand_written_credential_does_not_auto_wire(self):
        # The auto-wire is deliberately scoped to service-preset-generated
        # credentials (Credential.preset is not None). A hand-written
        # `credentials:` entry on a restricted `hosts:` entry is documented
        # to need its header listed by the operator -- this must stay that
        # way, or a raw credentials entry would start silently getting a
        # header allowlisted for it that the operator never asked for.
        from config import Config
        cfg = Config.from_data({
            "credentials": [
                {"host": "api.example.com", "header": "Authorization",
                 "real_value": "tok"},
            ],
            "hosts": [
                {"host": "api.example.com", "rules": [
                    {"methods": ["GET"], "path": "/data"},
                ]},
            ],
        })
        rules = cfg.hosts["api.example.com"]
        assert "authorization" not in rules.request_headers
