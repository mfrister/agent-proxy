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
            assert preset.host_param is None

    def test_github_preset(self):
        preset = services.SERVICE_PRESETS["github"]
        # No static `hosts` entry: api.github.com is only reachable through
        # scope_template (scoped) or the explicit `unrestricted: true` opt-out.
        assert preset.hosts == {}
        assert preset.credential.header == "Authorization"
        assert preset.credential.on_host == "api.github.com"
        assert preset.credential.wrap("ghp_x") == "token ghp_x"

    def test_gitlab_preset(self):
        preset = services.SERVICE_PRESETS["gitlab"]
        assert preset.host_param is not None
        assert preset.host_param.name == "host"
        assert preset.host_param.required is True
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
        # Credential wiring, exercised via the explicit unrestricted opt-out
        # -- the scoped path (the actual security property) has its own
        # TestScopedServiceExpansion tests below.
        cfg = Config.from_data({"services": [
            {"service": "github", "fake_value": "ghp_fake", "real_value": "ghp_real",
             "unrestricted": True},
        ]})
        assert cfg.credentials == [Credential(
            host="api.github.com", header="Authorization",
            fake_value="token ghp_fake", real_value="token ghp_real",
            preset="github",
        )]
        assert "api.github.com" in cfg.hosts
        assert cfg.hosts["api.github.com"] is None

    def test_gitlab_with_host(self):
        cfg = Config.from_data({"services": [
            {"service": "gitlab", "host": "gitlab.example.com",
             "fake_value": "glpat-fake", "real_value": "glpat-real",
             "unrestricted": True},
        ]})
        assert cfg.credentials == [Credential(
            host="gitlab.example.com", header="PRIVATE-TOKEN",
            fake_value="glpat-fake", real_value="glpat-real",
            preset="gitlab",
        )]
        assert "gitlab.example.com" in cfg.hosts
        assert cfg.hosts["gitlab.example.com"] is None

    def test_registry_service_bare_string(self):
        cfg = Config.from_data({"services": ["npm"]})
        assert cfg.hosts["registry.npmjs.org"].source == "npm"
        assert cfg.credentials == []
        assert not any(v is None for v in cfg.hosts.values())
        assert cfg.host_config["registry.npmjs.org"].allow_response_cookies == []

    def test_allow_host_false_brokers_without_allowlisting(self):
        cfg = Config.from_data({"services": [
            {"service": "github", "fake_value": "ghp_fake",
             "real_value": "ghp_real", "allow_host": False, "unrestricted": True},
        ]})
        assert cfg.credentials[0].host == "api.github.com"
        assert "api.github.com" not in cfg.hosts

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
                 "real_value": "${GITHUB_TOKEN}", "unrestricted": True},
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
        rules = cfg.hosts["registry.npmjs.org"]
        assert "authorization" in rules.request_headers
        # The catalog's own npm preset is untouched (frozen dataclass replaced,
        # not mutated).
        assert "authorization" not in registries.PRESETS["npm"]["registry.npmjs.org"].request_headers


# ── ServicePreset.build_scope ───────────────────────────────────────────────────

class TestBuildScope:
    def test_unknown_param_rejected(self):
        preset = services.SERVICE_PRESETS["github"]
        with pytest.raises(ValueError, match="unknown scope param"):
            preset.build_scope({"bogus": ["x"]})

    def test_empty_list_rejected(self):
        preset = services.SERVICE_PRESETS["github"]
        with pytest.raises(ValueError, match="non-empty list"):
            preset.build_scope({"repos": []})

    def test_scalar_for_list_param_rejected(self):
        preset = services.SERVICE_PRESETS["github"]
        with pytest.raises(ValueError, match="non-empty list"):
            preset.build_scope({"repos": "myorg/myrepo"})

    def test_list_for_scalar_param_rejected(self):
        # github/gitlab's own scope_params are all list=True; exercise the
        # scalar branch directly with a synthetic single-value param.
        preset = services.ServicePreset(
            name="synthetic",
            scope_params=(services.ScopeParam("region", r"[a-z]{2,8}", list=False),),
        )
        with pytest.raises(ValueError, match="single value"):
            preset.build_scope({"region": ["us-east"]})

    def test_non_string_value_rejected(self):
        preset = services.SERVICE_PRESETS["github"]
        with pytest.raises(ValueError, match="must be a string"):
            preset.build_scope({"repos": [123]})

    def test_malformed_value_rejected(self):
        preset = services.SERVICE_PRESETS["github"]
        with pytest.raises(ValueError, match="does not match"):
            preset.build_scope({"repos": ["not a valid repo!!"]})

    def test_no_scope_at_all_rejected(self):
        preset = services.SERVICE_PRESETS["github"]
        with pytest.raises(ValueError, match="at least one scope param"):
            preset.build_scope({})

    def test_case_variant_repo_still_matches(self):
        # GitHub/GitLab resolve owner/repo case-insensitively.
        preset = services.SERVICE_PRESETS["github"]
        escaped = preset.build_scope({"repos": ["MyOrg/MyRepo"]})
        spec = preset.scope_template(escaped, {}, None)
        rules = registries.compile_host_rules(spec["api.github.com"], source="github")
        result = registries.evaluate(
            rules, method="GET", path_with_query="/repos/myorg/myrepo",
            headers={}, body_len=0,
        )
        assert isinstance(result, registries.Allowed)

    def test_error_names_service_and_param(self):
        preset = services.SERVICE_PRESETS["github"]
        with pytest.raises(ValueError, match=r"github.*repos"):
            preset.build_scope({"repos": ["nope!!"]})

    def test_gitlab_unknown_param_rejected(self):
        preset = services.SERVICE_PRESETS["gitlab"]
        with pytest.raises(ValueError, match="unknown scope param"):
            preset.build_scope({"projects": ["team/backend"], "extra": ["x"]})


# ── Scoped GitHub rules: the actual security property ──────────────────────────
#
# These compile the generated spec with registries.compile_host_rules and
# drive it through registries.evaluate, so the real rule engine is under
# test, not just the template string.

def _github_eval(scope, flags, method, path, body_len=0, content_type=None):
    preset = services.SERVICE_PRESETS["github"]
    escaped = preset.build_scope(scope)
    spec = preset.scope_template(escaped, flags, None)
    rules = registries.compile_host_rules(spec["api.github.com"], source="github")
    return registries.evaluate(
        rules, method=method, path_with_query=path, headers={},
        body_len=body_len, content_type=content_type,
    )


class TestScopedGitHubRules:
    def test_regex_metacharacters_matched_literally(self):
        # '+' isn't a legal GitHub repo-name character, so build_scope's own
        # pattern would reject it before this ever reaches literal_alternation
        # -- bypass that gate here (as literal_alternation(items) directly) to
        # prove the *template + compiled rule set*, not just build_scope's
        # allowlist, treats operator input literally rather than as regex.
        preset = services.SERVICE_PRESETS["github"]
        for repo in ("myorg/a.b", "myorg/a+b"):
            escaped = {"repos": registries.literal_alternation([repo])}
            spec = preset.scope_template(escaped, {}, None)
            rules = registries.compile_host_rules(spec["api.github.com"], source="github")
            result = registries.evaluate(
                rules, method="GET", path_with_query="/repos/myorg/axb",
                headers={}, body_len=0,
            )
            assert isinstance(result, registries.Violation), repo

    def test_in_scope_repo_allowed_out_of_scope_denied(self):
        scope = {"repos": ["myorg/myrepo"]}
        allowed = _github_eval(scope, {}, "GET", "/repos/myorg/myrepo")
        denied = _github_eval(scope, {}, "GET", "/repos/otherorg/otherrepo")
        assert isinstance(allowed, registries.Allowed)
        assert isinstance(denied, registries.Violation)

    def test_org_scope_is_boundary_anchored(self):
        scope = {"orgs": ["myorg"]}
        allowed = _github_eval(scope, {}, "GET", "/repos/myorg/anything")
        evil = _github_eval(scope, {}, "GET", "/repos/myorg-evil/repo")
        assert isinstance(allowed, registries.Allowed)
        assert isinstance(evil, registries.Violation)

    def test_traversal_denied(self):
        scope = {"repos": ["myorg/myrepo"]}
        result = _github_eval(
            scope, {}, "GET", "/repos/myorg/myrepo/../../otherorg/x"
        )
        assert isinstance(result, registries.Violation)

    def test_percent_encoded_traversal_denied(self):
        scope = {"repos": ["myorg/myrepo"]}
        result = _github_eval(
            scope, {}, "GET", "/repos/myorg/myrepo%2e%2e/x"
        )
        assert isinstance(result, registries.Violation)

    def test_write_gates_post_to_issues(self):
        scope = {"repos": ["myorg/myrepo"]}
        path = "/repos/myorg/myrepo/issues"
        without_write = _github_eval(scope, {}, "POST", path, body_len=10,
                                      content_type="application/json")
        with_write = _github_eval(scope, {"write": True}, "POST", path, body_len=10,
                                   content_type="application/json")
        assert isinstance(without_write, registries.Violation)
        assert isinstance(with_write, registries.Allowed)

    def test_write_still_bounds_body_size_and_content_type(self):
        scope = {"repos": ["myorg/myrepo"]}
        path = "/repos/myorg/myrepo/issues"
        oversized = _github_eval(scope, {"write": True}, "POST", path,
                                  body_len=100_000, content_type="application/json")
        wrong_type = _github_eval(scope, {"write": True}, "POST", path,
                                   body_len=10, content_type="text/plain")
        assert isinstance(oversized, registries.Violation)
        assert isinstance(wrong_type, registries.Violation)

    def test_graphql_gated_by_flag(self):
        scope = {"repos": ["myorg/myrepo"]}
        path = "/graphql"
        without = _github_eval(scope, {}, "POST", path, body_len=10,
                                content_type="application/json")
        with_flag = _github_eval(scope, {"graphql": True}, "POST", path, body_len=10,
                                  content_type="application/json")
        assert isinstance(without, registries.Violation)
        assert isinstance(with_flag, registries.Allowed)

    def test_authorization_survives_header_scrubbing(self):
        preset = services.SERVICE_PRESETS["github"]
        escaped = preset.build_scope({"repos": ["myorg/myrepo"]})
        rules_no_write = registries.compile_host_rules(
            preset.scope_template(escaped, {}, None)["api.github.com"], source="github"
        )
        rules_write = registries.compile_host_rules(
            preset.scope_template(escaped, {"write": True}, None)["api.github.com"],
            source="github",
        )
        assert "authorization" in rules_no_write.request_headers
        assert "authorization" in rules_write.request_headers
        assert "content-type" in rules_write.request_headers
        assert "content-type" not in rules_no_write.request_headers


# ── Scoped GitLab rules ──────────────────────────────────────────────────────────

def _gitlab_eval(scope, flags, method, path, body_len=0, content_type=None,
                  host="gitlab.example.com"):
    preset = services.SERVICE_PRESETS["gitlab"]
    escaped = preset.build_scope(scope)
    spec = preset.scope_template(escaped, flags, host)
    rules = registries.compile_host_rules(spec[host], source="gitlab")
    return registries.evaluate(
        rules, method=method, path_with_query=path, headers={},
        body_len=body_len, content_type=content_type,
    )


class TestScopedGitLabRules:
    def test_percent_encoded_project_in_scope_allowed(self):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", "/api/v4/projects/team%2Fbackend")
        assert isinstance(result, registries.Allowed)

    def test_percent_encoded_project_out_of_scope_denied(self):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", "/api/v4/projects/other%2Fproject")
        assert isinstance(result, registries.Violation)

    def test_group_scope_allows_any_project_under_it(self):
        scope = {"groups": ["team/sandbox"]}
        allowed = _gitlab_eval(scope, {}, "GET", "/api/v4/projects/team%2Fsandbox%2Fanysub")
        evil = _gitlab_eval(scope, {}, "GET", "/api/v4/projects/team%2Fsandbox-evil%2Fx")
        assert isinstance(allowed, registries.Allowed)
        assert isinstance(evil, registries.Violation)

    def test_traversal_denied(self):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(
            scope, {}, "GET", "/api/v4/projects/team%2Fbackend%2e%2e/x"
        )
        assert isinstance(result, registries.Violation)

    def test_write_gates_post_to_issues(self):
        scope = {"projects": ["team/backend"]}
        path = "/api/v4/projects/team%2Fbackend/issues"
        without_write = _gitlab_eval(scope, {}, "POST", path, body_len=10,
                                      content_type="application/json")
        with_write = _gitlab_eval(scope, {"write": True}, "POST", path, body_len=10,
                                   content_type="application/json")
        assert isinstance(without_write, registries.Violation)
        assert isinstance(with_write, registries.Allowed)

    def test_authorization_header_present_for_credential(self):
        # gitlab's credential header is PRIVATE-TOKEN, not Authorization --
        # it must survive AllowlistAddon's header scrubbing the same way.
        preset = services.SERVICE_PRESETS["gitlab"]
        escaped = preset.build_scope({"projects": ["team/backend"]})
        host = "gitlab.example.com"
        rules_no_write = registries.compile_host_rules(
            preset.scope_template(escaped, {}, host)[host], source="gitlab"
        )
        rules_write = registries.compile_host_rules(
            preset.scope_template(escaped, {"write": True}, host)[host], source="gitlab"
        )
        assert "private-token" in rules_no_write.request_headers
        assert "private-token" in rules_write.request_headers
        assert "content-type" in rules_write.request_headers
        assert "content-type" not in rules_no_write.request_headers
