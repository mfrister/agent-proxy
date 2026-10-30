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
        assert cfg.hosts["api.github.com"][0].rules is None

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
        assert cfg.hosts["gitlab.example.com"][0].rules is None

    def test_registry_service_bare_string(self):
        cfg = Config.from_data({"services": ["npm"]})
        assert cfg.hosts["registry.npmjs.org"][0].rules.source == "npm"
        assert cfg.credentials == []
        assert all(e.rules is not None for entries in cfg.hosts.values() for e in entries)
        assert cfg.hosts["registry.npmjs.org"][0].host_config.allow_response_cookies == []

    def test_credential_attached_to_its_hosts_entry(self):
        cfg = Config.from_data({"services": [
            {"service": "github", "fake_value": "ghp_fake",
             "real_value": "ghp_real", "unrestricted": True},
        ]})
        [entry] = cfg.hosts["api.github.com"]
        assert entry.credential is cfg.credentials[0]

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
        rules = cfg.hosts["registry.npmjs.org"][0].rules
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

    def test_current_user_allowed(self):
        # glab auth login/status verifies the token via GET /api/v4/user.
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", "/api/v4/user")
        assert isinstance(result, registries.Allowed)

    @pytest.mark.parametrize("method,path", [
        ("GET", "/api/v4/user?x=1"),
        ("GET", "/api/v4/users"),
        ("GET", "/api/v4/user/keys"),
        ("GET", "/api/v4/users/1"),
        ("PUT", "/api/v4/user"),
    ])
    def test_current_user_rule_is_exact(self, method, path):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {"write": True}, method, path)
        assert isinstance(result, registries.Violation)

    # Query encoded the way glab sends it: client-go's url.Values.Encode,
    # sorted keys, ',' as %2C.
    GLAB_ISSUE_LIST = ("/api/v4/projects/team%2Fbackend/issues?in=title%2Cdescription"
                       "&order_by=created_at&page=1&per_page=30&sort=desc&state=opened")

    def test_glab_default_issue_list_allowed(self):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", self.GLAB_ISSUE_LIST)
        assert isinstance(result, registries.Allowed)

    @pytest.mark.parametrize("param", [
        "search=login+fails+on+%2Fapi",
        "labels=bug%2Cpriority%3A%3Ahigh%2Cneeds+review",
        "not%5Blabels%5D=wontfix",
        "milestone=Release+2.0",
        "milestone=None",
        "confidential=true",
        "issue_type=incident",
        "iteration_id=42",
        "assignee_id=17",
        "assignee_id=None",
        "assignee_id=Any",
        "not%5Bassignee_id%5D=17",
        "author_id=17",
        "not%5Bauthor_id%5D=17",
        "created_after=2026-10-01T00%3A00%3A00Z",
        "created_before=2026-10-01T00%3A00%3A00%2B02%3A00",
        "updated_after=2026-10-01T00%3A00%3A00.123Z",
        "updated_before=2026-10-01T00%3A00%3A00Z",
    ])
    def test_glab_issue_list_filters_allowed(self, param):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", f"{self.GLAB_ISSUE_LIST}&{param}")
        assert isinstance(result, registries.Allowed)

    @pytest.mark.parametrize("param", [
        "scope=all",                                # not a glab issue list flag
        "iids%5B%5D=1",
        "order_by=id%3B",
        "sort=random",
        "in=title%2Cnotes",
        "assignee_id=someone",
        "created_after=yesterday",
        "search=" + "a" * 256,                      # over the length bound
        "search=%00",                               # outside the character class
        "labels=" + "%2C".join(["l"] * 21),         # over 20 labels
    ])
    def test_glab_issue_list_bad_params_denied(self, param):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", f"{self.GLAB_ISSUE_LIST}&{param}")
        assert isinstance(result, registries.Violation)

    def test_glab_mr_lookup_by_source_branch_allowed(self):
        scope = {"projects": ["team/backend"]}
        path = ("/api/v4/projects/team%2Fbackend/merge_requests"
                "?per_page=30&source_branch=feature%2Fgovulncheck-update-go")
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Allowed)

    def test_glab_mr_lookup_bad_source_branch_denied(self):
        scope = {"projects": ["team/backend"]}
        path = "/api/v4/projects/team%2Fbackend/merge_requests?source_branch=a%3Bb"
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Violation)

    GLAB_MR_LIST = ("/api/v4/projects/team%2Fbackend/merge_requests"
                    "?page=1&per_page=30&state=opened")

    @pytest.mark.parametrize("param", [
        "source_branch=feature%2Fx",
        "target_branch=main",
        "order_by=merged_at",
        "sort=asc",
        "search=fix+login+on+%2Fapi",
        "milestone=Release+2.0",
        "environment=production",
        "labels=bug%2Cpriority%3A%3Ahigh",
        "not%5Blabels%5D=wontfix",
        "wip=yes",
        "scope=assigned_to_me",
        "author_id=17",
        "assignee_id=Any",
        "reviewer_id=17",
        "created_after=2026-10-01T00%3A00%3A00Z",
        "deployed_before=2026-10-01T00%3A00%3A00%2B02%3A00",
    ])
    def test_glab_mr_list_filters_allowed(self, param):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", f"{self.GLAB_MR_LIST}&{param}")
        assert isinstance(result, registries.Allowed)

    @pytest.mark.parametrize("param", [
        "scope=all",
        "author_username=someone",
        "order_by=id",
        "wip=maybe",
        "assignee_id=None",
        "search=" + "a" * 101,                      # over the length bound
        "environment=" + "a" * 101,
        "labels=" + "a" * 65,
        "labels=" + "%2C".join(["l"] * 11),         # over 10 labels
        "source_branch=a%3Bb",
    ])
    def test_glab_mr_list_bad_params_denied(self, param):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", f"{self.GLAB_MR_LIST}&{param}")
        assert isinstance(result, registries.Violation)

    @pytest.mark.parametrize("path", [
        "/merge_requests/7?include_diverged_commits_count=true"
        "&include_rebase_in_progress=true&render_html=true",
        "/merge_requests/7/approval_state",
        "/merge_requests/7/pipelines",
        "/merge_requests/7/pipelines?page=2&per_page=20",
        "/merge_requests/7/discussions?page=1&per_page=30&sort=asc",
    ])
    def test_glab_mr_view_allowed(self, path):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", f"/api/v4/projects/team%2Fbackend{path}")
        assert isinstance(result, registries.Allowed)

    @pytest.mark.parametrize("path", [
        "/merge_requests/7?render_html=yes",
        "/merge_requests/7/approval_state?x=1",
        "/merge_requests/7/pipelines?ref=main",
        "/merge_requests/7/discussions?sort=random",
    ])
    def test_glab_mr_view_bad_params_denied(self, path):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", f"/api/v4/projects/team%2Fbackend{path}")
        assert isinstance(result, registries.Violation)

    # Encoded the way glab ci sends them (client-go, sorted keys).
    @pytest.mark.parametrize("path", [
        "/pipelines?page=1",
        "/pipelines?order_by=id&page=1&per_page=50&ref=feature%2Fx&scope=branches"
        "&sha=0123abcd&sort=desc&source=merge_request_event&status=failed"
        "&updated_after=2026-10-01T00%3A00%3A00Z&username=some.user&yaml_errors=true",
        "/pipelines?name=Nightly+build&page=1",
        "/pipelines/latest?ref=main",
        "/pipelines/123",
        "/pipelines/123/jobs?per_page=500",
        "/pipelines/123/jobs?page=2&per_page=100&scope%5B%5D=failed",
        "/pipelines/123/bridges?page=1&per_page=500",
        "/pipeline_schedules",
        "/pipeline_schedules?page=1&per_page=30",
        "/pipeline_schedules?scope=active",
        "/jobs/456",
        "/jobs/456/trace",
        "/jobs/artifacts/feature/x/download?job=build+linux",
        "/repository/commits/0123abcd/statuses?all=true",
    ])
    def test_glab_ci_reads_allowed(self, path):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", f"/api/v4/projects/team%2Fbackend{path}")
        assert isinstance(result, registries.Allowed)

    @pytest.mark.parametrize("method,path", [
        ("GET", "/pipelines/123/variables"),        # may carry trigger-time secrets
        ("GET", "/variables"),
        ("GET", "/pipelines?status=bogus"),
        ("GET", "/pipelines?name=" + "a" * 101),
        ("GET", "/pipelines/latest?ref=a%3Bb"),
        ("GET", "/pipeline_schedules/9"),           # includes schedule variables
        ("GET", "/pipeline_schedules?scope=all"),
        ("POST", "/pipeline_schedules"),            # glab schedule create
        ("POST", "/pipeline_schedules/9/play"),     # glab schedule run
        ("DELETE", "/pipeline_schedules/9"),
        ("GET", "/jobs/456/artifacts/some/file"),
        ("POST", "/pipeline"),                      # glab ci run
        ("POST", "/pipelines/123/retry"),
        ("POST", "/pipelines/123/cancel"),
        ("DELETE", "/pipelines/123"),
        ("POST", "/jobs/456/play"),
        ("POST", "/jobs/456/retry"),
        ("POST", "/jobs/456/cancel"),
        ("POST", "/trigger/pipeline"),
    ])
    def test_glab_ci_writes_and_secrets_denied(self, method, path):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {"write": True}, method,
                              f"/api/v4/projects/team%2Fbackend{path}")
        assert isinstance(result, registries.Violation)

    @pytest.mark.parametrize("flags,allowed", [({}, False), ({"write": True}, True)])
    def test_glab_ci_lint_needs_write(self, flags, allowed):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, flags, "POST",
                              "/api/v4/projects/team%2Fbackend/ci/lint", body_len=10,
                              content_type="application/json")
        assert isinstance(result, registries.Allowed if allowed else registries.Violation)

    def test_issue_notes_list_allowed(self):
        # glab issue view --comments
        scope = {"projects": ["team/backend"]}
        path = "/api/v4/projects/team%2Fbackend/issues/7/notes?page=2&per_page=20&sort=asc"
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Allowed)

    def test_issue_notes_post_still_needs_write(self):
        scope = {"projects": ["team/backend"]}
        path = "/api/v4/projects/team%2Fbackend/issues/7/notes"
        result = _gitlab_eval(scope, {}, "POST", path, body_len=10,
                              content_type="application/json")
        assert isinstance(result, registries.Violation)

    def test_milestone_lookup_by_title_allowed(self):
        # --milestone <title> on glab issue create/update
        scope = {"projects": ["team/backend"]}
        path = ("/api/v4/projects/team%2Fbackend/milestones"
                "?include_parent_milestones=true&per_page=30&title=Release+2.0")
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Allowed)

    @pytest.mark.parametrize("path", [
        "/api/v4/projects/team%2Fbackend/milestones?search=x",
        "/api/v4/projects/team%2Fbackend/milestones/3",
        "/api/v4/projects/other%2Fproject/milestones?title=Release+2.0",
    ])
    def test_milestone_lookup_other_shapes_denied(self, path):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Violation)

    def test_project_fetch_with_glab_create_flags_allowed(self):
        # glab issue create fetches the project before posting anything.
        scope = {"projects": ["team/backend"]}
        path = "/api/v4/projects/team%2Fbackend?license=true&with_custom_attributes=true"
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Allowed)

    def test_project_fetch_other_query_denied(self):
        scope = {"projects": ["team/backend"]}
        path = "/api/v4/projects/team%2Fbackend?license=yes"
        result = _gitlab_eval(scope, {}, "GET", path)
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

    @pytest.mark.parametrize("action,body_len", [
        ("subscribe", 0),
        ("unsubscribe", 0),
        ("time_estimate", 20),
        ("add_spent_time", 20),
        ("reset_time_estimate", 0),
        ("reset_spent_time", 0),
    ])
    def test_write_gates_issue_subscription_and_time_tracking(self, action, body_len):
        scope = {"projects": ["team/backend"]}
        path = f"/api/v4/projects/team%2Fbackend/issues/7/{action}"
        content_type = "application/json" if body_len else None
        without_write = _gitlab_eval(scope, {}, "POST", path, body_len=body_len,
                                     content_type=content_type)
        with_write = _gitlab_eval(scope, {"write": True}, "POST", path, body_len=body_len,
                                  content_type=content_type)
        assert isinstance(without_write, registries.Violation)
        assert isinstance(with_write, registries.Allowed)

    @pytest.mark.parametrize("action", ["subscribe", "reset_spent_time"])
    def test_bodyless_issue_actions_reject_a_body(self, action):
        scope = {"projects": ["team/backend"]}
        path = f"/api/v4/projects/team%2Fbackend/issues/7/{action}"
        result = _gitlab_eval(scope, {"write": True}, "POST", path, body_len=20,
                              content_type="application/json")
        assert isinstance(result, registries.Violation)

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


# ── GitLab path percent-encoding hardening ────────────────────────────────────
#
# GL_PATH used to be a character class with a free '%' member, so any %XX
# sequence (not just the %2[fF] encoded separator GitLab's API actually
# needs) rode through as an ordinary path character. GL_PATH now spells the
# encoded separator out as an explicit `%2[fF]` alternative instead, so a
# free-floating '%' can no longer smuggle an overlong/invalid UTF-8 encoding
# of '.' (e.g. %C0%AE) past evaluate()'s literal '%2e' traversal check.

class TestGitLabPercentEncodingHardening:
    def test_overlong_utf8_dot_in_file_path_denied(self):
        scope = {"projects": ["team/backend"]}
        path = "/api/v4/projects/team%2Fbackend/repository/files/dir%C0%AEfile.py?ref=main"
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Violation)

    def test_bare_ordinary_percent_encoding_denied(self):
        # %41 is a perfectly ordinary encoding of 'A' -- this proves '%' is
        # no longer a free character in the path class, not merely that
        # malformed encodings are caught.
        scope = {"projects": ["team/backend"]}
        path = "/api/v4/projects/team%2Fbackend/repository/files/%41.py?ref=main"
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Violation)

    def test_encoded_separator_case_variants_still_allowed(self):
        scope = {"projects": ["team/backend"]}
        lower = _gitlab_eval(scope, {}, "GET", "/api/v4/projects/team%2fbackend")
        upper = _gitlab_eval(scope, {}, "GET", "/api/v4/projects/team%2Fbackend")
        assert isinstance(lower, registries.Allowed)
        assert isinstance(upper, registries.Allowed)

    def test_nested_subgroup_project_path_still_allowed(self):
        scope = {"projects": ["team/sub/backend"]}
        result = _gitlab_eval(scope, {}, "GET", "/api/v4/projects/team%2Fsub%2Fbackend")
        assert isinstance(result, registries.Allowed)

    def test_group_scoped_path_still_allowed(self):
        scope = {"groups": ["team/sandbox"]}
        result = _gitlab_eval(scope, {}, "GET", "/api/v4/projects/team%2Fsandbox%2Fproj")
        assert isinstance(result, registries.Allowed)

    def test_deepest_legal_nesting_still_allowed(self):
        # ScopeParam("projects", ...){1,10}) allows up to 11 segments total.
        segs = [f"seg{i}" for i in range(11)]
        scope = {"projects": ["/".join(segs)]}
        path = "/api/v4/projects/" + "%2F".join(segs)
        result = _gitlab_eval(scope, {}, "GET", path)
        assert isinstance(result, registries.Allowed)

    def test_boundary_prefix_injection_still_denied(self):
        scope = {"groups": ["team/sandbox"]}
        result = _gitlab_eval(
            scope, {}, "GET", "/api/v4/projects/team%2Fsandbox-evil%2Fproj"
        )
        assert isinstance(result, registries.Violation)

    def test_over_deep_path_still_denied(self):
        scope = {"projects": ["team/backend"]}
        result = _gitlab_eval(
            scope, {}, "GET", "/api/v4/projects/team%2Fbackend%2Fextra"
        )
        assert isinstance(result, registries.Violation)
