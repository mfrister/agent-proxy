"""
Tests for the registry rule engine and preset data.

Run with:  pytest test_registries.py -v
"""

import re

import pytest

import registries
from registries import (
    Allowed,
    Violation,
    compile_host_rules,
    evaluate,
    literal_alternation,
)


def check(preset: str, host: str, method: str, path: str, body_len: int = 0,
          content_type: str | None = None):
    """Evaluate a request against a preset host with no extra headers."""
    return evaluate(
        registries.PRESETS[preset][host],
        method=method,
        path_with_query=path,
        headers={},
        body_len=body_len,
        content_type=content_type,
    )


HEX = "abcdef0123456789" * 4  # 64 hex chars


# ── Preset vectors ─────────────────────────────────────────────────────────────
# (preset, host, method, path+query, expected_allow)

VECTORS = [
    # go — module proxy
    ("go", "proxy.golang.org", "GET", "/golang.org/x/tools/@v/list", True),
    ("go", "proxy.golang.org", "GET", "/golang.org/x/tools/@v/v0.30.0.info", True),
    ("go", "proxy.golang.org", "GET", "/golang.org/x/tools/@v/v0.30.0.mod", True),
    ("go", "proxy.golang.org", "GET", "/github.com/!burnt!sushi/toml/@v/v1.3.2.zip", True),
    ("go", "proxy.golang.org", "GET", "/golang.org/x/text/@latest", True),
    ("go", "proxy.golang.org", "GET",
     "/golang.org/x/text/@v/v0.0.0-20230815205955-abcdefabcdef.info", True),
    ("go", "proxy.golang.org", "GET",
     "/github.com/docker/docker/@v/v20.10.24+incompatible.mod", True),
    # go — sumdb fetched through the module proxy
    ("go", "proxy.golang.org", "GET", "/sumdb/sum.golang.org/supported", True),
    ("go", "proxy.golang.org", "GET", "/sumdb/sum.golang.org/latest", True),
    ("go", "proxy.golang.org", "GET",
     "/sumdb/sum.golang.org/lookup/golang.org/x/text@v0.14.0", True),
    ("go", "proxy.golang.org", "GET", "/sumdb/sum.golang.org/tile/8/0/x123/x456/789", True),
    ("go", "sum.golang.org", "GET", "/latest", True),
    ("go", "sum.golang.org", "GET", "/lookup/github.com/pkg/errors@v0.9.1", True),
    ("go", "sum.golang.org", "GET", "/tile/8/data/012", True),
    ("go", "sum.golang.org", "GET", "/tile/8/2/000.p/57", True),
    # go — negatives
    ("go", "proxy.golang.org", "POST", "/golang.org/x/tools/@v/list", False),
    ("go", "proxy.golang.org", "GET", "/golang.org/x/tools/@v/list?x=1", False),
    ("go", "proxy.golang.org", "GET", "/../etc/passwd", False),
    ("go", "proxy.golang.org", "GET", "/UPPER/module/@v/list", False),
    ("go", "proxy.golang.org", "GET", "/" + "a" * 300 + "/@v/list", False),

    # npm
    ("npm", "registry.npmjs.org", "GET", "/express", True),
    ("npm", "registry.npmjs.org", "GET", "/JSONStream", True),
    ("npm", "registry.npmjs.org", "GET", "/@types/node", True),
    ("npm", "registry.npmjs.org", "GET", "/@types%2fnode", True),
    ("npm", "registry.npmjs.org", "GET", "/@types%2Fnode", True),
    ("npm", "registry.npmjs.org", "GET", "/express/-/express-4.18.2.tgz", True),
    ("npm", "registry.npmjs.org", "GET", "/@babel/core/-/core-7.23.0.tgz", True),
    # npm — negatives (audit and search are blocked by design)
    ("npm", "registry.npmjs.org", "POST", "/-/npm/v1/security/advisories/bulk", False),
    ("npm", "registry.npmjs.org", "POST", "/-/npm/v1/security/audits/quick", False),
    ("npm", "registry.npmjs.org", "GET", "/-/v1/search?text=secret", False),
    ("npm", "registry.npmjs.org", "GET", "/express?write=true", False),
    ("npm", "registry.npmjs.org", "PUT", "/express", False),
    ("npm", "registry.npmjs.org", "GET", "/%65xpress", False),

    # docker
    ("docker", "registry-1.docker.io", "GET", "/v2/", True),
    ("docker", "registry-1.docker.io", "HEAD", "/v2/library/ubuntu/manifests/24.04", True),
    ("docker", "registry-1.docker.io", "GET",
     f"/v2/library/ubuntu/manifests/sha256:{HEX}", True),
    ("docker", "registry-1.docker.io", "GET", f"/v2/library/ubuntu/blobs/sha256:{HEX}", True),
    ("docker", "registry-1.docker.io", "GET", f"/v2/a/b/c/d/manifests/latest", True),
    ("docker", "auth.docker.io", "GET",
     "/token?service=registry.docker.io&scope=repository:library/ubuntu:pull", True),
    ("docker", "auth.docker.io", "GET",
     "/token?service=registry.docker.io&scope=repository:library/ubuntu:pull&client_id=docker",
     True),
    ("docker", "production.cloudflare.docker.com", "GET",
     f"/registry-v2/docker/registry/v2/blobs/sha256/ab/{HEX}/data"
     "?Expires=1719900000&Signature=aBc~123_-&Key-Pair-Id=APKAJ123", True),
    ("docker", "production.cloudfront.docker.com", "GET",
     f"/registry-v2/docker/registry/v2/blobs/sha256/55/{HEX}/data"
     "?Expires=1719900000&Signature=aBc~123_-&Key-Pair-Id=APKAJ123", True),
    # docker — negatives
    ("docker", "auth.docker.io", "GET",
     "/token?service=registry.docker.io&scope=repository:library/ubuntu:push", False),
    ("docker", "auth.docker.io", "GET",
     "/token?service=evil.example.com&scope=repository:x:pull", False),
    ("docker", "registry-1.docker.io", "PUT", "/v2/library/ubuntu/blobs/uploads/", False),
    ("docker", "registry-1.docker.io", "POST", "/v2/library/ubuntu/blobs/uploads/", False),
    ("docker", "registry-1.docker.io", "GET",
     "/v2/library/ubuntu/blobs/sha512:" + "a" * 128, False),
    ("docker", "registry-1.docker.io", "GET",
     "/v2/library/ubuntu/manifests/" + "x" * 200, False),

    # ghcr
    ("ghcr", "ghcr.io", "GET", "/v2/", True),
    ("ghcr", "ghcr.io", "GET", "/token?service=ghcr.io&scope=repository:owner/repo:pull", True),
    ("ghcr", "ghcr.io", "GET", "/v2/owner/repo/manifests/latest", True),
    ("ghcr", "ghcr.io", "HEAD", f"/v2/owner/repo/manifests/sha256:{HEX}", True),
    ("ghcr", "ghcr.io", "GET", f"/v2/owner/repo/blobs/sha256:{HEX}", True),
    ("ghcr", "pkg-containers.githubusercontent.com", "GET",
     f"/ghcr1/blobs/sha256:{HEX}?se=2026-07-02T00:00:00Z&sig=q1w2e3", True),
    # ghcr — negatives
    ("ghcr", "ghcr.io", "POST", "/v2/owner/repo/blobs/uploads/", False),
    ("ghcr", "ghcr.io", "GET", "/token?service=ghcr.io&scope=repository:owner/repo:push", False),

    # pypi
    ("pypi", "pypi.org", "GET", "/simple/", True),
    ("pypi", "pypi.org", "GET", "/simple/requests/", True),
    ("pypi", "pypi.org", "GET", "/simple/requests", True),
    ("pypi", "pypi.org", "GET", "/pypi/requests/json", True),
    ("pypi", "files.pythonhosted.org", "GET",
     "/packages/aa/bb/" + "c" * 60 + "/requests-2.31.0-py3-none-any.whl", True),
    # pypi — negatives
    ("pypi", "pypi.org", "GET", "/simple/Requests/", False),
    ("pypi", "pypi.org", "POST", "/simple/requests/", False),
    ("pypi", "pypi.org", "GET", "/search/?q=secret", False),

    # crates
    ("crates", "index.crates.io", "GET", "/config.json", True),
    ("crates", "index.crates.io", "GET", "/se/rd/serde", True),
    ("crates", "index.crates.io", "GET", "/3/a/axo", True),
    ("crates", "index.crates.io", "GET", "/1/a", True),
    ("crates", "crates.io", "GET", "/api/v1/crates/serde/1.0.190/download", True),
    ("crates", "static.crates.io", "GET", "/crates/serde/serde-1.0.190.crate", True),
    ("crates", "static.crates.io", "GET", "/crates/serde/1.0.190/download", True),
    # crates — negatives
    ("crates", "crates.io", "PUT", "/api/v1/crates/new", False),
    ("crates", "crates.io", "GET", "/api/v1/crates?q=secret", False),
    ("crates", "index.crates.io", "GET", "/se/rd/SERDE", False),
]


@pytest.mark.parametrize(
    "preset,host,method,path,expected",
    VECTORS,
    ids=[f"{p}-{m}-{path[:60]}" for p, _, m, path, _ in VECTORS],
)
def test_preset_vectors(preset, host, method, path, expected):
    verdict = check(preset, host, method, path)
    if expected:
        assert isinstance(verdict, Allowed), f"expected allow, got: {verdict}"
    else:
        assert isinstance(verdict, Violation), "expected violation, got allow"


# ── Engine behavior ────────────────────────────────────────────────────────────

def simple_rules(**spec_overrides):
    spec = {
        "rules": [
            {"methods": ["GET", "HEAD"], "path": "/repo/[a-z0-9-]{1,64}",
             "query": {"version": "[a-z0-9.]{1,32}"}},
        ],
    }
    spec.update(spec_overrides)
    return compile_host_rules(spec, source="test")


class TestEvaluate:
    def test_fullmatch_prefix_attack(self):
        # A pattern must match the whole path, not a prefix of it
        verdict = evaluate(simple_rules(), "GET", "/repo/foo/../../etc", {}, 0)
        assert isinstance(verdict, Violation)
        verdict = evaluate(simple_rules(), "GET", "/repo/foo/extra", {}, 0)
        assert isinstance(verdict, Violation)

    def test_query_allowed_param(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/foo?version=1.2.3", {}, 0)
        assert isinstance(verdict, Allowed)

    def test_query_unknown_param_rejected(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/foo?data=secret", {}, 0)
        assert isinstance(verdict, Violation)
        assert "data" in verdict.reason

    def test_query_bad_value_rejected(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/foo?version=UPPER", {}, 0)
        assert isinstance(verdict, Violation)

    def test_valueless_query_field_still_checked(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/foo?smuggled-data", {}, 0)
        assert isinstance(verdict, Violation)

    def test_body_rejected(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/foo", {}, 10)
        assert isinstance(verdict, Violation)
        assert "body" in verdict.reason

    def test_url_too_long(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/" + "a" * 5000, {}, 0)
        assert isinstance(verdict, Violation)

    def test_percent_encoded_traversal_rejected(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/%2e%2e", {}, 0)
        assert isinstance(verdict, Violation)

    def test_method_violation_reason(self):
        verdict = evaluate(simple_rules(), "POST", "/repo/foo", {}, 0)
        assert isinstance(verdict, Violation)
        assert "POST" in verdict.reason

    def test_wildcard_query_param_name_bounded(self):
        rules = compile_host_rules({
            "rules": [{"methods": ["GET"], "path": "/blob",
                       "query": {"*": "[a-z0-9]{0,64}"}}],
        }, source="test")
        assert isinstance(evaluate(rules, "GET", "/blob?sig=abc123", {}, 0), Allowed)
        long_name = "n" * 50
        verdict = evaluate(rules, "GET", f"/blob?{long_name}=x", {}, 0)
        assert isinstance(verdict, Violation)


class TestHeaderScrubbing:
    def test_unknown_header_dropped_base_kept(self):
        verdict = evaluate(
            simple_rules(), "GET", "/repo/foo",
            {"Accept": "*/*", "X-Exfil": "secret", "User-Agent": "curl"},
            0,
        )
        assert isinstance(verdict, Allowed)
        assert verdict.drop_headers == ("X-Exfil",)

    def test_authorization_dropped_unless_declared(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/foo",
                           {"Authorization": "Bearer x"}, 0)
        assert verdict.drop_headers == ("Authorization",)

        rules = simple_rules(request_headers=["authorization"])
        verdict = evaluate(rules, "GET", "/repo/foo", {"Authorization": "Bearer x"}, 0)
        assert verdict.drop_headers == ()

    def test_overlong_value_clamped(self):
        verdict = evaluate(simple_rules(), "GET", "/repo/foo",
                           {"User-Agent": "u" * 600}, 0)
        assert verdict.clamp_headers == (("User-Agent", 512),)

    def test_docker_registry_allows_authorization(self):
        rules = registries.PRESETS["docker"]["registry-1.docker.io"]
        verdict = evaluate(rules, "GET", "/v2/", {"Authorization": "Bearer tok"}, 0)
        assert isinstance(verdict, Allowed)
        assert verdict.drop_headers == ()


class TestCompileGuardrails:
    def test_unbounded_star_rejected(self):
        with pytest.raises(ValueError, match="Unbounded"):
            compile_host_rules({"rules": [{"methods": ["GET"], "path": "/x/.*"}]}, "test")

    def test_unbounded_plus_rejected(self):
        with pytest.raises(ValueError, match="Unbounded"):
            compile_host_rules({"rules": [{"methods": ["GET"], "path": "/x/[a-z]+"}]}, "test")

    def test_open_ended_repetition_rejected(self):
        with pytest.raises(ValueError, match="Unbounded"):
            compile_host_rules(
                {"rules": [{"methods": ["GET"], "path": "/x/[a-z]{3,}"}]}, "test")

    def test_bounded_class_with_plus_literal_ok(self):
        # '+' inside a character class is a literal, not a quantifier
        rules = compile_host_rules(
            {"rules": [{"methods": ["GET"], "path": "/x/[a-z+]{1,10}"}]}, "test")
        assert isinstance(evaluate(rules, "GET", "/x/a+b", {}, 0), Allowed)

    def test_percent_requires_flag(self):
        with pytest.raises(ValueError, match="allow_percent"):
            compile_host_rules({"rules": [{"methods": ["GET"], "path": "/a%2fb"}]}, "test")

    def test_unbounded_query_pattern_rejected(self):
        with pytest.raises(ValueError, match="Unbounded"):
            compile_host_rules({"rules": [
                {"methods": ["GET"], "path": "/x", "query": {"v": ".*"}},
            ]}, "test")

    def test_all_presets_compile_and_are_get_head_only(self):
        for name, hosts in registries.PRESETS.items():
            for host, host_rules in hosts.items():
                assert host_rules.source == name
                for rule in host_rules.rules:
                    assert rule.methods <= {"GET", "HEAD"}, (name, host)

    def test_allow_body_without_max_body_bytes_rejected(self):
        with pytest.raises(ValueError, match="max_body_bytes"):
            compile_host_rules({"rules": [
                {"methods": ["POST"], "path": "/write", "allow_body": True},
            ]}, "test")

    def test_allow_body_with_zero_max_body_bytes_rejected(self):
        # max_body_bytes must be positive, not just present
        with pytest.raises(ValueError, match="max_body_bytes"):
            compile_host_rules({"rules": [
                {"methods": ["POST"], "path": "/write",
                 "allow_body": True, "max_body_bytes": 0},
            ]}, "test")

    def test_max_body_bytes_without_allow_body_rejected(self):
        with pytest.raises(ValueError, match="allow_body"):
            compile_host_rules({"rules": [
                {"methods": ["POST"], "path": "/write", "max_body_bytes": 64},
            ]}, "test")


# ── Per-rule request bodies ──────────────────────────────────────────────────

def body_rules(**rule_overrides):
    rule = {
        "methods": ["POST"], "path": "/write",
        "allow_body": True, "max_body_bytes": 64,
        "content_types": ["application/json"],
    }
    rule.update(rule_overrides)
    return compile_host_rules({"rules": [rule]}, source="test")


class TestAllowBody:
    def test_bounded_body_accepted(self):
        verdict = evaluate(body_rules(), "POST", "/write", {}, 32, "application/json")
        assert isinstance(verdict, Allowed)

    def test_oversized_body_rejected(self):
        verdict = evaluate(body_rules(), "POST", "/write", {}, 65, "application/json")
        assert isinstance(verdict, Violation)
        assert "exceeds" in verdict.reason

    def test_wrong_content_type_rejected(self):
        verdict = evaluate(body_rules(), "POST", "/write", {}, 10, "text/plain")
        assert isinstance(verdict, Violation)
        assert "content-type" in verdict.reason

    def test_content_type_parameters_ignored(self):
        # only the base media type (before ';') is checked against content_types
        verdict = evaluate(body_rules(), "POST", "/write", {}, 10,
                            "application/json; charset=utf-8")
        assert isinstance(verdict, Allowed)

    def test_content_types_none_accepts_any(self):
        rules = body_rules(content_types=None)
        verdict = evaluate(rules, "POST", "/write", {}, 10, "anything/whatever")
        assert isinstance(verdict, Allowed)

    def test_rule_without_allow_body_still_rejects_any_body(self):
        # simple_rules() default: allow_body=False
        verdict = evaluate(simple_rules(), "GET", "/repo/foo", {}, 1)
        assert isinstance(verdict, Violation)
        assert "body" in verdict.reason


# ── Wildcard-repeat lint ───────────────────────────────────────────────────────

class TestWildcardRepeatLint:
    # Every spelling of "a bounded repeat whose body can match '/' without
    # saying so explicitly" — the grouping-construct bypasses that defeated
    # the old '.{' substring search, plus one nested a level deeper.
    BYPASS_PATTERNS = [
        ".{0,512}",
        "(?:.){0,512}",
        "(.){0,512}",
        "(a.){0,512}",
        "(?:(a.)){0,5}",       # nested one level deeper
        "((?:.)){0,5}",        # nested one level deeper, no literal
    ]

    @pytest.mark.parametrize("frag", BYPASS_PATTERNS)
    def test_bypass_spellings_rejected_in_path(self, frag):
        with pytest.raises(ValueError, match="cross-segment wildcard"):
            compile_host_rules({"rules": [
                {"methods": ["GET"], "path": "/x/" + frag},
            ]}, "test")

    @pytest.mark.parametrize("frag", BYPASS_PATTERNS)
    def test_bypass_spellings_rejected_in_query_value(self, frag):
        # Finding 2: query-value patterns previously only ran _assert_bounded,
        # never this lint, so all of these compiled unrejected before the fix.
        with pytest.raises(ValueError, match="cross-segment wildcard"):
            compile_host_rules({"rules": [
                {"methods": ["GET"], "path": "/x", "query": {"v": frag}},
            ]}, "test")

    def test_explicit_character_class_accepted(self):
        rules = compile_host_rules({"rules": [
            {"methods": ["GET"], "path": "/x/[A-Za-z0-9._/-]{0,512}"},
        ]}, "test")
        assert isinstance(evaluate(rules, "GET", "/x/foo/bar.txt", {}, 0), Allowed)

    def test_explicit_character_class_accepted_in_query_value(self):
        rules = compile_host_rules({"rules": [
            {"methods": ["GET"], "path": "/x",
             "query": {"v": "[A-Za-z0-9._-]{1,100}"}},
        ]}, "test")
        assert isinstance(evaluate(rules, "GET", "/x?v=abc.def", {}, 0), Allowed)

    def test_bounded_segment_class_accepted(self):
        # [A-Za-z0-9._-]{1,100} — a tightly-scoped single-segment class, no '/'.
        rules = compile_host_rules({"rules": [
            {"methods": ["GET"], "path": "/x/[A-Za-z0-9._-]{1,100}"},
        ]}, "test")
        assert isinstance(evaluate(rules, "GET", "/x/my-repo.git", {}, 0), Allowed)

    def test_escaped_dot_before_bounded_quantifier_not_flagged(self):
        # \.{1,2} quantifies the escaped (literal) dot itself — bounded
        # repetition of a specific character, not a stand-in for "any char".
        # (single dot, not two — ".." would separately trip the traversal check)
        rules = compile_host_rules({"rules": [
            {"methods": ["GET"], "path": r"/x/a\.{1,2}"},
        ]}, "test")
        assert isinstance(evaluate(rules, "GET", "/x/a.", {}, 0), Allowed)
        assert isinstance(evaluate(rules, "GET", "/x/aXX", {}, 0), Violation)

    def test_dot_inside_character_class_not_flagged(self):
        # [.]{1,4} is a character class containing only '.' — bounded and
        # specific, unlike a bare '.' which matches almost anything.
        # (single dot — ".." would separately trip the traversal check)
        rules = compile_host_rules({"rules": [
            {"methods": ["GET"], "path": "/x/[.]{1,4}"},
        ]}, "test")
        assert isinstance(evaluate(rules, "GET", "/x/.", {}, 0), Allowed)

    def test_negated_class_excluding_slash_accepted(self):
        # [^/]{0,64} can never match '/' — bounded to a single path segment,
        # so it's safe and useful (unlike a bare '.', which crosses segments).
        rules = compile_host_rules({"rules": [
            {"methods": ["GET"], "path": "/x/[^/]{0,64}"},
        ]}, "test")
        assert isinstance(evaluate(rules, "GET", "/x/one-segment", {}, 0), Allowed)
        assert isinstance(evaluate(rules, "GET", "/x/two/segments", {}, 0), Violation)

    def test_negated_class_not_excluding_slash_rejected(self):
        # [^x]{0,512} excludes only 'x' — '/' (and almost everything else)
        # still matches, so this is the same disguised wildcard as '.{0,512}'.
        with pytest.raises(ValueError, match="cross-segment wildcard"):
            compile_host_rules({"rules": [
                {"methods": ["GET"], "path": "/x/[^x]{0,512}"},
            ]}, "test")

    def test_all_presets_still_compile(self):
        # Import-time coverage is implicit (PRESETS is built at import), but
        # this documents the intent explicitly: the lint must not be so
        # strict that it breaks any curated preset.
        for name, hosts in registries.PRESETS.items():
            for host, host_rules in hosts.items():
                assert host_rules.rules, (name, host)


# ── literal_alternation ───────────────────────────────────────────────────────

class TestLiteralAlternation:
    def test_matches_items_literally(self):
        pattern = literal_alternation(("a.b", "c(d"))
        assert re.fullmatch(pattern, "a.b")
        assert re.fullmatch(pattern, "c(d")

    def test_unescaped_metacharacters_do_not_leak_through(self):
        # if '.' or '(' were left unescaped, "axb" or a bare "d" would match
        pattern = literal_alternation(("a.b", "c(d"))
        assert re.fullmatch(pattern, "axb") is None
        assert re.fullmatch(pattern, "d") is None

    def test_case_insensitive(self):
        # GitHub/GitLab resolve owner/repo case-insensitively
        pattern = literal_alternation(("MyOrg/MyRepo",))
        assert re.fullmatch(pattern, "MyOrg/MyRepo")
        assert re.fullmatch(pattern, "myorg/myrepo")
        assert re.fullmatch(pattern, "MYORG/MYREPO")
