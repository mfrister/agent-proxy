"""
Tests for numeric GitLab project ID resolution (gitlab_resolver.py).

Run with:  pytest test_gitlab_resolver.py -v
"""

import asyncio
import json

import httpx
import pytest

from config import Credential
import gitlab_resolver
from gitlab_resolver import FOUND_TTL, NOT_FOUND_TTL, GitLabProjectResolver

CRED = Credential(host="gitlab.example.com", header="PRIVATE-TOKEN",
                  real_value="glpat-real", fake_value="glpat-fake")


class FakeGitLab:
    """Fetch stand-in: project id -> (status, body), recording each call."""

    def __init__(self, projects=None):
        self.projects = projects or {}
        self.calls = []

    async def __call__(self, project_id, credential):
        self.calls.append((project_id, credential))
        await asyncio.sleep(0)
        result = self.projects.get(project_id, (404, None))
        if isinstance(result, Exception):
            raise result
        return result


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def found(path):
    return 200, {"id": 1, "path_with_namespace": path}


def make(projects=None):
    gitlab, clock = FakeGitLab(projects), Clock()
    return GitLabProjectResolver("gitlab.example.com", fetch=gitlab, clock=clock), gitlab, clock


def resolve(resolver, path, credential=CRED):
    return asyncio.run(resolver.resolve(path, credential))


class TestResolve:
    @pytest.mark.parametrize("path,expected", [
        ("/api/v4/projects/1901", "/api/v4/projects/team%2Fbackend"),
        ("/api/v4/projects/1901/merge_requests/7/pipelines?page=2",
         "/api/v4/projects/team%2Fbackend/merge_requests/7/pipelines?page=2"),
        ("/api/v4/projects/1901?license=true", "/api/v4/projects/team%2Fbackend?license=true"),
    ])
    def test_numeric_id_replaced_by_encoded_path(self, path, expected):
        resolver, gitlab, _ = make({"1901": found("team/backend")})
        assert resolve(resolver, path) == expected
        assert gitlab.calls == [("1901", CRED)]

    @pytest.mark.parametrize("path", [
        "/api/v4/projects/team%2Fbackend/issues",
        "/api/v4/projects/1901abc",
        "/api/v4/projects/12345678901",               # over 10 digits
        "/api/v4/user",
        "/api/v4/projects",
    ])
    def test_other_paths_untouched_without_lookup(self, path):
        resolver, gitlab, _ = make({"1901": found("team/backend")})
        assert resolve(resolver, path) is None
        assert gitlab.calls == []

    def test_unusual_characters_stay_encoded(self):
        resolver, _, _ = make({"1": found("team/a b?c")})
        assert resolve(resolver, "/api/v4/projects/1") == "/api/v4/projects/team%2Fa%20b%3Fc"

    def test_lookup_logged_without_token(self, capsys):
        resolver, _, _ = make({"1901": found("team/backend")})
        resolve(resolver, "/api/v4/projects/1901")
        out = capsys.readouterr().out
        assert json.loads(out) == {"event": "gitlab_project_resolved",
                                   "host": "gitlab.example.com",
                                   "project_id": "1901", "path": "team/backend"}
        assert "glpat-real" not in out


class TestCache:
    def test_found_cached_until_ttl(self):
        resolver, gitlab, clock = make({"1901": found("team/backend")})
        resolve(resolver, "/api/v4/projects/1901")
        clock.now += FOUND_TTL - 1
        resolve(resolver, "/api/v4/projects/1901/issues")
        assert len(gitlab.calls) == 1

    def test_moved_project_rechecked_after_ttl(self):
        resolver, gitlab, clock = make({"1901": found("team/backend")})
        resolve(resolver, "/api/v4/projects/1901")
        gitlab.projects["1901"] = found("elsewhere/backend")
        clock.now += FOUND_TTL
        assert resolve(resolver, "/api/v4/projects/1901") == "/api/v4/projects/elsewhere%2Fbackend"

    @pytest.mark.parametrize("status", [403, 404])
    def test_not_found_cached_briefly(self, status):
        resolver, gitlab, clock = make({"1": (status, None)})
        assert resolve(resolver, "/api/v4/projects/1") is None
        resolve(resolver, "/api/v4/projects/1")
        assert len(gitlab.calls) == 1
        clock.now += NOT_FOUND_TTL
        resolve(resolver, "/api/v4/projects/1")
        assert len(gitlab.calls) == 2

    @pytest.mark.parametrize("result", [
        httpx.ConnectTimeout("timeout"),
        ValueError("bad json"),
        (500, None),
        (200, {"unexpected": True}),
    ])
    def test_errors_not_cached(self, result):
        resolver, gitlab, _ = make({"1": result})
        assert resolve(resolver, "/api/v4/projects/1") is None
        resolve(resolver, "/api/v4/projects/1")
        assert len(gitlab.calls) == 2

    def test_concurrent_requests_share_one_lookup(self):
        resolver, gitlab, _ = make({"1901": found("team/backend")})

        async def both():
            return await asyncio.gather(
                resolver.resolve("/api/v4/projects/1901/issues", CRED),
                resolver.resolve("/api/v4/projects/1901/merge_requests", CRED),
            )

        assert asyncio.run(both()) == ["/api/v4/projects/team%2Fbackend/issues",
                                       "/api/v4/projects/team%2Fbackend/merge_requests"]
        assert len(gitlab.calls) == 1


    def test_cache_bounded(self, monkeypatch):
        monkeypatch.setattr(gitlab_resolver, "MAX_CACHE", 3)
        resolver, gitlab, clock = make({str(i): found(f"team/p{i}") for i in range(5)})
        resolve(resolver, "/api/v4/projects/0")
        clock.now += FOUND_TTL                      # 0 has expired
        for i in range(1, 5):
            resolve(resolver, f"/api/v4/projects/{i}")
        assert list(resolver._cache) == ["2", "3", "4"]


class TestHttpFetch:
    def _resolver(self, handler):
        return GitLabProjectResolver("gitlab.example.com",
                                     transport=httpx.MockTransport(handler))

    def test_request_shape(self):
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"path_with_namespace": "team/backend"})

        assert resolve(self._resolver(handler), "/api/v4/projects/1901/issues") == \
            "/api/v4/projects/team%2Fbackend/issues"
        [request] = seen
        assert request.method == "GET"
        assert str(request.url) == "https://gitlab.example.com/api/v4/projects/1901"
        assert request.headers["PRIVATE-TOKEN"] == "glpat-real"

    def test_without_credential_sends_no_token(self):
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(404)

        assert resolve(self._resolver(handler), "/api/v4/projects/1", credential=None) is None
        assert "PRIVATE-TOKEN" not in seen[0].headers

    def test_redirect_not_followed(self):
        def handler(request):
            return httpx.Response(302, headers={"Location": "https://evil.example/"})

        assert resolve(self._resolver(handler), "/api/v4/projects/1") is None

    def test_transport_error_denies(self):
        def handler(request):
            raise httpx.ConnectError("refused")

        assert resolve(self._resolver(handler), "/api/v4/projects/1") is None


class TestThroughConfig:
    """The gitlab preset's resolver, driven by the real addons."""

    def _state(self, scope):
        from config import Config, ProxyState
        cfg = Config.from_data({"services": [{
            "service": "gitlab", "host": "gitlab.example.com", "scope": scope,
            "fake_value": "glpat-fake", "real_value": "glpat-real",
        }]})
        state = ProxyState(config_path="config.yaml")
        state.apply(cfg)
        return state

    def _run(self, state, path, projects):
        from addon import AllowlistAddon, CredentialBrokerAddon, PathResolverAddon
        from test_addon import make_flow
        gitlab = FakeGitLab(projects)
        for entry in state.hosts["gitlab.example.com"]:
            entry.rules.path_resolver._fetch = gitlab
        flow = make_flow("gitlab.example.com", path=path, scheme="https", port=443,
                         headers={"PRIVATE-TOKEN": "glpat-fake"})
        asyncio.run(PathResolverAddon(state).request(flow))
        AllowlistAddon(state).request(flow)
        CredentialBrokerAddon(state).request(flow)
        return flow, gitlab

    def test_group_scope_allows_numeric_id(self):
        state = self._state({"groups": ["cloud/load-balancer"]})
        flow, gitlab = self._run(state, "/api/v4/projects/1901/issues/3",
                                 {"1901": found("cloud/load-balancer/lb-service")})
        assert flow.response is None
        assert flow.request.path == "/api/v4/projects/1901/issues/3"
        assert flow.request.headers["PRIVATE-TOKEN"] == "glpat-real"
        assert gitlab.calls[0][1].real_value == "glpat-real"

    @pytest.mark.parametrize("projects", [
        {"1901": found("other/lb-service")},
        {},                                         # 404
    ])
    def test_out_of_scope_or_unknown_id_denied(self, projects):
        state = self._state({"groups": ["cloud/load-balancer"]})
        flow, _ = self._run(state, "/api/v4/projects/1901/issues/3", projects)
        assert flow.response.status_code == 503
