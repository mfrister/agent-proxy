"""
Tests for the mitmproxy sandbox proxy addons (addon.py).

Run with:  pytest test_addon.py -v
"""

import json
import os
import signal
import time
from unittest.mock import MagicMock

import pytest

from config import Credential
from conftest import make_restricted, make_state


# ── Test helpers ───────────────────────────────────────────────────────────────

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
CRED = Credential(
    host="api.example.com",
    header="Authorization",
    fake_value="Bearer sk-fake",
    real_value="Bearer sk-real",
)


# ── Happy eyeballs ─────────────────────────────────────────────────────────────

class TestHappyEyeballs:
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
        addon = AllowlistAddon(make_state(hosts={"good.com": None}))
        flow = make_flow("good.com")
        addon.request(flow)
        assert flow.response is None

    def test_blocked_host_gets_503(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(hosts={}))
        flow = make_flow("evil.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 503
        assert b"pending human approval" in flow.response.content
        assert flow.response.headers.get("Retry-After") == "5"

    def test_blocked_host_logged(self):
        from addon import AllowlistAddon
        state = make_state(hosts={})
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
            hosts={},
            temp_allows={"temp.com": time.time() + 60},
        )
        addon = AllowlistAddon(state)
        flow = make_flow("temp.com")
        addon.request(flow)
        assert flow.response is None

    def test_temp_allow_expired_blocks(self):
        from addon import AllowlistAddon
        state = make_state(
            hosts={},
            temp_allows={"temp.com": time.time() - 1},
        )
        addon = AllowlistAddon(state)
        flow = make_flow("temp.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 503

    def test_multiple_denials_all_logged(self):
        from addon import AllowlistAddon
        state = make_state(hosts={})
        addon = AllowlistAddon(state)
        for host in ["a.com", "b.com", "c.com"]:
            addon.request(make_flow(host))
        assert len(state.deny_log) == 3

    def test_denial_entry_typed_pending_approval(self):
        from addon import AllowlistAddon
        state = make_state(hosts={})
        AllowlistAddon(state).request(make_flow("evil.com"))
        assert state.deny_log[0]["type"] == "pending_approval"


# ── Registry policy (restricted hosts) ─────────────────────────────────────────

class TestRegistryPolicy:
    def test_matching_request_passes(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(hosts=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo")
        addon.request(flow)
        assert flow.response is None
        assert flow.metadata["registry"] == "testpreset"

    def test_allowed_query_param_passes(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(hosts=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo?version=1.2.3")
        addon.request(flow)
        assert flow.response is None

    def test_violation_gets_503_with_retry_after(self, capsys):
        from addon import AllowlistAddon
        state = make_state(hosts=make_restricted())
        addon = AllowlistAddon(state)
        flow = make_flow("registry.example.com", method="POST", path="/pkg/foo")
        addon.request(flow)
        assert flow.response.status_code == 503
        assert b"not currently allowed by policy" in flow.response.content
        assert b"pending human approval" in flow.response.content
        assert flow.response.headers.get("Retry-After") == "5"
        entry = state.deny_log[0]
        assert entry["type"] == "policy_violation"
        assert "POST" in entry["reason"]
        event = json.loads(capsys.readouterr().out)
        assert event["event"] == "registry_policy_violation"
        assert event["policy"] == "testpreset"

    def test_violation_response_indistinguishable_from_pending_approval(self, capsys):
        # The client only ever sees the HTTP response, so a policy violation
        # and an unconfigured host must look identical to it (status +
        # Retry-After) -- only the deny-log `type` tells them apart.
        from addon import AllowlistAddon
        violation_state = make_state(hosts=make_restricted())
        violation_addon = AllowlistAddon(violation_state)
        violation_flow = make_flow("registry.example.com", method="POST", path="/pkg/foo")
        violation_addon.request(violation_flow)
        capsys.readouterr()  # drain the registry_policy_violation audit line

        pending_state = make_state(hosts={})
        pending_addon = AllowlistAddon(pending_state)
        pending_flow = make_flow("evil.com")
        pending_addon.request(pending_flow)

        assert violation_flow.response.status_code == pending_flow.response.status_code
        assert (violation_flow.response.headers.get("Retry-After")
                == pending_flow.response.headers.get("Retry-After"))
        assert violation_state.deny_log[0]["type"] == "policy_violation"
        assert pending_state.deny_log[0]["type"] == "pending_approval"

    def test_disallowed_query_param_blocked(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(hosts=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo?data=secret")
        addon.request(flow)
        assert flow.response.status_code == 503

    def test_body_on_get_blocked(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(hosts=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo", body=b"exfil")
        addon.request(flow)
        assert flow.response.status_code == 503

    def test_unrestricted_host_passes_without_temp_allow(self):
        # An unrestricted entry permits on its own: an expired temp allow
        # for the same host is irrelevant.
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(
            hosts={"registry.example.com": None},
            temp_allows={"registry.example.com": time.time() - 1},
        ))
        flow = make_flow("registry.example.com", method="POST", path="/anything")
        addon.request(flow)
        assert flow.response is None

    def test_temp_allow_beats_restricted(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(
            hosts=make_restricted(),
            temp_allows={"registry.example.com": time.time() + 60},
        ))
        flow = make_flow("registry.example.com", method="POST", path="/anything")
        addon.request(flow)
        assert flow.response is None

    def test_unlisted_host_still_gets_503(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(hosts=make_restricted()))
        flow = make_flow("other.com")
        addon.request(flow)
        assert flow.response.status_code == 503

    def test_headers_scrubbed_names_logged_values_not(self, capsys):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(hosts=make_restricted()))
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
        addon = AllowlistAddon(make_state(hosts=make_restricted()))
        flow = make_flow("registry.example.com", path="/pkg/foo",
                         headers={"User-Agent": "u" * 600})
        addon.request(flow)
        assert flow.response is None
        assert len(flow.request.headers["User-Agent"]) == 512

    def test_declared_header_survives(self):
        from addon import AllowlistAddon
        addon = AllowlistAddon(make_state(
            hosts=make_restricted(request_headers=["authorization"]),
        ))
        flow = make_flow("registry.example.com", path="/pkg/foo",
                         headers={"Authorization": "Bearer tok"})
        addon.request(flow)
        assert flow.request.headers["Authorization"] == "Bearer tok"


# ── Several entries on one host ────────────────────────────────────────────────

def _rules(path, source, **extra):
    import registries
    return registries.compile_host_rules(
        {"rules": [{"methods": ["GET"], "path": path}], **extra}, source=source,
    )


class TestMultiEntryMatching:
    def test_first_permitting_entry_wins_and_is_stamped(self):
        from addon import AllowlistAddon
        from config import HostEntry
        first = HostEntry(rules=_rules("/a", "first"))
        second = HostEntry(rules=_rules("/b", "second"))
        addon = AllowlistAddon(make_state(hosts={"h.com": [first, second]}))
        flow = make_flow("h.com", path="/b")
        addon.request(flow)
        assert flow.response is None
        assert flow.metadata["host_entry"] is second
        assert flow.metadata["registry"] == "second"

    def test_only_winning_entry_scrubs_headers(self):
        # The first entry would keep X-Keep, but it doesn't permit the
        # request, so the second entry's (stricter) header policy applies.
        from addon import AllowlistAddon
        from config import HostEntry
        lax = HostEntry(rules=_rules("/a", "lax", request_headers=["x-keep"]))
        strict = HostEntry(rules=_rules("/b", "strict"))
        addon = AllowlistAddon(make_state(hosts={"h.com": [lax, strict]}))
        flow = make_flow("h.com", path="/b", headers={"X-Keep": "v"})
        addon.request(flow)
        assert flow.response is None
        assert "X-Keep" not in flow.request.headers

    def test_unrestricted_entry_permits_beside_restricted(self):
        from addon import AllowlistAddon
        from config import HostEntry
        restricted = HostEntry(rules=_rules("/a", "scoped"))
        open_entry = HostEntry()
        addon = AllowlistAddon(make_state(hosts={"h.com": [restricted, open_entry]}))
        flow = make_flow("h.com", method="POST", path="/anything", headers={"X-Any": "v"})
        addon.request(flow)
        assert flow.response is None
        assert flow.metadata["host_entry"] is open_entry
        assert flow.request.headers["X-Any"] == "v"

    def test_denial_reports_first_rejecting_entry(self, capsys):
        from addon import AllowlistAddon
        from config import HostEntry
        state = make_state(hosts={"h.com": [
            HostEntry(rules=_rules("/a", "first")),
            HostEntry(rules=_rules("/b", "second")),
        ]})
        flow = make_flow("h.com", method="POST", path="/a")
        AllowlistAddon(state).request(flow)
        assert flow.response.status_code == 503
        assert b"policy 'first'" in flow.response.content
        assert "POST" in state.deny_log[0]["reason"]
        assert json.loads(capsys.readouterr().out)["policy"] == "first"

    def test_temp_allow_is_an_appended_entry_keeping_cookie_policy(self):
        from addon import AllowlistAddon
        from config import HostConfig, HostEntry
        scoped = HostEntry(rules=_rules("/a", "scoped"),
                           host_config=HostConfig(allow_response_cookies=[]))
        addon = AllowlistAddon(make_state(
            hosts={"h.com": [scoped]},
            temp_allows={"h.com": time.time() + 60},
        ))
        in_scope = make_flow("h.com", path="/a")
        addon.request(in_scope)
        assert in_scope.metadata["host_entry"] is scoped

        out_of_scope = make_flow("h.com", method="POST", path="/x")
        addon.request(out_of_scope)
        assert out_of_scope.response is None
        temp = out_of_scope.metadata["host_entry"]
        assert temp.rules is None
        assert temp.host_config.allow_response_cookies == []


# ── CredentialBrokerAddon ──────────────────────────────────────────────────────

def make_broker(*entries, host="api.example.com"):
    """A CredentialBrokerAddon whose state has `entries` for `host`."""
    from addon import CredentialBrokerAddon
    return CredentialBrokerAddon(make_state(hosts={host: list(entries)}))


def matched_flow(entry, host="api.example.com", **kwargs):
    """A flow as AllowlistAddon leaves it after `entry` permitted it."""
    flow = make_flow(host, **kwargs)
    flow.metadata["host_entry"] = entry
    return flow


class TestCredentialBrokerAddon:
    def test_fake_swapped_for_real(self, capsys):
        from config import HostEntry
        entry = HostEntry(credential=CRED)
        flow = matched_flow(entry, headers={"Authorization": "Bearer sk-fake"})
        make_broker(entry).request(flow)
        assert flow.request.headers["Authorization"] == "Bearer sk-real"
        assert flow.response is None
        entry = json.loads(capsys.readouterr().out)
        assert entry["event"] == "credential_injected"
        assert entry["mode"] == "swap"
        assert entry["header"] == "Authorization"
        assert entry["host"] == "api.example.com"

    def test_no_header_passes_through(self, capsys):
        from config import HostEntry
        entry = HostEntry(credential=CRED)
        flow = matched_flow(entry, headers={})
        make_broker(entry).request(flow)
        assert flow.response is None
        assert capsys.readouterr().out == ""

    def test_unexpected_value_blocks(self):
        from config import HostEntry
        entry = HostEntry(credential=CRED)
        flow = matched_flow(entry, headers={"Authorization": "Bearer injected"})
        make_broker(entry).request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_non_matching_host_unchanged(self):
        from config import HostEntry
        broker = make_broker(HostEntry(credential=CRED))
        flow = matched_flow(HostEntry(), host="other.com",
                            headers={"Authorization": "Bearer anything"})
        broker.request(flow)
        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer anything"

    def test_real_value_not_in_log(self, capsys):
        from config import HostEntry
        entry = HostEntry(credential=CRED)
        flow = matched_flow(entry, headers={"Authorization": "Bearer injected"})
        make_broker(entry).request(flow)
        captured = capsys.readouterr().out
        assert "sk-real" not in captured

    def test_skips_already_denied_flow(self):
        from config import HostEntry
        from mitmproxy import http
        entry = HostEntry(credential=CRED)
        flow = matched_flow(entry, headers={"Authorization": "Bearer injected"})
        # Simulate AllowlistAddon already set a 503
        flow.response = http.Response.make(503, "pending human approval")
        make_broker(entry).request(flow)
        # Should not overwrite the existing response
        assert flow.response.status_code == 503
        assert b"pending human approval" in flow.response.content

    def test_inject_mode_sets_header_when_absent(self, capsys):
        from config import HostEntry
        entry = HostEntry(credential=Credential(
            host="api.example.com", header="Cookie", real_value="session=abc123"))
        flow = matched_flow(entry, headers={})
        make_broker(entry).request(flow)
        assert flow.request.headers["Cookie"] == "session=abc123"
        assert flow.response is None
        entry = json.loads(capsys.readouterr().out)
        assert entry["event"] == "credential_injected"
        assert entry["mode"] == "inject"

    def test_inject_mode_overwrites_existing_header(self, capsys):
        from config import HostEntry
        entry = HostEntry(credential=Credential(
            host="api.example.com", header="Cookie", real_value="session=abc123"))
        flow = matched_flow(entry, headers={"Cookie": "old=value"})
        make_broker(entry).request(flow)
        assert flow.request.headers["Cookie"] == "session=abc123"
        assert flow.response is None
        entry = json.loads(capsys.readouterr().out)
        assert entry["event"] == "credential_injected"
        assert entry["mode"] == "inject"

    def test_inject_mode_does_not_affect_other_hosts(self):
        from config import HostEntry
        broker = make_broker(HostEntry(credential=Credential(
            host="api.example.com", header="Cookie", real_value="session=abc123")))
        flow = matched_flow(HostEntry(), host="other.com", headers={})
        broker.request(flow)
        assert "Cookie" not in flow.request.headers
        assert flow.response is None

    def test_sibling_entry_credential_withheld_and_stripped(self, capsys):
        # The request was permitted by an entry without a credential: the
        # sibling's credential isn't brokered, and its header is stripped
        # rather than forwarding the client's fake token.
        from config import HostEntry
        credentialed, plain = HostEntry(credential=CRED), HostEntry()
        flow = matched_flow(plain, headers={"Authorization": "Bearer sk-fake"})
        make_broker(credentialed, plain).request(flow)
        assert flow.response is None
        assert "Authorization" not in flow.request.headers
        out = capsys.readouterr().out
        event = json.loads(out)
        assert event["event"] == "credential_withheld"
        assert event["headers"] == ["Authorization"]
        assert "sk-fake" not in out and "sk-real" not in out

    def test_matched_credential_header_not_stripped_by_sibling(self):
        # Two credentialed entries sharing a header: the matched one's
        # header is brokered, not withheld on account of the sibling.
        from config import HostEntry
        other = HostEntry(credential=Credential(
            host="api.example.com", header="authorization",
            fake_value="Bearer other-fake", real_value="Bearer other-real"))
        entry = HostEntry(credential=CRED)
        flow = matched_flow(entry, headers={"Authorization": "Bearer sk-fake"})
        make_broker(other, entry).request(flow)
        assert flow.request.headers["Authorization"] == "Bearer sk-real"


# ── Allowlist + broker together: credentials bound to entries ─────────────────

def run_pipeline(state, flow):
    from addon import AllowlistAddon, CredentialBrokerAddon
    AllowlistAddon(state).request(flow)
    CredentialBrokerAddon(state).request(flow)
    return flow


GH_FAKE = "token ghp_fake"
GH_REAL = "token ghp_real"


def scoped_github_config(**extra):
    from config import Config
    return Config.from_data({
        "services": [{
            "service": "github", "scope": {"repos": ["myorg/myrepo"]},
            "fake_value": "ghp_fake", "real_value": "ghp_real",
        }],
        **extra,
    })


def state_from(cfg, **overrides):
    from config import ProxyState
    state = ProxyState(config_path="config.yaml", **overrides)
    state.apply(cfg)
    return state


class TestEntryBoundCredentials:
    IN_SCOPE = "/repos/myorg/myrepo/issues"
    OUT_OF_SCOPE = "/repos/otherorg/secret/issues"

    def test_credentialed_entry_listed_second_still_brokers_in_scope(self):
        # Ordering footgun: an earlier unauthenticated entry that also permits
        # the in-scope path must not shadow the credentialed one when the
        # client presents the fake token.
        from config import Config
        cfg = Config.from_data({"hosts": [
            {"host": "api.example.com", "rules": [
                {"methods": ["GET"], "path": "/repos/[a-z/]{1,64}"},
            ]},
            {"host": "api.example.com", "rules": [
                {"methods": ["GET", "POST"], "path": "/repos/myorg/myrepo/[a-z]{1,32}"},
            ], "credential": {"header": "Authorization",
                              "fake_value": GH_FAKE, "real_value": GH_REAL}},
        ]})
        state = state_from(cfg)

        in_scope = run_pipeline(state, make_flow(
            "api.example.com", path="/repos/myorg/myrepo/issues",
            headers={"Authorization": GH_FAKE}))
        assert in_scope.response is None
        assert in_scope.request.headers["Authorization"] == GH_REAL

        out_of_scope = run_pipeline(state, make_flow(
            "api.example.com", path="/repos/otherorg/public",
            headers={"Authorization": GH_FAKE}))
        assert out_of_scope.response is None
        assert "Authorization" not in out_of_scope.request.headers

    def test_credentialed_entry_scope_still_enforced_when_presented(self):
        # Presenting the fake only reorders; a request neither entry permits
        # is still denied, with the credentialed entry's reason.
        from config import Config
        cfg = Config.from_data({"hosts": [
            {"host": "api.example.com", "rules": [{"methods": ["GET"], "path": "/public"}]},
            {"host": "api.example.com", "rules": [{"methods": ["GET"], "path": "/private"}],
             "credential": {"header": "Authorization",
                            "fake_value": GH_FAKE, "real_value": GH_REAL}},
        ]})
        state = state_from(cfg)
        flow = run_pipeline(state, make_flow(
            "api.example.com", method="POST", path="/private",
            headers={"Authorization": GH_FAKE}))
        assert flow.response.status_code == 503
        assert "POST" in state.deny_log[0]["reason"]

    def _assert_out_of_scope_withheld(self, state):
        in_scope = run_pipeline(state, make_flow(
            "api.github.com", path=self.IN_SCOPE, headers={"Authorization": GH_FAKE}))
        assert in_scope.response is None
        assert in_scope.request.headers["Authorization"] == GH_REAL

        out_of_scope = run_pipeline(state, make_flow(
            "api.github.com", path=self.OUT_OF_SCOPE, headers={"Authorization": GH_FAKE}))
        assert out_of_scope.response is None  # allowlisted some other way
        assert "Authorization" not in out_of_scope.request.headers

    def test_unrestricted_hosts_entry_does_not_leak_scoped_credential(self):
        self._assert_out_of_scope_withheld(state_from(
            scoped_github_config(hosts=["api.github.com"])))

    def test_temp_allow_does_not_leak_scoped_credential(self):
        self._assert_out_of_scope_withheld(state_from(
            scoped_github_config(),
            temp_allows={"api.github.com": time.time() + 60},
        ))

    def test_out_of_scope_without_other_route_denied(self):
        state = state_from(scoped_github_config())
        flow = run_pipeline(state, make_flow(
            "api.github.com", path=self.OUT_OF_SCOPE, headers={"Authorization": GH_FAKE}))
        assert flow.response.status_code == 503
        assert flow.request.headers["Authorization"] == GH_FAKE  # never forwarded


def dormant_github_config(**extra):
    from config import Config
    return Config.from_data({
        "services": [{
            "service": "github", "enabled": False, "scope": {"repos": ["myorg/myrepo"]},
            "fake_value": "ghp_fake", "real_value": "ghp_real",
        }],
        **extra,
    })


class TestTemporarilyEnabledServices:
    IN_SCOPE = "/repos/myorg/myrepo/issues"
    OUT_OF_SCOPE = "/repos/otherorg/secret/issues"

    def test_disabled_service_denies(self):
        state = state_from(dormant_github_config())
        flow = run_pipeline(state, make_flow(
            "api.github.com", path=self.IN_SCOPE, headers={"Authorization": GH_FAKE}))
        assert flow.response.status_code == 503
        assert flow.request.headers["Authorization"] == GH_FAKE

    def test_temp_enabled_service_permits_and_brokers(self):
        state = state_from(dormant_github_config(),
                           temp_services={("github", None): time.time() + 60})
        flow = run_pipeline(state, make_flow(
            "api.github.com", path=self.IN_SCOPE, headers={"Authorization": GH_FAKE}))
        assert flow.response is None
        assert flow.request.headers["Authorization"] == GH_REAL
        assert flow.metadata["registry"] == "github"

    def test_temp_enabled_service_keeps_its_scope(self):
        state = state_from(dormant_github_config(),
                           temp_services={("github", None): time.time() + 60})
        flow = run_pipeline(state, make_flow(
            "api.github.com", path=self.OUT_OF_SCOPE, headers={"Authorization": GH_FAKE}))
        assert flow.response.status_code == 503

    def test_expired_temp_enable_denies(self):
        state = state_from(dormant_github_config(),
                           temp_services={("github", None): time.time() - 1})
        flow = run_pipeline(state, make_flow(
            "api.github.com", path=self.IN_SCOPE, headers={"Authorization": GH_FAKE}))
        assert flow.response.status_code == 503

    def test_temp_enabled_credential_withheld_when_sibling_wins(self):
        state = state_from(dormant_github_config(hosts=["api.github.com"]),
                           temp_services={("github", None): time.time() + 60})
        flow = run_pipeline(state, make_flow(
            "api.github.com", path=self.OUT_OF_SCOPE, headers={"Authorization": GH_FAKE}))
        assert flow.response is None
        assert "Authorization" not in flow.request.headers

    def test_dormant_credential_not_withheld_while_disabled(self):
        # A disabled service takes no part in matching: the fake token is
        # just client input to the hand-written unrestricted entry.
        state = state_from(dormant_github_config(hosts=["api.github.com"]))
        flow = run_pipeline(state, make_flow(
            "api.github.com", path=self.IN_SCOPE, headers={"Authorization": GH_FAKE}))
        assert flow.response is None
        assert flow.request.headers["Authorization"] == GH_FAKE


class TestDenialNamesDisabledServices:
    IN_SCOPE = "/repos/myorg/myrepo/issues"
    OUT_OF_SCOPE = "/repos/otherorg/secret/issues"

    def _deny(self, state, path):
        flow = run_pipeline(state, make_flow(
            "api.github.com", path=path, headers={"Authorization": GH_FAKE}))
        assert flow.response.status_code == 503
        return state.deny_log[-1]

    def test_pending_denial_names_permitting_disabled_service(self):
        entry = self._deny(state_from(dormant_github_config()), self.IN_SCOPE)
        assert entry["type"] == "pending_approval"
        assert entry["disabled_services"] == [{"service": "github"}]

    def test_violation_denial_names_permitting_disabled_service(self):
        from config import Config
        cfg = Config.from_data({
            "services": [{"service": "github", "enabled": False,
                          "unrestricted": True,
                          "fake_value": "ghp_fake", "real_value": "ghp_real"}],
            "hosts": [{"host": "api.github.com",
                       "rules": [{"methods": ["GET"], "path": "/public"}]}],
        })
        entry = self._deny(state_from(cfg), self.OUT_OF_SCOPE)
        assert entry["type"] == "policy_violation"
        assert entry["disabled_services"] == [{"service": "github"}]

    def test_disabled_service_out_of_its_scope_not_named(self):
        entry = self._deny(state_from(dormant_github_config()), self.OUT_OF_SCOPE)
        assert "disabled_services" not in entry

    def test_temp_enabled_service_not_named(self):
        # Already enabled for now -- the denial is its own scope's, not a
        # missing enable.
        state = state_from(dormant_github_config(),
                           temp_services={("github", None): time.time() + 60})
        entry = self._deny(state, self.OUT_OF_SCOPE)
        assert "disabled_services" not in entry

    def test_expired_temp_enable_named_again(self):
        state = state_from(dormant_github_config(),
                           temp_services={("github", None): time.time() - 1})
        entry = self._deny(state, self.IN_SCOPE)
        assert entry["disabled_services"] == [{"service": "github"}]

    def test_self_hosted_service_named_with_host(self):
        from config import Config
        cfg = Config.from_data({"services": [{
            "service": "gitlab", "host": "gl.example.com", "enabled": False,
            "unrestricted": True,
            "fake_value": "glpat-fake", "real_value": "glpat-real",
        }]})
        state = state_from(cfg)
        run_pipeline(state, make_flow("gl.example.com", path="/api/v4/projects"))
        assert state.deny_log[-1]["disabled_services"] == [
            {"service": "gitlab", "host": "gl.example.com"},
        ]

    def test_unrelated_denial_has_no_field(self):
        state = state_from(dormant_github_config())
        run_pipeline(state, make_flow("evil.com"))
        assert "disabled_services" not in state.deny_log[-1]


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
        from addon import setup_sighup

        config = tmp_path / "config.yaml"
        config.write_text("hosts:\n  - host: original.com\n")

        state = make_state(
            hosts={"original.com": None},
            config_path=str(config),
        )
        setup_sighup(state)

        config.write_text("hosts:\n  - host: original.com\n  - host: new.com\n")
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.05)

        assert "new.com" in state.hosts and state.hosts["new.com"][0].rules is None
        assert "original.com" in state.hosts and state.hosts["original.com"][0].rules is None

    def test_sighup_reloads_credentials(self, tmp_path):
        from addon import setup_sighup

        config = tmp_path / "config.yaml"
        yaml_template = (
            "hosts:\n"
            "  - host: api.example.com\n"
            "    credential:\n"
            "      header: Authorization\n"
            "      real_value: {}\n"
        )
        config.write_text(yaml_template.format("old-value"))

        state = make_state(config_path=str(config))
        state.reload()
        assert state.credentials[0].real_value == "old-value"
        setup_sighup(state)

        config.write_text(yaml_template.format("new-value"))
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.05)

        assert state.credentials[0].real_value == "new-value"
        assert state.hosts["api.example.com"][0].credential.real_value == "new-value"

    def test_sighup_reloads_restricted(self, tmp_path):
        from addon import setup_sighup

        config = tmp_path / "config.yaml"
        config.write_text("hosts: []\n")

        state = make_state(hosts={}, config_path=str(config))
        setup_sighup(state)
        assert state.hosts == {}

        config.write_text("services: [go]\n")
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.05)

        assert state.hosts["proxy.golang.org"][0].rules is not None


# ── Cookie allowlist (response side) ──────────────────────────────────────────

def make_response_flow(host, set_cookie_headers=None, host_config=None):
    """Return a mock HTTPFlow with response Set-Cookie headers.

    host_config, if given, is the HostConfig of the entry AllowlistAddon
    matched; None means no entry was stamped on the flow.
    """
    from unittest.mock import MagicMock
    from config import HostEntry
    flow = MagicMock()
    flow.request.pretty_host = host
    flow.metadata = {} if host_config is None else {"host_entry": HostEntry(host_config=host_config)}
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
        from addon import ResponseCookieFilterAddon
        addon = ResponseCookieFilterAddon(make_state())
        flow = make_response_flow("other.com", ["session=abc", "tracker=xyz"])
        addon.response(flow)
        assert flow.response._stored == ["session=abc", "tracker=xyz"]

    def test_host_config_none_restriction_passes_all(self):
        from addon import ResponseCookieFilterAddon
        from config import HostConfig
        addon = ResponseCookieFilterAddon(make_state())
        flow = make_response_flow("example.com", ["session=abc", "tracker=xyz"],
                                  host_config=HostConfig(allow_response_cookies=None))
        addon.response(flow)
        assert flow.response._stored == ["session=abc", "tracker=xyz"]

    def test_empty_allowlist_strips_all_cookies(self):
        from addon import ResponseCookieFilterAddon
        from config import HostConfig
        addon = ResponseCookieFilterAddon(make_state())
        flow = make_response_flow("example.com", ["session=abc", "tracker=xyz"],
                                  host_config=HostConfig(allow_response_cookies=[]))
        addon.response(flow)
        assert flow.response._stored == []

    def test_allowlist_keeps_only_named_cookie(self):
        from addon import ResponseCookieFilterAddon
        from config import HostConfig
        addon = ResponseCookieFilterAddon(make_state())
        flow = make_response_flow("example.com", ["csrftoken=abc123", "session=xyz"],
                                  host_config=HostConfig(allow_response_cookies=["csrftoken"]))
        addon.response(flow)
        assert flow.response._stored == ["csrftoken=abc123"]

    def test_multiple_set_cookie_headers_filtered(self):
        from addon import ResponseCookieFilterAddon
        from config import HostConfig
        addon = ResponseCookieFilterAddon(make_state())
        flow = make_response_flow("example.com", ["csrftoken=abc", "session=xyz", "lang=en", "tracker=1"],
                                  host_config=HostConfig(allow_response_cookies=["csrftoken", "lang"]))
        addon.response(flow)
        assert set(flow.response._stored) == {"csrftoken=abc", "lang=en"}
