"""
Tests for the management API (management_api.py).

Run with:  pytest test_management_api.py -v
"""

import time

import pytest
import yaml

from conftest import make_restricted, make_state


@pytest.fixture
def mgmt(tmp_path):
    """Flask test client wired to a fresh ProxyState with a temp config file."""
    from management_api import create_app

    config = tmp_path / "config.yaml"
    config.write_text("allowed_hosts:\n  - host: existing.com\n")

    state = make_state(
        allowlist={"existing.com"},
        config_path=str(config),
    )
    app = create_app(state)
    app.config["TESTING"] = True
    with app.test_client() as client:
        client._state = state
        yield client


class TestManagementAPI:
    def test_get_denied_empty(self, mgmt):
        r = mgmt.get("/denied")
        assert r.status_code == 200
        assert r.get_json() == []

    def test_get_denied_with_entries(self, mgmt):
        state = mgmt._state
        with state.deny_lock:
            state.deny_log.append({
                "timestamp": "2024-01-01T00:00:00+00:00",
                "host": "evil.com",
                "url": "http://evil.com/",
                "method": "GET",
            })
        data = mgmt.get("/denied").get_json()
        assert len(data) == 1
        assert data[0]["host"] == "evil.com"

    def test_get_allowlist_permanent(self, mgmt):
        data = mgmt.get("/allowlist").get_json()
        assert "existing.com" in data["permanent"]
        assert data["temporary"] == {}
        assert data["restricted"] == {}

    def test_get_allowlist_restricted_grouped_by_source(self, mgmt):
        mgmt._state.restricted = make_restricted()
        data = mgmt.get("/allowlist").get_json()
        assert data["restricted"] == {"testpreset": ["registry.example.com"]}

    def test_get_allowlist_active_temp_included(self, mgmt):
        state = mgmt._state
        with state.temp_lock:
            state.temp_allows["live.com"] = time.time() + 60
            state.temp_allows["dead.com"] = time.time() - 1  # expired
        data = mgmt.get("/allowlist").get_json()
        assert "live.com" in data["temporary"]
        assert "dead.com" not in data["temporary"]

    def test_post_allow_temp(self, mgmt):
        r = mgmt.post("/allow/temp", json={"host": "temp.com", "duration_seconds": 60})
        assert r.get_json()["ok"] is True
        state = mgmt._state
        with state.temp_lock:
            assert "temp.com" in state.temp_allows
            assert state.temp_allows["temp.com"] > time.time()

    def test_post_allow_permanent_updates_state(self, mgmt):
        r = mgmt.post("/allow/permanent", json={"host": "new.com"})
        assert r.get_json()["ok"] is True
        assert "new.com" in mgmt._state.allowlist

    def test_post_allow_permanent_clears_temp_entry(self, mgmt):
        state = mgmt._state
        with state.temp_lock:
            state.temp_allows["new.com"] = time.time() + 60
        r = mgmt.post("/allow/permanent", json={"host": "new.com"})
        assert r.get_json()["ok"] is True
        assert "new.com" in state.allowlist
        with state.temp_lock:
            assert "new.com" not in state.temp_allows

    def test_post_allow_permanent_clears_temp_when_already_permanent(self, mgmt):
        state = mgmt._state
        with state.temp_lock:
            state.temp_allows["existing.com"] = time.time() + 60
        r = mgmt.post("/allow/permanent", json={"host": "existing.com"})
        assert r.get_json()["ok"] is True
        with state.temp_lock:
            assert "existing.com" not in state.temp_allows

    def test_post_allow_permanent_writes_file(self, mgmt, tmp_path):
        mgmt.post("/allow/permanent", json={"host": "written.com"})
        config_path = mgmt._state.config_path
        with open(config_path) as f:
            data = yaml.safe_load(f)
        host_names = [
            h if isinstance(h, str) else h["host"]
            for h in data["allowed_hosts"]
        ]
        assert "written.com" in host_names

    def test_post_allow_permanent_idempotent(self, mgmt):
        mgmt.post("/allow/permanent", json={"host": "existing.com"})
        mgmt.post("/allow/permanent", json={"host": "existing.com"})
        with open(mgmt._state.config_path) as f:
            data = yaml.safe_load(f)
        host_names = [
            h if isinstance(h, str) else h["host"]
            for h in data["allowed_hosts"]
        ]
        assert host_names.count("existing.com") == 1

    def test_post_allow_permanent_writes_dict_format(self, mgmt):
        mgmt.post("/allow/permanent", json={"host": "newdict.com"})
        with open(mgmt._state.config_path) as f:
            data = yaml.safe_load(f)
        hosts = data["allowed_hosts"]
        assert any(
            (isinstance(h, dict) and h["host"] == "newdict.com") for h in hosts
        )

    def test_real_credential_never_appears_in_any_response(self, mgmt, tmp_path):
        # The management API must never expose brokered real credentials, and
        # /allow/permanent must round-trip the raw config (${KEY} references)
        # rather than the secret-expanded form.
        real_token = "REAL-SECRET-TOKEN-a3f9"
        from config import Credential
        state = mgmt._state
        state.credentials = [Credential(
            host="api.github.com", header="Authorization",
            fake_value="token ghp_fake", real_value=f"token {real_token}",
            preset="github",
        )]

        secrets = tmp_path / "secrets.yaml"
        secrets.write_text(f"GITHUB_TOKEN: {real_token}\n")
        with open(state.config_path, "w") as f:
            f.write(
                f"secrets_file: {secrets}\n"
                "allowed_hosts:\n  - host: existing.com\n"
                "services:\n"
                "  - service: github\n"
                "    fake_value: ghp_fake\n"
                "    real_value: ${GITHUB_TOKEN}\n"
            )

        responses = [
            mgmt.get("/denied"),
            mgmt.get("/allowlist"),
            mgmt.post("/allow/temp", json={"host": "temp.com"}),
            mgmt.post("/allow/permanent", json={"host": "new.com"}),
        ]
        for r in responses:
            assert real_token not in r.get_data(as_text=True)

        # The rewritten config still references the secret, not its value.
        with open(state.config_path) as f:
            written = f.read()
        assert real_token not in written
        assert "${GITHUB_TOKEN}" in written

    def test_post_allow_permanent_rejects_without_touching_disk_or_state(self, mgmt):
        # An unrelated bad section (e.g. a malformed credential) must not let
        # this endpoint write a new host to disk while failing to update the
        # in-memory allowlist -- that would leave the two out of sync.
        config_path = mgmt._state.config_path
        with open(config_path) as f:
            original = f.read()
        bad = original + "credentials:\n  - host: api.example.com\n"
        with open(config_path, "w") as f:
            f.write(bad)

        r = mgmt.post("/allow/permanent", json={"host": "new.com"})

        assert r.status_code == 500
        assert r.get_json()["ok"] is False
        assert "new.com" not in mgmt._state.allowlist
        with open(config_path) as f:
            assert f.read() == bad
