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


@pytest.fixture
def mgmt_secrets(mgmt, tmp_path):
    """The mgmt client with a secrets_file configured (required for tokens)."""
    secrets = tmp_path / "secrets.yaml"
    config_path = mgmt._state.config_path
    with open(config_path) as f:
        original = f.read()
    with open(config_path, "w") as f:
        f.write(f"secrets_file: {secrets}\n" + original)
    mgmt._secrets_path = secrets
    return mgmt


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


class TestServicesEndpoints:
    def test_available_catalog_has_no_secret_fields(self, mgmt):
        data = mgmt.get("/services/available").get_json()
        by_name = {item["name"]: item for item in data}
        assert by_name["npm"] == {
            "name": "npm", "needs_host": False, "needs_token": False,
            "hosts": ["registry.npmjs.org"],
        }
        assert by_name["github"]["needs_token"] is True
        assert by_name["github"]["header"] == "Authorization"
        assert by_name["github"]["fake_prefix"] == "ghp_"
        assert by_name["gitlab"]["needs_host"] is True
        for item in data:
            assert "real_value" not in item and "fake_value" not in item

    def test_post_registry_service_updates_state_and_config(self, mgmt):
        r = mgmt.post("/services", json={"service": "npm"})
        assert r.get_json() == {"ok": True, "service": {"service": "npm", "kind": "registry"}}
        assert "registry.npmjs.org" in mgmt._state.restricted
        with open(mgmt._state.config_path) as f:
            assert yaml.safe_load(f)["services"] == ["npm"]

    def test_post_credential_service_writes_secret_and_ref(self, mgmt_secrets):
        real = "REAL-SECRET-TOKEN-a3f9"
        r = mgmt_secrets.post("/services", json={"service": "github", "real_value": real})
        body = r.get_json()
        assert body["ok"] is True

        # Response carries the generated fake (for the CLI), never the real token.
        svc = body["service"]
        assert svc["kind"] == "credential"
        assert svc["header"] == "Authorization"
        assert svc["fake_value"].startswith("ghp_")
        assert len(svc["fake_value"]) == 40
        assert real not in r.get_data(as_text=True)

        # Real token lands only in secrets_file; config holds the ${KEY} ref.
        with open(mgmt_secrets._secrets_path) as f:
            assert yaml.safe_load(f) == {"CRED_GITHUB": real}
        with open(mgmt_secrets._state.config_path) as f:
            config_text = f.read()
        assert real not in config_text
        entry = yaml.safe_load(config_text)["services"][0]
        assert entry["real_value"] == "${CRED_GITHUB}"

        # State is live: credential brokered and host allowlisted.
        cred = mgmt_secrets._state.credentials[0]
        assert cred.real_value == f"token {real}"
        assert cred.fake_value == f"token {svc['fake_value']}"
        assert "api.github.com" in mgmt_secrets._state.allowlist

        # And GET /services stays redacted.
        listed = mgmt_secrets.get("/services")
        assert listed.get_json() == [svc]
        assert real not in listed.get_data(as_text=True)

    def test_post_gitlab_requires_host(self, mgmt_secrets):
        r = mgmt_secrets.post("/services", json={"service": "gitlab", "real_value": "x"})
        assert r.status_code == 400
        r = mgmt_secrets.post("/services", json={
            "service": "gitlab", "host": "gitlab.example.com", "real_value": "x",
        })
        assert r.get_json()["ok"] is True
        assert mgmt_secrets._state.credentials[0].host == "gitlab.example.com"

    def test_post_credential_requires_secrets_file(self, mgmt):
        r = mgmt.post("/services", json={"service": "github", "real_value": "x"})
        assert r.status_code == 400
        assert "secrets_file" in r.get_json()["error"]

    def test_post_credential_requires_real_value(self, mgmt_secrets):
        r = mgmt_secrets.post("/services", json={"service": "github"})
        assert r.status_code == 400
        assert "real_value" in r.get_json()["error"]

    def test_post_unknown_service_rejected(self, mgmt):
        assert mgmt.post("/services", json={"service": "nope"}).status_code == 400

    def test_post_duplicate_service_rejected(self, mgmt):
        mgmt.post("/services", json={"service": "npm"})
        assert mgmt.post("/services", json={"service": "npm"}).status_code == 409

    def test_post_rolls_back_secret_when_validation_fails(self, mgmt_secrets):
        # Break an unrelated config section after fixture setup, then attempt
        # to add a credential service: the secret written before validation
        # must be rolled back, and neither config nor state may change.
        config_path = mgmt_secrets._state.config_path
        with open(config_path) as f:
            original = f.read()
        bad = original + "credentials:\n  - host: api.example.com\n"
        with open(config_path, "w") as f:
            f.write(bad)

        r = mgmt_secrets.post("/services", json={"service": "github", "real_value": "x"})

        assert r.status_code == 500
        assert not mgmt_secrets._secrets_path.exists()
        assert mgmt_secrets._state.credentials == []
        with open(config_path) as f:
            assert f.read() == bad

    def test_put_rotates_secret_in_place(self, mgmt_secrets):
        mgmt_secrets.post("/services", json={"service": "github", "real_value": "old"})
        old_fake = mgmt_secrets._state.credentials[0].fake_value

        r = mgmt_secrets.put("/services", json={"service": "github", "real_value": "new"})
        assert r.get_json()["ok"] is True
        with open(mgmt_secrets._secrets_path) as f:
            assert yaml.safe_load(f) == {"CRED_GITHUB": "new"}
        cred = mgmt_secrets._state.credentials[0]
        assert cred.real_value == "token new"
        assert cred.fake_value == old_fake  # the CLI keeps its fake

    def test_put_unconfigured_service_404(self, mgmt_secrets):
        r = mgmt_secrets.put("/services", json={"service": "github", "real_value": "x"})
        assert r.status_code == 404

    def test_delete_removes_entry_and_secret(self, mgmt_secrets):
        mgmt_secrets.post("/services", json={"service": "github", "real_value": "tok"})
        r = mgmt_secrets.delete("/services", json={"service": "github"})
        assert r.get_json()["ok"] is True
        assert mgmt_secrets._state.credentials == []
        assert "api.github.com" not in mgmt_secrets._state.allowlist
        with open(mgmt_secrets._secrets_path) as f:
            assert yaml.safe_load(f) == {}
        with open(mgmt_secrets._state.config_path) as f:
            assert yaml.safe_load(f)["services"] == []

    def test_delete_keeps_secret_still_referenced_elsewhere(self, mgmt_secrets):
        mgmt_secrets.post("/services", json={"service": "github", "real_value": "tok"})
        # A hand-written credential referencing the same key must survive.
        config_path = mgmt_secrets._state.config_path
        with open(config_path) as f:
            data = yaml.safe_load(f)
        data["credentials"] = [{
            "host": "other.example.com", "header": "Authorization",
            "real_value": "${CRED_GITHUB}",
        }]
        with open(config_path, "w") as f:
            yaml.safe_dump(data, f)

        r = mgmt_secrets.delete("/services", json={"service": "github"})
        assert r.get_json()["ok"] is True
        with open(mgmt_secrets._secrets_path) as f:
            assert yaml.safe_load(f) == {"CRED_GITHUB": "tok"}

    def test_delete_unconfigured_service_404(self, mgmt):
        assert mgmt.delete("/services", json={"service": "npm"}).status_code == 404

    def test_secret_keys_deduped_per_host(self, mgmt_secrets):
        mgmt_secrets.post("/services", json={
            "service": "gitlab", "host": "a.example.com", "real_value": "ta",
        })
        mgmt_secrets.post("/services", json={
            "service": "gitlab", "host": "b.example.com", "real_value": "tb",
        })
        with open(mgmt_secrets._secrets_path) as f:
            secrets = yaml.safe_load(f)
        assert secrets == {
            "CRED_GITLAB_A_EXAMPLE_COM": "ta",
            "CRED_GITLAB_B_EXAMPLE_COM": "tb",
        }
        assert len(mgmt_secrets._state.credentials) == 2
