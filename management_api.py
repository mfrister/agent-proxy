"""
Management API for the sandbox proxy.

A small Flask app (loopback-only) that lets a human operator inspect denied
requests, grant temporary or permanent allowlist entries, and manage service
presets. Served in a background thread by ManagementApiAddon (see addon.py).

Real credentials are write-only through this API: they are accepted on
POST/PUT /services, persisted to the configured secrets_file, referenced from
config.yaml as ${KEY}, and never returned by any endpoint.
"""

import json
import logging
import os
import re
import secrets as py_secrets
import time

import yaml
from flask import Flask, jsonify, request as flask_request

import services as services_module
from config import Config, ProxyState


def _service_key(entry) -> tuple:
    """(service, host) identity of a raw `services` config entry."""
    if isinstance(entry, str):
        return entry, None
    return entry.get("service"), entry.get("host")


def _secret_key_for(service: str, host: str | None, existing: dict) -> str:
    """A fresh secrets_file key for a service credential, deduped."""
    raw = f"{service}_{host}" if host else service
    base = "CRED_" + re.sub(r"[^A-Za-z0-9]+", "_", raw).upper().strip("_")
    key, n = base, 2
    while key in existing:
        key, n = f"{base}_{n}", n + 1
    return key


def _secret_ref(entry) -> str | None:
    """The ${KEY} name an entry's real_value references, if any."""
    if not isinstance(entry, dict):
        return None
    m = re.fullmatch(r"\$\{([^}]+)\}", entry.get("real_value") or "")
    return m.group(1) if m else None


def _redacted_view(entry) -> dict:
    """A `services` entry as returned by the API: never real_value."""
    name, host = _service_key(entry)
    preset = services_module.SERVICE_PRESETS.get(name)
    view = {"service": name}
    if host:
        view["host"] = host
    if preset is not None and preset.credential is not None:
        view["kind"] = "credential"
        view["header"] = preset.credential.header
        if isinstance(entry, dict) and entry.get("fake_value"):
            view["fake_value"] = entry["fake_value"]
    else:
        view["kind"] = "registry"
    return view


def _generate_fake(spec) -> str:
    """A random fake token matching the service client's expected shape."""
    n = max(0, spec.fake_length - len(spec.fake_prefix))
    return spec.fake_prefix + py_secrets.token_hex((n + 1) // 2)[:n]


def create_app(state: ProxyState) -> Flask:
    app = Flask(__name__)
    # Silence werkzeug request logs and Flask startup banner
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    import flask.cli
    flask.cli.show_server_banner = lambda *_a, **_kw: None

    @app.get("/denied")
    def get_denied():
        with state.deny_lock:
            return jsonify(list(state.deny_log))

    @app.get("/allowlist")
    def get_allowlist_view():
        now = time.time()
        with state.temp_lock:
            active_temps = {
                h: exp for h, exp in state.temp_allows.items() if now < exp
            }
        restricted = {}
        for host, rules in state.restricted.items():
            restricted.setdefault(rules.source or "config", []).append(host)
        return jsonify({
            "permanent": sorted(state.allowlist),
            "temporary": active_temps,
            "restricted": {k: sorted(v) for k, v in restricted.items()},
        })

    @app.post("/allow/temp")
    def temp_allow():
        body = flask_request.get_json(force=True)
        host = body["host"]
        duration = float(body.get("duration_seconds", 300))
        with state.temp_lock:
            state.temp_allows[host] = time.time() + duration
        return jsonify({"ok": True})

    @app.post("/allow/permanent")
    def permanent_allow():
        host = flask_request.get_json(force=True)["host"]
        try:
            with open(state.config_path) as f:
                data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            data = {}
        hosts = data.get("allowed_hosts", [])
        host_names = [h if isinstance(h, str) else h["host"] for h in hosts]
        if host in host_names:
            # Already permanent; drop any lingering temp entry so it doesn't
            # keep showing as temporarily-allowed alongside the permanent one.
            with state.temp_lock:
                state.temp_allows.pop(host, None)
            return jsonify({"ok": True})

        new_data = {**data, "allowed_hosts": hosts + [{"host": host}]}
        try:
            # Validate against the full config (credentials, restricted_hosts,
            # etc. all reload together) before writing anything to disk, so a
            # pre-existing bad section elsewhere can't leave config.yaml and
            # the running state out of sync.
            config = Config.from_data(new_data)
        except Exception as e:
            print(json.dumps({"event": "config_error", "message": str(e)}))
            return jsonify({"ok": False, "error": str(e)}), 500

        with open(state.config_path, "w") as f:
            yaml.safe_dump(new_data, f)
        state.apply(config)
        # Promotion to permanent supersedes any temporary grant for this host.
        with state.temp_lock:
            state.temp_allows.pop(host, None)
        return jsonify({"ok": True})

    # ── Service presets ────────────────────────────────────────────────────

    def _read_config():
        try:
            with open(state.config_path) as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {}

    def _read_secrets(path):
        """(parsed dict, original file text or None if the file is missing)."""
        try:
            with open(path) as f:
                text = f.read()
            return yaml.safe_load(text) or {}, text
        except FileNotFoundError:
            return {}, None

    def _restore_secrets(path, original_text):
        if original_text is None:
            os.remove(path)
        else:
            with open(path, "w") as f:
                f.write(original_text)

    @app.get("/services/available")
    def get_services_available():
        catalog = []
        for name in sorted(services_module.SERVICE_PRESETS):
            preset = services_module.SERVICE_PRESETS[name]
            item = {
                "name": name,
                "needs_host": preset.param_host,
                "needs_token": preset.credential is not None,
                "hosts": sorted(preset.hosts),
            }
            if preset.credential is not None:
                item["header"] = preset.credential.header
                item["fake_prefix"] = preset.credential.fake_prefix
            catalog.append(item)
        return jsonify(catalog)

    @app.get("/services")
    def get_services():
        data = _read_config()
        return jsonify([_redacted_view(e) for e in data.get("services") or []])

    @app.post("/services")
    def add_service():
        body = flask_request.get_json(force=True)
        name = body.get("service")
        host = body.get("host")
        preset = services_module.SERVICE_PRESETS.get(name)
        if preset is None:
            return jsonify({"ok": False, "error": f"unknown service {name!r}"}), 400
        if host and not preset.param_host:
            return jsonify({"ok": False, "error": f"{name} does not take a host"}), 400

        data = _read_config()
        entries = list(data.get("services") or [])
        if any(_service_key(e) == (name, host) for e in entries):
            return jsonify({"ok": False, "error": "service already configured"}), 409

        rollback = None
        if preset.credential is None:
            new_entry = name
        else:
            spec = preset.credential
            if preset.param_host and not host:
                return jsonify({"ok": False, "error": f"{name} requires a host"}), 400
            if not body.get("real_value"):
                return jsonify({"ok": False, "error": "real_value is required"}), 400
            secrets_path = data.get("secrets_file")
            if not secrets_path:
                return jsonify({
                    "ok": False,
                    "error": "secrets_file must be configured to store the real token",
                }), 400

            secrets_data, original_text = _read_secrets(secrets_path)
            key = _secret_key_for(name, host, secrets_data)
            secrets_data[key] = body["real_value"]
            with open(secrets_path, "w") as f:
                yaml.safe_dump(secrets_data, f)
            rollback = (secrets_path, original_text)

            new_entry = {"service": name, "fake_value": _generate_fake(spec),
                         "real_value": "${" + key + "}"}
            if host:
                new_entry["host"] = host

        new_data = {**data, "services": entries + [new_entry]}
        try:
            config = Config.from_data(new_data)
        except Exception as e:
            if rollback:
                _restore_secrets(*rollback)
            print(json.dumps({"event": "config_error", "message": str(e)}))
            return jsonify({"ok": False, "error": str(e)}), 500

        with open(state.config_path, "w") as f:
            yaml.safe_dump(new_data, f)
        state.apply(config)
        return jsonify({"ok": True, "service": _redacted_view(new_entry)})

    @app.put("/services")
    def rotate_service_token():
        body = flask_request.get_json(force=True)
        name, host = body.get("service"), body.get("host")
        if not body.get("real_value"):
            return jsonify({"ok": False, "error": "real_value is required"}), 400

        data = _read_config()
        entry = next(
            (e for e in data.get("services") or [] if _service_key(e) == (name, host)),
            None,
        )
        if entry is None:
            return jsonify({"ok": False, "error": "service not configured"}), 404
        key = _secret_ref(entry)
        if key is None:
            return jsonify({
                "ok": False,
                "error": "service has no ${KEY} token reference to rotate",
            }), 400
        secrets_path = data.get("secrets_file")
        if not secrets_path:
            return jsonify({"ok": False, "error": "secrets_file is not configured"}), 400

        secrets_data, original_text = _read_secrets(secrets_path)
        secrets_data[key] = body["real_value"]
        with open(secrets_path, "w") as f:
            yaml.safe_dump(secrets_data, f)
        try:
            config = Config.from_data(data)
        except Exception as e:
            _restore_secrets(secrets_path, original_text)
            print(json.dumps({"event": "config_error", "message": str(e)}))
            return jsonify({"ok": False, "error": str(e)}), 500

        state.apply(config)
        return jsonify({"ok": True, "service": _redacted_view(entry)})

    @app.delete("/services")
    def remove_service():
        body = flask_request.get_json(force=True)
        name, host = body.get("service"), body.get("host")

        data = _read_config()
        entries = list(data.get("services") or [])
        entry = next((e for e in entries if _service_key(e) == (name, host)), None)
        if entry is None:
            return jsonify({"ok": False, "error": "service not configured"}), 404

        new_data = {**data, "services": [e for e in entries if e is not entry]}
        try:
            config = Config.from_data(new_data)
        except Exception as e:
            print(json.dumps({"event": "config_error", "message": str(e)}))
            return jsonify({"ok": False, "error": str(e)}), 500

        with open(state.config_path, "w") as f:
            yaml.safe_dump(new_data, f)
        state.apply(config)

        # The entry is gone from the config; scrub its secret, unless another
        # entry (service or hand-written credential) still references the key.
        key = _secret_ref(entry)
        secrets_path = data.get("secrets_file")
        if key and "${" + key + "}" in yaml.safe_dump(new_data):
            key = None
        if key and secrets_path:
            secrets_data, original_text = _read_secrets(secrets_path)
            if original_text is not None and key in secrets_data:
                del secrets_data[key]
                with open(secrets_path, "w") as f:
                    yaml.safe_dump(secrets_data, f)

        return jsonify({"ok": True})

    return app
