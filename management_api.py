"""
Management API for the sandbox proxy.

A small Flask app (loopback-only) that lets a human operator inspect denied
requests and grant temporary or permanent allowlist entries. Served in a
background thread by ManagementApiAddon (see addon.py).
"""

import json
import logging
import time

import yaml
from flask import Flask, jsonify, request as flask_request

from config import Config, ProxyState


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
        return jsonify({"ok": True})

    return app
