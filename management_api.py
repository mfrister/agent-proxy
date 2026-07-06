"""
Management API for the sandbox proxy.

A small Flask app (loopback-only) that lets a human operator inspect denied
requests and grant temporary or permanent allowlist entries. Served in a
background thread by ManagementApiAddon (see addon.py).
"""

import logging
import time

import yaml
from flask import Flask, jsonify, request as flask_request

from config import ProxyState


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
        if host not in host_names:
            hosts.append({"host": host})
            data["allowed_hosts"] = hosts
            with open(state.config_path, "w") as f:
                yaml.safe_dump(data, f)
        state.reload()
        return jsonify({"ok": True})

    return app
