"""
Tests for the TUI (tui.py), driven headlessly through Textual's pilot
against a real management API served from a thread.

Run with:  pytest test_tui.py -v
"""

import asyncio
import threading
import time

import pytest
import yaml
from werkzeug.serving import make_server

from config import Config, ProxyState
from test_addon import make_flow


@pytest.fixture
def proxy(tmp_path):
    """A ProxyState with npm disabled and one denied request it would permit,
    plus a management API serving it."""
    from addon import AllowlistAddon
    from management_api import create_app

    config = tmp_path / "config.yaml"
    config.write_text("services:\n  - {service: npm, enabled: false}\n")
    state = ProxyState(config_path=str(config))
    state.apply(Config.load(str(config)))
    AllowlistAddon(state).request(make_flow("registry.npmjs.org", path="/left-pad"))

    server = make_server("127.0.0.1", 0, create_app(state))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state.management_port = server.server_port
    yield state
    server.shutdown()


def run_tui(state, script):
    """Run the main TUI screen and `await script(app, pilot)` against it."""
    import tui

    async def main():
        app = tui.ProxyMonitor(mgmt_port=state.management_port)
        async with app.run_test() as pilot:
            await pilot.pause(0.5)
            await script(app, pilot)
    asyncio.run(main())


def left_rows(app):
    table = app.query_one("#denied-table")
    return [tuple(str(c) for c in table.get_row_at(i)) for i in range(table.row_count)]


async def refresh(app, pilot):
    await app.action_refresh()
    await pilot.pause(0.1)


def test_denied_row_offers_disabled_service(proxy):
    async def script(app, pilot):
        [(host, status, *_)] = left_rows(app)
        assert (host, status) == ("registry.npmjs.org", "pending ·svc")
        assert app.query_one("#url-bar").services == "npm"
    run_tui(proxy, script)


def test_enabling_from_denied_row_marks_it_resolved(proxy):
    async def script(app, pilot):
        await pilot.press("3", "e")
        await pilot.pause(0.5)
        denied, temp = left_rows(app)
        assert denied[0] == "registry.npmjs.org"
        assert denied[1].startswith("→ npm ")
        assert temp[:2] == ("npm", "temp svc")
        bar = app.query_one("#url-bar")
        assert bar.services == ""
        assert bar.enabled.startswith("npm (temp, ")
    run_tui(proxy, script)
    assert ("npm", None) in proxy.temp_services


def test_resolved_row_reverts_when_temp_enable_expires(proxy):
    async def script(app, pilot):
        await pilot.press("e")
        await pilot.pause(0.5)
        proxy.temp_services[("npm", None)] = time.time() - 1
        await refresh(app, pilot)
        [(_, status, *_)] = left_rows(app)
        assert status == "pending ·svc"
    run_tui(proxy, script)


def test_permanently_enabled_service_resolves_row(proxy):
    async def script(app, pilot):
        proxy.apply(Config.from_data({"services": ["npm"]}))
        # GET /services reads config.yaml, so persist the toggle there too.
        with open(proxy.config_path, "w") as f:
            f.write("services:\n  - npm\n")
        await refresh(app, pilot)
        [(_, status, *_)] = left_rows(app)
        assert status == "→ npm"
        assert app.query_one("#url-bar").enabled == "npm (permanent)"
        await pilot.press("e")
        await pilot.pause(0.3)
        assert any("No disabled service" in n.message for n in app._notifications)
    run_tui(proxy, script)
    assert proxy.temp_services == {}


def test_host_actions_ignore_temp_service_row(proxy):
    async def script(app, pilot):
        await pilot.press("e")
        await pilot.pause(0.5)
        await pilot.press("j", "t", "p")
        await pilot.pause(0.5)
    run_tui(proxy, script)
    assert proxy.temp_allows == {}
    with open(proxy.config_path) as f:
        assert "hosts" not in yaml.safe_load(f)
