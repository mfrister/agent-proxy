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
import tui
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
    # A short poll interval keeps shutdown() from waiting out the 0.5s default.
    threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True).start()
    state.management_port = server.server_port
    yield state
    server.shutdown()


class Monitor(tui.ProxyMonitor):
    """The main screen with the 1s poll timer disabled, so a test decides
    when refreshes happen: the initial one from on_mount, the one an action
    ends with, or an explicit refresh(). Each completed refresh sets
    `refreshed`, so a test can wait for one instead of sleeping."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.refreshed = asyncio.Event()

    async def _poll_tick(self) -> None:
        pass

    async def _do_refresh(self) -> None:
        await super()._do_refresh()
        self.refreshed.set()


def run_tui(state, script):
    """Run the main TUI screen and `await script(app, pilot)` against it,
    once the initial refresh has landed."""
    async def main():
        app = Monitor(mgmt_port=state.management_port)
        async with app.run_test() as pilot:
            await asyncio.wait_for(app.refreshed.wait(), timeout=5)
            await script(app, pilot)
    asyncio.run(main())


def left_rows(app):
    table = app.query_one("#denied-table")
    return [tuple(str(c) for c in table.get_row_at(i)) for i in range(table.row_count)]


async def press(app, pilot, *keys):
    """Press keys and wait for any worker they start (the `e` action and
    its closing refresh run in one)."""
    await pilot.press(*keys)
    await app.workers.wait_for_complete()


async def refresh(app, pilot):
    await app.action_refresh()
    await pilot.pause()


def test_denied_row_offers_disabled_service(proxy):
    async def script(app, pilot):
        [(host, status, *_)] = left_rows(app)
        assert (host, status) == ("registry.npmjs.org", "pending ·svc")
        assert app.query_one("#url-bar").services == "npm"
    run_tui(proxy, script)


def test_enabling_from_denied_row_marks_it_resolved(proxy):
    async def script(app, pilot):
        await press(app, pilot, "3", "e")
        denied, temp = left_rows(app)
        assert denied[0] == "registry.npmjs.org"
        assert denied[1].startswith("→ npm ")
        assert temp[:2] == ("npm", "temp svc")
        bar = app.query_one("#url-bar")
        assert bar.services == ""
        assert bar.enabled.startswith("npm (temp, ")
    run_tui(proxy, script)
    assert proxy.temp_services[("npm", None)] > time.time() + 3600  # 2h picked


def test_resolved_row_reverts_when_temp_enable_expires(proxy):
    async def script(app, pilot):
        await press(app, pilot, "e")
        proxy.temp_services[("npm", None)] = time.time() - 1
        await refresh(app, pilot)
        [(_, status, *_)] = left_rows(app)
        assert status == "pending ·svc"
    run_tui(proxy, script)


def test_permanently_enabled_service_resolves_row(proxy):
    async def script(app, pilot):
        with open(proxy.config_path, "w") as f:
            f.write("services:\n  - npm\n")
        proxy.reload()
        await refresh(app, pilot)
        [(_, status, *_)] = left_rows(app)
        assert status == "→ npm"
        assert app.query_one("#url-bar").enabled == "npm (permanent)"
        await press(app, pilot, "e")
        assert any("No disabled service" in n.message for n in app._notifications)
    run_tui(proxy, script)
    assert proxy.temp_services == {}


def test_host_actions_ignore_temp_service_row(proxy):
    async def script(app, pilot):
        await press(app, pilot, "e")
        await press(app, pilot, "j", "t", "p")
        assert app._left_rows[app.query_one("#denied-table").cursor_row]["category"] \
            == "temp-service"
        assert proxy.temp_allows == {}
        # Positive control: the same keys and wait do act on a host row.
        await press(app, pilot, "k", "t")
        assert "registry.npmjs.org" in proxy.temp_allows
    run_tui(proxy, script)
    with open(proxy.config_path) as f:
        assert "hosts" not in yaml.safe_load(f)


def test_denials_still_shown_when_service_state_unavailable(proxy, monkeypatch):
    # GET /services failing (e.g. an API error) degrades to the deny log's
    # own view of disabled services, instead of the whole screen reporting
    # the proxy as disconnected.
    import management_api

    def boom(entry):
        raise RuntimeError("boom")
    monkeypatch.setattr(management_api, "_redacted_view", boom)

    async def script(app, pilot):
        [(host, status, *_)] = left_rows(app)
        assert (host, status) == ("registry.npmjs.org", "pending ·svc")
        status_bar = str(app.query_one("#status-bar").render())
        assert "service state unavailable" in status_bar
        assert "disconnected" not in status_bar
    run_tui(proxy, script)
