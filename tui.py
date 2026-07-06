"""Terminal UI for the agent-proxy management API."""

from __future__ import annotations

import argparse
import asyncio
import os
import time
from datetime import datetime

import httpx
from rich.markup import escape
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Focus
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Static

DURATIONS: list[tuple[str, int]] = [("1m", 60), ("10m", 600), ("2h", 7200)]


def _fmt_time(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        return dt.astimezone().strftime("%H:%M:%S")
    except Exception:
        return iso


def _fmt_expires(epoch: float) -> str:
    remaining = epoch - time.time()
    if remaining <= 0:
        return "expired"
    m, s = divmod(int(remaining), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m"
    return f"{m}m {s}s"


class DurationBar(Static):
    """Shows the three duration options with the active one highlighted."""

    duration_idx: reactive[int] = reactive(0)

    def render(self) -> str:
        parts = []
        for i, (label, _) in enumerate(DURATIONS):
            if i == self.duration_idx:
                parts.append(f"[bold reverse] {label} [/bold reverse]")
            else:
                parts.append(f"  {label}  ")
        dur_str = "".join(parts)
        return f"Duration: {dur_str}   [dim]t[/dim]=temp  [dim]p[/dim]=perm  [dim]r[/dim]=refresh  [dim]q[/dim]=quit"


class UrlBar(Static):
    """Shows the full URL of the selected denied entry, plus the policy
    violation reason when there is one."""

    url: reactive[str] = reactive("")
    reason: reactive[str] = reactive("")

    def render(self) -> str:
        if not self.url:
            return "[dim]URL: —[/dim]"
        line = f"[dim]URL:[/dim] {escape(self.url)}"
        if self.reason:
            line += f"  [red]✗ {escape(self.reason)}[/red]"
        return line


class ProxyMonitor(App[None]):
    CSS = """
    Screen {
        layout: vertical;
    }

    #panels {
        height: 1fr;
    }

    #denied-pane {
        width: 1fr;
        border: solid $primary;
        border-title-align: left;
    }

    #denied-pane:focus-within {
        border: solid $accent;
    }

    #allowed-pane {
        width: 1fr;
        border: solid $primary;
        border-title-align: left;
    }

    #allowed-pane:focus-within {
        border: solid $accent;
    }

    DataTable {
        height: 1fr;
    }

    #url-bar {
        height: 1;
        background: $surface;
        padding: 0 1;
    }

    DurationBar {
        height: 1;
        background: $panel;
        padding: 0 1;
    }

    #status-bar {
        height: 1;
        background: $surface;
        color: $text-muted;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=False),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("tab", "switch_pane", "Switch pane", show=False),
        Binding("1", "select_duration('0')", "1m", show=False),
        Binding("2", "select_duration('1')", "10m", show=False),
        Binding("3", "select_duration('2')", "2h", show=False),
        Binding("d", "cycle_duration", "Cycle duration", show=False),
        Binding("t", "temp_allow", "Temp allow", show=False),
        Binding("p", "perm_allow", "Perm allow", show=False),
        Binding("k", "move_up", "Up", show=False),
        Binding("j", "move_down", "Down", show=False),
    ]

    def __init__(self, mgmt_port: int = 8082) -> None:
        super().__init__()
        self.base_url = f"http://127.0.0.1:{mgmt_port}"
        # Raw denied rows (deduplicated, newest-first)
        self._denied_rows: list[dict] = []
        # Left-pane rows: denied entries followed by temp-allowed entries, each
        # tagged with a "category" ("denied" or "temp"). Indexed 1:1 by the left
        # table's cursor row for selection and the url-bar.
        self._left_rows: list[dict] = []
        # Guards against overlapping fetches (fetch timeout > poll interval)
        self._refreshing = False
        self._consecutive_failures = 0
        # Ticks to skip before the next poll attempt (exponential backoff)
        self._skip_ticks = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="status-bar")
        with Horizontal(id="panels"):
            with Vertical(id="denied-pane"):
                yield DataTable(id="denied-table", cursor_type="row", zebra_stripes=True)
            with Vertical(id="allowed-pane"):
                yield DataTable(id="allowed-table", cursor_type="row", zebra_stripes=True)
        yield UrlBar(id="url-bar")
        yield DurationBar(id="dur-bar")
        yield Footer()

    def on_mount(self) -> None:
        denied_pane = self.query_one("#denied-pane", Vertical)
        denied_pane.border_title = "DENIED / TEMP-ALLOWED"

        allowed_pane = self.query_one("#allowed-pane", Vertical)
        allowed_pane.border_title = "ALLOWED"

        denied_table = self.query_one("#denied-table", DataTable)
        denied_table.add_columns("Host", "Status", "Method", "Time")

        allowed_table = self.query_one("#allowed-table", DataTable)
        allowed_table.add_columns("Host", "Status")

        denied_table.focus()

        self.set_interval(1, self._poll_tick)
        self.call_after_refresh(self._refresh_data)

    def _focused_pane(self) -> str:
        """Return 'denied' or 'allowed' depending on which table is focused."""
        focused = self.focused
        if focused is not None and getattr(focused, "id", None) == "denied-table":
            return "denied"
        return "allowed"

    async def _poll_tick(self) -> None:
        if self._skip_ticks > 0:
            self._skip_ticks -= 1
            return
        await self._refresh_data()

    async def _refresh_data(self) -> None:
        if self._refreshing:
            return
        self._refreshing = True
        try:
            await self._do_refresh()
        finally:
            self._refreshing = False

    async def _do_refresh(self) -> None:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                denied_r, allow_r = await asyncio.gather(
                    client.get(f"{self.base_url}/denied"),
                    client.get(f"{self.base_url}/allowlist"),
                )
            denied_data: list[dict] = denied_r.json()
            allowlist: dict = allow_r.json()
        except Exception as exc:
            self._consecutive_failures += 1
            self._skip_ticks = min(2 ** (self._consecutive_failures - 1), 30)
            if self._consecutive_failures == 1:
                self.notify(f"Fetch error: {exc}", severity="error", timeout=4)
            self.query_one("#status-bar", Static).update(
                f"  {self.base_url}  |  [red]disconnected[/red] "
                f"({escape(str(exc) or exc.__class__.__name__)})  |  "
                f"retrying in {self._skip_ticks}s"
            )
            return

        if self._consecutive_failures:
            self.notify("Reconnected to proxy API")
        self._consecutive_failures = 0

        # Deduplicate: keep the most recent entry per host, sort newest first
        seen: dict[str, dict] = {}
        for entry in denied_data:
            host = entry.get("host", "")
            existing = seen.get(host)
            if existing is None or entry["timestamp"] > existing["timestamp"]:
                seen[host] = entry
        self._denied_rows = sorted(seen.values(), key=lambda e: e["timestamp"], reverse=True)

        # Combined left pane: denied rows (newest-first) then temp-allowed rows.
        temp = allowlist.get("temporary", {})
        self._left_rows = [{**e, "category": "denied"} for e in self._denied_rows]
        self._left_rows += [
            {"category": "temp", "host": host, "expires": expires}
            for host, expires in sorted(temp.items())
        ]

        self._update_denied_table()
        self._update_allowed_table(allowlist)
        self._update_url_bar()

        now = datetime.now().strftime("%H:%M:%S")
        self.query_one("#status-bar", Static).update(
            f"  {self.base_url}  |  Last updated: {now}  |  Polling every 1s"
        )

    def _update_denied_table(self) -> None:
        dt = self.query_one("#denied-table", DataTable)
        current_row = dt.cursor_row
        dt.clear()
        for row in self._left_rows:
            if row["category"] == "temp":
                status_cell = Text("temp", style="green")
                method = ""
                time_cell = _fmt_expires(row["expires"])
            else:
                # Entries without a type predate typed deny logging → pending
                if row.get("type") == "policy_violation":
                    status_cell = Text("violation", style="bold red")
                else:
                    status_cell = Text("pending", style="yellow")
                method = row.get("method", "")
                time_cell = _fmt_time(row.get("timestamp", ""))
            dt.add_row(
                row.get("host", ""),
                status_cell,
                method,
                time_cell,
                key=f"{row['category']}:{row.get('host', '')}",
            )
        if current_row < len(self._left_rows):
            dt.move_cursor(row=current_row)

    def _update_allowed_table(self, allowlist: dict) -> None:
        at = self.query_one("#allowed-table", DataTable)
        at.clear()
        for host in sorted(allowlist.get("permanent", [])):
            at.add_row(host, "permanent", key=f"p:{host}")
        restricted = allowlist.get("restricted", {})
        for source in sorted(restricted):
            for host in sorted(restricted[source]):
                at.add_row(
                    Text(host, style="dim"),
                    Text(f"restricted ({source})", style="dim"),
                    key=f"r:{host}",
                )

    def _update_url_bar(self) -> None:
        url_bar = self.query_one("#url-bar", UrlBar)
        if self._focused_pane() != "denied" or not self._left_rows:
            url_bar.url = ""
            url_bar.reason = ""
            return
        dt = self.query_one("#denied-table", DataTable)
        row_idx = dt.cursor_row
        if 0 <= row_idx < len(self._left_rows):
            row = self._left_rows[row_idx]
            # Temp-allowed rows have no request URL/reason to show.
            url_bar.url = "" if row["category"] == "temp" else row.get("url", "")
            url_bar.reason = "" if row["category"] == "temp" else row.get("reason", "")
        else:
            url_bar.url = ""
            url_bar.reason = ""

    def on_data_table_cursor_moved(self, event: DataTable.CursorMoved) -> None:
        if event.data_table.id == "denied-table":
            self._update_url_bar()

    def on_focus(self, event: Focus) -> None:
        # Update url-bar when focus changes between tables
        self.call_after_refresh(self._update_url_bar)

    def action_switch_pane(self) -> None:
        if self._focused_pane() == "denied":
            self.query_one("#allowed-table", DataTable).focus()
        else:
            self.query_one("#denied-table", DataTable).focus()

    def action_move_up(self) -> None:
        table_id = f"#{self._focused_pane()}-table"
        self.query_one(table_id, DataTable).action_cursor_up()

    def action_move_down(self) -> None:
        table_id = f"#{self._focused_pane()}-table"
        self.query_one(table_id, DataTable).action_cursor_down()

    def action_select_duration(self, idx: str) -> None:
        i = int(idx)
        if 0 <= i < len(DURATIONS):
            self.query_one("#dur-bar", DurationBar).duration_idx = i

    def action_cycle_duration(self) -> None:
        bar = self.query_one("#dur-bar", DurationBar)
        bar.duration_idx = (bar.duration_idx + 1) % len(DURATIONS)

    async def action_refresh(self) -> None:
        self._skip_ticks = 0
        await self._refresh_data()

    def _selected_left_host(self) -> str | None:
        """Host of the selected left-pane row (denied or temp-allowed)."""
        if self._focused_pane() != "denied" or not self._left_rows:
            return None
        dt = self.query_one("#denied-table", DataTable)
        row_idx = dt.cursor_row
        if 0 <= row_idx < len(self._left_rows):
            return self._left_rows[row_idx].get("host")
        return None

    async def action_temp_allow(self) -> None:
        host = self._selected_left_host()
        if not host:
            return
        bar = self.query_one("#dur-bar", DurationBar)
        label, seconds = DURATIONS[bar.duration_idx]
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    f"{self.base_url}/allow/temp",
                    json={"host": host, "duration_seconds": seconds},
                )
            r.raise_for_status()
            self.notify(f"Temporarily allowed {host} for {label}")
        except Exception as exc:
            self.notify(f"Error: {exc}", severity="error", timeout=5)
            return
        await self._refresh_data()

    async def action_perm_allow(self) -> None:
        host = self._selected_left_host()
        if not host:
            return
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    f"{self.base_url}/allow/permanent",
                    json={"host": host},
                )
            r.raise_for_status()
            self.notify(f"Permanently allowed {host}")
        except Exception as exc:
            self.notify(f"Error: {exc}", severity="error", timeout=5)
            return
        await self._refresh_data()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent Proxy TUI")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PROXY_MGMT_PORT", "8082")),
        help="Management API port (default: $PROXY_MGMT_PORT or 8082)",
    )
    args = parser.parse_args()
    ProxyMonitor(mgmt_port=args.port).run()
