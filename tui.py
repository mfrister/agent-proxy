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
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Focus
from textual.reactive import reactive
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, Static

DURATIONS: list[tuple[str, int]] = [("1m", 60), ("10m", 600), ("2h", 7200)]


async def _api_request(base_url: str, method: str, path: str, body: dict | None = None):
    """Call the management API; raise RuntimeError with the API's error text."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.request(method, f"{base_url}{path}", json=body)
    try:
        data = r.json()
    except Exception:
        r.raise_for_status()
        raise RuntimeError(f"unexpected response: {r.text[:200]}")
    if r.status_code >= 400:
        error = data.get("error") if isinstance(data, dict) else None
        raise RuntimeError(error or f"HTTP {r.status_code}")
    return data


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
        return (
            f"Duration: {dur_str}   [dim]t[/dim]=temp  [dim]p[/dim]=perm  "
            f"[dim]s[/dim]=services  [dim]r[/dim]=refresh  [dim]q[/dim]=quit"
        )


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


class PickServiceScreen(ModalScreen[dict | None]):
    """Pick a service preset from the /services/available catalog."""

    CSS = """
    PickServiceScreen {
        align: center middle;
    }
    #pick-dialog {
        width: 76;
        height: auto;
        max-height: 80%;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    #pick-table {
        height: auto;
        max-height: 20;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("j", "cursor_down", "Down", show=False),
    ]

    def __init__(self, catalog: list[dict]) -> None:
        super().__init__()
        self._catalog = catalog

    def compose(self) -> ComposeResult:
        with Vertical(id="pick-dialog"):
            yield Label("Add service — Enter to select, Esc to cancel")
            yield DataTable(id="pick-table", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        table = self.query_one("#pick-table", DataTable)
        table.add_columns("Service", "Kind", "Hosts / header")
        for item in self._catalog:
            if item["needs_token"]:
                kind = "credential"
                detail = f"{', '.join(item['hosts']) or '<your host>'} ({item['header']})"
            else:
                kind = "registry"
                detail = ", ".join(item["hosts"])
            table.add_row(item["name"], kind, detail, key=item["name"])
        table.focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_cursor_up(self) -> None:
        self.query_one("#pick-table", DataTable).action_cursor_up()

    def action_cursor_down(self) -> None:
        self.query_one("#pick-table", DataTable).action_cursor_down()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # DataTable emits this on Enter (and click) for the cursor row.
        self.dismiss(self._catalog[event.cursor_row])


class TextPromptScreen(ModalScreen[str | None]):
    """One-line text prompt; password=True masks the input."""

    CSS = """
    TextPromptScreen {
        align: center middle;
    }
    #prompt-dialog {
        width: 76;
        height: auto;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, prompt: str, password: bool = False) -> None:
        super().__init__()
        self._prompt = prompt
        self._password = password

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt-dialog"):
            yield Label(self._prompt)
            yield Input(password=self._password, id="prompt-input")

    def on_mount(self) -> None:
        self.query_one("#prompt-input", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip() or None)


class ConfirmScreen(ModalScreen[bool]):
    """Yes/no confirmation."""

    CSS = """
    ConfirmScreen {
        align: center middle;
    }
    #confirm-dialog {
        width: 60;
        height: auto;
        border: thick $warning;
        background: $surface;
        padding: 1 2;
    }
    """

    BINDINGS = [
        Binding("y", "yes", "Yes"),
        Binding("n,escape", "no", "No"),
    ]

    def __init__(self, question: str) -> None:
        super().__init__()
        self._question = question

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Label(self._question)
            yield Label("[dim]y[/dim]=yes  [dim]n[/dim]=no")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


class ServicesScreen(Screen):
    """Configured service presets, with add / rotate-token / remove.

    Real tokens are entered once (masked) and sent to the management API,
    which stores them in secrets_file; they are never displayed or re-fetched.
    The generated fake token stays visible — it's what the CLI is given.
    """

    CSS = """
    #services-pane {
        border: solid $primary;
        border-title-align: left;
        height: 1fr;
    }
    #services-hint {
        height: 1;
        background: $panel;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("escape,q", "back", "Back"),
        Binding("a", "add_service", "Add"),
        Binding("o", "rotate_token", "Rotate token"),
        Binding("e", "edit_scope", "Edit scope"),
        Binding("x", "remove_service", "Remove"),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("j", "cursor_down", "Down", show=False),
    ]

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self._rows: list[dict] = []
        # name -> /services/available catalog item; loaded once (presets are
        # static for the lifetime of the process) and used to render the
        # Scope column and drive the add/edit prompts.
        self._catalog: dict[str, dict] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="services-pane"):
            yield DataTable(id="services-table", cursor_type="row", zebra_stripes=True)
        yield Static(
            "[dim]a[/dim]=add  [dim]o[/dim]=rotate token  [dim]e[/dim]=edit scope  "
            "[dim]x[/dim]=remove  [dim]r[/dim]=refresh  [dim]esc[/dim]=back",
            id="services-hint",
        )
        yield Footer()

    def on_mount(self) -> None:
        pane = self.query_one("#services-pane", Vertical)
        pane.border_title = "SERVICES"
        table = self.query_one("#services-table", DataTable)
        table.add_columns("Service", "Host", "Kind", "Header", "Fake token", "Scope")
        table.focus()
        self.run_worker(self._refresh())

    def _scope_cell(self, row: dict) -> Text | str:
        """Render a row's Scope column: named scope + flags, with any
        `unscoped` flag highlighted so the blanket-access choice stays
        visible in the table, not just at the moment it was made."""
        if row.get("unrestricted"):
            return Text("UNRESTRICTED", style="bold red")
        preset = self._catalog.get(row["service"], {})
        scope_params = preset.get("scope_params") or []
        scope_flags = preset.get("scope_flags") or []
        if not scope_params:
            return ""

        text = Text()
        scope = row.get("scope") or {}
        for param in scope_params:
            values = scope.get(param["name"])
            if not values:
                continue
            if isinstance(values, list):
                values = ",".join(values)
            if text.plain:
                text.append("  ")
            text.append(f"{param['name']}={values}")
        for flag in scope_flags:
            if not row.get(flag["name"]):
                continue
            if text.plain:
                text.append("  ")
            text.append(flag["name"], style="bold red" if flag["unscoped"] else None)
        return text if text.plain else Text("—", style="dim")

    async def _refresh(self) -> None:
        if not self._catalog:
            try:
                catalog = await _api_request(self.base_url, "GET", "/services/available")
                self._catalog = {item["name"]: item for item in catalog}
            except Exception:
                pass  # table still renders; Scope column just loses highlighting
        try:
            self._rows = await _api_request(self.base_url, "GET", "/services")
        except Exception as exc:
            self.notify(f"Fetch error: {exc}", severity="error", timeout=5)
            return
        table = self.query_one("#services-table", DataTable)
        current_row = table.cursor_row
        table.clear()
        for row in self._rows:
            table.add_row(
                row["service"],
                row.get("host", ""),
                row["kind"],
                row.get("header", ""),
                row.get("fake_value", ""),
                self._scope_cell(row),
                key=f"{row['service']}:{row.get('host', '')}",
            )
        if current_row < len(self._rows):
            table.move_cursor(row=current_row)

    def _selected(self) -> dict | None:
        table = self.query_one("#services-table", DataTable)
        if 0 <= table.cursor_row < len(self._rows):
            return self._rows[table.cursor_row]
        return None

    def _identity(self, row: dict) -> dict:
        body = {"service": row["service"]}
        if row.get("host"):
            body["host"] = row["host"]
        return body

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_cursor_up(self) -> None:
        self.query_one("#services-table", DataTable).action_cursor_up()

    def action_cursor_down(self) -> None:
        self.query_one("#services-table", DataTable).action_cursor_down()

    async def action_refresh(self) -> None:
        await self._refresh()

    async def _prompt_scope(self, name: str, scope_params: list[dict]) -> dict:
        """One TextPromptScreen per scope param; comma-separated for list
        params. A blank answer skips that param (no key in the result)."""
        scope: dict = {}
        for param in scope_params:
            prompt = f"{name} scope: {param['name']}"
            if param["list"]:
                prompt += " (comma-separated)"
            raw = await self.app.push_screen_wait(TextPromptScreen(f"{prompt}:"))
            if not raw:
                continue
            if param["list"]:
                values = [v.strip() for v in raw.split(",") if v.strip()]
                if values:
                    scope[param["name"]] = values
            else:
                scope[param["name"]] = raw.strip()
        return scope

    async def _prompt_scope_or_unrestricted(self, name: str, scope_params: list[dict]) -> dict | None:
        """Prompt every scope param; if the operator leaves all of them
        blank, spell out the consequence in plain language before granting
        blanket access. Returns {"scope": {...}} or {"unrestricted": True},
        or None if the operator declined unrestricted access (caller should
        abort -- this is the one place that blanket-access decision is made
        by a human, so there is no silent fallback).
        """
        scope = await self._prompt_scope(name, scope_params)
        if scope:
            return {"scope": scope}
        confirmed = await self.app.push_screen_wait(ConfirmScreen(
            f"No scope given for {name}.\n\n"
            f"[bold red]Without a scope, {name} will be able to reach "
            f"EVERYTHING the token can reach[/bold red] -- every repo, org, "
            "or project it's valid for, not just the ones you name here.\n\n"
            f"Grant {name} unrestricted access anyway?"
        ))
        return {"unrestricted": True} if confirmed else None

    async def _prompt_flags(self, name: str, scope_flags: list[dict]) -> dict:
        """One ConfirmScreen per declared flag. Always records True/False
        explicitly (not just True on yes) so an edit can turn a flag back
        off, not only on."""
        flags: dict = {}
        for flag in scope_flags:
            question = f"Enable {flag['name']} for {name}?\n\n{flag['description']}"
            if flag["unscoped"]:
                question += (
                    "\n\n[bold red]This defeats scoping[/bold red] -- it lets "
                    f"{name} reach beyond the scope named above."
                )
            flags[flag["name"]] = await self.app.push_screen_wait(ConfirmScreen(question))
        return flags

    @work
    async def action_add_service(self) -> None:
        try:
            catalog = await _api_request(self.base_url, "GET", "/services/available")
        except Exception as exc:
            self.notify(f"Fetch error: {exc}", severity="error", timeout=5)
            return
        item = await self.app.push_screen_wait(PickServiceScreen(catalog))
        if item is None:
            return
        body = {"service": item["name"]}
        if item["host_param"]:
            host = await self.app.push_screen_wait(TextPromptScreen(
                f"Host for {item['name']} (e.g. gitlab.example.com):"
            ))
            if not host:
                return
            body["host"] = host
        if item["needs_token"]:
            token = await self.app.push_screen_wait(TextPromptScreen(
                f"Real token for {item['name']} — stored in secrets_file, "
                "never shown again:",
                password=True,
            ))
            if not token:
                return
            body["real_value"] = token
        if item["scope_params"]:
            scoping = await self._prompt_scope_or_unrestricted(item["name"], item["scope_params"])
            if scoping is None:
                self.notify(f"Add cancelled — {item['name']} needs a scope", severity="warning")
                return
            body.update(scoping)
        if item["scope_flags"]:
            body.update(await self._prompt_flags(item["name"], item["scope_flags"]))
        try:
            result = await _api_request(self.base_url, "POST", "/services", body)
        except Exception as exc:
            self.notify(f"Error: {exc}", severity="error", timeout=8)
            return
        fake = result["service"].get("fake_value")
        if fake:
            self.notify(
                f"Added {item['name']}. Give the CLI the fake token "
                f"(also in the table): {fake}",
                timeout=10,
            )
        else:
            self.notify(f"Added {item['name']}")
        await self._refresh()

    @work
    async def action_edit_scope(self) -> None:
        row = self._selected()
        if row is None:
            return
        preset = self._catalog.get(row["service"])
        if not preset or not preset["scope_params"]:
            self.notify(f"{row['service']} has no scope to edit", severity="warning")
            return
        scoping = await self._prompt_scope_or_unrestricted(row["service"], preset["scope_params"])
        if scoping is None:
            self.notify("Scope edit cancelled — no scope given", severity="warning")
            return
        body = {**self._identity(row), **scoping}
        if preset["scope_flags"]:
            body.update(await self._prompt_flags(row["service"], preset["scope_flags"]))
        try:
            # Extended PUT /services: scope/flags only, never real_value --
            # editing scope must not touch the brokered token.
            await _api_request(self.base_url, "PUT", "/services", body)
        except Exception as exc:
            self.notify(f"Error: {exc}", severity="error", timeout=8)
            return
        self.notify(f"Updated scope for {row['service']}")
        await self._refresh()

    @work
    async def action_rotate_token(self) -> None:
        row = self._selected()
        if row is None:
            return
        if row["kind"] != "credential":
            self.notify("Registry services have no token to rotate", severity="warning")
            return
        token = await self.app.push_screen_wait(TextPromptScreen(
            f"New real token for {row['service']} — the fake token the CLI "
            "holds stays the same:",
            password=True,
        ))
        if not token:
            return
        try:
            await _api_request(
                self.base_url, "PUT", "/services",
                {**self._identity(row), "real_value": token},
            )
        except Exception as exc:
            self.notify(f"Error: {exc}", severity="error", timeout=8)
            return
        self.notify(f"Rotated token for {row['service']}")
        await self._refresh()

    @work
    async def action_remove_service(self) -> None:
        row = self._selected()
        if row is None:
            return
        label = row["service"] + (f" ({row['host']})" if row.get("host") else "")
        confirmed = await self.app.push_screen_wait(ConfirmScreen(
            f"Remove service {label}? Its host access and any stored token "
            "are removed."
        ))
        if not confirmed:
            return
        try:
            await _api_request(self.base_url, "DELETE", "/services", self._identity(row))
        except Exception as exc:
            self.notify(f"Error: {exc}", severity="error", timeout=8)
            return
        self.notify(f"Removed {label}")
        await self._refresh()


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
        Binding("s", "services", "Services", show=False),
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

    def action_services(self) -> None:
        self.push_screen(ServicesScreen(self.base_url))

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
