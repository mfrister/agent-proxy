# agent-proxy

**Warning:** This is an experimental more-or-less vibe-coded project. I've had a look a the code, but haven't thoroughly vetted it.

mitmproxy addon that acts as the sole HTTP/HTTPS egress point for an LLM agent sandbox. Enforces a domain allowlist, brokers API credentials so real secrets never enter the sandbox, strips unwanted `Set-Cookie` response headers, and exposes a management API for runtime changes.

## Setup

```
uv sync
```

## Run

```bash
# headless
uv run mitmdump -s addon.py

# with web UI
uv run mitmweb -s addon.py
```

Point the agent at the proxy and install the CA cert:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem
```

The CA cert is generated on first run at `~/.mitmproxy/` (or the path set by `--set confdir=`).

**Lima VM:** Instead of setting the env vars manually, run `setup-lima-proxy.sh` to install the CA cert into the VM's system trust store and write the proxy env to `/etc/profile.d/proxy.sh` in one step:

```bash
./setup-lima-proxy.sh [<vm-name>] [--proxy-port <port>]
```

## Configuration

**`config.yaml`** — domain allowlist and per-host options. Copy `config.default.yaml` as your starting point: it's the canonical format reference, with a worked, test-covered example of every section (`hosts`, `services`, `credentials`, and the secrets file).

The options most setups touch:

- **`hosts:`** — a plain hostname (or a `{host: ...}` mapping) is unrestricted. A mapping can add `allow_response_cookies` to filter `Set-Cookie` headers: omit it to pass all through (default), `[]` to strip everything, or a list to allowlist specific cookies. See the `cookies` example in `config.default.yaml`.

### Service presets

One `services:` entry grants a named service exactly the egress it needs — read-only **registry presets** (`go`, `npm`, `docker`, `ghcr`, `pypi`, `crates`; full per-preset host/allows table in [docs/service-presets.md](docs/service-presets.md#presets)) or **scoped API presets** (`github`, `gitlab`) that broker a credential and restrict the host to the repos/orgs or projects/groups named under `scope:`, instead of blanket access:

```yaml
services:
  - go
  - npm
  - service: github
    scope:
      repos: [myorg/myrepo, myorg/other]
      orgs: [myorg-sandbox]           # every repo under this org
    fake_value: "ghp_…fake"           # the CLI holds the fake token, the proxy
    real_value: "${GITHUB_TOKEN}"     # swaps in the real one on the way out
```

`write: true` opts in to issue/PR/comment (or MR/note) writes; `unrestricted: true` is the explicit, logged opt-out from scoping back to blanket host access, and `allow_host: false` brokers a token without granting its host any access at all. See the `services` example in `config.default.yaml` for the full option set (including self-hosted `gitlab` and `graphql`), and [docs/service-presets.md](docs/service-presets.md) for the threat model, restriction design, and known limitations.

### Custom credentials

For services without a preset, `credentials:` entries configure the broker directly: **swap mode** (the agent sends a placeholder `fake_value`; the proxy substitutes the real one before forwarding, and blocks any other non-empty value) or **inject mode** (the proxy sets the header unconditionally — omit `fake_value`). See the `credentials` example in `config.default.yaml`, which shows both forms.

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `PROXY_CONFIG` | `config.yaml` | Path to config YAML (see `config.default.yaml` for example) |
| `PROXY_MGMT_PORT` | `8082` | Management API port the TUI connects to |

## Terminal UI

A terminal UI for monitoring and managing the proxy at runtime:

```bash
uv run python tui.py
# or with a custom port:
uv run python tui.py --port 9000
```

The port defaults to `$PROXY_MGMT_PORT` (or 8082 if unset).

![TUI screenshot](docs/tui-screenshot.svg)

The UI polls every 5 seconds and shows two panels:

- **DENIED** — recent blocked connections, deduplicated by host, newest first. Both kinds of denial return 503 with `Retry-After` to the client, so the **Type** column is how the TUI (not the client) tells them apart: `pending` (host not configured at all, awaiting human approval) vs. `violation` (host is configured but the request failed its registry policy). The full URL of the highlighted row — plus the violation reason, if any — is shown below the panels.
- **ALLOWED** — current allowlist: permanent hosts, temporary allows with live countdown, and restricted hosts with their preset name (dimmed). Temp- or perm-allowing a restricted host lifts its restrictions.

Key bindings:

| Key | Action |
|---|---|
| `↑` / `↓` or `k` / `j` | Navigate rows |
| `Tab` | Switch focus between panels |
| `1` / `2` / `3` | Select duration: 1m / 10m / 2h |
| `d` | Cycle through durations |
| `t` | Temporarily allow the selected denied host |
| `p` | Permanently allow the selected denied host |
| `s` | Open the services view |
| `r` | Force refresh |
| `q` | Quit |

The **services view** (`s`) manages service presets: `a` adds one (pick the service; for self-hosted services enter the host; scoped API presets prompt for each scope param — a blank answer for all of them asks for explicit confirmation before granting unrestricted access — and then for each opt-in flag; for credential services the fake token is auto-generated and the real token is entered once, masked, and stored in `secrets_file` — it is never shown again), `e` edits a scoped service's scope/flags without touching its token, `o` rotates a real token in place, `x` removes a service along with its stored secret. The table's **Scope** column shows the configured scope and flags, with `unrestricted`/unscoped flags highlighted so the blanket-access choice stays visible.

## Management API

Runs on `127.0.0.1:8082` (not proxied).

| Method | Path | Body | Description |
|---|---|---|---|
| GET | `/allowlist` | — | Permanent + active temporary allows |
| GET | `/denied` | — | Recent denied requests |
| POST | `/allow/temp` | `{"host": "…", "duration_seconds": 60}` | Add TTL-based allow; `duration_seconds` defaults to 300 |
| POST | `/allow/permanent` | `{"host": "…"}` | Append to current config file and reload |
| GET | `/services/available` | — | Service preset catalog (name, needs_token, host_param, scope_params, scope_flags, header, fake prefix) |
| GET | `/services` | — | Configured services, redacted (never real tokens) |
| POST | `/services` | `{"service": "github", "host"?: "…", "scope"?: {…}, "unrestricted"?: true, "real_value"?: "…", <flags>}` | Add a service: generates the fake token, stores the real one in `secrets_file`, writes a `${KEY}` ref to config.yaml |
| PUT | `/services` | `{"service": "…", "host"?: "…", "real_value"?: "…", "scope"?: {…}, "unrestricted"?: true, <flags>}` | Rotate the real token and/or edit scope/flags in place (at least one field required) |
| DELETE | `/services` | `{"service": "…", "host"?: "…"}` | Remove the service and its stored secret |

Real credentials are write-only: accepted on POST/PUT `/services`, persisted to `secrets_file`, and never returned by any endpoint.

Reload allowlist without restart: `kill -HUP <pid>`

## Tests

```bash
uv run pytest            # unit tests
uv run pytest test_functional.py -v   # integration tests (starts real proxy)
```

## License

MIT
