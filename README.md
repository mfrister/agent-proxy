# agent-proxy

mitmproxy addon that acts as the sole HTTP/HTTPS egress point for an LLM agent sandbox. Enforces a domain allowlist, brokers API credentials so real secrets never enter the sandbox, and exposes a management API for runtime changes.

## Setup

```
uv sync
```

## Run

```bash
# headless
PROXY_CREDENTIALS='...' uv run mitmdump -s addon.py

# with web UI
PROXY_CREDENTIALS='...' uv run mitmweb -s addon.py
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

**`config.yaml`** — domain allowlist:

```yaml
allowed_hosts:
  - api.anthropic.com
  - github.com
```

**`PROXY_CREDENTIALS`** — credential mappings (JSON array). The proxy swaps `fake_value` for `real_value` on matching requests, so the agent only ever sees fake keys:

```json
[
  {
    "host": "api.openai.com",
    "header": "Authorization",
    "fake_value": "Bearer sk-fake",
    "real_value": "Bearer sk-real"
  }
]
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `PROXY_CONFIG` | `config.yaml` | Path to allowlist YAML |
| `PROXY_CREDENTIALS` | `[]` | JSON credential mappings |
| `PROXY_MGMT_PORT` | `8081` | Management API port |

## Management API

Runs on `127.0.0.1:8081` (not proxied).

| Method | Path | Body | Description |
|---|---|---|---|
| GET | `/allowlist` | — | Permanent + active temporary allows |
| GET | `/denied` | — | Recent denied requests |
| POST | `/allow/temp` | `{"host": "…", "duration_seconds": 60}` | Add TTL-based allow |
| POST | `/allow/permanent` | `{"host": "…"}` | Append to `config.yaml` and reload |

Reload allowlist without restart: `kill -HUP <pid>`

## Tests

```bash
uv run pytest            # unit tests
uv run pytest test_functional.py -v   # integration tests (starts real proxy)
```
