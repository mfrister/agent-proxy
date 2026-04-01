## mitmproxy Sandbox Proxy — Implementation Summary

### Context

This proxy acts as the sole network egress point for an LLM agent running in a sandbox. The agent has no direct internet access — all HTTP and HTTPS traffic is forced through mitmproxy, which enforces a domain allowlist, logs what the agent is doing, and brokers API credentials so that real secrets never exist inside the sandbox environment. During development, `mitmweb` provides a live browser UI to inspect flows and debug what the agent is actually reaching out to. The management API is the operational surface for allowlist changes: denied requests are immediately visible, new domains can be permanently added or temporarily unblocked for a limited time window without restarting the proxy.

---

### Architecture

```
Agent process
  └─ HTTP_PROXY=http://proxy:8080
       └─ mitmproxy (port 8080)
            ├─ AllowlistAddon        — domain allow/deny
            ├─ CredentialBrokerAddon — fake→real key swap
            ├─ LoggingAddon          — structured request/deny log
            └─ TempAllowAddon        — TTL-based temporary permits
                 └─ forwarded to upstream API
```

The agent's `HTTP_PROXY` / `HTTPS_PROXY` env vars point at mitmproxy. All traffic, including HTTPS, is intercepted via MITM — mitmproxy's CA cert must be injected into the agent's trust store (e.g. `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, or the OS cert bundle depending on runtime).

---

### Addons

Run headless via `mitmdump -s addon.py`, or with the web UI via `mitmweb -s addon.py` during development. All addons live in one file or a package and share state via a simple in-process store (dict + lock, or SQLite for persistence).

**1. Allowlist + deny logging**
- Permanent allowlist loaded from a YAML/JSON file at startup
- On each `request()` hook: check `flow.request.pretty_host` against the set
- Denied → set `flow.response` to a 403 immediately, log structured entry (timestamp, host, full URL, method) to a deny log
- Reload allowlist from disk on `SIGHUP` for non-temporary changes

**2. Credential broker**
- Mapping of `host → {header, fake_value, real_value}` loaded at startup from env vars or a secrets manager call
- On `request()`: for matching hosts, compare header value to expected fake; if match, replace with real value in-place
- If unexpected value (not fake, not empty): block and alert — indicates prompt injection or agent misbehavior
- Response scrubber on `response()`: scan body for real credential strings, replace with `[REDACTED]` as defense-in-depth
- Real credentials are never logged

**3. Temporary allows**
- In-memory dict of `host → expires_at` timestamp, protected by a lock
- Checked after the permanent allowlist: `now < expires_at` → allow
- A small companion HTTP management API (separate thread, separate port, not proxied) exposes:
  - `GET /denied` — recent deny log
  - `POST /allow/temp {host, duration_seconds}` — add TTL entry
  - `POST /allow/permanent {host}` — append to allowlist file + reload
  - `GET /allowlist` — current state (permanent + active temporaries)

---

### Key Implementation Notes

- **`pretty_host`** resolves the correct hostname for both HTTP and HTTPS flows — prefer it over `flow.request.host`
- **Body rewriting** requires buffering: set `flow.request.stream = False` to ensure the full body is available before the `request()` hook fires
- **`Content-Length`** must be updated after body rewriting — mitmproxy handles this automatically if you assign to `flow.request.content`
- **Don't log real credentials** — audit your logging calls; log the fake value (confirms agent identity) but never the substituted real value
- **Test the scrubber** with a unit test that puts a real credential string into a mock response body — easy to forget edge cases like error responses from the upstream API that echo back the key
