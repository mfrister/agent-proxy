"""
Service presets: named descriptors granting a service controlled egress.

A service preset bundles everything one service needs into a single
`services:` entry in config.yaml:

  - hosts, each either fully allowed or restricted to a read-only rule set
    (package-registry rule data comes from registries.PRESETS), and
  - optionally a brokered credential: the agent's CLI is configured with a
    fake token and the proxy swaps in the real one before forwarding.

Presets are pure descriptors. Config.from_data (config.py) expands them into
the existing primitives — allowlist, restricted, credentials, host_config —
and the existing engines enforce: the rule engine in registries.py for
restricted hosts, CredentialBrokerAddon in addon.py for credentials.

See docs/service-presets.md for the threat model and per-preset details.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

import registries


@dataclass(frozen=True)
class ScopeParam:
    """One key an operator may set under an entry's `scope:` mapping."""

    name: str                  # key under an entry's `scope:` mapping
    pattern: str                # fullmatch-checked against each raw value
    list: bool = True           # True: YAML list; False: scalar
    required: bool = False


@dataclass(frozen=True)
class ScopeFlag:
    """One boolean opt-in key on a service entry, e.g. `write:`, `graphql:`."""

    name: str                  # boolean key on the entry, e.g. "write", "graphql"
    description: str            # shown by the management API and TUI
    unscoped: bool = False      # True: enabling this defeats scoping; warn loudly


@dataclass(frozen=True)
class CredentialSpec:
    """How a service's API token is presented on the wire."""

    header: str
    value_template: str         # contains "{token}", e.g. "token {token}"
    on_host: str | None = None  # literal host the credential attaches to;
                                # None = the entry's `host` (self-hosted services)
    fake_prefix: str = ""       # prefix for auto-generated fake tokens, so the
    fake_length: int = 32       # fake passes the client's local format checks

    def wrap(self, token: str) -> str:
        return self.value_template.replace("{token}", token)


@dataclass(frozen=True)
class ServicePreset:
    name: str = ""               # the SERVICE_PRESETS key; used in error messages
    hosts: dict = field(default_factory=dict)
    # host -> registries.HostRules (restricted) | None (fully allowed)
    credential: CredentialSpec | None = None
    host_param: ScopeParam | None = None
    # entry must supply `host:`, validated against host_param.pattern; when
    # credential.on_host is None the host also carries the credential
    # (self-hosted services). Replaces the old bare `param_host: bool`.
    scope_params: tuple = ()     # tuple[ScopeParam, ...] — keys under `scope:`
    scope_flags: tuple = ()      # tuple[ScopeFlag, ...] — boolean opt-in keys
    scope_template: Callable | None = None
    # (escaped: dict[str, str], flags: dict[str, bool], host: str | None)
    #     -> dict[host, rule-spec dict]

    def build_scope(self, raw: dict) -> dict:
        """Validate raw `scope:` values and return {param: escaped-alternation}.

        Every raw value is checked against its ScopeParam's pattern with
        re.fullmatch, then escaped through registries.literal_alternation --
        the single place operator input turns into regex. scope_template
        only ever sees this escaped output, never a raw operator string, so
        a preset author cannot forget to escape it.
        """
        raw = raw or {}
        known = {p.name: p for p in self.scope_params}
        unknown = sorted(k for k in raw if k not in known)
        if unknown:
            raise ValueError(
                f"{self.name}: unknown scope param(s): {', '.join(unknown)}; "
                f"available: {sorted(known)}"
            )

        escaped = {}
        for param in self.scope_params:
            if param.name not in raw:
                if param.required:
                    raise ValueError(
                        f"{self.name}: scope param {param.name!r} is required"
                    )
                continue
            value = raw[param.name]
            if param.list:
                if not isinstance(value, list) or not value:
                    raise ValueError(
                        f"{self.name}: scope param {param.name!r} must be a "
                        f"non-empty list, got {value!r}"
                    )
                items = value
            else:
                if isinstance(value, list):
                    raise ValueError(
                        f"{self.name}: scope param {param.name!r} must be a "
                        f"single value, not a list: {value!r}"
                    )
                items = [value]
            for item in items:
                if not isinstance(item, str):
                    raise ValueError(
                        f"{self.name}: scope param {param.name!r} value "
                        f"{item!r} must be a string"
                    )
                if not re.fullmatch(param.pattern, item):
                    raise ValueError(
                        f"{self.name}: scope param {param.name!r} value "
                        f"{item!r} does not match the required pattern"
                    )
            escaped[param.name] = registries.literal_alternation(items)

        if self.scope_params and not escaped:
            raise ValueError(
                f"{self.name}: at least one scope param must be supplied "
                f"({', '.join(p.name for p in self.scope_params)})"
            )
        return escaped


# ── GitHub / GitLab scoped rule builders ────────────────────────────────────────
#
# Curated, read-only-by-default rule sets for api.github.com and a self-hosted
# GitLab's /api/v4. `scope_template` callables below receive only the escaped
# alternation text `ServicePreset.build_scope` produces (never a raw operator
# string), plus the entry's boolean flags and (for gitlab) its host. Writes
# and GraphQL are opt-in flags; API access only, git-over-HTTPS is out of
# scope for this change (see docs/service-presets.md).

GH_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
GH_REPO = r"[A-Za-z0-9._-]{1,100}"
GH_NUM = r"\d{1,10}"                       # issue/PR number
GH_SHA = r"[0-9a-fA-F]{4,40}"              # commit/tree/blob sha, full or abbreviated
GH_REF = r"[A-Za-z0-9._/-]{1,250}"         # branch/tag/ref name; may contain '/'
GH_PATH = r"[A-Za-z0-9._/-]{0,512}"        # contents path; explicit class includes '/'
GH_STATE = r"open|closed|all"
GH_PER_PAGE = r"[1-9][0-9]{0,2}"           # 1-999
GH_PAGE = r"[1-9][0-9]{0,3}"               # 1-9999

GL_SEG = r"[A-Za-z0-9._-]{1,100}"          # one namespace/project path segment
GL_IID = r"\d{1,10}"                       # issue/MR internal id
GL_SHA = r"[0-9a-fA-F]{4,40}"
GL_REF = r"[A-Za-z0-9._/-]{1,250}"
GL_PATH = r"[A-Za-z0-9._/%-]{0,512}"       # repository file path; may arrive percent-encoded
GL_STATE = r"opened|closed|merged|all"
GL_PER_PAGE = r"[1-9][0-9]{0,2}"
GL_PAGE = r"[1-9][0-9]{0,3}"

_WRITE_BODY = dict(allow_body=True, max_body_bytes=65_536,
                    content_types=["application/json"])


def _github_rules(escaped: dict, flags: dict, host: str | None) -> dict:
    """Curated read-only (plus opt-in write/graphql) rules for api.github.com.

    {REPOS} is the union of the escaped exact `repos` and each escaped `orgs`
    entry followed by the bounded GH_REPO class -- an org alternative only
    matches when immediately followed by a literal '/', so `myorg` cannot
    prefix-match `myorg-evil`.
    """
    alts = []
    if "repos" in escaped:
        alts.append(escaped["repos"])
    if "orgs" in escaped:
        alts.append(f"{escaped['orgs']}/{GH_REPO}")
    repos = "(?:" + "|".join(alts) + ")"

    rules = [
        registries._r(f"/repos/{repos}"),
        registries._r(f"/repos/{repos}/contents"),
        registries._r(f"/repos/{repos}/contents/{GH_PATH}", query={"ref": GH_REF}),
        registries._r(f"/repos/{repos}/commits",
                      query={"sha": GH_REF, "per_page": GH_PER_PAGE, "page": GH_PAGE}),
        registries._r(f"/repos/{repos}/commits/{GH_SHA}"),
        registries._r(f"/repos/{repos}/branches",
                      query={"per_page": GH_PER_PAGE, "page": GH_PAGE}),
        registries._r(f"/repos/{repos}/branches/{GH_REF}"),
        registries._r(f"/repos/{repos}/pulls",
                      query={"state": GH_STATE, "per_page": GH_PER_PAGE, "page": GH_PAGE}),
        registries._r(f"/repos/{repos}/pulls/{GH_NUM}"),
        registries._r(f"/repos/{repos}/issues",
                      query={"state": GH_STATE, "per_page": GH_PER_PAGE, "page": GH_PAGE}),
        registries._r(f"/repos/{repos}/issues/{GH_NUM}"),
        registries._r(f"/repos/{repos}/git/refs"),
        registries._r(f"/repos/{repos}/git/refs/{GH_REF}"),
        registries._r(f"/repos/{repos}/git/trees/{GH_SHA}", query={"recursive": "0|1|true|false"}),
        registries._r(f"/repos/{repos}/git/blobs/{GH_SHA}"),
    ]

    request_headers = {"authorization"}
    if flags.get("write"):
        request_headers.add("content-type")
        rules += [
            registries._r(f"/repos/{repos}/issues", methods=["POST"], **_WRITE_BODY),
            registries._r(f"/repos/{repos}/issues/{GH_NUM}", methods=["PATCH"], **_WRITE_BODY),
            registries._r(f"/repos/{repos}/issues/{GH_NUM}/comments", methods=["POST"], **_WRITE_BODY),
            registries._r(f"/repos/{repos}/pulls", methods=["POST"], **_WRITE_BODY),
            registries._r(f"/repos/{repos}/pulls/{GH_NUM}", methods=["PATCH"], **_WRITE_BODY),
        ]
    if flags.get("graphql"):
        request_headers.add("content-type")
        rules.append(registries._r("/graphql", methods=["POST"], **_WRITE_BODY))

    return {"api.github.com": {"rules": rules, "request_headers": sorted(request_headers)}}


def _gitlab_encode(alternation: str) -> str:
    """Translate an already-escaped literal_alternation's '/' separators into
    GitLab's %2F project-id encoding. re.escape does not escape '/' (it is
    not a regex metacharacter), so the escaped text still has it literally;
    this is a wire-format transform on that already-safe text, not a second
    pass over raw operator input.
    """
    return alternation.replace("/", "%2[fF]")


def _gitlab_rules(escaped: dict, flags: dict, host: str | None) -> dict:
    """Curated read-only (plus opt-in write) rules for a self-hosted GitLab's
    /api/v4, scoped to {id} = the %2F-encoded project path. Every rule needs
    allow_percent=True since {id} always contains a literal '%'.
    """
    alts = []
    if "projects" in escaped:
        alts.append(_gitlab_encode(escaped["projects"]))
    if "groups" in escaped:
        alts.append(f"{_gitlab_encode(escaped['groups'])}%2[fF]{GL_SEG}")
    project_id = "(?:" + "|".join(alts) + ")"
    base = f"/api/v4/projects/{project_id}"

    rules = [
        registries._r(base, allow_percent=True),
        registries._r(f"{base}/repository/files/{GL_PATH}",
                      query={"ref": GL_REF}, allow_percent=True),
        registries._r(f"{base}/repository/commits",
                      query={"ref_name": GL_REF, "per_page": GL_PER_PAGE, "page": GL_PAGE},
                      allow_percent=True),
        registries._r(f"{base}/repository/commits/{GL_SHA}", allow_percent=True),
        registries._r(f"{base}/repository/branches",
                      query={"per_page": GL_PER_PAGE, "page": GL_PAGE}, allow_percent=True),
        registries._r(f"{base}/repository/branches/{GL_REF}", allow_percent=True),
        registries._r(f"{base}/merge_requests",
                      query={"state": GL_STATE, "per_page": GL_PER_PAGE, "page": GL_PAGE},
                      allow_percent=True),
        registries._r(f"{base}/merge_requests/{GL_IID}", allow_percent=True),
        registries._r(f"{base}/issues",
                      query={"state": GL_STATE, "per_page": GL_PER_PAGE, "page": GL_PAGE},
                      allow_percent=True),
        registries._r(f"{base}/issues/{GL_IID}", allow_percent=True),
        registries._r(f"{base}/repository/tree",
                      query={"ref": GL_REF, "path": GL_PATH, "per_page": GL_PER_PAGE,
                             "page": GL_PAGE},
                      allow_percent=True),
        registries._r(f"{base}/repository/blobs/{GL_SHA}", allow_percent=True),
    ]

    request_headers = {"private-token"}
    if flags.get("write"):
        request_headers.add("content-type")
        write_kwargs = {**_WRITE_BODY, "allow_percent": True}
        rules += [
            registries._r(f"{base}/issues", methods=["POST"], **write_kwargs),
            registries._r(f"{base}/issues/{GL_IID}", methods=["PUT"], **write_kwargs),
            registries._r(f"{base}/issues/{GL_IID}/notes", methods=["POST"], **write_kwargs),
            registries._r(f"{base}/merge_requests", methods=["POST"], **write_kwargs),
            registries._r(f"{base}/merge_requests/{GL_IID}", methods=["PUT"], **write_kwargs),
        ]

    return {host: {"rules": rules, "request_headers": sorted(request_headers)}}


SERVICE_PRESETS = {
    # Package registries: restricted read-only rule sets, no credential.
    **{name: ServicePreset(name=name, hosts=dict(hosts))
       for name, hosts in registries.PRESETS.items()},

    # GitHub CLI (gh) against github.com. gh sends
    # `Authorization: token <t>` on REST calls to api.github.com.
    #
    # No `hosts` entry: api.github.com is reachable only through
    # scope_template below. Config.from_data requires every entry to supply
    # either `scope:` (compiled through scope_template) or the explicit,
    # logged `unrestricted: true` opt-out -- there is no default-open path.
    "github": ServicePreset(
        name="github",
        credential=CredentialSpec(
            header="Authorization",
            value_template="token {token}",
            on_host="api.github.com",
            fake_prefix="ghp_",
            fake_length=40,   # ghp_ + 36 chars, like a real classic PAT
        ),
        scope_params=(
            ScopeParam("repos", rf"{GH_OWNER}/{GH_REPO}"),   # exact owner/repo
            ScopeParam("orgs", GH_OWNER),                    # every repo under an org
        ),
        scope_flags=(
            ScopeFlag("write", "allow issue/PR/comment writes"),
            ScopeFlag("graphql", "allow POST /graphql — UNSCOPED", unscoped=True),
        ),
        scope_template=_github_rules,
    ),

    # GitLab CLI (glab) against a self-hosted instance; the entry supplies the
    # host. glab (go-gitlab) sends `PRIVATE-TOKEN: <t>`, no value prefix.
    #
    # See the github preset's comment above: the operator-supplied host is
    # scoped through scope_template by default, same as github; there is no
    # `hosts` entry granting it blanket access.
    "gitlab": ServicePreset(
        name="gitlab",
        host_param=ScopeParam("host", r"[A-Za-z0-9.-]{1,253}", list=False, required=True),
        credential=CredentialSpec(
            header="PRIVATE-TOKEN",
            value_template="{token}",
            fake_prefix="glpat-",
            fake_length=26,   # glpat- + 20 chars, like a real PAT
        ),
        scope_params=(
            ScopeParam("projects", rf"{GL_SEG}(?:/{GL_SEG}){{1,10}}"),  # nested subgroups
            ScopeParam("groups", rf"{GL_SEG}(?:/{GL_SEG}){{0,9}}"),
        ),
        scope_flags=(
            ScopeFlag("write", "allow issue/MR/note writes"),
        ),
        scope_template=_gitlab_rules,
    ),
}
