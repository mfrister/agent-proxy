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


SERVICE_PRESETS = {
    # Package registries: restricted read-only rule sets, no credential.
    **{name: ServicePreset(name=name, hosts=dict(hosts))
       for name, hosts in registries.PRESETS.items()},

    # GitHub CLI (gh) against github.com. gh sends
    # `Authorization: token <t>` on REST calls to api.github.com.
    "github": ServicePreset(
        name="github",
        hosts={"api.github.com": None},
        credential=CredentialSpec(
            header="Authorization",
            value_template="token {token}",
            on_host="api.github.com",
            fake_prefix="ghp_",
            fake_length=40,   # ghp_ + 36 chars, like a real classic PAT
        ),
    ),

    # GitLab CLI (glab) against a self-hosted instance; the entry supplies the
    # host. glab (go-gitlab) sends `PRIVATE-TOKEN: <t>`, no value prefix.
    "gitlab": ServicePreset(
        name="gitlab",
        host_param=ScopeParam("host", r"[A-Za-z0-9.-]{1,253}", list=False, required=True),
        credential=CredentialSpec(
            header="PRIVATE-TOKEN",
            value_template="{token}",
            fake_prefix="glpat-",
            fake_length=26,   # glpat- + 20 chars, like a real PAT
        ),
    ),
}
