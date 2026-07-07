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

from dataclasses import dataclass, field

import registries


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
    hosts: dict = field(default_factory=dict)
    # host -> registries.HostRules (restricted) | None (fully allowed)
    credential: CredentialSpec | None = None
    param_host: bool = False    # entry must supply `host:`; it is fully allowed
                                # and, when credential.on_host is None, carries
                                # the credential (self-hosted services)


SERVICE_PRESETS = {
    # Package registries: restricted read-only rule sets, no credential.
    **{name: ServicePreset(hosts=dict(hosts))
       for name, hosts in registries.PRESETS.items()},

    # GitHub CLI (gh) against github.com. gh sends
    # `Authorization: token <t>` on REST calls to api.github.com.
    "github": ServicePreset(
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
        param_host=True,
        credential=CredentialSpec(
            header="PRIVATE-TOKEN",
            value_template="{token}",
            fake_prefix="glpat-",
            fake_length=26,   # glpat- + 20 chars, like a real PAT
        ),
    ),
}
