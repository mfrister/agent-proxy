"""
Configuration loading and shared proxy state.

Config YAML format:

  secrets_file: /path/to/secrets.yaml   # optional; separate file with secret values

  management_port: 8082                  # management API port (default: 8082)

  happy_eyeballs_delay: 0.25             # race IPv6/IPv4 upstream connects
                                         # (RFC 8305); 0 disables. Works around
                                         # mitmproxy issue #8088; needs restart.

  credentials:
    - host: api.example.com
      header: Authorization
      fake_value: "Bearer sk-fake"       # swap mode: agent sends fake, proxy swaps real
      real_value: "${MY_API_KEY}"        # ${KEY} references a key in secrets_file
    - host: internal.example.com
      header: Cookie
      real_value: "session=abc123"       # inject mode: omit fake_value

  allowed_hosts:
    - api.anthropic.com                  # plain string: all cookies pass through
    - host: platform.claude.com
      allow_response_cookies: []         # no cookies allowed (all stripped)
    - host: internal.example.com
      allow_response_cookies:
        - csrftoken                      # only csrftoken passes through

  allowed_registries: [go, npm, docker]  # read-only package-registry presets
                                         # (see registries.PRESETS and
                                         # docs/registry-presets.md)

  restricted_hosts:                      # custom rule sets, same engine as presets
    - host: artifacts.internal.example.com
      rules:
        - methods: [GET, HEAD]
          path: "/repo/[a-z0-9-]{1,64}/[a-zA-Z0-9._-]{1,128}"
          query:                         # omit `query` to forbid query strings
            version: "[a-z0-9.]{1,32}"
      request_headers: [authorization]   # extras beyond the base header allowlist

  Precedence: allowed_hosts (unrestricted) > temporary allows (unrestricted)
  > restricted rules (403 on violation) > pending approval (503).
  Note: swap-mode credentials on a restricted host require the header to be
  listed in that host's request_headers, or scrubbing removes it before the
  broker sees it. Inject-mode credentials are unaffected (injected post-scrub).

Secrets file format (simple flat key/value map):

  MY_API_KEY: "Bearer sk-real-key-here"
  OTHER_SECRET: "some-value"
"""

import collections
import json
import re
import threading
from dataclasses import dataclass, field

import yaml

import registries


@dataclass
class HostConfig:
    allow_response_cookies: list[str] | None = None
    # None means no restriction; a list (even empty) enables filtering


@dataclass(frozen=True)
class Credential:
    host: str
    header: str
    real_value: str
    fake_value: str | None = None  # None means inject mode


def _expand_secrets(obj, secrets: dict):
    """Recursively expand ${KEY} references in string values using the secrets map."""
    if isinstance(obj, str):
        def replace(m):
            key = m.group(1)
            if key not in secrets:
                raise KeyError(f"Secret key not found in secrets_file: ${{{key}}}")
            return str(secrets[key])
        return re.sub(r'\$\{([^}]+)\}', replace, obj)
    if isinstance(obj, dict):
        return {k: _expand_secrets(v, secrets) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_secrets(item, secrets) for item in obj]
    return obj


def _host_entries(data: dict, section: str) -> list:
    """Validate a section as a list of str-or-dict entries, dicts having a "host" key."""
    entries = data.get(section) or []
    if not isinstance(entries, list):
        raise ValueError(f"{section} must be a list, got {type(entries).__name__}")
    for i, item in enumerate(entries):
        if isinstance(item, str):
            continue
        if not isinstance(item, dict) or not isinstance(item.get("host"), str):
            raise ValueError(f"{section}[{i}] must be a string or a mapping with a 'host' key")
    return entries


@dataclass(frozen=True)
class Config:
    """A complete, validated proxy configuration.

    Built only by Config.load, which parses the YAML and secrets file exactly
    once and raises on any invalid section — so a Config either exists fully
    formed or not at all (no partial policy state).
    """

    allowlist: set[str]
    host_config: dict[str, HostConfig]
    credentials: list[Credential]
    restricted: dict  # host -> registries.HostRules
    management_port: int = 8082
    happy_eyeballs_delay: float = 0.25

    @classmethod
    def load(cls, path: str) -> "Config":
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            print(json.dumps({
                "event": "config_warning",
                "message": f"config file not found: {path}; starting with empty config (deny-all)",
            }))
            data = {}

        secrets = {}
        secrets_path = data.get("secrets_file")
        if secrets_path:
            with open(secrets_path) as f:
                secrets = yaml.safe_load(f) or {}
        data = _expand_secrets(data, secrets)

        allowed_hosts = _host_entries(data, "allowed_hosts")
        restricted_hosts = _host_entries(data, "restricted_hosts")

        allowlist = {i if isinstance(i, str) else i["host"] for i in allowed_hosts}

        credentials = []
        for i, entry in enumerate(data.get("credentials") or []):
            if not isinstance(entry, dict):
                raise ValueError(f"credentials[{i}] must be a mapping")
            missing = [k for k in ("host", "header", "real_value") if k not in entry]
            if missing:
                raise ValueError(f"credentials[{i}] missing required key(s): {', '.join(missing)}")
            credentials.append(Credential(
                host=entry["host"],
                header=entry["header"],
                real_value=entry["real_value"],
                fake_value=entry.get("fake_value"),
            ))

        # Restricted-host rule sets: expand `allowed_registries` preset names,
        # then compile custom `restricted_hosts` entries. A custom entry for a
        # host that a preset also covers replaces the preset's rules for that host.
        restricted = {}
        for name in data.get("allowed_registries") or []:
            if name not in registries.PRESETS:
                raise ValueError(
                    f"Unknown registry preset {name!r}; available: {sorted(registries.PRESETS)}"
                )
            restricted.update(registries.PRESETS[name])
        for item in restricted_hosts:
            restricted[item["host"]] = registries.compile_host_rules(item, source="config")

        for host in sorted(set(restricted) & allowlist):
            print(json.dumps({
                "event": "config_warning",
                "message": (
                    f"host {host} is in both allowed_hosts and a restricted rule set; "
                    "allowed_hosts wins (unrestricted)"
                ),
            }))

        # Per-host cookie rules. Restricted hosts strip all response cookies by
        # default: registries don't need them, and Set-Cookie is a
        # session/tracking channel into the sandbox.
        host_config = {}
        for name in data.get("allowed_registries") or []:
            for host in registries.PRESETS.get(name, {}):
                host_config[host] = HostConfig(allow_response_cookies=[])
        for item in restricted_hosts:
            host_config[item["host"]] = HostConfig(
                allow_response_cookies=item.get("allow_response_cookies", [])
            )
        for item in allowed_hosts:
            if not isinstance(item, str):
                host_config[item["host"]] = HostConfig(
                    allow_response_cookies=item.get("allow_response_cookies")
                )

        return cls(
            allowlist=allowlist,
            host_config=host_config,
            credentials=credentials,
            restricted=restricted,
            management_port=int(data.get("management_port", 8082)),
            happy_eyeballs_delay=float(data.get("happy_eyeballs_delay", 0.25) or 0),
        )


@dataclass
class ProxyState:
    config_path: str  # path to config YAML, used by reload()
    allowlist: set[str] = field(default_factory=set)
    credentials: list[Credential] = field(default_factory=list)
    host_config: dict[str, HostConfig] = field(default_factory=dict)
    restricted: dict = field(default_factory=dict)  # host -> registries.HostRules
    management_port: int = 8082
    temp_allows: dict[str, float] = field(default_factory=dict)  # host -> expires_at (epoch)
    temp_lock: threading.Lock = field(default_factory=threading.Lock)
    deny_log: collections.deque = field(default_factory=lambda: collections.deque(maxlen=1000))
    deny_lock: threading.Lock = field(default_factory=threading.Lock)

    def apply(self, config: Config) -> None:
        """Swap in a validated config.

        Replace-not-mutate: each policy field is rebound to a fresh object, so
        readers on other threads see either the old or the new object, never a
        half-updated one. management_port is intentionally not re-applied —
        the API server is already bound; the port is set once at construction.
        """
        self.allowlist = set(config.allowlist)
        self.host_config = dict(config.host_config)
        self.credentials = list(config.credentials)
        self.restricted = dict(config.restricted)

    def reload(self) -> None:
        """Re-read the config file and apply it. Shared by SIGHUP and the API."""
        self.apply(Config.load(self.config_path))
