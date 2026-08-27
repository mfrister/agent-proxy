"""
Configuration loading and shared proxy state.

Config YAML format:

  secrets_file: /path/to/secrets.yaml   # optional; separate file with secret values

  management_port: 8082                  # management API port (default: 8082)

  happy_eyeballs_delay: 0.25             # race IPv6/IPv4 upstream connects
                                         # (RFC 8305); 0 disables. Works around
                                         # mitmproxy issue #8088; needs restart.

  hosts:
    - api.anthropic.com                  # plain string: unrestricted, all cookies pass
    - host: platform.claude.com          # mapping, no `rules`: unrestricted
      allow_response_cookies: []         # no cookies allowed (all stripped)
    - host: internal.example.com
      allow_response_cookies:
        - csrftoken                      # only csrftoken passes through
    - host: artifacts.internal.example.com   # mapping with `rules`: restricted,
      rules:                                 # same engine as service presets
        - methods: [GET, HEAD]
          path: "/repo/[a-z0-9-]{1,64}/[a-zA-Z0-9._-]{1,128}"
          query:                         # omit `query` to forbid query strings
            version: "[a-z0-9.]{1,32}"
      request_headers: [authorization]   # extras beyond the base header allowlist

  services:                              # service presets (see services.SERVICE_PRESETS
    - npm                                # and docs/service-presets.md). Bare string:
    - go                                 # read-only package-registry rule sets.
    - service: github                    # credential presets broker an API token:
      fake_value: "ghp_fake…"            # the CLI sends the fake, the proxy swaps
      real_value: "${GITHUB_TOKEN}"      # in the real one. ${KEY} -> secrets_file.
    - service: gitlab                    # self-hosted services take the host in
      host: gitlab.example.com           # the entry
      fake_value: "glpat-fake…"
      real_value: "${GITLAB_TOKEN}"
      # allow_host: false                # broker the token but don't allowlist the host

  credentials:                           # custom credentials (escape hatch)
    - host: api.example.com
      header: Authorization
      fake_value: "Bearer sk-fake"       # swap mode: agent sends fake, proxy swaps real
      real_value: "${MY_API_KEY}"        # ${KEY} references a key in secrets_file
    - host: internal.example.com
      header: Cookie
      real_value: "session=abc123"       # inject mode: omit fake_value

  Precedence: unrestricted hosts entry > temporary allows (unrestricted)
  > restricted rules (403 on violation) > pending approval (503).
  Note: swap-mode credentials on a restricted host require the header to be
  listed in that host's request_headers, or scrubbing removes it before the
  broker sees it. Inject-mode credentials are unaffected (injected post-scrub).
  Service presets wire this automatically; hand-written `credentials` entries
  on a restricted `hosts:` entry must list the header themselves.

Secrets file format (simple flat key/value map):

  MY_API_KEY: "Bearer sk-real-key-here"
  OTHER_SECRET: "some-value"
"""

import collections
import dataclasses
import json
import re
import threading
from dataclasses import dataclass, field

import yaml

import registries
import services as services_module


@dataclass
class HostConfig:
    allow_response_cookies: list[str] | None = None
    # None means no restriction; a list (even empty) enables filtering


# Structural keys on a `services:` entry that are never a preset-declared
# ScopeFlag -- anything else on the entry must be one, so a typo'd flag name
# (e.g. "wrtie: true") is a hard error instead of a silently-ignored no-op.
_SERVICE_ENTRY_KEYS = frozenset({
    "service", "host", "scope", "unrestricted", "real_value", "fake_value", "allow_host",
})


@dataclass(frozen=True)
class Credential:
    host: str
    header: str
    real_value: str
    fake_value: str | None = None  # None means inject mode
    preset: str | None = None      # service preset that produced this entry
                                   # (informational, like HostRules.source)


def _expand_secret_string(value: str, secrets: dict) -> str:
    """Expand ${KEY} references in a single string value using the secrets map."""
    def replace(m):
        key = m.group(1)
        if key not in secrets:
            raise KeyError(f"Secret key not found in secrets_file: ${{{key}}}")
        return str(secrets[key])
    return re.sub(r'\$\{([^}]+)\}', replace, value)


def _expand_secret_fields(data: dict, secrets: dict) -> dict:
    """Expand ${KEY} references, but only in the fields documented to carry
    them: `real_value`/`fake_value` on `credentials[]` and `services[]`
    entries (see the module docstring and docs/service-presets.md -- these
    are the only documented uses of ${KEY}).

    Deliberately *not* a recursive whole-document expansion: every other
    field (host, scope values, ...) is validated against a pattern after
    this step, and a validation failure echoes the offending value back in
    its ValueError message. Expanding those fields too would let a
    `${KEY}` placed somewhere other than real_value/fake_value (e.g.
    `services[].host` or a `scope:` value) turn a routine pattern-mismatch
    error into a verbatim secret leak, in an HTTP response body (the
    management API surfaces ValueError text to the operator) or on stdout
    (Config.load's startup/SIGHUP path). Restricting expansion to the two
    fields that actually need it closes that channel at the root, rather
    than trying to scrub secrets out of error messages after the fact.
    """
    def expand_entry(entry):
        if not isinstance(entry, dict):
            return entry
        new_entry = dict(entry)
        for key in ("real_value", "fake_value"):
            if isinstance(new_entry.get(key), str):
                new_entry[key] = _expand_secret_string(new_entry[key], secrets)
        return new_entry

    new_data = dict(data)
    for section in ("credentials", "services"):
        if isinstance(new_data.get(section), list):
            new_data[section] = [expand_entry(e) for e in new_data[section]]
    return new_data


def require_bool(container: dict, name: str, default: bool | None = None) -> bool:
    """Read a boolean config/API key strictly.

    Only an actual `True`/`False` is accepted -- never a string ("no",
    "false", "0", ...) or an int (0, 1). YAML happily parses a hand-quoted
    `unrestricted: "no"` as the Python str "no", and a JSON API client can
    send any JSON type for a field; Python's bare `bool(...)` treats any
    non-empty string (including "no" and "false") and any nonzero int as
    truthy. For a key that gates broad access -- `unrestricted`, a service
    scope flag such as `write`/`graphql`, `allow_host` -- that coercion
    silently grants exactly the access the operator (or API caller) meant to
    decline. Being strict here is deliberate, not merely consistent.
    """
    if name not in container:
        if default is None:
            raise ValueError(f"{name!r} is required and must be true or false")
        return default
    value = container[name]
    if not isinstance(value, bool):
        raise ValueError(f"{name!r} must be true or false, got {value!r}")
    return value


def _host_entries(data: dict, section: str = "hosts") -> list:
    """Validate `hosts:` as a list of str-or-dict entries, dicts having a "host" key.

    An entry compiles to a restricted rule set iff it carries a "rules" key;
    otherwise it's unrestricted (a bare string is always unrestricted, since
    there's no mapping to hang a "rules" list off of).
    """
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

    Built only by Config.load or Config.from_data, which parse the config and
    secrets file exactly once and raise on any invalid section — so a Config
    either exists fully formed or not at all (no partial policy state).
    """

    hosts: dict  # host -> registries.HostRules (restricted) | None (unrestricted)
    host_config: dict[str, HostConfig]
    credentials: list[Credential]
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
        return cls.from_data(data)

    @classmethod
    def from_data(cls, data: dict) -> "Config":
        """Validate an already-parsed config dict (no file I/O beyond secrets_file).

        Lets a caller validate a prospective config (e.g. the management API
        checking a rewritten config.yaml) before persisting it, instead of
        writing first and finding out it doesn't load.
        """
        secrets = {}
        secrets_path = data.get("secrets_file")
        if secrets_path:
            with open(secrets_path) as f:
                secrets = yaml.safe_load(f) or {}
        data = _expand_secret_fields(data, secrets)

        if "allowed_registries" in data:
            raise ValueError(
                "allowed_registries was renamed to services; "
                "move the preset names there (e.g. services: [go, npm])"
            )
        if "allowed_hosts" in data:
            raise ValueError(
                "allowed_hosts was merged into hosts; "
                "move entries there unchanged (e.g. hosts: [api.anthropic.com])"
            )
        if "restricted_hosts" in data:
            raise ValueError(
                "restricted_hosts was merged into hosts; "
                "move entries there unchanged (each entry keeps its 'rules' list)"
            )

        host_entries = _host_entries(data)

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

        # Service presets: each `services` entry expands into the existing
        # primitives — hosts (restricted or unrestricted) and brokered
        # credentials. Restricted hosts strip all response cookies by default:
        # registries don't need them, and Set-Cookie is a session/tracking
        # channel into the sandbox.
        hosts = {}
        host_config = {}
        for i, entry in enumerate(data.get("services") or []):
            if isinstance(entry, str):
                entry = {"service": entry}
            if not isinstance(entry, dict) or not isinstance(entry.get("service"), str):
                raise ValueError(
                    f"services[{i}] must be a string or a mapping with a 'service' key"
                )
            name = entry["service"]
            preset = services_module.SERVICE_PRESETS.get(name)
            if preset is None:
                raise ValueError(
                    f"Unknown service preset {name!r}; "
                    f"available: {sorted(services_module.SERVICE_PRESETS)}"
                )

            # host_param generalizes the old bare `param_host: bool` -- the
            # entry supplies the key host_param names (currently always
            # "host") and it's checked against host_param.pattern like any
            # other ScopeParam value.
            resolved_host = None
            if preset.host_param:
                hp = preset.host_param
                raw_host = entry.get(hp.name)
                if not isinstance(raw_host, str):
                    raise ValueError(f"services[{i}] ({name}) requires a {hp.name!r}")
                if not re.fullmatch(hp.pattern, raw_host):
                    raise ValueError(
                        f"services[{i}] ({name}): {hp.name!r} {raw_host!r} "
                        f"does not match the required pattern"
                    )
                resolved_host = raw_host
            elif "host" in entry:
                raise ValueError(f"services[{i}] ({name}) does not take a 'host'")

            spec = preset.credential
            cred_host = None
            if spec is None:
                extra = [k for k in ("real_value", "fake_value") if k in entry]
                if extra:
                    raise ValueError(
                        f"services[{i}] ({name}) takes no credential; "
                        f"unexpected key(s): {', '.join(extra)}"
                    )
            else:
                cred_host = spec.on_host or resolved_host
                missing = [k for k in ("real_value", "fake_value") if not entry.get(k)]
                if missing:
                    raise ValueError(
                        f"services[{i}] ({name}) missing required key(s): "
                        f"{', '.join(missing)}"
                    )
                credentials.append(Credential(
                    host=cred_host,
                    header=spec.header,
                    real_value=spec.wrap(entry["real_value"]),
                    fake_value=spec.wrap(entry["fake_value"]),
                    preset=name,
                ))

            # Any entry key beyond the fixed structural ones must be a
            # preset-declared ScopeFlag -- catches a typo'd flag (e.g.
            # "wrtie: true") that would otherwise silently leave a service
            # more (or less) open than the operator intended.
            known_flags = {f.name: f for f in preset.scope_flags}
            unknown_flags = sorted(
                k for k in entry if k not in _SERVICE_ENTRY_KEYS and k not in known_flags
            )
            if unknown_flags:
                raise ValueError(
                    f"services[{i}] ({name}): unknown key(s) {', '.join(unknown_flags)}; "
                    f"available flags: {sorted(known_flags)}"
                )
            flags = {
                f.name: True for f in preset.scope_flags
                if f.name in entry and require_bool(entry, f.name, False)
            }
            for f in preset.scope_flags:
                if flags.get(f.name) and f.unscoped:
                    print(json.dumps({
                        "event": "service_flag_unscoped",
                        "service": name,
                        "flag": f.name,
                        "message": f"{name}: {f.name} defeats scoping ({f.description})",
                    }))

            # preset.hosts carries only static, always-on hosts (package
            # registries; empty for github/gitlab). A preset that declares
            # scope_params must additionally be scoped or explicitly opted
            # out -- this is the control that closes blanket GitHub/GitLab
            # access: no scope and no opt-out is a hard error, not a warning,
            # because a log line among many is too easy to miss here.
            preset_hosts = dict(preset.hosts)
            if preset.scope_params:
                has_scope = "scope" in entry
                unrestricted = require_bool(entry, "unrestricted", False)
                if has_scope and unrestricted:
                    raise ValueError(
                        f"services[{i}] ({name}): 'scope' and 'unrestricted: true' "
                        f"are mutually exclusive"
                    )
                if not has_scope and not unrestricted:
                    raise ValueError(
                        f"services[{i}] ({name}) must be scoped: set 'scope:' "
                        f"(available params: {sorted(p.name for p in preset.scope_params)}) "
                        f"or 'unrestricted: true' to explicitly opt out of scoping"
                    )
                if unrestricted:
                    # The explicit, logged opt-out -- every host this entry
                    # could otherwise touch (static preset.hosts, plus the
                    # resolved host_param/credential host) is granted
                    # blanket access instead of a compiled rule set.
                    unrestricted_hosts = set(preset.hosts) | {
                        h for h in (resolved_host, cred_host) if h is not None
                    }
                    for h in unrestricted_hosts:
                        preset_hosts[h] = None
                        print(json.dumps({
                            "event": "service_unrestricted",
                            "service": name,
                            "host": h,
                            "message": f"{name}: unrestricted access granted to {h}",
                        }))
                else:
                    escaped = preset.build_scope(entry.get("scope"))
                    spec_by_host = preset.scope_template(escaped, flags, resolved_host)
                    for host, rule_spec in spec_by_host.items():
                        preset_hosts[host] = registries.compile_host_rules(rule_spec, source=name)
            elif resolved_host is not None:
                preset_hosts[resolved_host] = None

            allow_cred_host = require_bool(entry, "allow_host", True)
            # Later `services` entries can overwrite an earlier one's host
            # here (last write wins), unlike the old separate allowlist/
            # restricted split where "unrestricted once added" always won.
            # Harmless today -- no two shipped presets share a host, and
            # scoping is equal-or-more-restrictive than the old default --
            # but a future preset pair sharing a host would make entry order
            # significant; order such entries deliberately.
            for host, rules in preset_hosts.items():
                if rules is not None:
                    hosts[host] = rules
                    host_config[host] = HostConfig(allow_response_cookies=[])
                elif host != cred_host or allow_cred_host:
                    hosts[host] = None

            # A swap-mode credential on a restricted host only works if its
            # header survives that host's header scrubbing; wire it in so
            # combined presets are correct by construction. This now really
            # fires for scoped github/gitlab entries, since their hosts are
            # compiled HostRules instead of always None.
            cred_rules = hosts.get(cred_host)
            if spec is not None and isinstance(cred_rules, registries.HostRules):
                hosts[cred_host] = dataclasses.replace(
                    cred_rules,
                    request_headers=cred_rules.request_headers | {spec.header.lower()},
                )

        # Hand-written `hosts:` entries compile with the same engine and are
        # applied last, so one naming a host a service preset also covers
        # replaces whatever the preset produced for that host — restricted or
        # not, in either direction.
        for item in host_entries:
            if isinstance(item, str):
                hosts[item] = None
                continue
            host = item["host"]
            if "rules" in item:
                hosts[host] = registries.compile_host_rules(item, source="config")
                # A hand-written entry for a host a credentialed service
                # preset also touches replaces that preset's compiled rules
                # entirely -- including the request_headers merge above that
                # keeps the credential header alive through AllowlistAddon's
                # scrubbing. Left alone, CredentialBrokerAddon (which runs
                # after AllowlistAddon) never sees the header to swap, and
                # the request goes upstream unauthenticated -- silently, since
                # that looks like a normal 200, not a policy_violation or a
                # pending approval. Re-wire it the same way, but only for
                # service-preset-generated credentials: a hand-written
                # `credentials:` entry on a restricted `hosts:` entry is
                # documented (module docstring) to need its header listed by
                # the operator, so it's deliberately not covered here.
                preset_headers = {
                    c.header.lower() for c in credentials
                    if c.host == host and c.preset is not None
                }
                if preset_headers:
                    hosts[host] = dataclasses.replace(
                        hosts[host],
                        request_headers=hosts[host].request_headers | preset_headers,
                    )
                    print(json.dumps({
                        "event": "hosts_entry_rewires_credential_header",
                        "host": host,
                        "headers": sorted(preset_headers),
                        "message": (
                            f"{host}: hand-written hosts: entry replaced a "
                            f"credentialed service preset's rules; re-added "
                            f"{sorted(preset_headers)} to request_headers so "
                            f"the credential still reaches upstream"
                        ),
                    }))
                host_config[host] = HostConfig(
                    allow_response_cookies=item.get("allow_response_cookies", [])
                )
            else:
                hosts[host] = None
                host_config[host] = HostConfig(
                    allow_response_cookies=item.get("allow_response_cookies")
                )

        return cls(
            hosts=hosts,
            host_config=host_config,
            credentials=credentials,
            management_port=int(data.get("management_port", 8082)),
            happy_eyeballs_delay=float(data.get("happy_eyeballs_delay", 0.25) or 0),
        )


@dataclass
class ProxyState:
    config_path: str  # path to config YAML, used by reload()
    hosts: dict = field(default_factory=dict)  # host -> registries.HostRules | None
    credentials: list[Credential] = field(default_factory=list)
    host_config: dict[str, HostConfig] = field(default_factory=dict)
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
        self.hosts = dict(config.hosts)
        self.host_config = dict(config.host_config)
        self.credentials = list(config.credentials)

    def reload(self) -> None:
        """Re-read the config file and apply it. Shared by SIGHUP and the API."""
        self.apply(Config.load(self.config_path))
