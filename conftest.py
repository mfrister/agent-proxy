"""Shared test helpers for the sandbox proxy test suite."""


def _entries(value):
    """Wrap a bare HostRules/None host value as a single-entry list."""
    from config import HostEntry
    return value if isinstance(value, list) else [HostEntry(rules=value)]


def make_state(**overrides):
    """Return a ProxyState with sensible defaults, merged with any overrides.

    `hosts` values may be a bare HostRules (restricted) or None
    (unrestricted), shorthand for a single-entry list.
    """
    from config import ProxyState

    defaults = dict(
        hosts={"allowed.com": None},
        config_path="config.yaml",
    )
    defaults.update(overrides)
    defaults["hosts"] = {h: _entries(v) for h, v in defaults["hosts"].items()}
    return ProxyState(**defaults)


def make_restricted(**spec_overrides):
    """Compiled rules for a simple restricted test host."""
    import registries
    spec = {
        "rules": [
            {"methods": ["GET", "HEAD"], "path": "/pkg/[a-z0-9-]{1,64}",
             "query": {"version": "[a-z0-9.]{1,32}"}},
        ],
    }
    spec.update(spec_overrides)
    return {"registry.example.com": _entries(
        registries.compile_host_rules(spec, source="testpreset"))}
