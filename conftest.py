"""Shared test helpers for the sandbox proxy test suite."""


def make_state(**overrides):
    """Return a ProxyState with sensible defaults, merged with any overrides."""
    from config import ProxyState

    defaults = dict(
        allowlist={"allowed.com"},
        config_path="config.yaml",
    )
    defaults.update(overrides)
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
    return {"registry.example.com": registries.compile_host_rules(spec, source="testpreset")}
