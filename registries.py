"""
Registry access rules: read-only package-registry presets and the rule engine
that enforces them.

A "restricted host" sits between a fully allowed host and a denied one: requests
are permitted only if they match a per-host rule set (method + anchored path
pattern + query-param allowlist), carry no body, and use only allowlisted
request headers. Curated presets for common package registries live in PRESETS;
users can define custom rule sets under `restricted_hosts` in config.yaml using
the same schema.

Threat model, restriction design, and known limitations are documented in
docs/service-presets.md.

Pattern guardrails (enforced at compile time, for presets and user rules alike):
  - Patterns are matched with re.fullmatch, never search.
  - Unbounded quantifiers (*, +, {n,}) are rejected; every repetition must have
    an explicit upper bound.
  - A literal `%` in a path pattern requires allow_percent: true on the rule,
    so percent-encoding smuggling has to be opted into deliberately.
"""

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl


# ── Rule schema ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RouteRule:
    methods: frozenset          # e.g. frozenset({"GET", "HEAD"})
    path: re.Pattern            # matched with .fullmatch() against the path (no query)
    query: dict | None = None   # param name -> compiled value pattern.
                                # None = query string must be absent.
                                # A "*" key matches any parameter whose name
                                # fullmatches _WILDCARD_PARAM_NAME (CDN signed URLs).
    allow_percent: bool = False # permit literal % in the request path


@dataclass(frozen=True)
class HostRules:
    rules: tuple                    # tuple[RouteRule, ...]
    request_headers: frozenset = frozenset()  # extras beyond BASE_REQUEST_HEADERS
    max_url_len: int = 4096
    source: str = ""                # preset name or "config" — for logging


@dataclass(frozen=True)
class Allowed:
    drop_headers: tuple = ()    # header names to delete before forwarding
    clamp_headers: tuple = ()   # (header name, max length) pairs to truncate


@dataclass(frozen=True)
class Violation:
    reason: str


# ── Request-header policy ──────────────────────────────────────────────────────

# Headers any restricted host may receive. Everything else is scrubbed: header
# values only reach the registry operator once host/path/query are pinned, but
# scrubbing prevents accidental credential leakage (Cookie etc.) and protocol
# tricks (Upgrade is absent, so no WebSocket).
BASE_REQUEST_HEADERS = frozenset({
    "host", "accept", "accept-encoding", "user-agent", "connection",
    "content-length", "range", "if-none-match", "if-modified-since", "te",
})

HEADER_VALUE_CAPS = {
    "accept": 1024,        # Docker clients send long media-type lists
    "user-agent": 512,     # pip's UA embeds platform JSON
    "authorization": 8192, # registry-issued Bearer tokens (Docker Hub, GHCR)
    "if-none-match": 512,
}
DEFAULT_HEADER_VALUE_CAP = 256

_WILDCARD_PARAM_NAME = re.compile(r"[A-Za-z0-9_.-]{1,40}")


# ── Pattern compilation with guardrails ────────────────────────────────────────

_CHAR_CLASS = re.compile(r"\[(?:\\.|[^\]])*\]")
_ESCAPE = re.compile(r"\\.")


def _assert_bounded(pattern: str):
    """Reject unbounded repetition so no pattern can match arbitrary data."""
    stripped = _ESCAPE.sub("E", _CHAR_CLASS.sub("C", pattern))
    if "*" in stripped or "+" in stripped or re.search(r"\{\d+,\}", stripped):
        raise ValueError(
            f"Unbounded quantifier (*, + or {{n,}}) in pattern: {pattern!r}"
        )


def _compile_path(pattern: str, allow_percent: bool) -> re.Pattern:
    _assert_bounded(pattern)
    if "%" in pattern and not allow_percent:
        raise ValueError(
            f"Path pattern contains '%' but rule does not set allow_percent: {pattern!r}"
        )
    return re.compile(pattern)


def compile_host_rules(spec: dict, source: str) -> HostRules:
    """Compile one host's rule spec (preset data or config.yaml dict)."""
    rules = []
    for r in spec["rules"]:
        allow_percent = bool(r.get("allow_percent", False))
        query = None
        if r.get("query") is not None:
            query = {}
            for name, pat in r["query"].items():
                _assert_bounded(pat)
                query[name] = re.compile(pat)
        rules.append(RouteRule(
            methods=frozenset(m.upper() for m in r["methods"]),
            path=_compile_path(r["path"], allow_percent),
            query=query,
            allow_percent=allow_percent,
        ))
    return HostRules(
        rules=tuple(rules),
        request_headers=frozenset(h.lower() for h in spec.get("request_headers", [])),
        max_url_len=int(spec.get("max_url_len", 4096)),
        source=source,
    )


# ── Evaluation ─────────────────────────────────────────────────────────────────

def _check_query(rule: RouteRule, query: str):
    """Return a violation reason string, or None if the query string is OK."""
    if rule.query is None:
        return None if query == "" else "query string not allowed for this path"
    if query == "":
        return None
    # keep_blank_values=True so valueless fields ("?flag") are still returned
    # and validated rather than silently dropped-and-forwarded.
    for name, value in parse_qsl(query, keep_blank_values=True):
        pat = rule.query.get(name)
        if pat is None and "*" in rule.query and _WILDCARD_PARAM_NAME.fullmatch(name):
            pat = rule.query["*"]
        if pat is None:
            return f"query parameter {name!r} not allowed"
        if not pat.fullmatch(value):
            return f"query parameter {name!r} has a disallowed value"
    return None


def evaluate(host_rules: HostRules, method: str, path_with_query: str,
             headers, has_body: bool):
    """
    Check one request against a host's rules.

    Returns Allowed (with headers to scrub) or Violation (with a reason).
    `headers` is any mapping supporting .items(); mitmproxy Headers works.
    """
    if len(path_with_query) > host_rules.max_url_len:
        return Violation(f"URL exceeds {host_rules.max_url_len} characters")

    path, _, query = path_with_query.partition("?")
    if ".." in path or "%2e" in path.lower():
        return Violation("path contains a traversal sequence")

    reason = "path does not match any allowed pattern for this host"
    matched = False
    for rule in host_rules.rules:
        if "%" in path and not rule.allow_percent:
            continue
        if not rule.path.fullmatch(path):
            continue
        if method.upper() not in rule.methods:
            reason = f"method {method} not allowed for this path"
            continue
        query_error = _check_query(rule, query)
        if query_error:
            reason = query_error
            continue
        matched = True
        break
    if not matched:
        return Violation(reason)

    if has_body:
        return Violation("request body not allowed")

    allowed_headers = BASE_REQUEST_HEADERS | host_rules.request_headers
    drop, clamp = [], []
    for name, value in headers.items():
        lname = name.lower()
        if lname not in allowed_headers:
            drop.append(name)
            continue
        cap = HEADER_VALUE_CAPS.get(lname, DEFAULT_HEADER_VALUE_CAP)
        if len(value) > cap:
            clamp.append((name, cap))
    return Allowed(drop_headers=tuple(drop), clamp_headers=tuple(clamp))


# ── Preset data ────────────────────────────────────────────────────────────────
#
# Patterns are deliberately grammar-based: bounded segment lengths and tight
# character classes rather than entropy heuristics. See docs/service-presets.md
# for the per-registry rationale and residual risks.

def seg(chars: str, lo: int, hi: int) -> str:
    """One bounded path segment: a character class with an explicit length range."""
    return f"[{chars}]{{{lo},{hi}}}"


HEX64 = "[a-f0-9]{64}"
GO_MODULE = seg(r"a-z0-9._~!/-", 1, 250)      # ! = bang-encoded uppercase
GO_VERSION = seg(r"a-zA-Z0-9.+~_!-", 1, 100)  # semver incl. pseudo-versions, +incompatible
NPM_NAME = seg(r"a-zA-Z0-9._-", 1, 214)       # uppercase for legacy packages (JSONStream)
NPM_FILE = seg(r"a-zA-Z0-9._-", 1, 224)
OCI_SEG = r"[a-z0-9][a-z0-9._-]{0,127}"
OCI_NAME = f"{OCI_SEG}(?:/{OCI_SEG}){{0,3}}"
OCI_TAG = r"[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}"
OCI_REF = f"(?:sha256:{HEX64}|{OCI_TAG})"
SUMDB_TILE = r"tile/\d{1,2}/(?:\d{1,2}|data)/(?:x\d{3}/){0,3}\d{1,3}(?:\.p/\d{1,3})?"
PYPI_PROJECT = seg("a-z0-9-", 1, 128)         # PEP 503 normalized names
CRATE = seg("a-z0-9_-", 1, 64)
CRATE_VERSION = seg(r"a-zA-Z0-9.+-", 1, 64)
# CDN signed-URL query values (decoded): base64ish plus timestamp separators.
# parse_qsl decodes '+' to space, hence the space in the class.
CDN_VALUE = seg(r"A-Za-z0-9 %+/=:@._~-", 0, 600)

GET_HEAD = ["GET", "HEAD"]


def _r(path: str, query: dict | None = None, methods: list = GET_HEAD,
       allow_percent: bool = False) -> dict:
    return {"methods": methods, "path": path, "query": query,
            "allow_percent": allow_percent}


def _preset(name: str, hosts: dict) -> dict:
    return {host: compile_host_rules(spec, source=name) for host, spec in hosts.items()}


PRESETS = {
    # Go module proxy + checksum DB. The toolchain fetches the sumdb *through*
    # the module proxy by default (/sumdb/... paths), so both shapes are needed.
    "go": _preset("go", {
        "proxy.golang.org": {"rules": [
            _r(f"/{GO_MODULE}/@v/list"),
            _r(f"/{GO_MODULE}/@v/{GO_VERSION}\\.(?:info|mod|zip)"),
            _r(f"/{GO_MODULE}/@latest"),
            _r(r"/sumdb/sum\.golang\.org/supported"),
            _r(r"/sumdb/sum\.golang\.org/latest"),
            _r(f"/sumdb/sum\\.golang\\.org/lookup/{GO_MODULE}@{GO_VERSION}"),
            _r(f"/sumdb/sum\\.golang\\.org/{SUMDB_TILE}"),
        ]},
        "sum.golang.org": {"rules": [
            _r("/latest"),
            _r(f"/lookup/{GO_MODULE}@{GO_VERSION}"),
            _r(f"/{SUMDB_TILE}"),
        ]},
    }),

    # npm packuments + tarballs. Audit (POST, ships the whole dependency tree)
    # and search (?text=...) stay blocked by design; npm works with --no-audit.
    "npm": _preset("npm", {
        "registry.npmjs.org": {"rules": [
            _r(f"/{NPM_NAME}"),
            _r(f"/@{NPM_NAME}/{NPM_NAME}"),
            _r(f"/@{NPM_NAME}%2[fF]{NPM_NAME}", allow_percent=True),
            _r(f"/{NPM_NAME}/-/{NPM_FILE}\\.tgz"),
            _r(f"/@{NPM_NAME}/{NPM_NAME}/-/{NPM_FILE}\\.tgz"),
        ]},
    }),

    # Docker Hub: registry API, token endpoint (scope pinned to :pull), and the
    # CDN hosts that blob GETs redirect to (Cloudflare or CloudFront, varies
    # over time/region — same path shape and signed-URL params on both).
    "docker": _preset("docker", {
        "registry-1.docker.io": {
            "rules": [
                _r("/v2/"),
                _r(f"/v2/{OCI_NAME}/manifests/{OCI_REF}"),
                _r(f"/v2/{OCI_NAME}/blobs/sha256:{HEX64}"),
            ],
            "request_headers": ["authorization"],
        },
        "auth.docker.io": {"rules": [
            _r("/token", methods=["GET"], query={
                "service": r"registry\.docker\.io",
                "scope": f"repository:{OCI_NAME}:pull",
                "account": seg("a-zA-Z0-9._-", 1, 64),
                "client_id": seg("a-zA-Z0-9._-", 1, 64),
            }),
        ]},
        "production.cloudflare.docker.com": {"rules": [
            _r(f"/registry-v2/docker/registry/v2/blobs/sha256/[a-f0-9]{{2}}/{HEX64}/data",
               query={"*": CDN_VALUE}),
        ]},
        "production.cloudfront.docker.com": {"rules": [
            _r(f"/registry-v2/docker/registry/v2/blobs/sha256/[a-f0-9]{{2}}/{HEX64}/data",
               query={"*": CDN_VALUE}),
        ]},
    }),

    # GitHub Container Registry + its blob CDN.
    "ghcr": _preset("ghcr", {
        "ghcr.io": {
            "rules": [
                _r("/v2/"),
                _r("/token", methods=["GET"], query={
                    "service": r"ghcr\.io",
                    "scope": f"repository:{OCI_NAME}:pull",
                }),
                _r(f"/v2/{OCI_NAME}/manifests/{OCI_REF}"),
                _r(f"/v2/{OCI_NAME}/blobs/sha256:{HEX64}"),
            ],
            "request_headers": ["authorization"],
        },
        "pkg-containers.githubusercontent.com": {"rules": [
            _r(f"/ghcr1/blobs/sha256:{HEX64}", query={"*": CDN_VALUE}),
        ]},
    }),

    # PyPI simple index + file host. % allowed in filenames (encoded '+' in
    # wheel local versions).
    "pypi": _preset("pypi", {
        "pypi.org": {"rules": [
            _r("/simple/"),
            _r(f"/simple/{PYPI_PROJECT}/?"),
            _r(f"/pypi/{PYPI_PROJECT}/json"),
        ]},
        "files.pythonhosted.org": {"rules": [
            _r(f"/packages/(?:{seg('A-Za-z0-9._+-', 1, 64)}/){{2,4}}"
               f"{seg('A-Za-z0-9._+%-', 1, 256)}",
               allow_percent=True),
        ]},
    }),

    # crates.io: sparse index, API download endpoint, and static file host.
    "crates": _preset("crates", {
        "index.crates.io": {"rules": [
            _r(r"/config\.json"),
            _r(f"/1/{seg('a-z0-9_-', 1, 1)}"),
            _r(f"/2/{seg('a-z0-9_-', 2, 2)}"),
            _r(f"/3/{seg('a-z0-9_-', 1, 1)}/{seg('a-z0-9_-', 3, 3)}"),
            _r(f"/{seg('a-z0-9_-', 2, 2)}/{seg('a-z0-9_-', 2, 2)}/{seg('a-z0-9_-', 4, 64)}"),
        ]},
        "crates.io": {"rules": [
            _r(f"/api/v1/crates/{CRATE}/{CRATE_VERSION}/download"),
        ]},
        "static.crates.io": {"rules": [
            _r(f"/crates/{CRATE}/{CRATE}-{CRATE_VERSION}\\.crate"),
            _r(f"/crates/{CRATE}/{CRATE_VERSION}/download"),
        ]},
    }),
}
