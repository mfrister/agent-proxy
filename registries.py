r"""
Registry access rules: read-only package-registry presets and the rule engine
that enforces them.

A "restricted host" sits between a fully allowed host and a denied one: requests
are permitted only if they match a per-host rule set (method + anchored path
pattern + query-param allowlist), and use only allowlisted request headers.
A request body is rejected unless the matched rule opts in with allow_body,
in which case it is still bounded by max_body_bytes and, optionally, pinned to
a set of allowed content types. Curated presets for common package registries
live in PRESETS; users can define custom rule sets under `hosts:` in
config.yaml using the same schema (an entry with a `rules` key).

Threat model, restriction design, and known limitations are documented in
docs/service-presets.md.

Pattern guardrails (enforced at compile time, identically for path patterns
and query-value patterns, for presets and user rules alike):
  - Patterns are matched with re.fullmatch, never search.
  - Unbounded quantifiers (*, +, {n,}) are rejected; every repetition must have
    an explicit upper bound.
  - A bounded repeat (e.g. `{0,512}`) whose body can match '/' *opaquely* is
    rejected — not just a bare '.' immediately before the quantifier, but
    every equivalent spelling at any nesting depth: `(?:.)`, `(.)`, a
    negated class/category that doesn't specifically exclude '/' (`[^x]`,
    `\W`, `\S`, `\D`), and so on. Each of these is a near-unbounded wildcard
    in disguise. An explicit, deliberately-scoped character class that lists
    '/' among its members (e.g. `[A-Za-z0-9._/-]{0,512}`) is allowed, since
    that inclusion is visible and intentional rather than implicit.
  - A literal `%` in a path pattern requires allow_percent: true on the rule,
    so percent-encoding smuggling has to be opted into deliberately.
"""

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl

# Private stdlib API: re._parser is the regex engine's own parser (named
# sre_parse before Python 3.11; the project's floor is 3.12.8). It's the only
# sound way to answer "can this bounded repeat's body match '/'?" regardless
# of how many grouping constructs sit between a wildcard-ish construct and
# its quantifier -- a textual/substring check can always be defeated by
# another construct in between (see _find_dangerous_repeat's docstring).
# If this private module is ever removed or restructured, PRESETS (compiled
# at import time, bottom of this file) fails to import and every test errors
# immediately and loudly -- there's no way for a break here to silently stop
# enforcing the guardrail.
import re._parser as _sre_parse


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
    allow_body: bool = False    # permit a non-empty body on this route
    max_body_bytes: int | None = None  # required and > 0 iff allow_body
    content_types: frozenset | None = None  # None = any; else allowed base
                                             # media types (lowercased)


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


_SLASH = ord("/")


def _build_category_slash_table() -> dict:
    """Does each of the six built-in class shorthands (\\d \\D \\s \\S \\w \\W)
    match '/'? Derived by asking re's own parser+matcher rather than
    hardcoded, so it can't silently drift from actual regex semantics if a
    future Python release ever changes what counts as a "word" character.
    """
    table = {}
    for esc in (r"\d", r"\D", r"\s", r"\S", r"\w", r"\W"):
        [(_, members)] = _sre_parse.parse(esc)  # [(IN, [(CATEGORY, cat)])]
        [(_, cat)] = members
        table[cat] = bool(re.compile(esc).fullmatch("/"))
    return table


_CATEGORY_MATCHES_SLASH = _build_category_slash_table()


def _category_matches_slash(cat) -> bool:
    # A category outside the six built-ins (obscure locale/linebreak
    # variants this codebase never writes) is unknown — fail safe.
    return _CATEGORY_MATCHES_SLASH.get(cat, True)


def _members_match_slash(items) -> bool:
    """True if the union of these character-class members (literals, ranges,
    category shorthands — ignoring any leading NEGATE marker) includes '/'.
    """
    for op, av in items:
        if op == _sre_parse.LITERAL and av == _SLASH:
            return True
        if op == _sre_parse.RANGE and av[0] <= _SLASH <= av[1]:
            return True
        if op == _sre_parse.CATEGORY and _category_matches_slash(av):
            return True
    return False


def _in_is_opaque_slash_source(items) -> bool:
    """Classify a character class (the args of a parsed IN node).

    A *negated* class ([^...]) is defined by what it excludes, so it's
    opaque unless the exclusion set specifically covers '/': [^/] can never
    match '/', but [^x] admits it (and everything else) by omission.

    A *positive* class ([...]) is defined by what it explicitly lists, so a
    literal '/' or a range spanning it is a deliberate, visible choice — the
    "rest of path" pattern scoped rule sets need, e.g.
    [A-Za-z0-9._/-]{0,512} — not opaque. The one exception is a
    complement-flavoured shorthand used *inside* a positive class (\\W, \\S,
    \\D): those admit '/' the same way a negated class does, just without a
    top-level NEGATE marker, so they're still opaque.
    """
    negate = bool(items) and items[0][0] == _sre_parse.NEGATE
    members = items[1:] if negate else items
    if negate:
        return not _members_match_slash(members)
    return any(op == _sre_parse.CATEGORY and _category_matches_slash(av)
               for op, av in members)


def _body_has_opaque_slash(subpattern) -> bool:
    """Recursively scan a parsed subpattern for a construct that can match
    '/' *opaquely* — i.e. by not excluding it, rather than by deliberately
    listing it (see _in_is_opaque_slash_source). Called on the body of a
    bounded repeat, since that's what turns "one path segment" into "rest
    of the URL", silently, when repeated ~hundreds of times.
    """
    for op, av in subpattern:
        if op == _sre_parse.ANY:
            return True
        elif op == _sre_parse.NOT_LITERAL:
            if av != _SLASH:
                return True
        elif op == _sre_parse.LITERAL:
            pass  # a specific character, deliberate no matter which one
        elif op == _sre_parse.IN:
            if _in_is_opaque_slash_source(av):
                return True
        elif op in (_sre_parse.MAX_REPEAT, _sre_parse.MIN_REPEAT):
            _, max_, body = av
            if max_ != 0 and _body_has_opaque_slash(body):
                return True
        elif op == _sre_parse.SUBPATTERN:
            if _body_has_opaque_slash(av[3]):
                return True
        elif op == _sre_parse.BRANCH:
            if any(_body_has_opaque_slash(b) for b in av[1]):
                return True
        elif op in (_sre_parse.ASSERT, _sre_parse.ASSERT_NOT):
            pass  # zero-width: a lookaround doesn't add characters to the match
        elif op == _sre_parse.AT:
            pass  # anchor: zero-width
        elif op in (_sre_parse.GROUPREF, _sre_parse.GROUPREF_EXISTS):
            return True  # backreference: captured content unknown — fail safe
        else:
            return True  # any node type not recognised above — fail safe
    return False


def _find_dangerous_repeat(subpattern) -> bool:
    """Walk the whole parsed pattern for a bounded repeat whose body can
    match '/' opaquely, at any nesting depth.

    This replaces a textual/substring search (the previous approach: strip
    escapes and character classes, then look for the literal substring
    '.{'). That approach is structurally unsound — it can always be
    defeated by putting another construct between the wildcard-ish token
    and its quantifier: `(?:.){0,512}`, `(.){0,512}`, `(a.){0,512}` all
    sail past a '.{' substring search untouched. Parsing the pattern with
    the regex engine's own parser and walking the resulting tree catches
    every spelling of "this repeat's body can match '/'" uniformly,
    regardless of how it's nested.
    """
    for op, av in subpattern:
        if op in (_sre_parse.MAX_REPEAT, _sre_parse.MIN_REPEAT):
            _, max_, body = av
            if max_ != 0 and _body_has_opaque_slash(body):
                return True
            if _find_dangerous_repeat(body):
                return True
        elif op == _sre_parse.SUBPATTERN:
            if _find_dangerous_repeat(av[3]):
                return True
        elif op == _sre_parse.BRANCH:
            if any(_find_dangerous_repeat(b) for b in av[1]):
                return True
        elif op in (_sre_parse.ASSERT, _sre_parse.ASSERT_NOT):
            if _find_dangerous_repeat(av[1]):
                return True
    return False


def _assert_no_wildcard_repeat(pattern: str):
    """Reject a bounded repeat (e.g. `{0,512}`) whose body can match '/'
    opaquely — a bare '.', `(?:.)`, `(.)`, a negated class/category that
    doesn't specifically exclude '/' (`[^x]`, `\\W`, `\\S`, `\\D`), etc.,
    at any nesting depth. _assert_bounded only rejects unbounded repetition,
    so `.{0,512}` sails through it — but a bare '.' still matches almost
    anything (including '/'), so that's a ~512-byte near-unbounded wildcard
    wearing a bound as a disguise. Scoped rule sets need genuine "rest of
    path" segments, which makes this reachable in practice; require an
    explicit character class instead (e.g. `[A-Za-z0-9._/-]{0,512}`), which
    this does *not* reject even though it too can match '/' — that's a
    deliberate, visible inclusion rather than an implicit one.
    """
    if _find_dangerous_repeat(_sre_parse.parse(pattern)):
        raise ValueError(
            f"A bounded repeat in this pattern can match '/' without saying "
            f"so explicitly (a bare '.', a negated class/category that "
            f"doesn't exclude '/', etc.) — this silently turns a scoped "
            f"path or query rule into a cross-segment wildcard. Use an "
            f"explicit character class that lists exactly what's allowed, "
            f"e.g. [A-Za-z0-9._/-]{{0,512}}: {pattern!r}"
        )


def _assert_pattern_safe(pattern: str):
    """Both compile-time guardrails (unbounded quantifiers, opaque '/'
    -matching repeats), applied uniformly to every pattern this module
    compiles — path *and* query value — so a future third call site can't
    reintroduce either gap by only calling one of them.
    """
    _assert_bounded(pattern)
    _assert_no_wildcard_repeat(pattern)


def _compile_path(pattern: str, allow_percent: bool) -> re.Pattern:
    _assert_pattern_safe(pattern)
    if "%" in pattern and not allow_percent:
        raise ValueError(
            f"Path pattern contains '%' but rule does not set allow_percent: {pattern!r}"
        )
    return re.compile(pattern)


def literal_alternation(items) -> str:
    """Case-insensitive alternation of re.escape'd literals.

    GitHub and GitLab resolve owner/repo case-insensitively, so a case-sensitive
    match would deny legitimate requests (over-restrictive, never permissive).
    (?i:...) is scoped, so it does not loosen the rest of the pattern.
    """
    return "(?i:" + "|".join(re.escape(i) for i in items) + ")"


def compile_host_rules(spec: dict, source: str) -> HostRules:
    """Compile one host's rule spec (preset data or config.yaml dict)."""
    rules = []
    for r in spec["rules"]:
        allow_percent = bool(r.get("allow_percent", False))
        allow_body = bool(r.get("allow_body", False))
        max_body_bytes = r.get("max_body_bytes")
        if allow_body and not (max_body_bytes and max_body_bytes > 0):
            raise ValueError(
                f"allow_body requires a positive max_body_bytes: {r!r}"
            )
        if max_body_bytes is not None and not allow_body:
            raise ValueError(
                f"max_body_bytes without allow_body has no effect: {r!r}"
            )
        content_types = r.get("content_types")
        if content_types is not None:
            content_types = frozenset(ct.lower() for ct in content_types)
        query = None
        if r.get("query") is not None:
            query = {}
            for name, pat in r["query"].items():
                # Same guardrails as path patterns (_assert_pattern_safe), not
                # just _assert_bounded — a query value has no '/' boundary
                # semantics, but an opaque near-unbounded wildcard there is
                # still a near-unbounded wildcard, and the module-level
                # guardrail contract above covers "presets and user rules
                # alike" without scoping itself to paths only.
                _assert_pattern_safe(pat)
                query[name] = re.compile(pat)
        rules.append(RouteRule(
            methods=frozenset(m.upper() for m in r["methods"]),
            path=_compile_path(r["path"], allow_percent),
            query=query,
            allow_percent=allow_percent,
            allow_body=allow_body,
            max_body_bytes=max_body_bytes,
            content_types=content_types,
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
             headers, body_len: int, content_type: str | None = None):
    """
    Check one request against a host's rules.

    Returns Allowed (with headers to scrub) or Violation (with a reason).
    `headers` is any mapping supporting .items(); mitmproxy Headers works.
    `body_len` should be the actual buffered body length, not a client-supplied
    Content-Length (which can lie).
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

    # Body check comes after the match so it can consult the matched rule
    # (allow_body/max_body_bytes/content_types are per-rule, not per-host).
    if body_len > 0:
        if not rule.allow_body:
            return Violation("request body not allowed")
        if body_len > rule.max_body_bytes:
            return Violation(f"request body exceeds {rule.max_body_bytes} bytes")
        if rule.content_types is not None:
            base = (content_type or "").split(";", 1)[0].strip().lower()
            if base not in rule.content_types:
                return Violation(f"content-type {content_type!r} not allowed for this path")

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
       allow_percent: bool = False, allow_body: bool = False,
       max_body_bytes: int | None = None, content_types: list | None = None) -> dict:
    return {"methods": methods, "path": path, "query": query,
            "allow_percent": allow_percent, "allow_body": allow_body,
            "max_body_bytes": max_body_bytes, "content_types": content_types}


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
