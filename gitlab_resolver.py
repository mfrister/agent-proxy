"""
Numeric GitLab project IDs for the gitlab service preset.

The preset's rules scope by project path (`/api/v4/projects/team%2Fbackend`),
but GitLab also accepts the numeric ID (`/api/v4/projects/1901`). A
GitLabProjectResolver is the preset's path_resolver (see registries.HostRules
and PathResolverAddon): it looks the ID up on the instance with the entry's
own credential and hands back the same path with the ID replaced by the
encoded project path, so the ordinary rules decide whether it's in scope.
The forwarded request keeps the ID.
"""

import asyncio
import json
import re
import time
from urllib.parse import quote

import httpx

_PROJECT_ID_PATH = re.compile(r"/api/v4/projects/(\d{1,10})((?:/[^?]*)?(?:\?.*)?)", re.DOTALL)

FOUND_TTL = 600.0     # a project moved out of scope stays reachable this long
NOT_FOUND_TTL = 60.0  # 403/404: unknown ID, or one the token can't see
TIMEOUT = 5.0
MAX_CACHE = 10_000    # bounds memory if the agent walks through IDs


class GitLabProjectResolver:
    def __init__(self, host: str, fetch=None, clock=time.monotonic, transport=None):
        self.host = host
        # async (project_id, credential) -> (status, parsed JSON body or None)
        self._fetch = fetch or self._http_fetch
        self._transport = transport  # httpx transport override, for tests
        self._clock = clock
        self._cache = {}    # project id -> (expires_at, project path | None)
        self._pending = {}  # project id -> in-flight lookup task

    async def resolve(self, path_with_query: str, credential) -> str | None:
        m = _PROJECT_ID_PATH.fullmatch(path_with_query)
        if not m:
            return None
        project_id, rest = m.groups()
        project = await self._project_path(project_id, credential)
        if project is None:
            return None
        # Encoded like glab sends it; any character a project path can't
        # contain stays percent-encoded and fails the rules.
        return f"/api/v4/projects/{quote(project, safe='')}{rest}"

    async def _project_path(self, project_id: str, credential) -> str | None:
        cached = self._cache.get(project_id)
        if cached is not None and self._clock() < cached[0]:
            return cached[1]
        task = self._pending.get(project_id)
        if task is None:
            task = asyncio.ensure_future(self._lookup(project_id, credential))
            self._pending[project_id] = task
            task.add_done_callback(lambda _: self._pending.pop(project_id, None))
        # Shielded: one cancelled request mustn't cancel the shared lookup.
        return await asyncio.shield(task)

    async def _lookup(self, project_id: str, credential) -> str | None:
        try:
            status, body = await self._fetch(project_id, credential)
        except (httpx.HTTPError, OSError, ValueError) as e:
            self._log("gitlab_project_resolve_failed", project_id, error=type(e).__name__)
            return None
        path = body.get("path_with_namespace") if isinstance(body, dict) else None
        if status == 200 and isinstance(path, str):
            self._store(project_id, FOUND_TTL, path)
            self._log("gitlab_project_resolved", project_id, path=path)
            return path
        if status in (403, 404):
            self._store(project_id, NOT_FOUND_TTL, None)
        self._log("gitlab_project_resolve_failed", project_id, status=status)
        return None

    def _store(self, project_id: str, ttl: float, path: str | None):
        now = self._clock()
        if len(self._cache) >= MAX_CACHE:
            self._cache = {k: v for k, v in self._cache.items() if now < v[0]}
            while len(self._cache) >= MAX_CACHE:
                del self._cache[next(iter(self._cache))]  # oldest insertion
        self._cache.pop(project_id, None)
        self._cache[project_id] = (now + ttl, path)

    async def _http_fetch(self, project_id: str, credential):
        headers = {credential.header: credential.real_value} if credential else {}
        # Direct, like mitmproxy's own upstream connections; certifi trust
        # store, mitmproxy's default for upstream verification.
        async with httpx.AsyncClient(trust_env=False, timeout=TIMEOUT,
                                     transport=self._transport) as client:
            r = await client.get(f"https://{self.host}/api/v4/projects/{project_id}",
                                 headers=headers)
        return r.status_code, (r.json() if r.status_code == 200 else None)

    def _log(self, event: str, project_id: str, **fields):
        print(json.dumps({"event": event, "host": self.host,
                          "project_id": project_id, **fields}))
