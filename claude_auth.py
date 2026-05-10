"""
Claude subscription OAuth flow and token management.

Facilitates logging into Claude via a Pro/Max subscription from outside the
sandbox VM. The proxy holds the real tokens; the sandbox only ever sees the
configured fake placeholder.

Typical operator workflow
-------------------------
1. Configure ``claude_subscription`` in config.yaml (token_file, etc.).
2. Visit ``http://localhost:<mgmt_port>/claude/login`` in a browser on the host.
3. Complete the Claude login in that browser tab.
4. The callback stores tokens; Claude Code inside the sandbox now works.

Token refresh is handled automatically on every call to ``get_header_value()``.

OAuth endpoints are configurable so they can be updated if Claude's auth URLs
change, or overridden for testing.
"""

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Optional

import httpx


# Anthropic / Claude Code OAuth defaults.
# These match the authorization flow initiated by `claude login`.
DEFAULT_AUTH_URL = "https://claude.ai/oauth/authorize"
DEFAULT_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
DEFAULT_CLIENT_ID = "9d1c250a-e61b-48f7-9a12-c6ac30e5d9a6"
DEFAULT_SCOPES = "openid email profile"

# Refresh proactively this many seconds before the token actually expires.
_REFRESH_BUFFER_SECONDS = 60


class ClaudeAuthError(Exception):
    """Raised when an OAuth operation fails."""


class ClaudeAuthManager:
    """
    Manages Claude subscription OAuth2 PKCE tokens for use by the proxy.

    Thread-safe: all public methods acquire ``_lock`` before touching state.
    Tokens are persisted to ``token_file`` (mode 0600) so they survive proxy
    restarts.

    ``get_header_value()`` is called on every proxied request and returns the
    complete ``Authorization`` header value (e.g. ``"Bearer eyJ..."``) after
    refreshing the token if needed.  It returns ``None`` when no login has been
    completed.
    """

    def __init__(
        self,
        token_file: Path,
        auth_url: str = DEFAULT_AUTH_URL,
        token_url: str = DEFAULT_TOKEN_URL,
        client_id: str = DEFAULT_CLIENT_ID,
        scopes: str = DEFAULT_SCOPES,
    ) -> None:
        self.token_file = Path(token_file)
        self.auth_url = auth_url
        self.token_url = token_url
        self.client_id = client_id
        self.scopes = scopes

        self._lock = threading.Lock()
        self._tokens: Optional[dict] = None
        self._pending_verifier: Optional[str] = None
        self._pending_state: Optional[str] = None
        self._pending_redirect_uri: Optional[str] = None

        self._load_tokens()

    # ── Persistence ────────────────────────────────────────────────────────────

    def _load_tokens(self) -> None:
        if not self.token_file.exists():
            return
        try:
            with open(self.token_file) as f:
                self._tokens = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._tokens = None

    def _save_tokens(self) -> None:
        """Atomically write tokens to disk; sets permissions to 0600."""
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.token_file.with_suffix(".tmp")
        try:
            with open(tmp, "w") as f:
                json.dump(self._tokens, f)
            tmp.replace(self.token_file)
            os.chmod(self.token_file, 0o600)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise

    # ── PKCE helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _make_pkce() -> tuple[str, str]:
        """Return a ``(verifier, S256_challenge)`` pair."""
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return verifier, challenge

    # ── Login flow ─────────────────────────────────────────────────────────────

    def start_login(self, redirect_uri: str) -> str:
        """
        Begin the OAuth PKCE flow.

        Returns the authorization URL that the operator should open in a
        browser.  Internal state (verifier, nonce, redirect_uri) is held in
        memory until ``complete_login()`` is called.
        """
        verifier, challenge = self._make_pkce()
        state = secrets.token_urlsafe(16)

        with self._lock:
            self._pending_verifier = verifier
            self._pending_state = state
            self._pending_redirect_uri = redirect_uri

        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": self.scopes,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        return f"{self.auth_url}?{urllib.parse.urlencode(params)}"

    def complete_login(self, code: str, state: str) -> None:
        """
        Exchange the authorization code for tokens.

        ``state`` must match the value stored by ``start_login()`` (CSRF
        protection).  Raises ``ClaudeAuthError`` on any failure; tokens are
        only written on full success.
        """
        with self._lock:
            if state != self._pending_state:
                raise ClaudeAuthError("State mismatch — possible CSRF attack")
            verifier = self._pending_verifier
            redirect_uri = self._pending_redirect_uri
            self._pending_verifier = None
            self._pending_state = None
            self._pending_redirect_uri = None

        if not verifier or not redirect_uri:
            raise ClaudeAuthError("No login in progress — call start_login() first")

        try:
            resp = httpx.post(
                self.token_url,
                json={
                    "grant_type": "authorization_code",
                    "client_id": self.client_id,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": verifier,
                },
                timeout=15,
            )
        except httpx.RequestError as exc:
            raise ClaudeAuthError(f"Token exchange network error: {exc}") from exc

        if resp.status_code != 200:
            raise ClaudeAuthError(
                f"Token exchange failed: HTTP {resp.status_code} — {resp.text[:300]}"
            )

        data = resp.json()
        with self._lock:
            self._tokens = {
                "access_token": data["access_token"],
                "refresh_token": data.get("refresh_token"),
                "expires_at": time.time() + float(data.get("expires_in", 3600)),
                "token_type": data.get("token_type", "Bearer"),
            }
            self._save_tokens()

    # ── Token access ───────────────────────────────────────────────────────────

    def get_header_value(self) -> Optional[str]:
        """
        Return the complete ``Authorization`` header value for the current
        valid token (e.g. ``"Bearer eyJ..."``), refreshing first if the token
        is within ``_REFRESH_BUFFER_SECONDS`` of expiry.

        Returns ``None`` if no login has been completed.
        """
        with self._lock:
            if not self._tokens:
                return None
            if time.time() > self._tokens["expires_at"] - _REFRESH_BUFFER_SECONDS:
                self._refresh_locked()
            token = self._tokens.get("access_token")
            token_type = self._tokens.get("token_type", "Bearer")

        if not token:
            return None
        return f"{token_type} {token}"

    def _refresh_locked(self) -> None:
        """
        Attempt to refresh the access token.  Must be called with ``_lock``
        held.  On any failure the existing (potentially stale) token is kept
        so the proxy can keep trying on subsequent requests rather than hard-
        failing.
        """
        refresh_token = (self._tokens or {}).get("refresh_token")
        if not refresh_token:
            return

        try:
            resp = httpx.post(
                self.token_url,
                json={
                    "grant_type": "refresh_token",
                    "client_id": self.client_id,
                    "refresh_token": refresh_token,
                },
                timeout=15,
            )
        except httpx.RequestError:
            return  # keep stale token; retry on next request

        if resp.status_code != 200:
            return  # keep stale token rather than clearing it

        data = resp.json()
        self._tokens["access_token"] = data["access_token"]
        self._tokens["expires_at"] = time.time() + float(data.get("expires_in", 3600))
        if "refresh_token" in data:
            self._tokens["refresh_token"] = data["refresh_token"]
        self._save_tokens()

    # ── Status / logout ────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Return a JSON-serialisable dict describing the current auth state."""
        with self._lock:
            if not self._tokens:
                return {"logged_in": False}
            expires_in = max(0.0, self._tokens["expires_at"] - time.time())
            return {
                "logged_in": True,
                "expires_in_seconds": int(expires_in),
                "has_refresh_token": bool(self._tokens.get("refresh_token")),
            }

    def logout(self) -> None:
        """Clear stored tokens from memory and disk."""
        with self._lock:
            self._tokens = None
        self.token_file.unlink(missing_ok=True)
