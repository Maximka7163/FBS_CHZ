from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import secrets
import threading

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


LOCAL_BROWSER_SESSION_COOKIE = "sellari_local_browser_session"
_LOCAL_BROWSER_SESSION_BYTES = 32
_LOCAL_BROWSER_SESSION_TTL = timedelta(hours=12)
_LOCAL_BROWSER_SESSION_MAX = 64
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def is_well_formed_local_browser_session_id(value: str | None) -> bool:
    return bool(value and _TOKEN_RE.fullmatch(value))


class LocalBrowserSessionStore:
    """Bounded in-memory registry for opaque local browser-session identifiers."""

    def __init__(
        self,
        *,
        ttl: timedelta = _LOCAL_BROWSER_SESSION_TTL,
        max_sessions: int = _LOCAL_BROWSER_SESSION_MAX,
    ) -> None:
        if ttl.total_seconds() <= 0:
            raise ValueError("local browser session TTL must be positive")
        if max_sessions < 1:
            raise ValueError("local browser session capacity must be positive")
        self._ttl = ttl
        self._max_sessions = max_sessions
        self._sessions: dict[str, datetime] = {}
        self._lock = threading.RLock()

    def _prune(self, now: datetime) -> None:
        for session_id, expires_at in list(self._sessions.items()):
            if expires_at <= now:
                self._sessions.pop(session_id, None)
        while len(self._sessions) >= self._max_sessions:
            oldest = next(iter(self._sessions), None)
            if oldest is None:
                break
            self._sessions.pop(oldest, None)

    def resolve(self, presented: str | None) -> tuple[str, bool]:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._prune(now)
            if is_well_formed_local_browser_session_id(presented):
                expires_at = self._sessions.get(presented)
                if expires_at is not None and expires_at > now:
                    return presented, False

            while True:
                session_id = secrets.token_urlsafe(_LOCAL_BROWSER_SESSION_BYTES)
                if session_id not in self._sessions:
                    break
            self._sessions[session_id] = now + self._ttl
            return session_id, True


class LocalBrowserSessionMiddleware(BaseHTTPMiddleware):
    """Issue/validate the invisible local browser binding used by Browser CAdES."""

    async def dispatch(self, request: Request, call_next):
        store = getattr(request.app.state, "local_browser_sessions", None)
        if not isinstance(store, LocalBrowserSessionStore):
            return JSONResponse(
                status_code=503,
                content={
                    "detail": {
                        "code": "LOCAL_BROWSER_SESSION_UNAVAILABLE",
                        "message": "Local browser session registry is unavailable",
                    }
                },
            )

        presented = request.cookies.get(LOCAL_BROWSER_SESSION_COOKIE)
        session_id, issued = store.resolve(presented)
        request.state.local_browser_session_id = session_id

        response = await call_next(request)
        if issued:
            response.set_cookie(
                LOCAL_BROWSER_SESSION_COOKIE,
                session_id,
                httponly=True,
                secure=request.url.scheme == "https",
                samesite="strict",
                path="/",
            )
        return response
