"""Default-deny authentication for every route.

The platform shipped with none: 101 operations, all of them answering requests
that carried no credential at all. This closes that at the edge rather than
route by route, because a per-route dependency is a list somebody has to
remember to add to, and the route added next week is the one that gets missed.
Everything is denied unless it is on the allowlist below.

Two credential kinds are accepted, because two kinds of caller exist:

* A browser sends the session cookie, set by /api/auth/login. It reaches the
  backend through the Next.js rewrite, so it is same-origin and needs no CORS
  credential dance.
* A machine — the Wazuh/TraceCat alert ingest — sends `Authorization: Bearer
  tip_...` or `X-API-Key`. Those callers cannot log in interactively, and
  giving them a user password would be worse.

AUTH_MODE exists because this is a live SOC pipeline. In `monitor` the
decision is made and logged but the request still runs, so an operator can see
exactly which callers have no credential before anything starts being rejected.
In `enforce` the same decision returns 401. Nothing else differs between them.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import ApiKey, User
from app.security.credentials import SESSION_COOKIE, hash_api_key, read_session

logger = logging.getLogger(__name__)

# Reachable without a credential, and each one for a stated reason.
PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        # The container healthcheck calls this over loopback. Locking it would
        # make the API unstartable rather than secure.
        "/api/health",
        # You cannot present a credential until you have one.
        "/api/auth/login",
        # Answers "am I logged in" for the UI, and returns 401 when not — the
        # frontend needs that answer before it can decide to show the login page.
        "/api/auth/me",
        # Reports the mode and whether this caller is known. The UI reads it to
        # decide whether to show a login wall at all, so it cannot be behind one.
        "/api/auth/status",
    }
)

# Prefixes that are public. Kept separate from exact paths so a stray prefix
# cannot silently expose a whole subtree.
PUBLIC_PREFIXES: tuple[str, ...] = ()


class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        path = request.url.path

        # CORS preflight carries no credentials by definition, and blocking it
        # breaks the browser before the real request is ever attempted.
        if request.method == "OPTIONS":
            return await call_next(request)

        if _is_public(path):
            return await call_next(request)

        identity = _identify(request, settings)
        if identity is not None:
            request.state.identity = identity
            return await call_next(request)

        # An appliance whose webhook cannot carry a header still has to be able
        # to deliver. The exemption is deliberately narrow: this exact address,
        # posting to the ingest route, and nothing else. A read or a delete from
        # the same host is refused like any other anonymous caller.
        trusted = _trusted_ingest(request, settings)
        if trusted is not None:
            request.state.identity = trusted
            logger.info(
                "Ingest accepted from trusted address %s (%s %s) — no credential presented",
                trusted["id"],
                request.method,
                path,
            )
            return await call_next(request)

        mode = str(getattr(settings, "auth_mode", "enforce") or "enforce").strip().lower()
        client = request.client.host if request.client else "unknown"
        if mode == "monitor":
            # Deliberately noisy: the whole point of this mode is that somebody
            # reads these lines and configures the callers they name.
            logger.warning(
                "UNAUTHENTICATED %s %s from %s — allowed because AUTH_MODE=monitor",
                request.method,
                path,
                client,
            )
            request.state.identity = None
            return await call_next(request)

        logger.info("Rejected unauthenticated %s %s from %s", request.method, path, client)
        return JSONResponse(
            status_code=401,
            content={
                "detail": (
                    "Authentication required. Sign in for a session cookie, or send an "
                    "API key as 'Authorization: Bearer tip_...' or 'X-API-Key'."
                )
            },
            headers={"WWW-Authenticate": "Bearer"},
        )


def _trusted_ingest(request: Request, settings) -> dict | None:
    """The network exemption, or None.

    Three things have to line up, and each one is load-bearing:

    * The **peer address** — `request.client.host`, the address the packets
      actually came from. X-Forwarded-For is never consulted: it is a header
      the caller writes, so trusting it would let anyone claim to be the
      appliance. If this API is ever put behind a real reverse proxy, that
      proxy's address becomes the peer and this exemption must be reworked
      rather than pointed at the header.
    * The **method**, POST only.
    * The **path**, from a configured list.

    The reason for the last two: the platform's own frontend container reaches
    this API from the compose bridge, so every browser request arrives from a
    single internal address. An exemption keyed on address alone would hand
    every anonymous browser a complete bypass.
    """
    networks = settings.ingest_trusted_networks
    if not networks:
        return None
    if request.method != "POST":
        return None
    if request.url.path not in settings.ingest_trusted_path_set:
        return None

    peer = request.client.host if request.client else None
    if not peer:
        return None
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return None
    if not any(address in network for network in networks):
        return None
    return {"kind": "trusted_network", "id": peer, "role": "ingest"}


def _is_public(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


def _identify(request: Request, settings) -> dict | None:
    """Who is calling, or None. Never raises — a lookup failure is a refusal."""
    try:
        presented = _presented_api_key(request)
        if presented:
            return _identify_api_key(presented)

        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie:
            user_id = read_session(cookie, settings.session_secret)
            if user_id:
                return _identify_user(user_id)
    except Exception as exc:
        logger.warning("Authentication lookup failed, treating as unauthenticated: %s", exc)
    return None


def _presented_api_key(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return (request.headers.get("x-api-key") or "").strip() or None


def _identify_api_key(presented: str) -> dict | None:
    digest = hash_api_key(presented)
    with Session(sync_engine) as db:
        row = db.execute(select(ApiKey).where(ApiKey.key_hash == digest)).scalars().first()
        if row is None or not row.active:
            return None
        # Last-used is what lets an operator retire a key nobody is sending any
        # more, which is the only way a key list stays honest over time.
        row.last_used_at = datetime.now(timezone.utc)
        row.use_count = int(row.use_count or 0) + 1
        db.commit()
        return {"kind": "api_key", "id": str(row.id), "label": row.label, "role": row.role}


def _identify_user(user_id: str) -> dict | None:
    with Session(sync_engine) as db:
        row = db.get(User, _as_uuid(user_id))
        if row is None or not row.active:
            return None
        return {"kind": "user", "id": str(row.id), "username": row.username, "role": row.role}


def _as_uuid(value: str):
    import uuid as _uuid

    try:
        return _uuid.UUID(str(value))
    except ValueError:
        return None
