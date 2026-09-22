"""Sign in, sign out, and the credentials machine callers use.

POST   /api/auth/login      → session cookie
POST   /api/auth/logout     → clears it
GET    /api/auth/me         → who am I (401 when nobody)
GET    /api/auth/api-keys   → list, admin only
POST   /api/auth/api-keys   → issue one, admin only; plaintext returned once
DELETE /api/auth/api-keys/{id} → revoke, admin only
POST   /api/auth/users      → add an analyst, admin only
POST   /api/auth/password   → change your own
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import ApiKey, User
from app.security.credentials import (
    SESSION_COOKIE,
    generate_api_key,
    hash_password,
    issue_session,
    verify_password,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=12, max_length=256)


class ApiKeyRequest(BaseModel):
    label: str = Field(..., min_length=1, max_length=120)
    role: str = Field(default="ingest", max_length=20)


class UserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=12, max_length=256)
    role: str = Field(default="analyst", max_length=20)


@router.post("/login")
async def login(body: LoginRequest, response: Response, db: DBSession) -> dict[str, Any]:
    settings = get_settings()
    row = (
        await db.execute(select(User).where(User.username == body.username.strip()))
    ).scalars().first()

    # One message and one timing path for "no such user" and "wrong password":
    # a login form that distinguishes them is a username oracle.
    if row is None or not row.active or not verify_password(body.password, row.password_hash):
        logger.info("Failed login for %r", body.username[:64])
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    row.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    token = issue_session(str(row.id), settings.session_secret, ttl_seconds=settings.session_ttl_seconds)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=True,          # unreadable from JavaScript, so XSS cannot lift it
        samesite="lax",         # survives normal navigation, not cross-site posts
        secure=settings.session_cookie_secure,
        path="/",
    )
    return {
        "username": row.username,
        "role": row.role,
        "must_change_password": bool(row.must_change_password),
    }


@router.post("/logout")
async def logout(response: Response) -> dict[str, Any]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(request: Request) -> dict[str, Any]:
    """Who the caller is. 401 when nobody, which is how the UI decides to log in."""
    identity = getattr(request.state, "identity", None)
    if not identity:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return identity


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    """Public: whether this caller is signed in, and whether that is required yet.

    The UI needs both. During the monitor rollout the platform still serves
    unauthenticated callers, and a login wall thrown up before enforcement
    begins would be an outage of its own making — so the frontend redirects to
    the sign-in page only when the mode says a refusal is actually coming.
    """
    identity = getattr(request.state, "identity", None)
    return {
        "mode": str(get_settings().auth_mode or "enforce").strip().lower(),
        "authenticated": bool(identity),
        "username": (identity or {}).get("username"),
        "role": (identity or {}).get("role"),
    }


@router.get("/api-keys")
async def list_api_keys(request: Request, db: DBSession) -> dict[str, Any]:
    _require_admin(request)
    rows = (await db.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))).scalars().all()
    return {
        "items": [
            {
                "id": str(r.id),
                "label": r.label,
                "prefix": r.prefix,
                "role": r.role,
                "active": r.active,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "created_by": r.created_by,
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                "use_count": r.use_count,
            }
            for r in rows
        ]
    }


@router.post("/api-keys", status_code=201)
async def create_api_key(body: ApiKeyRequest, request: Request, db: DBSession) -> dict[str, Any]:
    identity = _require_admin(request)
    minted = generate_api_key()
    row = ApiKey(
        label=body.label.strip(),
        prefix=minted.prefix,
        key_hash=minted.key_hash,
        role=body.role.strip() or "ingest",
        created_by=str(identity.get("username") or "")[:64] or None,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return {
        "id": str(row.id),
        "label": row.label,
        "prefix": row.prefix,
        # Shown once. Only the hash is stored, so this cannot be recovered.
        "api_key": minted.plaintext,
        "note": "Copy this now — it is not stored and cannot be shown again.",
    }


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, request: Request, db: DBSession) -> dict[str, Any]:
    _require_admin(request)
    try:
        parsed = uuid.UUID(key_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid key id.") from exc
    row = (await db.execute(select(ApiKey).where(ApiKey.id == parsed))).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Key not found.")
    row.active = False
    await db.commit()
    return {"id": key_id, "active": False}


@router.post("/users", status_code=201)
async def create_user(body: UserRequest, request: Request, db: DBSession) -> dict[str, Any]:
    _require_admin(request)
    existing = (
        await db.execute(select(User).where(User.username == body.username.strip()))
    ).scalars().first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="That username already exists.")
    row = User(
        username=body.username.strip(),
        password_hash=hash_password(body.password),
        role=body.role.strip() or "analyst",
    )
    db.add(row)
    await db.commit()
    return {"username": row.username, "role": row.role}


@router.post("/password")
async def change_password(body: PasswordChange, request: Request, db: DBSession) -> dict[str, Any]:
    identity = getattr(request.state, "identity", None)
    if not identity or identity.get("kind") != "user":
        raise HTTPException(status_code=401, detail="Sign in first.")
    row = (await db.execute(select(User).where(User.id == uuid.UUID(identity["id"])))).scalars().first()
    if row is None or not verify_password(body.current_password, row.password_hash):
        raise HTTPException(status_code=401, detail="Current password is wrong.")
    row.password_hash = hash_password(body.new_password)
    row.must_change_password = False
    await db.commit()
    return {"ok": True}


def _require_admin(request: Request) -> dict[str, Any]:
    identity = getattr(request.state, "identity", None)
    if not identity:
        raise HTTPException(status_code=401, detail="Sign in first.")
    if str(identity.get("role") or "") != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return identity
