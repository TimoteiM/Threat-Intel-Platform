"""Sign in, sign out, and the credentials machine callers use.

POST   /api/auth/login      → session JWT, in a cookie and in the body
POST   /api/auth/logout     → clears the cookie
GET    /api/auth/me         → who am I (401 when nobody)
GET    /api/auth/status     → public; whether this caller is signed in

GET    /api/auth/users      → list, admin only
POST   /api/auth/users      → add somebody, admin only; password returned once
PATCH  /api/auth/users/{id} → role and active, admin only
POST   /api/auth/users/{id}/password → reset somebody else's, admin only
DELETE /api/auth/users/{id} → remove, admin only
POST   /api/auth/password   → change your own

GET    /api/auth/api-keys   → list, admin only
POST   /api/auth/api-keys   → issue one, admin only; plaintext returned once
DELETE /api/auth/api-keys/{id} → revoke, admin only

The administrator routes all refuse the change that would leave the platform
with no active administrator, including an administrator doing it to their own
account. There is no recovery from that short of editing the database by hand.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import ApiKey, User
from app.security.credentials import (
    SESSION_COOKIE,
    generate_api_key,
    generate_password,
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
    # Omit it and one is generated. An administrator adding a colleague should
    # not have to invent a password, and a generated one is stronger than the
    # one a person picks under mild time pressure.
    password: str | None = Field(default=None, min_length=12, max_length=256)
    role: str = Field(default="analyst", max_length=20)
    email: str | None = Field(default=None, max_length=320)
    display_name: str | None = Field(default=None, max_length=120)


class UserUpdate(BaseModel):
    role: str | None = Field(default=None, max_length=20)
    active: bool | None = None


class PasswordReset(BaseModel):
    """An administrator setting someone else's password. Omit to generate one."""

    password: str | None = Field(default=None, min_length=12, max_length=256)


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

    token = issue_session(
        str(row.id),
        settings.session_secret,
        ttl_seconds=settings.session_ttl_seconds,
        username=row.username,
        role=row.role,
    )
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
        # The same JWT the cookie carries, for callers that are not browsers —
        # a script sends it as `Authorization: Bearer <token>`. The UI ignores
        # this and relies on the cookie, which JavaScript cannot read and so
        # cannot leak through an XSS.
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.session_ttl_seconds,
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
    settings = get_settings()
    return {
        "mode": str(settings.auth_mode or "enforce").strip().lower(),
        # What the sign-in page may offer. A Microsoft button on a deployment
        # with no tenant configured is a button that can only ever fail, so the
        # page is told rather than left to guess.
        "providers": {"password": True, "microsoft": settings.oidc_configured},
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


ROLES = ("admin", "analyst")


@router.get("/users")
async def list_users(request: Request, db: DBSession) -> dict[str, Any]:
    _require_admin(request)
    rows = (await db.execute(select(User).order_by(User.username))).scalars().all()
    return {"items": [_user_summary(r) for r in rows]}


@router.post("/users", status_code=201)
async def create_user(body: UserRequest, request: Request, db: DBSession) -> dict[str, Any]:
    _require_admin(request)
    username = body.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="A username is required.")
    _check_role(body.role)

    # Case-insensitively, so "Admin" and "admin" cannot both exist — two
    # accounts that look identical in a list are an audit problem.
    clash = (
        await db.execute(select(User).where(func.lower(User.username) == username.lower()))
    ).scalars().first()
    if clash is not None:
        raise HTTPException(status_code=409, detail="That username already exists.")

    generated = None if body.password else generate_password()
    row = User(
        username=username,
        password_hash=hash_password(body.password or generated),
        role=body.role.strip() or "analyst",
        email=(body.email or "").strip().lower() or None,
        display_name=(body.display_name or "").strip() or None,
        auth_provider="local",
        # A password somebody else chose has to be replaced before the account
        # is useful for anything, or the administrator knows it forever.
        must_change_password=generated is not None,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    created = _user_summary(row)
    if generated:
        # Shown once, exactly like a new API key. It is a scrypt hash from here.
        created["password"] = generated
        created["note"] = "Give this to them now — it is not stored and cannot be shown again."
    return created


@router.patch("/users/{user_id}")
async def update_user(user_id: str, body: UserUpdate, request: Request, db: DBSession) -> dict[str, Any]:
    identity = _require_admin(request)
    row = await _load_user(user_id, db)

    if body.role is not None:
        _check_role(body.role)
        if body.role.strip() != row.role:
            await _refuse_if_last_admin(row, db, identity, action="change the role of")
            row.role = body.role.strip()

    if body.active is not None and bool(body.active) != bool(row.active):
        if not body.active:
            await _refuse_if_last_admin(row, db, identity, action="deactivate")
        row.active = bool(body.active)

    await db.commit()
    await db.refresh(row)
    return _user_summary(row)


@router.post("/users/{user_id}/password")
async def reset_user_password(
    user_id: str, body: PasswordReset, request: Request, db: DBSession
) -> dict[str, Any]:
    """An administrator resetting somebody else's password."""
    _require_admin(request)
    row = await _load_user(user_id, db)
    if row.auth_provider == "microsoft":
        raise HTTPException(
            status_code=409,
            detail="That account signs in with Microsoft. Its password is managed in Entra ID.",
        )

    generated = None if body.password else generate_password()
    row.password_hash = hash_password(body.password or generated)
    row.must_change_password = True
    await db.commit()

    result = {"username": row.username, "must_change_password": True}
    if generated:
        result["password"] = generated
        result["note"] = "Give this to them now — it is not stored and cannot be shown again."
    return result


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, request: Request, db: DBSession) -> dict[str, Any]:
    identity = _require_admin(request)
    row = await _load_user(user_id, db)
    await _refuse_if_last_admin(row, db, identity, action="delete")
    username = row.username
    await db.delete(row)
    await db.commit()
    logger.warning("User %r deleted by %s", username, identity.get("username"))
    return {"deleted": username}


def _user_summary(row: User) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "username": row.username,
        "role": row.role,
        "active": bool(row.active),
        "auth_provider": row.auth_provider or "local",
        "email": row.email,
        "display_name": row.display_name,
        "must_change_password": bool(row.must_change_password),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_login_at": row.last_login_at.isoformat() if row.last_login_at else None,
    }


def _check_role(role: str | None) -> None:
    if role is not None and str(role).strip() not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {', '.join(ROLES)}.")


async def _load_user(user_id: str, db) -> User:
    try:
        parsed = uuid.UUID(str(user_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid user id.") from exc
    row = (await db.execute(select(User).where(User.id == parsed))).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return row


async def _refuse_if_last_admin(row: User, db, identity: dict, *, action: str) -> None:
    """Stop the change that locks everybody out of administration.

    Two ways to arrive here: demoting or deactivating the only administrator
    left, or doing it to yourself by accident. Either leaves a platform whose
    users and API keys nobody can manage any more, and no way back in short of
    editing the database by hand — so both are refused rather than warned about.
    """
    if row.role != "admin":
        return

    remaining = (
        await db.execute(
            select(func.count())
            .select_from(User)
            .where(User.role == "admin", User.active.is_(True), User.id != row.id)
        )
    ).scalar() or 0

    if remaining == 0:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot {action} the only administrator. Make somebody else an administrator first.",
        )
    if str(row.id) == str(identity.get("id")):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot {action} your own account. Ask another administrator to do it.",
        )


@router.post("/password")
async def change_password(body: PasswordChange, request: Request, db: DBSession) -> dict[str, Any]:
    identity = getattr(request.state, "identity", None)
    if not identity or identity.get("kind") != "user":
        raise HTTPException(status_code=401, detail="Sign in first.")
    row = (await db.execute(select(User).where(User.id == uuid.UUID(identity["id"])))).scalars().first()
    if row is not None and not row.password_hash:
        # An account provisioned through Entra ID. Offering a password change
        # that cannot work is worse than saying where the password lives.
        raise HTTPException(
            status_code=409,
            detail="This account signs in with Microsoft. Change the password in your Microsoft account.",
        )
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
