"""Sign in with a Microsoft work account.

GET /api/auth/oidc/start     → redirects the browser to Entra ID
GET /api/auth/oidc/callback  → validates the reply and issues our session cookie

Both are public, necessarily: someone who has not signed in yet has no
credential to present. What protects them is the signed flow cookie, not the
middleware — see app/security/oidc.py for what each guard is there to stop.

The end of a successful flow is the *same* session cookie `POST /auth/login`
issues. Nothing downstream — middleware, route handlers, the UI — knows or
cares which way somebody got in, so single sign-on adds no second notion of
what it means to be authenticated.

Failures always land back on /login with a short code rather than a stack trace
or a JSON body. The person who needs the detail is the operator reading the
log; the person seeing the page is either a colleague whose account is not set
up, or someone probing.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select

from app.config import get_settings
from app.dependencies import DBSession
from app.models.database import User
from app.security import oidc
from app.security.credentials import SESSION_COOKIE, issue_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth/oidc", tags=["auth"])


@router.get("/start")
async def start(request: Request, next: str = "/dashboard") -> RedirectResponse:
    settings = get_settings()
    if not settings.oidc_configured:
        return _back_to_login("sso_unavailable")

    flow = oidc.start_flow(next)
    try:
        metadata = await oidc.get_metadata(settings.oidc_tenant_id)
        destination = oidc.authorization_url(metadata, settings, flow)
    except oidc.OIDCError as exc:
        logger.error("Could not begin Microsoft sign-in: %s", exc)
        return _back_to_login("sso_unavailable")

    response = RedirectResponse(destination, status_code=302)
    response.set_cookie(
        oidc.OIDC_FLOW_COOKIE,
        oidc.seal_flow(flow, settings.session_secret),
        max_age=oidc.FLOW_TTL_SECONDS,
        httponly=True,
        # Lax, not Strict: the callback arrives as a top-level navigation from
        # login.microsoftonline.com, and Strict would withhold the cookie on
        # exactly that request — the flow would fail every single time.
        samesite="lax",
        secure=settings.session_cookie_secure,
        path="/",
    )
    return response


@router.get("/callback")
async def callback(
    request: Request,
    db: DBSession,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> RedirectResponse:
    settings = get_settings()
    if not settings.oidc_configured:
        return _back_to_login("sso_unavailable")

    flow = oidc.open_flow(request.cookies.get(oidc.OIDC_FLOW_COOKIE), settings.session_secret)

    if error:
        # Entra declined — consent withheld, blocked by Conditional Access, or
        # the person simply cancelled. Their own error page already explained.
        logger.warning("Microsoft sign-in returned %s: %s", error, str(error_description)[:300])
        return _clear_flow(_back_to_login("sso_failed"))

    if flow is None:
        # No cookie, or it expired, or it was tampered with. Also what an
        # unsolicited callback looks like, which is the attack this stops.
        logger.warning("Microsoft sign-in callback with no valid flow cookie")
        return _clear_flow(_back_to_login("sso_expired"))

    if not code or not state or not _same(state, flow.state):
        logger.warning("Microsoft sign-in callback failed the state check")
        return _clear_flow(_back_to_login("sso_failed"))

    try:
        metadata = await oidc.get_metadata(settings.oidc_tenant_id)
        tokens = await oidc.exchange_code(metadata, settings, code=code, verifier=flow.verifier)
        claims = await oidc.validate_id_token(
            tokens["id_token"], metadata, settings, expected_nonce=flow.nonce
        )
        principal = oidc.principal_from_claims(claims)
        oidc.check_domain(principal.email, settings)
    except oidc.OIDCError as exc:
        logger.warning("Microsoft sign-in rejected: %s", exc)
        return _clear_flow(_back_to_login("sso_failed"))
    except Exception as exc:  # noqa: BLE001 — a sign-in must never 500 at a user
        logger.error("Microsoft sign-in failed unexpectedly: %s", exc, exc_info=True)
        return _clear_flow(_back_to_login("sso_failed"))

    user = await _resolve_user(db, principal, settings)
    if user is None:
        logger.warning("Microsoft sign-in by %s has no account here", principal.email)
        return _clear_flow(_back_to_login("sso_no_account"))

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    logger.info("Microsoft sign-in: %s (%s)", user.username, principal.email)
    response = _clear_flow(RedirectResponse(flow.next_path, status_code=302))
    response.set_cookie(
        SESSION_COOKIE,
        issue_session(
            str(user.id),
            settings.session_secret,
            ttl_seconds=settings.session_ttl_seconds,
            username=user.username,
            role=user.role,
        ),
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        path="/",
    )
    return response


async def _resolve_user(db, principal: oidc.Principal, settings) -> User | None:
    """The account this person signs in as, creating it if that is allowed.

    Three ways to land on a record, in descending order of trustworthiness:

    1. `external_id` — the tenant's immutable object id. Someone who changed
       their name last month is still the same person and keeps their history.
    2. The address, matched against `email` or an existing `username`. This is
       what links a pre-existing local account to the directory, so an
       administrator who was created by hand does not end up with two records.
       Safe only because the address came from a signed token issued by the one
       tenant we accept — never from anything the caller typed.
    3. Nothing matched, so create one, if auto-provisioning is on.
    """
    existing = (
        await db.execute(select(User).where(User.external_id == principal.subject))
    ).scalars().first()

    if existing is None:
        existing = (
            await db.execute(
                select(User).where(
                    func.lower(User.email) == principal.email,
                )
            )
        ).scalars().first()

    if existing is None:
        existing = (
            await db.execute(
                select(User).where(func.lower(User.username) == principal.email)
            )
        ).scalars().first()

    if existing is not None:
        if not existing.active:
            # Deactivating someone has to survive them holding a perfectly
            # valid Microsoft account, or it is not a deactivation.
            logger.warning("Microsoft sign-in by deactivated account %s", existing.username)
            return None
        existing.external_id = principal.subject
        existing.email = principal.email
        existing.display_name = principal.display_name
        existing.auth_provider = "microsoft"
        # Role is deliberately not touched: whatever an administrator set here
        # stands, and signing in through a new route never re-grades anyone.
        return existing

    if not settings.oidc_auto_provision:
        return None

    user = User(
        username=await _free_username(db, principal.email),
        password_hash=None,
        role="admin" if principal.email in settings.oidc_admin_email_set else (settings.oidc_default_role or "analyst"),
        auth_provider="microsoft",
        external_id=principal.subject,
        email=principal.email,
        display_name=principal.display_name,
        active=True,
        # There is no password to change.
        must_change_password=False,
    )
    db.add(user)
    await db.flush()
    logger.info("Provisioned %r from Microsoft sign-in as %s", user.username, user.role)
    return user


async def _free_username(db, email: str) -> str:
    """The local part if nobody has it, otherwise the whole address.

    Short names read better in the sidebar, but correctness wins over tidiness:
    two people called `admin` in different directories must not collide.
    """
    local = email.split("@", 1)[0][:64]
    taken = (
        await db.execute(select(User).where(func.lower(User.username) == local.lower()))
    ).scalars().first()
    return local if taken is None else email[:64]


def _same(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(str(left), str(right))


def _back_to_login(reason: str) -> RedirectResponse:
    return RedirectResponse(f"/login?error={reason}", status_code=302)


def _clear_flow(response: RedirectResponse) -> RedirectResponse:
    """One flow cookie, one use. Whatever happened, it does not get replayed."""
    response.delete_cookie(oidc.OIDC_FLOW_COOKIE, path="/")
    return response
