"""
Machine-to-machine alert ingest.

Another platform POSTs a raw alert body to /api/alert-investigations and either
polls the run or gets the finished report list delivered to a callback URL. This
module holds the pieces that only that path needs:

    body hashing + dedupe   — the same alert delivered twice reuses one run
    callback URL validation — we POST to a caller-supplied address, so the target
                              is checked before anything is queued
    signature               — HMAC-SHA256 over the delivered body when a secret
                              is configured

The ingest endpoint is not authenticated (deployments restrict it at the network
layer), which is exactly why the callback target is validated and the route is
rate-limited: an unauthenticated caller must not be able to turn this service
into a request proxy.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.database import AlertBodyInvestigationRun

logger = logging.getLogger(__name__)

# A run in one of these states has nothing to hand back, so an identical alert
# body arriving again starts fresh instead of reusing it.
NON_REUSABLE_STATUSES = frozenset({"failed", "cancelled"})

_WHITESPACE = re.compile(r"\s+")


class CallbackUrlError(ValueError):
    """The caller-supplied callback URL is not one we will POST to."""


def alert_body_hash(alert_body: str) -> str:
    """
    Stable fingerprint of an alert body.

    Whitespace is collapsed before hashing so the same alert re-sent with
    different line wrapping or trailing spaces still matches.
    """
    normalized = _WHITESPACE.sub(" ", str(alert_body or "")).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


async def find_duplicate_run(
    db: AsyncSession,
    body_hash: str,
    *,
    window_minutes: int | None = None,
) -> AlertBodyInvestigationRun | None:
    """The most recent usable run for this exact alert body, if one is fresh enough."""
    if not body_hash:
        return None
    settings = get_settings()
    window = int(window_minutes if window_minutes is not None else settings.alert_ingest_dedupe_window_minutes)
    if window <= 0:
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)

    try:
        result = await db.execute(
            select(AlertBodyInvestigationRun)
            .where(
                AlertBodyInvestigationRun.alert_body_hash == body_hash,
                AlertBodyInvestigationRun.created_at >= cutoff,
                AlertBodyInvestigationRun.status.not_in(tuple(NON_REUSABLE_STATUSES)),
            )
            .order_by(AlertBodyInvestigationRun.created_at.desc())
            .limit(1)
        )
        return result.scalars().first()
    except Exception as exc:  # a dedupe miss is better than a failed ingest
        logger.warning("Alert dedupe lookup failed: %s", exc)
        return None


def validate_callback_url(url: str | None) -> str | None:
    """
    Return the callback URL if we are willing to POST to it.

    Refuses anything but http/https, and refuses loopback, link-local (including
    cloud metadata at 169.254.169.254), multicast and otherwise reserved
    addresses. Private ranges stay allowed unless ALERT_CALLBACK_ALLOW_PRIVATE is
    off — the platform receiving our reports is usually on the same network.
    """
    candidate = str(url or "").strip()
    if not candidate:
        return None

    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise CallbackUrlError("callback_url must be an http:// or https:// address")
    if not parsed.hostname:
        raise CallbackUrlError("callback_url has no host")

    allow_private = get_settings().alert_callback_allow_private
    for address in _resolve(parsed.hostname):
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise CallbackUrlError(f"callback_url resolves to a blocked address ({address})")
        if address.is_reserved:
            raise CallbackUrlError(f"callback_url resolves to a reserved address ({address})")
        if address.is_private and not allow_private:
            raise CallbackUrlError(f"callback_url resolves to a private address ({address})")
    return candidate


def sign_payload(body: bytes) -> str | None:
    """`sha256=<hex>` HMAC of the delivered body, or None when unconfigured."""
    secret = str(get_settings().alert_callback_secret or "")
    if not secret:
        return None
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _resolve(hostname: str) -> list[ipaddress._BaseAddress]:
    """Every address the callback host resolves to (the literal, if it is one)."""
    try:
        return [ipaddress.ip_address(hostname.strip("[]"))]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise CallbackUrlError(f"callback_url host does not resolve ({hostname})") from exc

    addresses: list[ipaddress._BaseAddress] = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not addresses:
        raise CallbackUrlError(f"callback_url host does not resolve ({hostname})")
    return addresses
