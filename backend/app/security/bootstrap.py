"""Make sure there is a way in, exactly once, and say so loudly.

Turning on default-deny with no accounts in the database locks everyone out,
including whoever has to fix it. On first boot this creates one administrator
and one ingest API key and writes both to the log — the only time either
plaintext exists. Afterwards it does nothing.

The credentials go to the log rather than a file because the log is the one
place an operator is already looking when a container starts, and because a
file on disk is a credential nobody remembers to delete.
"""

from __future__ import annotations

import logging
import secrets

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import sync_engine
from app.models.database import ApiKey, User
from app.security.credentials import generate_api_key, generate_password, hash_password

logger = logging.getLogger(__name__)

INGEST_KEY_LABEL = "Alert ingest (bootstrap)"


def ensure_bootstrap_credentials() -> None:
    """Never raises: a failure here must not stop the API from starting."""
    try:
        settings = get_settings()
        with Session(sync_engine) as db:
            _ensure_admin(db, settings)
            _ensure_ingest_key(db)
    except Exception as exc:
        logger.error("Could not verify bootstrap credentials: %s", exc)


def _ensure_admin(db: Session, settings) -> None:
    if db.execute(select(func.count()).select_from(User)).scalar():
        return

    username = (settings.bootstrap_admin_username or "admin").strip() or "admin"
    supplied = (settings.bootstrap_admin_password or "").strip()
    password = supplied or generate_password()

    db.add(
        User(
            username=username,
            password_hash=hash_password(password),
            role="admin",
            # Only force a change on a password the operator did not choose.
            must_change_password=not supplied,
        )
    )
    db.commit()

    if supplied:
        logger.warning("Created administrator %r with the password from BOOTSTRAP_ADMIN_PASSWORD", username)
        return
    _banner(
        "ADMINISTRATOR ACCOUNT CREATED",
        f"username: {username}",
        f"password: {password}",
        "Change it after signing in. This is the only time it is shown.",
    )


def _ensure_ingest_key(db: Session) -> None:
    if db.execute(select(func.count()).select_from(ApiKey)).scalar():
        return

    minted = generate_api_key()
    db.add(
        ApiKey(
            label=INGEST_KEY_LABEL,
            prefix=minted.prefix,
            key_hash=minted.key_hash,
            role="ingest",
            created_by="bootstrap",
        )
    )
    db.commit()
    _banner(
        "ALERT INGEST API KEY CREATED",
        f"key: {minted.plaintext}",
        "Send it from Wazuh/TraceCat as:",
        f"    Authorization: Bearer {minted.plaintext}",
        "Only its hash is stored — it cannot be shown again.",
    )


def warn_on_overbroad_ingest_trust(settings) -> None:
    """Shout if the ingest exemption covers this platform's own frontend.

    Every browser request reaches the API from the frontend container's address
    on the compose bridge. A trusted range that includes it does not exempt an
    appliance — it exempts everyone with a browser, silently, and the logs will
    look entirely normal afterwards. Private-range entries are the usual way
    that happens, so they are called out by name.
    """
    import ipaddress

    networks = settings.ingest_trusted_networks
    if not networks:
        return

    # The compose bridge. Anything covering it is the failure described above.
    bridge = ipaddress.ip_network("172.16.0.0/12")
    for network in networks:
        try:
            overlaps = network.overlaps(bridge)
        except TypeError:  # v4 against v6
            continue
        if overlaps and network.prefixlen < 32:
            _banner(
                "INGEST TRUST RANGE MAY COVER THIS PLATFORM'S OWN FRONTEND",
                f"range: {network}",
                "Browser traffic reaches the API from the compose bridge, so a range",
                "covering it exempts every anonymous browser, not just the appliance.",
                "Use the appliance's exact address (a /32) instead.",
            )
    logger.info(
        "Ingest exemption active for %s on %s",
        ", ".join(str(n) for n in networks),
        ", ".join(sorted(settings.ingest_trusted_path_set)) or "(no paths configured)",
    )


def resolve_session_secret(settings) -> str:
    """The configured signing secret, or a per-boot one with a warning.

    A generated secret means every restart invalidates every session. That is a
    safe default — the unsafe default would be a constant baked into the image,
    which is a forgeable cookie on every deployment that ever runs it.
    """
    configured = (getattr(settings, "session_secret", "") or "").strip()
    if configured:
        return configured
    generated = secrets.token_urlsafe(48)
    logger.warning(
        "SESSION_SECRET is not set — generated one for this process. Sessions will "
        "not survive a restart, and separate workers will reject each other's "
        "cookies. Set SESSION_SECRET in .env."
    )
    return generated


def _banner(title: str, *lines: str) -> None:
    rule = "=" * 72
    logger.warning("\n%s\n  %s\n%s\n%s\n%s", rule, title, rule, "\n".join(f"  {ln}" for ln in lines), rule)
