"""Store, open and rotate per-tenant integration credentials.

The only module that decrypts. Everything else — the API, the status service,
the page — works with "is a secret set" and never with the secret.

Three rules, each with a test asserting the direction that does damage:

**Write-only.** A credential is settable through the API and never readable
back. `set_secret` takes plaintext; nothing in this module returns it except
`open_for_tenant`, whose only callers are connectors. No API serializer may
call it, and `test_integration_secrets.py` asserts no response model carries
a secret-shaped field.

**Tenant isolation at the query layer.** Every function takes `scope` as a
required keyword and filters through `tenant_scope`. Not a default of `None`
meaning "no filter": a parameter someone forgets to pass must never be the
one that opens a read up, and this table holds credentials. A restricted
scope with no tenants resolves to SQL `false`.

**Nothing is stored in the clear.** `secret_box` raises when no encryption
key is configured rather than falling back to plaintext. An outage and a
breach must not share a code path.

Rotation
--------
`rotate_all` re-encrypts every row under the primary key and returns counts,
including how many it could **not** open — because "all rows re-encrypted" is
a claim quantifying over every row, so something has to be able to count the
ones left. `SecretBox.needs_rotation` makes that a query rather than an
assertion.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.security import secret_box
from app.services import tenant_scope


class IntegrationNotConfigured(LookupError):
    """No credential is stored for this tenant and tool.

    A distinct type, because the connector must record it as an absence —
    "not configured" is not "the provider had nothing".
    """


class IntegrationToolUnknown(ValueError):
    """No connector implements this tool.

    Raised rather than storing a row for it: a credential for a tool nothing
    can use is a secret held for no reason, and the catalogue is derived from
    the code precisely so this cannot be configured by typo.
    """


#: Config keys that must never hold a secret. The config column is returned
#: by the API; a credential placed there would be readable, which is the
#: write-only rule defeated by the back door.
_SECRET_SHAPED = ("secret", "password", "token", "key", "credential", "passwd")


@dataclass(frozen=True)
class OpenedCredential:
    """A credential, decrypted, for a connector's own use.

    Never serialised. `__repr__` is overridden so a stray log line or an
    exception rendering locals cannot print it — the standing rule is that a
    credential reaches no log, no error body and no response, and a dataclass
    repr is the easiest way to break it by accident.
    """

    tenant_id: str
    tool: str
    client_id: str
    client_secret: str
    config: dict[str, Any]

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return (
            f"OpenedCredential(tenant_id={self.tenant_id!r}, "
            f"tool={self.tool!r}, client_id='[redacted]', "
            f"client_secret='[redacted]')"
        )

    __str__ = __repr__


def _assert_known_tool(tool: str) -> Any:
    from app.services.integration_status_service import catalogue

    spec = catalogue().get(tool)
    if spec is None:
        raise IntegrationToolUnknown(
            f"No connector implements {tool!r}. The tool catalogue is derived "
            "from the collectors that declare `integration = True`, so a tool "
            "cannot be configured before it is implemented."
        )
    return spec


def _reject_secret_shaped_config(config: dict[str, Any] | None) -> dict[str, Any]:
    """Keep credentials out of the column that is returned to callers."""
    cfg = {k: v for k, v in (config or {}).items() if v is not None}
    for key in cfg:
        lowered = str(key).lower()
        if any(marker in lowered for marker in _SECRET_SHAPED):
            raise ValueError(
                f"Config field {key!r} is credential-shaped. The config column "
                "is returned through the API; secrets go in the sealed column "
                "and are never readable back."
            )
    return cfg


async def _row(db: AsyncSession, tenant_id: str, tool: str, *,
               scope: tenant_scope.TenantScope) -> Any:
    from app.models.database import TenantIntegration

    # Bind the session to this scope before touching the table.
    #
    # `tenant_integrations` carries a row-level policy, so an unbound session
    # reads zero rows and a write is refused outright. That is the safe
    # direction and it is also the one that caused an outage on 2026-10-19:
    # nothing bound it, so every integration read as unconfigured for a day
    # and configuring one returned 500. See migration 073.
    await tenant_scope.bind(db, scope)

    stmt = select(TenantIntegration).where(
        TenantIntegration.tenant_id == tenant_id,
        TenantIntegration.tool == tool,
    )
    stmt = tenant_scope.apply(stmt, TenantIntegration.tenant_id, scope)
    return (await db.execute(stmt)).scalars().first()


async def configure(
    db: AsyncSession,
    *,
    tenant_id: str,
    tool: str,
    config: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
    scope: tenant_scope.TenantScope,
    actor: str | None = None,
    actor_role: str | None = None,
) -> Any:
    """Create or update one tenant's configuration for one tool.

    Secrets are sealed before storage. Omitting a secret **leaves the stored
    one in place** rather than clearing it — the UI cannot send back a value
    it is never given, so an absent field must mean "unchanged", or saving a
    config change would silently wipe the credential.
    """
    from app.models.database import IntegrationAudit, TenantIntegration

    tenant_scope.assert_can_read(scope, tenant_id)
    await tenant_scope.bind(db, scope)
    spec = _assert_known_tool(tool)
    cfg = _reject_secret_shaped_config(config)

    supplied = {
        k: v for k, v in (secrets or {}).items()
        if k in spec.secret_fields and str(v or "").strip()
    }

    row = await _row(db, tenant_id, tool, scope=scope)
    created = row is None
    if created:
        row = TenantIntegration(tenant_id=tenant_id, tool=tool, config={}, health={})
        db.add(row)

    if cfg:
        row.config = {**(row.config or {}), **cfg}
    row.configured_by = actor
    row.updated_at = datetime.now(timezone.utc)

    if supplied:
        # All secret fields for a tool are sealed as one blob: they are used
        # together and rotate together, and one ciphertext means one key_id
        # per row rather than one per field.
        merged = dict(_open_blob(row) or {})
        merged.update(supplied)
        sealed = secret_box.from_settings().encrypt(json.dumps(merged))
        row.secret_ciphertext = sealed.ciphertext
        row.secret_key_id = sealed.key_id
        row.secret_set_at = datetime.now(timezone.utc)
        # Verification is invalidated by a new credential. Leaving the old
        # `verified_ok` would show green for a secret that has never been
        # tried — the exact state `configured_unverified` exists to name.
        row.health = {}

    db.add(IntegrationAudit(
        tenant_id=tenant_id, tool=tool,
        action="configured" if created else "reconfigured",
        actor=actor, actor_role=actor_role,
        # What changed, never what it changed to.
        detail={
            "config_fields_set": sorted(cfg),
            "secret_fields_set": sorted(supplied),
            "verification_reset": bool(supplied),
        },
    ))
    await db.commit()
    await db.refresh(row)
    return row


def _open_blob(row: Any) -> dict[str, Any] | None:
    """The stored secret blob, decrypted, or None if nothing is stored."""
    if not getattr(row, "secret_ciphertext", None):
        return None
    raw = secret_box.from_settings().decrypt(row.secret_ciphertext)
    try:
        parsed = json.loads(raw)
    except Exception:  # noqa: BLE001
        return None
    return parsed if isinstance(parsed, dict) else None


async def open_for_tenant(
    db: AsyncSession, tenant_id: str, tool: str, *,
    scope: tenant_scope.TenantScope,
) -> OpenedCredential:
    """Decrypt this tenant's credential, for a connector's own use.

    The one function that returns plaintext. Its callers are connectors; no
    API serializer may call it.
    """
    row = await _row(db, tenant_id, tool, scope=scope)
    if row is None or not row.secret_ciphertext:
        raise IntegrationNotConfigured(
            f"{tool} is not configured for tenant {tenant_id!r}."
        )
    blob = _open_blob(row) or {}
    return OpenedCredential(
        tenant_id=tenant_id, tool=tool,
        client_id=str(blob.get("client_id") or ""),
        client_secret=str(blob.get("client_secret") or ""),
        config=row.config if isinstance(row.config, dict) else {},
    )


def open_for_tenant_sync(tenant_id: str, tool: str) -> OpenedCredential:
    """The synchronous path, for collectors.

    Collectors run under the sync engine. Scoped `INTERNAL` because a
    collector is the platform acting for the tenant it was given — and the
    tenant it was given is the only one it reads, by the `tenant_id ==`
    predicate below, not by trusting the scope to narrow it.
    """
    from sqlalchemy.orm import Session

    from app.db.session import sync_engine
    from app.models.database import TenantIntegration

    with Session(sync_engine) as db:
        # A connector resolving its own tenant's credential. The scope is that
        # one tenant: this path is reached from a run that already carries it,
        # and binding anything wider would hand a connector the ability to
        # read a credential it has no business with.
        tenant_scope.bind_sync(
            db, tenant_scope.TenantScope(tenant_ids=(str(tenant_id),),
                                         actor=f"connector:{tool}")
        )
        row = (
            db.execute(
                select(TenantIntegration).where(
                    TenantIntegration.tenant_id == tenant_id,
                    TenantIntegration.tool == tool,
                )
            )
            .scalars()
            .first()
        )
        if row is None or not row.secret_ciphertext:
            raise IntegrationNotConfigured(
                f"{tool} is not configured for tenant {tenant_id!r}."
            )
        blob = _open_blob(row) or {}
        return OpenedCredential(
            tenant_id=tenant_id, tool=tool,
            client_id=str(blob.get("client_id") or ""),
            client_secret=str(blob.get("client_secret") or ""),
            config=row.config if isinstance(row.config, dict) else {},
        )


async def record_health(
    db: AsyncSession, *, tenant_id: str, tool: str, direction: str,
    result: dict[str, Any], scope: tenant_scope.TenantScope,
    actor: str | None = None,
) -> Any:
    """Store the outcome of a real authenticated call.

    Stored whether it passed or failed, with the timestamp and the reason. A
    credential that fails verification stays saved and is shown as failing —
    never as configured-and-fine, and never discarded, because an operator
    needs to see the reason to fix it.
    """
    from app.models.database import IntegrationAudit

    # Bound for the same reason as everywhere else in this module:
    # the table has a row-level policy, and an unbound session reads
    # nothing and writes nothing. These two can be called on a session
    # nobody else bound. See migration 073.
    await tenant_scope.bind(db, scope)

    tenant_scope.assert_can_read(scope, tenant_id)
    row = await _row(db, tenant_id, tool, scope=scope)
    if row is None:
        raise IntegrationNotConfigured(
            f"{tool} is not configured for tenant {tenant_id!r}."
        )
    health = dict(row.health or {})
    # The token status travels; the token never does.
    stored = {k: v for k, v in result.items() if k != "access_token"}
    # `checked_at` is stamped here rather than left to each caller.
    #
    # The reader treats an entry without it as "no call has ever been made"
    # and discards everything else in the entry, so a caller that forgets it
    # writes a reason nobody will ever see. One did: the not-implemented
    # branch recorded a perfectly good explanation and the page showed the
    # generic "run Test connection" instead. A field a reader requires is
    # guaranteed by the writer, not by every writer remembering.
    stored.setdefault("checked_at", datetime.now(timezone.utc).isoformat())
    health[direction] = stored
    row.health = health
    row.updated_at = datetime.now(timezone.utc)

    db.add(IntegrationAudit(
        tenant_id=tenant_id, tool=tool, action="verified", actor=actor,
        detail={"direction": direction, "state": result.get("state"),
                "failure_kind": result.get("failure_kind")},
    ))
    await db.commit()
    await db.refresh(row)
    return row


async def remove(
    db: AsyncSession, *, tenant_id: str, tool: str,
    scope: tenant_scope.TenantScope, actor: str | None = None,
    actor_role: str | None = None,
) -> bool:
    """Delete one tenant's configuration. The audit row survives it."""
    from app.models.database import IntegrationAudit

    # Bound for the same reason as everywhere else in this module:
    # the table has a row-level policy, and an unbound session reads
    # nothing and writes nothing. These two can be called on a session
    # nobody else bound. See migration 073.
    await tenant_scope.bind(db, scope)

    tenant_scope.assert_can_read(scope, tenant_id)
    row = await _row(db, tenant_id, tool, scope=scope)
    if row is None:
        return False
    await db.delete(row)
    db.add(IntegrationAudit(
        tenant_id=tenant_id, tool=tool, action="removed",
        actor=actor, actor_role=actor_role, detail={},
    ))
    await db.commit()
    return True


async def rotate_all(
    db: AsyncSession, *, scope: tenant_scope.TenantScope,
    actor: str | None = None,
) -> dict[str, Any]:
    """Re-encrypt every credential under the primary key.

    The rotation path, present from day one rather than added after the first
    key is in use — a rotation built later has to handle rows written by two
    schemes at once.

    Returns counts **including `unopenable`**, because "every row
    re-encrypted" quantifies over all rows and something has to be able to
    count the ones left. A row that cannot be opened is named, not skipped
    silently: its credential has to be re-entered.
    """
    from app.models.database import IntegrationAudit, TenantIntegration

    box = secret_box.from_settings()
    if not box.configured:
        return {
            "rotated": 0, "already_current": 0, "unopenable": 0,
            "error": "No INTEGRATION_ENCRYPTION_KEY is configured, so nothing "
                     "can be rotated.",
        }

    await tenant_scope.bind(db, scope)
    stmt = select(TenantIntegration).where(
        TenantIntegration.secret_ciphertext.isnot(None)
    )
    stmt = tenant_scope.apply(stmt, TenantIntegration.tenant_id, scope)
    rows = list((await db.execute(stmt)).scalars().all())

    rotated = already = 0
    unopenable: list[dict[str, str]] = []
    for row in rows:
        if not box.needs_rotation(row.secret_key_id):
            already += 1
            continue
        try:
            sealed = box.rotate(row.secret_ciphertext)
        except secret_box.SecretBoxUndecryptable:
            unopenable.append({"tenant_id": row.tenant_id, "tool": row.tool})
            continue
        row.secret_ciphertext = sealed.ciphertext
        row.secret_key_id = sealed.key_id
        rotated += 1
        db.add(IntegrationAudit(
            tenant_id=row.tenant_id, tool=row.tool, action="rotated",
            actor=actor, detail={"to_key_id": sealed.key_id},
        ))

    await db.commit()
    return {
        "rotated": rotated,
        "already_current": already,
        "unopenable": len(unopenable),
        # Named, not counted: these credentials must be re-entered, and a
        # count tells nobody which.
        "unopenable_subjects": unopenable,
        "primary_key_id": box.primary_key_id,
        "complete": not unopenable,
    }
