"""Per-tenant integrations: configure, verify, and see what is working.

Keyed on `tenant_id`. Credentials live on the axis that carries
authorisation — `users.tenant_ids`, `users.all_tenants`,
`api_keys.tenant_ids` — because "may this user see this credential?" has to
have an answer in the data rather than in an invented join.

Four properties this surface holds, each with a test asserting the direction
that does damage:

**Write-only secrets.** `PUT` accepts them; nothing returns them. The
response models carry `secret_set: bool` and `secret_set_at`, never a value,
and `test_integration_secrets.py` asserts no response field is
credential-shaped and that a stored secret does not appear in any payload
this module produces.

**Admin-only writes.** `owner` and `admin` may configure; `analyst` may
read. Reads are tenant-scoped on top of that, so an analyst sees the status
of their own tenants and no credential at all.

**Isolation at the query layer.** Every read passes a `TenantScope` into the
service as a required keyword. A tenant outside the scope is **404, never
403** — the convention `tenant_scope` already sets, because a 403 confirms
the row exists and that is the fact a restricted caller is not entitled to.

**Verification is a real call.** `POST /verify` fetches a token and then
makes one authenticated API request, stores the outcome with its timestamp
and reason whether it passed or failed, and never discards a failure. A
credential that fails verification stays saved and is shown as failing.
"""

from __future__ import annotations

from datetime import datetime, timezone

import logging
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.auth import has_admin_rights
from app.dependencies import DBSession
from app.services import integration_credential_service as creds
from app.services import integration_status_service as status
from app.services import tenant_scope

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


# ── request / response models ────────────────────────────────────────────


class IntegrationConfigure(BaseModel):
    """What an admin sends to configure one tool for one tenant.

    `secrets` is write-only. **Omitting a field leaves the stored value in
    place** — the UI is never given the value, so it cannot send it back, and
    treating an absent field as "clear it" would wipe a credential every time
    somebody edited a base URL.
    """

    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)


class IntegrationStatusOut(BaseModel):
    """One tenant × tool, as a reader sees it.

    No secret field exists on this model, by construction rather than by
    omission at serialisation time: a field that is never declared cannot be
    populated by a later change.
    """

    tool: str
    label: str
    overall: str
    directions: dict[str, Any] = Field(default_factory=dict)
    configured: bool = False
    secret_set: bool = False
    secret_set_at: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    configured_by: str | None = None
    updated_at: str | None = None
    note: dict[str, Any] | None = None


# ── helpers ──────────────────────────────────────────────────────────────


def _identity(request: Request | None) -> dict[str, Any]:
    return dict(getattr(getattr(request, "state", None), "identity", None) or {})


def _scope(request: Request | None) -> tenant_scope.TenantScope:
    return tenant_scope.scope_of(_identity(request))


def _require_admin(request: Request | None) -> dict[str, Any]:
    """Writes are admin-only, and the audit record needs who.

    404 is wrong here and 403 is right: unlike a tenant the caller may not
    see, the *existence* of this endpoint is not a secret, and an analyst
    being told "not permitted" is the useful answer.
    """
    identity = _identity(request)
    role = str(identity.get("role") or "")
    if not has_admin_rights(role):
        raise HTTPException(
            403,
            "Configuring an integration requires an administrator. "
            "Integration credentials are per tenant and an analyst may read "
            "their status but not set them.",
        )
    return identity


# ── reads ────────────────────────────────────────────────────────────────


@router.get("/catalogue")
async def get_catalogue() -> dict[str, Any]:
    """Every implemented integration, derived from the collector registry.

    No credential, no tenant, so no scoping — this is what the *code*
    supports, identical for every caller. A tool absent from here is in the
    `not_implemented` state for every tenant, which is where CrowdStrike
    stood until this pass.
    """
    cat = status.catalogue()
    return {
        "tools": [spec.as_json() for spec in cat.values()],
        "states": list(status.STATES),
        "directions": [status.ENRICHMENT, status.INGEST],
        "note": (
            "Derived from the collectors that declare `integration = True`. "
            "There is no list of tool names: a connector added to "
            "COLLECTOR_REGISTRY appears here with nothing to update."
        ),
    }


@router.get("/matrix")
async def get_matrix(request: Request, db: DBSession) -> dict[str, Any]:
    """The cross-tenant matrix — which tenants have which tools.

    This is the view that answers "who has no EDR", so it lists every tenant
    the caller may read including those with no integrations at all: a tenant
    missing from the matrix would read as a tenant with nothing to report
    rather than one with no tools.
    """
    return await status.matrix(db, scope=_scope(request))


@router.get("/{tenant_id}")
async def get_for_tenant(
    tenant_id: str, request: Request, db: DBSession
) -> dict[str, Any]:
    """One tenant's card grid: every implemented tool with its status."""
    try:
        return await status.for_tenant(db, tenant_id, scope=_scope(request))
    except tenant_scope.TenantForbidden:
        # 404, never 403 — see the module docstring.
        raise HTTPException(404, "Tenant not found") from None


@router.get("/{tenant_id}/audit")
async def get_audit(
    tenant_id: str, request: Request, db: DBSession, limit: int = 50
) -> dict[str, Any]:
    """Who configured what, and when. Tenant-scoped like everything else."""
    from sqlalchemy import select

    from app.models.database import IntegrationAudit

    scope = _scope(request)
    tenant_scope.assert_can_read(scope, tenant_id)
    stmt = (
        select(IntegrationAudit)
        .where(IntegrationAudit.tenant_id == tenant_id)
        .order_by(IntegrationAudit.at.desc())
        .limit(max(1, min(int(limit), 200)))
    )
    stmt = tenant_scope.apply(stmt, IntegrationAudit.tenant_id, scope)
    rows = (await db.execute(stmt)).scalars().all()
    return {
        "tenant_id": tenant_id,
        "entries": [
            {
                "tool": r.tool,
                "action": r.action,
                "actor": r.actor,
                "actor_role": r.actor_role,
                # `detail` records what changed, never what it changed to.
                "detail": r.detail,
                "at": r.at.isoformat() if r.at else None,
            }
            for r in rows
        ],
    }


# ── writes ───────────────────────────────────────────────────────────────


@router.put("/{tenant_id}/{tool}")
async def configure(
    tenant_id: str,
    tool: str,
    request: Request,
    db: DBSession,
    body: IntegrationConfigure = Body(...),
    verify: bool = True,
) -> dict[str, Any]:
    """Configure one tool for one tenant, and verify it by default.

    **Test on save.** `verify=true` makes a real authenticated call before
    returning, so the operator learns in the same action whether the
    credential works. The result is stored either way: a credential that
    fails verification is saved and shown as failing, never as
    configured-and-fine, and never thrown away — the reason is what an
    operator needs to fix it.
    """
    # Deployment-managed integrations have no credential row to write, and a
    # write here takes no effect — a real operator saved
    # `{"tenant_field": "c00"}` for the log store on 2026-10-14, where `c00`
    # is a tenant id in the slot a field name belongs, and nothing read it.
    # Refused at the endpoint rather than hidden in one client, because the
    # client is not the boundary.
    _spec = status.catalogue().get(tool)
    if _spec is not None and _spec.managed == "deployment":
        raise HTTPException(
            400,
            f"{tool!r} is configured by the deployment, not through this API. "
            f"Its settings come from the environment and a row written here "
            f"would never be read. Change the deployment configuration and "
            f"recreate the containers instead.",
        )

    identity = _require_admin(request)
    scope = _scope(request)
    actor = str(identity.get("username") or identity.get("kind") or "unknown")
    role = str(identity.get("role") or "")

    try:
        tenant_scope.assert_can_read(scope, tenant_id)
    except HTTPException:
        raise HTTPException(404, "Tenant not found") from None

    try:
        await creds.configure(
            db, tenant_id=tenant_id, tool=tool,
            config=body.config, secrets=body.secrets,
            scope=scope, actor=actor, actor_role=role,
        )
    except creds.IntegrationToolUnknown as exc:
        raise HTTPException(400, str(exc)) from None
    except ValueError as exc:
        # Credential-shaped config key. The message names the field and not
        # its value.
        raise HTTPException(400, str(exc)) from None
    except Exception as exc:  # noqa: BLE001
        from app.security.secret_box import SecretBoxUnconfigured

        if isinstance(exc, SecretBoxUnconfigured):
            # The one failure an operator must see verbatim: nothing was
            # stored, deliberately, rather than stored in the clear.
            raise HTTPException(503, str(exc)) from None
        raise

    if verify:
        await _verify_now(db, tenant_id=tenant_id, tool=tool, scope=scope,
                          actor=actor)

    return await status.for_tenant(db, tenant_id, scope=scope)


@router.post("/{tenant_id}/{tool}/verify")
async def verify_now(
    tenant_id: str, tool: str, request: Request, db: DBSession
) -> dict[str, Any]:
    """Test the connection on demand, with a real authenticated call."""
    identity = _require_admin(request)
    scope = _scope(request)
    try:
        tenant_scope.assert_can_read(scope, tenant_id)
    except HTTPException:
        raise HTTPException(404, "Tenant not found") from None

    result = await _verify_now(
        db, tenant_id=tenant_id, tool=tool, scope=scope,
        actor=str(identity.get("username") or "unknown"),
    )
    return {"result": result,
            "status": await status.for_tenant(db, tenant_id, scope=scope)}


async def _verify_now(
    db: DBSession, *, tenant_id: str, tool: str,
    scope: tenant_scope.TenantScope, actor: str,
) -> dict[str, Any]:
    """Make the real call and store the outcome.

    The verifier is looked up from the connector rather than branched on the
    tool name here — a `if tool == "falcon"` would be the hand-maintained
    list wearing an if-statement.
    """
    spec = status.catalogue().get(tool)
    if spec is None:
        raise HTTPException(400, f"No connector implements {tool!r}.")

    # Deployment-configured integrations have no credential row to open, and
    # asking the store about one returns "not configured" for something that
    # is configured — which is exactly what "Test connection" on the log store
    # did. Dispatched to the module that owns the integration, not branched on
    # the tool name here.
    if spec.managed == "deployment":
        verifier = status.deployment_verifier_for(tool)
        if verifier is None:
            raise HTTPException(
                400,
                f"{tool!r} is configured by the deployment and provides no "
                f"verifier, so there is nothing to test from here.",
            )
        outcome = await verifier(tenant_id)
        return {
            "tool": tool,
            "direction": spec.directions[0] if spec.directions else "enrichment",
            "state": status.VERIFIED_OK if outcome.get("ok") else status.VERIFIED_FAILING,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "reason": outcome.get("reason"),
            "detail": {k: v for k, v in outcome.items()
                       if k not in ("ok", "reason")},
        }

    try:
        opened = await creds.open_for_tenant(db, tenant_id, tool, scope=scope)
    except creds.IntegrationNotConfigured as exc:
        raise HTTPException(400, str(exc)) from None
    except Exception as exc:  # noqa: BLE001
        # A credential that will not open — unfinished rotation, or a lost
        # key. Recorded as a failing verification rather than a 500, because
        # it is a state the page has to be able to show.
        result = {
            "state": status.VERIFIED_FAILING,
            "direction": status.ENRICHMENT,
            "reason": (
                f"The stored credential could not be opened "
                f"({type(exc).__name__}). Either INTEGRATION_ENCRYPTION_KEY "
                "was rotated without re-encrypting this row, or the key that "
                "sealed it is gone and the credential must be re-entered."
            ),
            "failure_kind": "credential_unreadable",
        }
        await creds.record_health(
            db, tenant_id=tenant_id, tool=tool, direction=status.ENRICHMENT,
            result=result, scope=scope, actor=actor,
        )
        return result

    # A tool whose fields are declared but whose connector does not exist yet.
    #
    # `_verifier_for` imports `app.integrations.{tool}_client` and raises HTTP
    # 400 when there is no module. That turned "Save and test" into an error
    # for Exabeam, SentinelOne and Cortex the moment their specs joined the
    # catalogue — and the error was misleading twice over: the credential HAD
    # been saved a moment earlier by `configure`, and nothing was wrong with
    # it. Seven saves were recorded against one tenant while the operator was
    # told each one failed.
    #
    # Recorded as a state rather than raised, because "stored, and nothing can
    # test it yet" is a true description that the page already renders.
    if not status.has_connector(tool):
        result = {
            "state": status.CONFIGURED_UNVERIFIED,
            "direction": spec.directions[0] if spec.directions else status.INGEST,
            "reason": (
                f"Saved. {spec.label} has no connector in this platform yet, so "
                f"the credential cannot be tested — this is an absence of "
                f"capability, not a problem with what you entered."
            ),
            "failure_kind": "not_implemented",
        }
        await creds.record_health(
            db, tenant_id=tenant_id, tool=tool,
            direction=str(result["direction"]), result=result,
            scope=scope, actor=actor,
        )
        return result

    verifier = _verifier_for(tool)
    result = verifier(
        client_id=opened.client_id,
        client_secret=opened.client_secret,
        config=opened.config,
    )
    await creds.record_health(
        db, tenant_id=tenant_id, tool=tool,
        direction=str(result.get("direction") or status.ENRICHMENT),
        result=result, scope=scope, actor=actor,
    )
    # Register the token expiry centrally, so one place knows which
    # credentials are near expiry rather than each integration keeping a
    # private timer — which is how the Spamhaus JWT's `exp` sat readable in
    # the database for 98 days with nothing reading it.
    token = result.get("token")
    if isinstance(token, dict):
        from app.services import credential_expiry_service as expiry

        expiry.record(tenant_id=tenant_id, tool=tool, token_status=token)
    return result


def _verifier_for(tool: str):
    """The connector's own verification function.

    Resolved from the connector module rather than a mapping here. A
    `{"falcon": ...}` dict in this file would be the ninth hand-maintained
    list, and a tool missing from it would be unverifiable with nothing to
    say so.
    """
    import importlib

    try:
        module = importlib.import_module(f"app.integrations.{tool}_client")
    except ModuleNotFoundError as exc:
        raise HTTPException(
            400,
            f"{tool!r} declares itself an integration but has no "
            f"app/integrations/{tool}_client.py to verify it with.",
        ) from exc
    verify_fn = getattr(module, "verify", None)
    if not callable(verify_fn):
        raise HTTPException(
            400, f"app/integrations/{tool}_client.py exposes no verify()."
        )
    return verify_fn


@router.delete("/{tenant_id}/{tool}", status_code=204)
async def remove(
    tenant_id: str, tool: str, request: Request, db: DBSession
) -> None:
    """Remove one tenant's configuration. The audit record survives it."""
    identity = _require_admin(request)
    scope = _scope(request)
    try:
        tenant_scope.assert_can_read(scope, tenant_id)
    except HTTPException:
        raise HTTPException(404, "Tenant not found") from None
    removed = await creds.remove(
        db, tenant_id=tenant_id, tool=tool, scope=scope,
        actor=str(identity.get("username") or "unknown"),
        actor_role=str(identity.get("role") or ""),
    )
    if not removed:
        raise HTTPException(404, "Integration not found")


@router.post("/rotate-keys")
async def rotate_keys(request: Request, db: DBSession) -> dict[str, Any]:
    """Re-encrypt every credential under the primary encryption key.

    Present from day one rather than added after the first key is in use: a
    rotation built later has to handle rows written under two schemes at
    once. Reports `unopenable` by name, because "every row re-encrypted"
    quantifies over all rows and something has to count the ones left.
    """
    identity = _require_admin(request)
    if not str(identity.get("role") or "") == "owner":
        raise HTTPException(
            403,
            "Rotating the integration encryption key is owner-only: it "
            "rewrites every tenant's stored credential.",
        )
    return await creds.rotate_all(
        db, scope=tenant_scope.INTERNAL,
        actor=str(identity.get("username") or "unknown"),
    )
