"""Which tools each tenant has, and whether they are actually working.

The status model, and why it has five states
--------------------------------------------
**"Enabled" is the word that cost seven months.** ThreatFox was enabled,
configured, present in the collector registry, and returning HTTP 401 on
every single call for seven months. Every flag the platform had said
healthy. So nothing here is a boolean somebody set — every state is derived
from a fact that cannot be asserted into existence:

| state | derived from |
|---|---|
| `not_implemented` | no connector in `COLLECTOR_REGISTRY` declares this tool |
| `not_configured` | no `tenant_integrations` row for this tenant and tool |
| `configured_unverified` | a row exists, and nothing has ever made a real call |
| `verified_ok` | the last real authenticated call succeeded, at T |
| `verified_failing` | the last real authenticated call failed, at T, with a reason |

`configured_unverified` is the state that did not exist before and matters
most: a credential that has been saved and never exercised is not a working
integration, and the previous vocabulary had no way to say so.

Two directions, never one badge
-------------------------------
An integration that answers queries and has stopped delivering detections is
healthy by one measure and dead by the other. One status would show green
through exactly that, so `enrichment` and `ingest` are tracked independently
and a tool reports a state per direction it actually has. A tool that only
does enrichment reports only enrichment — it is not `not_configured` for a
direction it does not possess.

The catalogue is derived
------------------------
From `COLLECTOR_REGISTRY`, filtered to connectors that set
`integration = True`. There is no list of tool names anywhere, because a list
would be the ninth hand-maintained registry here and the eight before it each
swallowed a feature silently. `test_integration_catalogue.py` fails if a
hard-coded tool list appears.

Isolation is at the query layer
-------------------------------
Every read takes a `TenantScope` as a **required keyword** and goes through
`tenant_scope.apply`. Not a default of `None` meaning "no filter": a
parameter someone forgets to pass must never be the one that opens a read up.
A restricted scope with no tenants resolves to SQL `false`, not to an absent
filter — `test_integration_isolation.py` asserts a restricted principal sees
nothing, and that the test fails if the restriction is removed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import tenant_scope
from app.services.absence import OUT_OF_SCOPE, absent

#: The five states. Ordered worst-known-first for a UI that sorts by concern;
#: `not_implemented` last because it is not a fault, it is an absence of
#: capability.
VERIFIED_FAILING = "verified_failing"
CONFIGURED_UNVERIFIED = "configured_unverified"
NOT_CONFIGURED = "not_configured"
VERIFIED_OK = "verified_ok"
NOT_IMPLEMENTED = "not_implemented"

STATES = (VERIFIED_FAILING, CONFIGURED_UNVERIFIED, NOT_CONFIGURED,
          VERIFIED_OK, NOT_IMPLEMENTED)

#: States in which this tool is not known to be working. Deliberately
#: includes `configured_unverified`: a saved credential nobody has exercised
#: is not a working integration, and the whole point of the fifth state is
#: that it must not read as the fourth.
NOT_WORKING = frozenset({VERIFIED_FAILING, CONFIGURED_UNVERIFIED,
                         NOT_CONFIGURED, NOT_IMPLEMENTED})

ENRICHMENT = "enrichment"
INGEST = "ingest"


@dataclass(frozen=True)
class ToolSpec:
    """One implemented integration, as the code declares it."""

    tool: str
    label: str
    directions: tuple[str, ...]
    config_fields: dict[str, str] = field(default_factory=dict)
    secret_fields: dict[str, str] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "label": self.label,
            "directions": list(self.directions),
            "config_fields": dict(self.config_fields),
            # Names and descriptions only. A secret field is declared so the
            # UI can render an input; its value is never read back.
            "secret_fields": dict(self.secret_fields),
        }


def catalogue() -> dict[str, ToolSpec]:
    """Every implemented integration, derived from the collector registry.

    Adding a connector that sets `integration = True` adds a tool here with
    nothing to update. Nothing enumerates tool names.
    """
    from app.collectors.registry import COLLECTOR_REGISTRY

    out: dict[str, ToolSpec] = {}
    for name, cls in sorted(COLLECTOR_REGISTRY.items()):
        if not getattr(cls, "integration", False):
            continue
        directions = tuple(
            d for d in getattr(cls, "integration_directions", ()) or ()
            if d in (ENRICHMENT, INGEST)
        )
        out[name] = ToolSpec(
            tool=name,
            label=str(getattr(cls, "integration_label", "") or name),
            directions=directions or (ENRICHMENT,),
            config_fields=dict(getattr(cls, "integration_config_fields", {}) or {}),
            secret_fields=dict(getattr(cls, "integration_secret_fields", {}) or {}),
        )
    return out


def _state_for_direction(row: Any, direction: str) -> dict[str, Any]:
    """The state of one direction of one configured integration.

    `row` is a `TenantIntegration`. Called only when a row exists, so
    `not_configured` and `not_implemented` are decided above this.
    """
    health = row.health if isinstance(row.health, dict) else {}
    entry = health.get(direction)
    if not isinstance(entry, dict) or not entry.get("checked_at"):
        return {
            "state": CONFIGURED_UNVERIFIED,
            "checked_at": None,
            "reason": (
                "A credential is stored and no real call has ever been made "
                "with it. Saved is not working — run Test connection."
            ),
        }
    state = str(entry.get("state") or "").strip()
    if state not in (VERIFIED_OK, VERIFIED_FAILING):
        # An unrecognised stored state is not quietly read as healthy.
        return {
            "state": VERIFIED_FAILING,
            "checked_at": entry.get("checked_at"),
            "reason": (
                f"The last verification recorded a state this code does not "
                f"recognise ({state or 'missing'!r}), so it is not read as "
                "working."
            ),
            "failure_kind": "unrecognised",
        }
    out = {
        "state": state,
        "checked_at": entry.get("checked_at"),
        "reason": entry.get("reason"),
    }
    for extra in ("failure_kind", "token", "base_url"):
        if entry.get(extra) is not None:
            out[extra] = entry[extra]
    return out


def status_of(spec: ToolSpec | None, row: Any, tool: str) -> dict[str, Any]:
    """The full per-direction status of one tenant × tool.

    `spec is None` means no connector implements this tool — the state that
    is true of every EDR in this platform today, so the page has to render it
    sensibly rather than treat it as an error.
    """
    if spec is None:
        return {
            "tool": tool,
            "label": tool,
            "overall": NOT_IMPLEMENTED,
            "directions": {},
            "configured": False,
            "note": absent(
                OUT_OF_SCOPE,
                "No connector in this platform implements this tool, so it "
                "cannot be configured for any tenant. This is an absence of "
                "capability, not a fault.",
                raw=tool,
            ).as_json(),
        }

    if row is None:
        per_direction = {
            d: {
                "state": NOT_CONFIGURED,
                "checked_at": None,
                "reason": "No credential is stored for this tenant.",
            }
            for d in spec.directions
        }
        return {
            "tool": spec.tool,
            "label": spec.label,
            "overall": NOT_CONFIGURED,
            "directions": per_direction,
            "configured": False,
        }

    per_direction = {d: _state_for_direction(row, d) for d in spec.directions}
    # The overall badge is the worst direction, by the order in STATES. A
    # tool answering queries while delivering nothing must not read green.
    overall = min(
        (per_direction[d]["state"] for d in per_direction),
        key=lambda s: STATES.index(s) if s in STATES else 0,
        default=NOT_CONFIGURED,
    )
    return {
        "tool": spec.tool,
        "label": spec.label,
        "overall": overall,
        "directions": per_direction,
        "configured": True,
        "secret_set": bool(row.secret_ciphertext),
        "secret_set_at": row.secret_set_at.isoformat() if row.secret_set_at else None,
        # Non-secret config only. A test asserts no credential-shaped key
        # reaches this payload.
        "config": row.config if isinstance(row.config, dict) else {},
        "configured_by": row.configured_by,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


async def _rows(db: AsyncSession, *, scope: tenant_scope.TenantScope,
                tenant_id: str | None = None) -> list[Any]:
    """Every integration row this scope may read.

    `scope` is a required keyword throughout this module. A default of `None`
    meaning "no filter" is how a scoped read quietly becomes an unscoped one,
    and this table holds credentials.
    """
    from app.models.database import TenantIntegration

    stmt = select(TenantIntegration)
    if tenant_id:
        stmt = stmt.where(TenantIntegration.tenant_id == tenant_id)
    stmt = tenant_scope.apply(stmt, TenantIntegration.tenant_id, scope)
    return list((await db.execute(stmt)).scalars().all())


async def for_tenant(
    db: AsyncSession, tenant_id: str, *, scope: tenant_scope.TenantScope
) -> dict[str, Any]:
    """The per-tenant card grid: every implemented tool, with its status."""
    tenant_scope.assert_can_read(scope, tenant_id)
    rows = {r.tool: r for r in await _rows(db, scope=scope, tenant_id=tenant_id)}
    cat = catalogue()

    tools = [status_of(cat.get(t), rows.get(t), t) for t in sorted(cat)]
    # A row for a tool no connector implements any more — a connector
    # removed while its configuration remains. Surfaced rather than hidden,
    # because a stored credential nothing can use is worth knowing about.
    orphans = [
        status_of(None, rows[t], t) for t in sorted(rows) if t not in cat
    ]
    return {
        "tenant_id": tenant_id,
        "tools": tools + orphans,
        "counts": _counts(tools + orphans),
    }


async def matrix(
    db: AsyncSession, *, scope: tenant_scope.TenantScope
) -> dict[str, Any]:
    """The cross-tenant matrix: which tenants have which tools.

    This is the view that answers "who has no EDR", so it lists every tenant
    this scope may read — including tenants with no integrations at all,
    because a tenant missing from the matrix reads as a tenant with nothing
    to report rather than a tenant with no tools.
    """
    from app.models.database import Tenant

    stmt = select(Tenant)
    stmt = tenant_scope.apply(stmt, Tenant.tenant_id, scope)
    tenants = [
        {"tenant_id": t.tenant_id, "name": t.name, "status": t.status}
        for t in (await db.execute(stmt)).scalars().all()
    ]

    rows = await _rows(db, scope=scope)
    by_tenant: dict[str, dict[str, Any]] = {}
    for r in rows:
        by_tenant.setdefault(r.tenant_id, {})[r.tool] = r

    cat = catalogue()
    cells = {
        t["tenant_id"]: {
            tool: status_of(cat.get(tool), by_tenant.get(t["tenant_id"], {}).get(tool), tool)
            for tool in sorted(cat)
        }
        for t in tenants
    }
    return {
        "tenants": sorted(tenants, key=lambda t: t["tenant_id"]),
        "tools": [cat[t].as_json() for t in sorted(cat)],
        "cells": cells,
        # Named, not just counted: a count tells nobody which tenant to go
        # and configure.
        "tenants_without_any_working": sorted(
            t["tenant_id"] for t in tenants
            if not any(
                cells[t["tenant_id"]][tool]["overall"] == VERIFIED_OK
                for tool in cells[t["tenant_id"]]
            )
        ),
    }


def _counts(tools: list[dict[str, Any]]) -> dict[str, int]:
    out = {s: 0 for s in STATES}
    for t in tools:
        state = t.get("overall")
        if state in out:
            out[state] += 1
    return out
