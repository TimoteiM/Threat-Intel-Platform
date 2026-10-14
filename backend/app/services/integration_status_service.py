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
from app.services.absence import (
    NEVER_OBSERVED,
    OUT_OF_SCOPE,
    TOO_LITTLE_HISTORY,
    absent,
)

#: The five states. Ordered worst-known-first for a UI that sorts by concern;
#: `not_implemented` last because it is not a fault, it is an absence of
#: capability.
VERIFIED_FAILING = "verified_failing"
CONFIGURED_UNVERIFIED = "configured_unverified"
NOT_CONFIGURED = "not_configured"
VERIFIED_OK = "verified_ok"
NOT_IMPLEMENTED = "not_implemented"

#: Worked before, and is not working now. **The state the defect removes.**
#:
#: `verified_failing` catches "configured but unusable". It does not catch a
#: configuration that *vanished*: SIEM log enrichment stopped on 2026-10-12
#: because `OPENSEARCH_TENANT_VALUES` went empty, which makes the integration
#: read as `not_configured` — and on a page listing unconfigured tools that is
#: invisible. Two days passed.
#:
#: So the distinguishing fact goes beside the status. It was already stored:
#: `alert_log_context` rows up to 2026-10-12 and none after. A tool that is
#: not working **and has a last success** is an incident; one that never
#: worked is an absence. First in STATES because the overall badge is the
#: worst direction by this index, and a stopped direction must not hide behind
#: a healthy one.
STOPPED = "stopped"

STATES = (
    STOPPED,
    VERIFIED_FAILING,
    CONFIGURED_UNVERIFIED,
    NOT_CONFIGURED,
    VERIFIED_OK,
    NOT_IMPLEMENTED,
)


#: States in which a last success means the tool has STOPPED rather than
#: merely being absent. `not_implemented` is excluded deliberately: no
#: connector exists, so there is nothing that could have stopped.
_CAN_HAVE_STOPPED = frozenset({
    NOT_CONFIGURED, VERIFIED_FAILING, CONFIGURED_UNVERIFIED,
})


#: How much longer than its own expectation an integration must be silent
#: before this calls it stopped. 3x, so ordinary jitter in alert arrival does
#: not produce an outage: the log store produces a row per analysed alert, and
#: alerts do not arrive on a schedule.
SILENCE_MULTIPLIER = 3.0


def continuity(
    *,
    state: str,
    last_succeeded_at: Any = None,
    now: Any = None,
    expected_interval_hours: float | None = None,
) -> dict[str, Any]:
    """Split "never worked" from "worked until Monday".

    Returns the state possibly upgraded to `stopped`, plus how long it has
    been silent, plus `last_success` as a value or a named absence — never as
    a zero date, because a rendered epoch reads as a measurement.
    """
    from datetime import datetime, timezone

    at = now or datetime.now(timezone.utc)
    if last_succeeded_at is None:
        return {
            "state": state,
            "stopped": False,
            "silent_for_hours": None,
            "expected_interval_hours": expected_interval_hours,
            "threshold_hours": None,
            "silence_verdict": None,
            "last_success": absent(
                NEVER_OBSERVED,
                "This integration has never produced a result, so there is "
                "nothing it could have stopped doing. Absence of "
                "configuration, not an outage.",
            ).as_json(),
        }

    delta = at - last_succeeded_at
    # Clamped at zero: clock skew must not make a stopped tool look recent,
    # and a negative duration would sort as the freshest thing on the page.
    hours = max(0.0, delta.total_seconds() / 3600.0)

    # `stopped` requires actual SILENCE, not merely a state that is not
    # verified_ok. The first version asserted stopped as soon as a last
    # success existed, which put STOPPED ("an outage") directly above "silent
    # 0.2h" on the log-store card — twelve minutes reported as an outage. Both
    # numbers were right; the model joining them was wrong, and a badge that
    # goes red while the thing works is the cry-wolf failure the
    # source-coverage work already paid for once.
    threshold = (
        None if expected_interval_hours is None
        else float(expected_interval_hours) * SILENCE_MULTIPLIER
    )
    if threshold is None:
        # No declared expectation, so no claim. Guessing an interval would
        # invent outages, and "I do not know how often this should produce"
        # is an absence rather than a verdict of healthy.
        silence_verdict: Any = absent(
            TOO_LITTLE_HISTORY,
            "This integration does not declare how often it should produce a "
            "result, so whether this silence is an outage cannot be judged "
            "from it. The last success date is reported; the verdict is not.",
        ).as_json()
        stopped = False
    else:
        stopped = state in _CAN_HAVE_STOPPED and hours > threshold
        silence_verdict = (
            f"Silent {round(hours, 1)}h against an expected {expected_interval_hours}h "
            f"(flagged beyond {round(threshold, 1)}h)."
        )

    return {
        "state": STOPPED if stopped else state,
        "stopped": stopped,
        "silent_for_hours": round(hours, 1),
        "expected_interval_hours": expected_interval_hours,
        "threshold_hours": None if threshold is None else round(threshold, 1),
        "silence_verdict": silence_verdict,
        "last_success": last_succeeded_at.isoformat(),
        "note": (
            f"Last produced a result {round(hours, 1)}h ago, past the "
            f"{round(threshold, 1)}h this integration should never exceed. It "
            f"worked before, so this is an outage and not an absence of "
            f"configuration."
        ) if stopped else None,
    }

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
    #: `edr` | `firewall` | `email` | ... — see CollectorBase. Grouping key
    #: for the page, derived from the connector's own declaration.
    category: str = "other"
    #: Where this integration's configuration lives.
    #:
    #: `credential_store` — a per-tenant `tenant_integrations` row, written
    #: through the API, verified by opening the stored secret.
    #: `deployment` — the deployment's own environment, read-only from the
    #: API. The log store is this: its config is the global `OPENSEARCH_*`
    #: values, there is no row to open, and "Test connection" returned HTTP
    #: 400 "not configured" because it asked the credential store about an
    #: integration that is not kept there. The UI uses this to decide whether
    #: to offer a form at all.
    managed: str = "credential_store"
    #: How often this integration should produce a result, in hours. Declared
    #: by the integration, because only it knows. `None` means "no claim",
    #: and `continuity()` then reports the last success without a verdict —
    #: a guessed interval invents outages.
    expected_interval_hours: float | None = None
    config_fields: dict[str, str] = field(default_factory=dict)
    secret_fields: dict[str, str] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "label": self.label,
            "category": self.category,
            "managed": self.managed,
            "expected_interval_hours": self.expected_interval_hours,
            "directions": list(self.directions),
            "config_fields": dict(self.config_fields),
            # Names and descriptions only. A secret field is declared so the
            # UI can render an input; its value is never read back.
            "secret_fields": dict(self.secret_fields),
        }


#: Integrations that are not collectors, and so cannot declare themselves
#: through `COLLECTOR_REGISTRY`. Each module that owns one exposes an
#: `INTEGRATION_SPEC`, so the declaration lives beside the thing it describes
#: and this module carries no tool names, labels or categories of its own —
#: which is what the catalogue-derivation tests require.
_SPEC_MODULES = ("app.services.opensearch_tenants",)


def _declared_elsewhere() -> dict[str, dict[str, Any]]:
    """`INTEGRATION_SPEC` from every module that declares one."""
    import importlib

    out: dict[str, dict[str, Any]] = {}
    for path in _SPEC_MODULES:
        spec = getattr(importlib.import_module(path), "INTEGRATION_SPEC", None)
        if isinstance(spec, dict) and spec.get("tool"):
            out[str(spec["tool"])] = spec
    return out


def catalogue() -> dict[str, ToolSpec]:
    """Every implemented integration, derived rather than enumerated.

    Adding a connector that sets `integration = True` adds a tool here with
    nothing to update. Integrations that are not collectors come from
    `NON_COLLECTOR_INTEGRATIONS`, which declares the same fields.
    """
    from app.collectors.registry import COLLECTOR_REGISTRY

    out: dict[str, ToolSpec] = {}
    for name, decl in _declared_elsewhere().items():
        out[name] = ToolSpec(
            tool=name,
            label=str(decl["label"]),
            category=str(decl["category"]),
            managed=str(decl.get("managed") or "deployment"),
            expected_interval_hours=decl.get("expected_interval_hours"),
            directions=tuple(decl["directions"]),
            config_fields=dict(decl.get("config_fields") or {}),
            secret_fields=dict(decl.get("secret_fields") or {}),
        )
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
            category=str(getattr(cls, "integration_category", "") or "other"),
            directions=directions or (ENRICHMENT,),
            config_fields=dict(getattr(cls, "integration_config_fields", {}) or {}),
            secret_fields=dict(getattr(cls, "integration_secret_fields", {}) or {}),
        )
    return out


def deployment_verifier_for(tool: str) -> Any:
    """The `verify` coroutine from the module that owns this integration.

    Resolved by import, like `last_success_for` and for the same reason: a
    `if tool == "opensearch"` here is the hand-maintained list wearing an
    if-statement, and this module's own source guard refuses it.
    """
    import importlib

    for path in _SPEC_MODULES:
        module = importlib.import_module(path)
        spec = getattr(module, "INTEGRATION_SPEC", None)
        if isinstance(spec, dict) and spec.get("tool") == tool:
            return getattr(module, "verify", None)
    return None


async def last_success_for(
    db: AsyncSession, tenant_id: str, tool: str, row: Any = None
) -> Any:
    """When this integration last actually produced something, or None.

    Derived from evidence the platform already stores, never from a flag, and
    **this module names no tool**: an integration that knows what its own
    evidence looks like exposes `last_success(db, tenant_id)` from the module
    that owns it. The first version of this branched on `tool == "opensearch"`
    and the catalogue's own source guard rejected it, correctly — that branch
    is the hand-listing the derivation rules exist to prevent.

    Returns None for "no evidence of ever having worked", which `continuity()`
    turns into a named absence rather than a date.
    """
    import importlib

    for path in _SPEC_MODULES:
        module = importlib.import_module(path)
        spec = getattr(module, "INTEGRATION_SPEC", None)
        resolver = getattr(module, "last_success", None)
        if isinstance(spec, dict) and spec.get("tool") == tool and resolver:
            return await resolver(db, tenant_id)

    # Everything else records its own verification outcomes on the row, keyed
    # by direction. The newest passing one is the last success.
    health = getattr(row, "health", None) or {}
    if not isinstance(health, dict):
        return None
    from datetime import datetime

    best = None
    for entry in health.values():
        if not isinstance(entry, dict) or entry.get("state") != VERIFIED_OK:
            continue
        stamp = entry.get("checked_at")
        if not stamp:
            continue
        try:
            when = datetime.fromisoformat(str(stamp))
        except ValueError:
            continue
        if best is None or when > best:
            best = when
    return best


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
            "category": "other",
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

    # Deployment-managed: the verdict comes from the deployment, row or no
    # row. Branching on `row is None` meant a stray credential row — one a
    # real operator created through a form that should never have been
    # offered — flipped this back to credential-store rules and the false
    # claim that a credential is stored.
    if spec.managed == "deployment":
        # No `tenant_integrations` row, and there never will be: this
        # integration is configured from the deployment. Judging it by
        # credential rules produced `configured_unverified`, whose meaning is
        # "a credential is stored" — false by construction — and a footer
        # saying "no credential stored" two lines below it. Its state comes
        # from whether the deployment config is usable, which only its own
        # verifier can answer, so until one runs this is unverified *without*
        # claiming anything about a secret.
        per_direction = {
            d: {
                "state": CONFIGURED_UNVERIFIED,
                "checked_at": None,
                "reason": (
                    "Configured by the deployment (.env). No test call has "
                    "been made from this process yet — there is no stored "
                    "credential involved either way."
                ),
            }
            for d in spec.directions
        }
        return {
            "tool": spec.tool,
            "label": spec.label,
            "category": spec.category,
            "managed": spec.managed,
            "overall": CONFIGURED_UNVERIFIED,
            "directions": per_direction,
            "configured": True,
            # Explicitly absent rather than False: this integration has no
            # secret in the credential store, so "no credential stored" is
            # not a finding about it.
            "secret_set": None,
            # A row that exists and is never read. Surfaced rather than
            # ignored: somebody created it and believes they configured
            # something, and silence would leave them believing it.
            "stray_credential_row": None if row is None else {
                "configured_by": getattr(row, "configured_by", None),
                "config": getattr(row, "config", None),
                "note": (
                    "A credential-store row exists for this integration and "
                    "is NOT read — its configuration comes from the "
                    "deployment. Nothing here takes effect. It can be "
                    "removed; the form that wrote it should not have been "
                    "offered."
                ),
            },
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
            "category": spec.category,
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
        "category": spec.category,
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

    tools = []
    for t in sorted(cat):
        entry = status_of(cat.get(t), rows.get(t), t)
        # The fact that splits "never worked" from "worked until Monday".
        # Attached to every tool, because the state it upgrades is
        # `not_configured` — the one a vanished configuration produces, and
        # the one that is invisible on a page of unconfigured tools.
        last = await last_success_for(db, tenant_id, t, rows.get(t))
        entry["continuity"] = continuity(
            state=entry["overall"], last_succeeded_at=last,
            expected_interval_hours=getattr(
                cat.get(t), "expected_interval_hours", None),
        )
        entry["overall"] = entry["continuity"]["state"]
        tools.append(entry)
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
    # Continuity here too, not only on the card grid. Attaching it to one view
    # and not the other is how a stopped integration keeps reading as
    # `not_configured` in the matrix — the same invisibility, surviving in the
    # view whose whole job is "who has nothing working". The join test caught
    # this: the component reads `continuity` and one payload branch lacked it.
    cells: dict[str, dict[str, Any]] = {}
    for t in tenants:
        tid = t["tenant_id"]
        row_for = by_tenant.get(tid, {})
        cells[tid] = {}
        for tool in sorted(cat):
            entry = status_of(cat.get(tool), row_for.get(tool), tool)
            last = await last_success_for(db, tid, tool, row_for.get(tool))
            entry["continuity"] = continuity(
                state=entry["overall"], last_succeeded_at=last,
                expected_interval_hours=getattr(
                    cat.get(tool), "expected_interval_hours", None),
            )
            entry["overall"] = entry["continuity"]["state"]
            cells[tid][tool] = entry
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
