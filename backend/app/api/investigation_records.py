"""Read an investigation record: the chain, with every step's claim.

The steps **are** the page. The summary, when there is one, sits above them
labelled as derived, with any entity or quantity it states that no step
recorded marked in place — so a summary cannot be read as evidence.

A chain that did not record fully says so above itself and is never presented
as the investigation.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Path as FastAPIPath, Query, Request
from sqlalchemy import select

from app.dependencies import DBSession
from app.services import tenant_scope
from app.services.investigation_step_render import presentation_of, render

router = APIRouter(prefix="/api/investigation-records",
                   tags=["investigation-records"])


def _step_json(step: Any) -> dict[str, Any]:
    fields = (step.query or {}).get("template_fields") or {}
    rendered = render(step.kind, fields)
    # A step whose template reads a field the payload lacks has no sentence.
    # Rendered as the absence it is, with the key named, rather than as a
    # well-formed sentence with a hole in it.
    text = rendered["text"]
    absence_kind = step.absence_kind
    absence_reason = step.absence_reason
    if rendered["templated"] and not rendered["renderable"]:
        text = None
        absence_kind = absence_kind or "check_failed"
        absence_reason = absence_reason or rendered["reason"]
    return {
        "ordinal": step.ordinal,
        "kind": step.kind,
        "question": step.question,
        "text": text,
        # `claim` / `no_claim` / `raw`, decided beside the renderer. The page
        # switches on this rather than inferring it from `absence_kind`, which
        # is a category and not a statement that the step said nothing.
        "presentation": presentation_of(rendered, absence_kind),
        "unrenderable_fields": rendered["missing"],
        # False means this kind has no template and the raw fields are shown.
        # Surfaced rather than hidden: an unregistered kind must look wrong.
        "templated": rendered["templated"],
        "source": step.source,
        "target": step.target,
        "verdict": step.verdict,
        "observables_found": step.observables_found,
        "observables_selected": step.observables_selected,
        "warrant": step.warrant,
        "absence_kind": absence_kind,
        "absence_reason": absence_reason,
        "duration_ms": step.duration_ms,
        "cost": step.cost,
        "response_truncated": step.response_truncated,
        "response_bytes": step.response_bytes,
        # The query is ours, so it is shown verbatim. The response excerpt is
        # the customer's and is not returned by this endpoint — it is stored
        # for an investigator with a reason to open the row, not rendered on a
        # page by default.
        "query": {k: v for k, v in (step.query or {}).items()
                  if k != "template_fields"},
    }


@router.get("/by-origin/{surface}/{origin_id}")
async def record_by_origin(
    db: DBSession,
    surface: str = FastAPIPath(...),
    origin_id: str = FastAPIPath(...),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """The record a surface produced for one run, alert or lookup."""
    from app.models.database import InvestigationRecord

    row = (await db.execute(
        select(InvestigationRecord).where(
            InvestigationRecord.origin_surface == surface,
            InvestigationRecord.origin_id == str(origin_id),
        )
    )).scalars().first()
    if row is None:
        raise HTTPException(404, "No investigation record for that origin.")
    return await _payload(db, row, request)


@router.get("/{record_id}")
async def record_by_id(
    db: DBSession,
    record_id: str = FastAPIPath(...),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    from app.models.database import InvestigationRecord

    try:
        parsed = uuid.UUID(record_id)
    except ValueError as exc:
        raise HTTPException(400, "Invalid record id.") from exc
    row = await db.get(InvestigationRecord, parsed)
    if row is None:
        raise HTTPException(404, "Investigation record not found.")
    return await _payload(db, row, request)


async def _payload(db: Any, row: Any, request: Any) -> dict[str, Any]:
    from app.models.database import InvestigationStep

    # Scoped like every other read. A record with no tenant is readable by a
    # caller who may read unassigned work, which is what `assert_can_read`
    # already decides — this does not invent a second rule for it.
    identity = getattr(getattr(request, "state", None), "identity", None)
    tenant_scope.assert_can_read(tenant_scope.scope_of(identity), row.tenant_id)

    steps = (await db.execute(
        select(InvestigationStep)
        .where(InvestigationStep.record_id == row.id)
        .order_by(InvestigationStep.ordinal)
    )).scalars().all()

    return {
        "id": str(row.id),
        "origin": {"surface": row.origin_surface, "id": row.origin_id},
        "tenant_id": row.tenant_id,
        "actor": {
            "kind": row.actor_kind,
            "user_id": str(row.actor_user_id) if row.actor_user_id else None,
            "recorded": row.actor_recorded,
        },
        "verdict": row.verdict,
        "summary": row.summary,
        "summary_unverified_entities": row.summary_unverified_entities,
        "summary_unverified_numerals": row.summary_unverified_numerals,
        # Above the chain on the page, by contract.
        "incomplete": row.incomplete,
        "incomplete_steps": row.incomplete_steps,
        "counters": {
            "steps_run": row.steps_run,
            "steps_escalated": row.steps_escalated,
            "observables_stopped": row.observables_stopped,
            "model_calls": row.model_calls,
        },
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "steps": [_step_json(s) for s in steps],
    }
