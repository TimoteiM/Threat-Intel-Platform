"""
Exclusion API — the indicators the platform treats as benign without collecting.

GET    /api/exclusions            -> List, newest first, with filters
POST   /api/exclusions            -> Add one (re-activates a matching inactive row)
POST   /api/exclusions/check      -> Would these indicators be excluded?
PATCH  /api/exclusions/{id}       -> Edit reason / expiry / scope / active
DELETE /api/exclusions/{id}       -> Remove

Adding an entry here stops collectors, VirusTotal quota and AI tokens being spent
on that indicator in every future alert — see `app/services/exclusion_service.py`
for what matching covers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, or_, select

from app.dependencies import DBSession
from app.models.database import Exclusion
from app.models.schemas import ExclusionCheckRequest, ExclusionCreate, ExclusionUpdate
from app.services.exclusion_service import (
    ExclusionError,
    ExclusionMatcher,
    INDICATOR_TYPES,
    load_matcher,
    normalize_exclusion,
)

router = APIRouter(prefix="/api/exclusions", tags=["exclusions"])


@router.get("")
async def list_exclusions(
    db: DBSession,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    indicator_type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    active: bool | None = Query(default=None),
) -> dict[str, Any]:
    """The exclusion list, newest first."""
    query = select(Exclusion)
    count_query = select(func.count(Exclusion.id))

    filters = []
    if indicator_type:
        kind = indicator_type.strip().lower()
        if kind not in INDICATOR_TYPES:
            raise HTTPException(400, f"indicator_type must be one of {', '.join(INDICATOR_TYPES)}")
        filters.append(Exclusion.indicator_type == kind)
    if active is not None:
        filters.append(Exclusion.active.is_(active))
    if (search or "").strip():
        pattern = f"%{search.strip().lower()}%"
        filters.append(
            or_(
                func.lower(Exclusion.value).like(pattern),
                func.lower(Exclusion.normalized_value).like(pattern),
                func.lower(Exclusion.reason).like(pattern),
            )
        )
    for clause in filters:
        query = query.where(clause)
        count_query = count_query.where(clause)

    rows = (
        await db.execute(query.order_by(Exclusion.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    total = (await db.execute(count_query)).scalar() or 0

    return {
        "items": [_serialize(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("", status_code=201)
async def create_exclusion(request: ExclusionCreate, db: DBSession) -> dict[str, Any]:
    """
    Add an indicator to the exclusion list.

    Re-submitting one that is already listed updates it rather than failing —
    an analyst adding `expertware.net` twice means "make sure it is excluded",
    and a duplicate-key error would be a worse answer than doing that.
    """
    try:
        kind, normalized = normalize_exclusion(request.indicator_type, request.value)
    except ExclusionError as exc:
        raise HTTPException(400, str(exc)) from exc

    existing = (
        await db.execute(
            select(Exclusion).where(
                Exclusion.indicator_type == kind,
                Exclusion.normalized_value == normalized,
            )
        )
    ).scalars().first()

    if existing is not None:
        existing.active = True
        existing.reason = request.reason.strip()
        existing.match_subdomains = bool(request.match_subdomains)
        existing.expires_at = _aware(request.expires_at)
        if request.added_by:
            existing.added_by = request.added_by
        await db.commit()
        await db.refresh(existing)
        return {**_serialize(existing), "already_listed": True}

    row = Exclusion(
        indicator_type=kind,
        value=request.value.strip(),
        normalized_value=normalized,
        reason=request.reason.strip(),
        added_by=(request.added_by or "").strip() or None,
        match_subdomains=bool(request.match_subdomains),
        expires_at=_aware(request.expires_at),
        active=True,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return {**_serialize(row), "already_listed": False}


@router.post("/check")
async def check_exclusions(request: ExclusionCheckRequest, db: DBSession) -> dict[str, Any]:
    """
    Would these indicators be skipped? Answers without touching a collector.

    Lets the UI show "3 of these 12 are already excluded" before an analyst
    spends a run finding out.
    """
    matcher = await load_matcher(db)
    results = []
    for item in request.indicators:
        hit = matcher.match(item.indicator_type, item.value)
        results.append(
            {
                "indicator_type": item.indicator_type,
                "value": item.value,
                "excluded": hit is not None,
                "exclusion": hit,
            }
        )
    return {"results": results, "excluded_count": sum(1 for r in results if r["excluded"])}


@router.patch("/{exclusion_id}")
async def update_exclusion(exclusion_id: str, request: ExclusionUpdate, db: DBSession) -> dict[str, Any]:
    """Edit an entry. The indicator itself is immutable — delete and re-add instead."""
    row = await _get(db, exclusion_id)
    if request.reason is not None:
        reason = request.reason.strip()
        if not reason:
            raise HTTPException(400, "reason cannot be emptied — it is why the entry exists")
        row.reason = reason
    if request.active is not None:
        row.active = bool(request.active)
    if request.match_subdomains is not None:
        row.match_subdomains = bool(request.match_subdomains)
    if request.expires_at is not None:
        row.expires_at = _aware(request.expires_at)
    if request.clear_expiry:
        row.expires_at = None
    await db.commit()
    await db.refresh(row)
    return _serialize(row)


@router.delete("/{exclusion_id}")
async def delete_exclusion(exclusion_id: str, db: DBSession) -> dict[str, Any]:
    """Remove an entry — the indicator is investigated normally again."""
    row = await _get(db, exclusion_id)
    await db.delete(row)
    await db.commit()
    return {"deleted": True, "id": exclusion_id}


# ── Internals ─────────────────────────────────────────────────────────────────


async def _get(db: DBSession, exclusion_id: str) -> Exclusion:
    try:
        parsed = uuid.UUID(exclusion_id)
    except ValueError as exc:
        raise HTTPException(400, "Invalid exclusion id") from exc
    row = await db.get(Exclusion, parsed)
    if row is None:
        raise HTTPException(404, "Exclusion not found")
    return row


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _serialize(row: Exclusion) -> dict[str, Any]:
    expires_at = _aware(row.expires_at)
    return {
        "id": str(row.id),
        "indicator_type": row.indicator_type,
        "value": row.value,
        "normalized_value": row.normalized_value,
        "reason": row.reason,
        "added_by": row.added_by,
        "match_subdomains": row.match_subdomains,
        "active": row.active,
        "expired": bool(expires_at and expires_at <= datetime.now(timezone.utc)),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "hit_count": row.hit_count,
        "last_hit_at": _aware(row.last_hit_at).isoformat() if row.last_hit_at else None,
        "created_at": _aware(row.created_at).isoformat() if row.created_at else None,
        "updated_at": _aware(row.updated_at).isoformat() if row.updated_at else None,
    }
