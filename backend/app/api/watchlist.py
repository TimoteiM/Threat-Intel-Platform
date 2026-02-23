"""
Watchlist API — manage watched domains.

POST   /api/watchlist                       -> Add domain to watchlist
GET    /api/watchlist                       -> List watched domains
PATCH  /api/watchlist/{id}                  -> Update status/notes/schedule
DELETE /api/watchlist/{id}                  -> Remove from watchlist
GET    /api/watchlist/{id}/alerts           -> List alerts for entry
POST   /api/watchlist/{id}/investigate      -> Launch investigation for watched domain
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, func

from app.dependencies import DBSession
from app.db.repository import WatchlistRepository
from app.models.database import Investigation
from app.models.schemas import WatchlistCreate, WatchlistUpdate, InvestigationCreate
from app.services.investigation_service import InvestigationService
from app.tasks.watchlist_task import compute_next_check
from app.utils.domain_utils import normalize_domain, validate_domain

router = APIRouter(prefix="/api/watchlist", tags=["watchlist"])

VALID_INTERVALS = {"weekly", "biweekly", "monthly"}


def _validate_schedule_interval(interval: str | None) -> str | None:
    """Validate and normalize schedule_interval. Returns None if disabled."""
    if interval is None or interval in ("", "none"):
        return None
    if interval not in VALID_INTERVALS:
        raise HTTPException(
            400,
            f"Invalid schedule_interval. Must be one of: {', '.join(sorted(VALID_INTERVALS))}"
        )
    return interval


async def _get_latest_investigation(session, domain: str) -> dict | None:
    """Look up the most recent investigation for a domain."""
    result = await session.execute(
        select(Investigation)
        .where(Investigation.domain == domain)
        .order_by(Investigation.created_at.desc())
        .limit(1)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        return None
    return {
        "id": str(inv.id),
        "state": inv.state,
        "classification": inv.classification,
        "risk_score": inv.risk_score,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
    }


async def _get_investigation_count(session, domain: str) -> int:
    """Count total investigations for a domain."""
    result = await session.execute(
        select(func.count(Investigation.id))
        .where(Investigation.domain == domain)
    )
    return result.scalar() or 0


def _serialize_entry(e, latest=None, inv_count=0) -> dict:
    """Serialize a watchlist entry to dict."""
    return {
        "id": str(e.id),
        "domain": e.domain,
        "notes": e.notes,
        "added_by": e.added_by,
        "status": e.status,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "last_checked_at": e.last_checked_at.isoformat() if e.last_checked_at else None,
        "alert_count": e.alert_count,
        "schedule_interval": e.schedule_interval,
        "next_check_at": e.next_check_at.isoformat() if e.next_check_at else None,
        "latest_investigation": latest,
        "investigation_count": inv_count,
    }


@router.post("")
async def create_watchlist_entry(request: WatchlistCreate, session: DBSession):
    """Add a domain to the watchlist."""
    domain = normalize_domain(request.domain)
    if not validate_domain(domain):
        raise HTTPException(400, f"Invalid domain: {request.domain}")

    interval = _validate_schedule_interval(request.schedule_interval)

    repo = WatchlistRepository(session)
    entry = await repo.create(
        domain=domain,
        notes=request.notes,
        added_by=request.added_by,
    )

    # Set schedule if provided
    if interval:
        now = datetime.now(timezone.utc)
        next_check = compute_next_check(interval, now)
        await repo.update(
            entry.id,
            schedule_interval=interval,
            next_check_at=next_check,
        )
        entry.schedule_interval = interval
        entry.next_check_at = next_check

    latest = await _get_latest_investigation(session, domain)

    return _serialize_entry(
        entry,
        latest=latest,
        inv_count=1 if latest else 0,
    )


@router.get("")
async def list_watchlist(
    session: DBSession,
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
    search: str | None = None,
):
    """List watched domains with pagination and latest investigation data."""
    repo = WatchlistRepository(session)
    entries = await repo.list_all(limit=limit, offset=offset, status=status, search=search)
    total = await repo.count(status=status, search=search)

    items = []
    for e in entries:
        latest = await _get_latest_investigation(session, e.domain)
        inv_count = await _get_investigation_count(session, e.domain)
        items.append(_serialize_entry(e, latest=latest, inv_count=inv_count))

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.patch("/{watchlist_id}")
async def update_watchlist_entry(
    watchlist_id: str,
    request: WatchlistUpdate,
    session: DBSession,
):
    """Update watchlist entry status, notes, or schedule."""
    repo = WatchlistRepository(session)
    entry = await repo.get(uuid.UUID(watchlist_id))
    if not entry:
        raise HTTPException(404, "Watchlist entry not found")

    fields = {}
    if request.status is not None:
        if request.status not in ("active", "paused", "removed"):
            raise HTTPException(400, "Invalid status. Must be: active, paused, removed")
        fields["status"] = request.status
    if request.notes is not None:
        fields["notes"] = request.notes

    # Handle schedule_interval update
    if request.schedule_interval is not None:
        interval = _validate_schedule_interval(request.schedule_interval)
        fields["schedule_interval"] = interval
        if interval:
            now = datetime.now(timezone.utc)
            fields["next_check_at"] = compute_next_check(interval, now)
        else:
            fields["next_check_at"] = None

    if fields:
        await repo.update(uuid.UUID(watchlist_id), **fields)

    return {"ok": True}


@router.delete("/{watchlist_id}")
async def delete_watchlist_entry(watchlist_id: str, session: DBSession):
    """Remove a domain from the watchlist."""
    repo = WatchlistRepository(session)
    entry = await repo.get(uuid.UUID(watchlist_id))
    if not entry:
        raise HTTPException(404, "Watchlist entry not found")

    await repo.delete(uuid.UUID(watchlist_id))
    return {"ok": True}


@router.get("/{watchlist_id}/alerts")
async def list_alerts(
    watchlist_id: str,
    session: DBSession,
    limit: int = 50,
    offset: int = 0,
):
    """List alerts for a watchlist entry."""
    repo = WatchlistRepository(session)
    entry = await repo.get(uuid.UUID(watchlist_id))
    if not entry:
        raise HTTPException(404, "Watchlist entry not found")

    alerts = await repo.get_alerts(uuid.UUID(watchlist_id), limit=limit, offset=offset)
    return [
        {
            "id": str(a.id),
            "alert_type": a.alert_type,
            "details_json": a.details_json,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "acknowledged": a.acknowledged,
        }
        for a in alerts
    ]


@router.post("/{watchlist_id}/investigate")
async def investigate_watchlist_domain(watchlist_id: str, session: DBSession):
    """Launch a new investigation for a watched domain."""
    repo = WatchlistRepository(session)
    entry = await repo.get(uuid.UUID(watchlist_id))
    if not entry:
        raise HTTPException(404, "Watchlist entry not found")

    if entry.status != "active":
        raise HTTPException(400, "Cannot investigate a paused/removed domain")

    service = InvestigationService(session)
    request = InvestigationCreate(
        domain=entry.domain,
        context=f"Watchlist re-investigation. Notes: {entry.notes or 'None'}",
    )
    try:
        result = await service.create(request)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Update last_checked_at and push next scheduled check forward if applicable
    update_fields: dict = {"last_checked_at": datetime.now(timezone.utc)}
    if entry.schedule_interval:
        update_fields["next_check_at"] = compute_next_check(
            entry.schedule_interval, datetime.now(timezone.utc)
        )
    await repo.update(uuid.UUID(watchlist_id), **update_fields)

    return result
