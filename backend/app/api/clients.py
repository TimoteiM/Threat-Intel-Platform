"""
Clients API — manage registered client organizations.

POST   /api/clients                               -> Create client
GET    /api/clients                               -> List clients
GET    /api/clients/{id}                          -> Get client details
PATCH  /api/clients/{id}                          -> Update client
DELETE /api/clients/{id}                          -> Delete client
GET    /api/clients/{id}/alerts                   -> List alerts for client

POST   /api/client-alerts/{id}/acknowledge        -> Acknowledge alert
POST   /api/client-alerts/{id}/resolve            -> Resolve alert
GET    /api/client-alerts                         -> Global alert feed
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, func, or_, desc

from app.dependencies import DBSession
from app.models.database import Client, ClientAlert
from app.models.schemas import ClientCreate, ClientUpdate

# ── Clients router ──────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/clients", tags=["clients"])


def _serialize_client(c: Client) -> dict:
    return {
        "id": str(c.id),
        "name": c.name,
        "domain": c.domain,
        "aliases": c.aliases or [],
        "brand_keywords": c.brand_keywords or [],
        "contact_email": c.contact_email,
        "notes": c.notes,
        "status": c.status,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "alert_count": c.alert_count,
        "last_alert_at": c.last_alert_at.isoformat() if c.last_alert_at else None,
        "default_collectors": c.default_collectors or [],
    }


def _serialize_alert(a: ClientAlert) -> dict:
    return {
        "id": str(a.id),
        "client_id": str(a.client_id),
        "investigation_id": str(a.investigation_id) if a.investigation_id else None,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "title": a.title,
        "details_json": a.details_json,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "acknowledged": a.acknowledged,
        "resolved": a.resolved,
    }


@router.post("", status_code=201)
async def create_client(request: ClientCreate, session: DBSession):
    """Register a new client organization."""
    domain = request.domain.lower().strip().removeprefix("www.")
    if not domain:
        raise HTTPException(400, "domain is required")

    client = Client(
        name=request.name.strip(),
        domain=domain,
        aliases=[a.lower().strip().removeprefix("www.") for a in request.aliases if a.strip()],
        brand_keywords=[k.lower().strip() for k in request.brand_keywords if k.strip()],
        contact_email=request.contact_email,
        notes=request.notes,
        default_collectors=request.default_collectors or [],
    )
    session.add(client)
    await session.commit()
    await session.refresh(client)
    return _serialize_client(client)


@router.get("")
async def list_clients(
    session: DBSession,
    limit: int = 25,
    offset: int = 0,
    search: str | None = None,
    status: str | None = None,
):
    """List registered clients with pagination."""
    query = select(Client)
    if status:
        query = query.where(Client.status == status)
    if search:
        query = query.where(
            or_(
                Client.name.ilike(f"%{search}%"),
                Client.domain.ilike(f"%{search}%"),
            )
        )

    count_q = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_q)
    total = total_result.scalar() or 0

    query = query.order_by(desc(Client.created_at)).limit(limit).offset(offset)
    result = await session.execute(query)
    clients = result.scalars().all()

    return {
        "items": [_serialize_client(c) for c in clients],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{client_id}")
async def get_client(client_id: str, session: DBSession):
    """Get a single client by ID."""
    result = await session.execute(
        select(Client).where(Client.id == uuid.UUID(client_id))
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")
    return _serialize_client(client)


@router.patch("/{client_id}")
async def update_client(client_id: str, request: ClientUpdate, session: DBSession):
    """Update client fields."""
    result = await session.execute(
        select(Client).where(Client.id == uuid.UUID(client_id))
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")

    if request.name is not None:
        client.name = request.name.strip()
    if request.domain is not None:
        client.domain = request.domain.lower().strip().removeprefix("www.")
    if request.aliases is not None:
        client.aliases = [a.lower().strip().removeprefix("www.") for a in request.aliases if a.strip()]
    if request.brand_keywords is not None:
        client.brand_keywords = [k.lower().strip() for k in request.brand_keywords if k.strip()]
    if request.contact_email is not None:
        client.contact_email = request.contact_email
    if request.notes is not None:
        client.notes = request.notes
    if request.status is not None:
        if request.status not in ("active", "paused"):
            raise HTTPException(400, "status must be 'active' or 'paused'")
        client.status = request.status
    if request.default_collectors is not None:
        client.default_collectors = request.default_collectors

    await session.commit()
    return _serialize_client(client)


@router.delete("/{client_id}")
async def delete_client(client_id: str, session: DBSession):
    """Delete a client and all their alerts."""
    result = await session.execute(
        select(Client).where(Client.id == uuid.UUID(client_id))
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(404, "Client not found")

    await session.delete(client)
    await session.commit()
    return {"ok": True}


@router.get("/{client_id}/alerts")
async def list_client_alerts(
    client_id: str,
    session: DBSession,
    limit: int = 25,
    offset: int = 0,
    resolved: bool | None = None,
    acknowledged: bool | None = None,
    severity: str | None = None,
):
    """List alerts for a specific client."""
    result = await session.execute(
        select(Client).where(Client.id == uuid.UUID(client_id))
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Client not found")

    query = select(ClientAlert).where(ClientAlert.client_id == uuid.UUID(client_id))
    if resolved is not None:
        query = query.where(ClientAlert.resolved == resolved)
    if acknowledged is not None:
        query = query.where(ClientAlert.acknowledged == acknowledged)
    if severity:
        query = query.where(ClientAlert.severity == severity)

    count_q = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_q)
    total = total_result.scalar() or 0

    query = query.order_by(desc(ClientAlert.created_at)).limit(limit).offset(offset)
    alerts_result = await session.execute(query)
    alerts = alerts_result.scalars().all()

    return {
        "items": [_serialize_alert(a) for a in alerts],
        "total": total,
    }


# ── Client Alerts router (separate prefix to avoid route conflicts) ──────────

alerts_router = APIRouter(prefix="/api/client-alerts", tags=["client-alerts"])


@alerts_router.get("")
async def list_all_alerts(
    session: DBSession,
    limit: int = 25,
    offset: int = 0,
    severity: str | None = None,
    resolved: bool | None = None,
    acknowledged: bool | None = None,
):
    """Global alert feed across all clients."""
    query = select(ClientAlert)
    if severity:
        query = query.where(ClientAlert.severity == severity)
    if resolved is not None:
        query = query.where(ClientAlert.resolved == resolved)
    if acknowledged is not None:
        query = query.where(ClientAlert.acknowledged == acknowledged)

    count_q = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_q)
    total = total_result.scalar() or 0

    query = query.order_by(desc(ClientAlert.created_at)).limit(limit).offset(offset)
    result = await session.execute(query)
    alerts = result.scalars().all()

    return {
        "items": [_serialize_alert(a) for a in alerts],
        "total": total,
    }


@alerts_router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, session: DBSession):
    """Mark an alert as acknowledged."""
    result = await session.execute(
        select(ClientAlert).where(ClientAlert.id == uuid.UUID(alert_id))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")

    alert.acknowledged = True
    await session.commit()
    return _serialize_alert(alert)


@alerts_router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: str, session: DBSession):
    """Mark an alert as resolved (and acknowledged)."""
    result = await session.execute(
        select(ClientAlert).where(ClientAlert.id == uuid.UUID(alert_id))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")

    alert.resolved = True
    alert.acknowledged = True
    await session.commit()
    return _serialize_alert(alert)
