"""
IP Lookup Tool — standalone IP reputation check with persistent history.

POST   /api/tools/ip-lookup              → Run lookup + save to history
GET    /api/tools/ip-lookup/history      → List past lookups (most recent first)
GET    /api/tools/ip-lookup/history/{id} → Get a specific saved lookup
DELETE /api/tools/ip-lookup/history/{id} → Delete a saved lookup

The reputation logic itself lives in app.services.ip_lookup_service so other
pipelines (e.g. alert-body investigations) reuse the exact same checks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select, delete

from app.dependencies import DBSession
from app.models.database import IPLookup
from app.services.ip_lookup_service import (
    ABUSEIPDB_CATEGORIES,
    build_ip_lookup_record,
    perform_ip_lookup,
)

router = APIRouter(tags=["tools"])
logger = logging.getLogger(__name__)

__all__ = ["router", "ABUSEIPDB_CATEGORIES"]


class IPLookupRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v.strip()


# ─── Lookup ───

@router.post("/api/tools/ip-lookup")
async def ip_lookup(request: IPLookupRequest, session: DBSession):
    """
    Run an IP reputation check (AbuseIPDB verbose + ThreatFox).
    Result is saved to history and returned immediately.
    """
    result = await asyncio.to_thread(perform_ip_lookup, request.ip)

    record = build_ip_lookup_record(result)
    session.add(record)
    await session.flush()

    result["id"] = str(record.id)
    return result


# ─── History ───

@router.get("/api/tools/ip-lookup/history")
async def list_ip_lookup_history(session: DBSession, limit: int = 50, offset: int = 0):
    """List past IP lookups, most recent first."""
    stmt = (
        select(IPLookup)
        .order_by(IPLookup.queried_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [_to_list_item(r) for r in rows]


@router.get("/api/tools/ip-lookup/history/{lookup_id}")
async def get_ip_lookup(lookup_id: str, session: DBSession):
    """Retrieve a specific saved IP lookup result."""
    try:
        uid = uuid.UUID(lookup_id)
    except ValueError:
        raise HTTPException(400, "Invalid lookup ID")

    row = await session.get(IPLookup, uid)
    if not row:
        raise HTTPException(404, "Lookup not found")
    return row.result_json | {"id": str(row.id)}


@router.delete("/api/tools/ip-lookup/history/{lookup_id}", status_code=204)
async def delete_ip_lookup(lookup_id: str, session: DBSession):
    """Delete a saved lookup from history."""
    try:
        uid = uuid.UUID(lookup_id)
    except ValueError:
        raise HTTPException(400, "Invalid lookup ID")

    await session.execute(delete(IPLookup).where(IPLookup.id == uid))


# ─── Helper ───

def _to_list_item(row: IPLookup) -> dict:
    return {
        "id": str(row.id),
        "ip": row.ip,
        "abuse_score": row.abuse_score,
        "isp": row.isp,
        "country_code": row.country_code,
        "threatfox_count": row.threatfox_count,
        "queried_at": row.queried_at.isoformat() if row.queried_at else None,
    }
