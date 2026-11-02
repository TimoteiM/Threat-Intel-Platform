"""
WHOIS History API — retrieve historical WHOIS snapshots for a domain.

GET /api/whois-history/{domain}
"""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import select

from app.dependencies import DBSession
from app.models.database import WHOISHistory

router = APIRouter(tags=["whois-history"])


@router.get("/api/whois-history/{domain:path}")
async def get_whois_history(domain: str, session: DBSession):
    """Return all WHOIS snapshots for a domain, newest first."""
    result = await session.execute(
        select(WHOISHistory)
        .where(WHOISHistory.domain == domain)
        .order_by(WHOISHistory.captured_at.desc())
    )
    snapshots = result.scalars().all()
    return [
        {
            "id": str(s.id),
            "domain": s.domain,
            "whois_json": s.whois_json,
            "captured_at": s.captured_at.isoformat() if s.captured_at else None,
            "investigation_id": str(s.investigation_id) if s.investigation_id else None,
            "changes_from_previous": s.changes_from_previous,
        }
        for s in snapshots
    ]
