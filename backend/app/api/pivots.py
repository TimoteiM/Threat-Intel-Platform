"""
Infrastructure Pivot API — find related investigations sharing infrastructure.

GET /api/investigations/{id}/pivots
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.dependencies import DBSession
from app.services.pivot_service import PivotService

router = APIRouter(tags=["pivots"])


@router.get("/api/investigations/{investigation_id}/pivots")
async def get_pivots(investigation_id: str, session: DBSession):
    """Find investigations sharing infrastructure with this one."""
    service = PivotService(session)

    try:
        result = await service.find_related(investigation_id)
    except ValueError:
        raise HTTPException(400, "Invalid investigation ID")

    return result
