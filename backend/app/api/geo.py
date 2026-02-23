"""
Geolocation API — resolve investigation IPs to map coordinates.

GET /api/investigations/{id}/geo-points
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.dependencies import DBSession
from app.services.investigation_service import InvestigationService
from app.services.geo_service import extract_geo_points

router = APIRouter(tags=["geo"])


@router.get("/api/investigations/{investigation_id}/geo-points")
async def get_geo_points(investigation_id: str, session: DBSession):
    """Return geo-located points for all IPs in the investigation evidence."""
    service = InvestigationService(session)
    evidence = await service.get_evidence(investigation_id)
    if not evidence:
        raise HTTPException(404, "Evidence not found")

    points = extract_geo_points(evidence)
    return points
