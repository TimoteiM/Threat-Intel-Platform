from __future__ import annotations

from fastapi import APIRouter

from app.dependencies import DBSession
from app.services.soc_indicator_service import SOCIndicatorService


router = APIRouter(prefix="/api/soc-indicators", tags=["soc-indicators"])


@router.get("/graph")
async def get_soc_indicator_graph(
    session: DBSession,
    search: str | None = None,
    severity: str | None = None,
    limit: int = 260,
):
    service = SOCIndicatorService(session)
    return await service.get_graph(search=search, severity=severity, limit=max(50, min(limit, 500)))
