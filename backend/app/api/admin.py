"""
Admin and operational health endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.models.schemas import APIHealthResponse
from app.services.api_health_service import get_api_health_snapshot

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/api-health", response_model=APIHealthResponse)
async def get_api_health() -> APIHealthResponse:
    return get_api_health_snapshot()
