"""
Admin and operational health endpoints.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter

from app.models.schemas import APIHealthResponse
from app.services.api_health_service import get_api_health_snapshot

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/api-health", response_model=APIHealthResponse)
async def get_api_health() -> APIHealthResponse:
    # On a cold cache this probes three providers with blocking HTTP calls, up
    # to 10s each. Inline on the event loop that is 30 seconds during which the
    # API answers nothing at all — which is what made this page return
    # "Internal Server Error" on first load and succeed on a refresh.
    return await asyncio.to_thread(get_api_health_snapshot)
