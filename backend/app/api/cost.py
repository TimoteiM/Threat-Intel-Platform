"""
Provider spend and the savings the platform's avoidance machinery produced.

GET /api/cost/dashboard -> requests per provider against limits, plus work avoided

Every layer built to skip redundant work records what it skipped on the run that
skipped it. This reads those records back, so "what did the exclusion list
actually save us" and "are we near the VirusTotal cap" have answers.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from app.dependencies import DBSession
from app.services.cost_dashboard_service import cost_dashboard

router = APIRouter(prefix="/api/cost", tags=["cost"])


@router.get("/dashboard")
async def get_cost_dashboard(
    db: DBSession,
    days: int = Query(default=30, ge=1, le=365),
) -> dict[str, Any]:
    return await cost_dashboard(db, days=days)
