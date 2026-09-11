"""
Provider spend and the savings the platform's avoidance machinery produced.

GET /api/cost/dashboard   -> requests per provider against limits, plus work avoided
GET /api/cost/ai-spend    -> what our own AI calls cost, metered from token usage
PUT /api/cost/ai-budget   -> the monthly figure the remaining number counts down from

Every layer built to skip redundant work records what it skipped on the run that
skipped it. This reads those records back, so "what did the exclusion list
actually save us" and "are we near the VirusTotal cap" have answers.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.dependencies import DBSession
from app.services.cost_dashboard_service import cost_dashboard
from app.services.ai_cost_service import ai_spend_summary, get_budget_usd, set_budget_usd

router = APIRouter(prefix="/api/cost", tags=["cost"])


@router.get("/dashboard")
async def get_cost_dashboard(
    db: DBSession,
    days: int = Query(default=30, ge=1, le=365),
) -> dict[str, Any]:
    return await cost_dashboard(db, days=days)


@router.get("/ai-spend")
async def get_ai_spend(
    days: int = Query(default=30, ge=1, le=90),
) -> dict[str, Any]:
    """What this application's AI calls cost, priced from their own token usage.

    Not a provider balance. Neither OpenAI nor Anthropic exposes remaining
    credit through an API — OpenAI's Usage API reports spend and needs an
    admin-scoped key — so this meters our own requests and counts them against
    a budget the analyst sets.
    """
    return ai_spend_summary(days=days)


class AIBudgetRequest(BaseModel):
    monthly_usd: float = Field(..., ge=0, le=1_000_000)


@router.put("/ai-budget")
async def put_ai_budget(body: AIBudgetRequest) -> dict[str, Any]:
    """Set the monthly budget, or clear it with 0."""
    try:
        saved = set_budget_usd(body.monthly_usd)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not store the budget: {exc}") from exc
    return {"monthly_usd": saved}


@router.get("/ai-budget")
async def get_ai_budget() -> dict[str, Any]:
    return {"monthly_usd": get_budget_usd()}
