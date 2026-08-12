"""
What the platform is spending, and what its savings machinery is saving.

Every layer built to avoid redundant work — alert-id dedupe, the exclusion list,
prior-investigation reuse, VT-for-hashes-only — records what it did on the run
it did it for. Nothing was reading those records back, so the saving was real
but invisible, and "are we near the VirusTotal cap?" had no answer short of
grepping logs.

This aggregates both halves from what is already stored:

    spend    provider requests today and this month, from the Redis counters
             every collector increments, against the configured limits
    savings  indicator lookups avoided, counted from the runs that avoided them

The savings figures are counts of work not done, not money. A skipped VT lookup
is worth a different amount to everyone, so the number of calls avoided is
reported and the valuation is left to the reader.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.database import AlertBodyInvestigationRun, Exclusion
from app.services.provider_usage_metrics import get_provider_usage

logger = logging.getLogger(__name__)

# Providers whose usage is worth showing a SOC. Ordered by how much a SOC
# actually has to ration them.
TRACKED_PROVIDERS = (
    ("virustotal", "VirusTotal"),
    ("anyrun", "ANY.RUN"),
    ("hybrid_analysis", "Hybrid Analysis"),
    ("urlscan", "URLScan"),
    ("abuseipdb", "AbuseIPDB"),
    ("shodan", "Shodan"),
    ("opencti", "OpenCTI"),
    ("otx", "AlienVault OTX"),
    ("brave_search", "Brave Search"),
    ("threatfox", "ThreatFox"),
    ("phishtank", "PhishTank"),
    ("openphish", "OpenPhish"),
    ("google_safe_browsing", "Google Safe Browsing"),
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic"),
)

AI_PROVIDERS = frozenset({"openai", "anthropic"})


async def cost_dashboard(db: AsyncSession, *, days: int = 30) -> dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, days))
    settings = get_settings()

    providers = [_provider_row(key, label, settings) for key, label in TRACKED_PROVIDERS]
    savings = await _savings(db, cutoff)

    return {
        "window_days": days,
        "providers": [row for row in providers if row["requests_today"] or row["requests_this_month"]],
        "providers_idle": [
            row["provider"] for row in providers
            if not row["requests_today"] and not row["requests_this_month"]
        ],
        "ai_requests_today": sum(
            row["requests_today"] for row in providers if row["key"] in AI_PROVIDERS
        ),
        "at_risk": [row for row in providers if row["percent_used"] is not None and row["percent_used"] >= 80],
        "savings": savings,
        "note": _note(providers, savings),
    }


# ── Spend ─────────────────────────────────────────────────────────────────────


def _provider_row(key: str, label: str, settings: Any) -> dict[str, Any]:
    usage = get_provider_usage(key)
    daily_limit = (settings.api_health_daily_limit_overrides_map or {}).get(key)
    monthly_limit = (settings.api_health_monthly_limit_overrides_map or {}).get(key)

    percent = None
    if daily_limit:
        percent = round(usage["requests_today"] / daily_limit * 100, 1)
    elif monthly_limit:
        percent = round(usage["requests_this_month"] / monthly_limit * 100, 1)

    return {
        "key": key,
        "provider": label,
        "requests_today": usage["requests_today"],
        "requests_this_month": usage["requests_this_month"],
        "daily_limit": daily_limit,
        "monthly_limit": monthly_limit,
        "percent_used": percent,
        "remaining_today": (
            max(int(daily_limit - usage["requests_today"]), 0) if daily_limit else None
        ),
    }


# ── Savings ───────────────────────────────────────────────────────────────────


async def _savings(db: AsyncSession, cutoff: datetime) -> dict[str, Any]:
    """
    Work avoided, counted from the runs that avoided it.

    Every figure here is an indicator lookup that did not happen, read back from
    what the run recorded at the time.
    """
    # Only the two roll-up blocks are read; `result_json` averages 14 KB and
    # pulling it for every run in the window dominated this endpoint.
    runs = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.result_extraction,
                AlertBodyInvestigationRun.result_summary,
            ).where(AlertBodyInvestigationRun.created_at >= cutoff)
        )
    ).all()

    excluded = reused = ai_skipped = 0
    investigated = 0
    for extraction, summary in runs:
        extraction = extraction or {}
        summary = summary or {}
        excluded += int(extraction.get("excluded_total") or 0)
        reused += int(summary.get("indicators_reused") or 0)
        investigated += int(summary.get("indicators_investigated") or 0)
        if str(summary.get("ai_analysis") or "") == "skipped":
            ai_skipped += 1

    duplicates = await _duplicate_deliveries(db, cutoff)
    exclusion_hits = int(
        (await db.execute(select(func.coalesce(func.sum(Exclusion.hit_count), 0)))).scalar() or 0
    )

    avoided = excluded + reused
    total_work = avoided + investigated
    return {
        "alert_runs": len(runs),
        "indicator_lookups_performed": investigated,
        "indicator_lookups_avoided": avoided,
        "avoided_by_exclusion_list": excluded,
        "avoided_by_prior_investigation_reuse": reused,
        "duplicate_alert_deliveries_absorbed": duplicates,
        "ai_analyses_skipped": ai_skipped,
        "exclusion_hits_all_time": exclusion_hits,
        # What share of the work the platform was asked to do it managed not to.
        "avoidance_rate": round(avoided / total_work, 3) if total_work else None,
    }


async def _duplicate_deliveries(db: AsyncSession, cutoff: datetime) -> int:
    """
    Re-deliveries absorbed by dedupe.

    A duplicate never creates a row — that is the point — so it cannot be
    counted directly. What *can* be counted is how many alert ids arrived more
    than once, which is the same population from the other side: for each id
    seen n times, n-1 deliveries were absorbed. Runs sharing an id are the
    evidence that ids repeat at all.
    """
    try:
        rows = (
            await db.execute(
                select(AlertBodyInvestigationRun.external_ref, func.count(AlertBodyInvestigationRun.id))
                .where(
                    AlertBodyInvestigationRun.created_at >= cutoff,
                    AlertBodyInvestigationRun.external_ref.isnot(None),
                )
                .group_by(AlertBodyInvestigationRun.external_ref)
                .having(func.count(AlertBodyInvestigationRun.id) > 1)
            )
        ).all()
    except Exception as exc:
        logger.warning("Duplicate-delivery count failed: %s", exc)
        return 0
    return sum(int(count) - 1 for _ref, count in rows)


def _note(providers: list[dict[str, Any]], savings: dict[str, Any]) -> str:
    pressured = [row for row in providers if (row["percent_used"] or 0) >= 80]
    if pressured:
        worst = max(pressured, key=lambda row: row["percent_used"])
        return (
            f"{worst['provider']} is at {worst['percent_used']}% of its configured limit. "
            f"Exclusions and reuse have avoided {savings['indicator_lookups_avoided']} "
            f"lookup(s) in this window."
        )
    rate = savings["avoidance_rate"]
    if rate is None:
        return "No alert runs in this window yet."
    return (
        f"{savings['indicator_lookups_avoided']} of "
        f"{savings['indicator_lookups_avoided'] + savings['indicator_lookups_performed']} "
        f"indicator lookups were avoided ({rate:.0%}) by the exclusion list and prior-investigation reuse."
    )
