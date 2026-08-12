"""
Dashboard analytics endpoint — aggregated stats across all investigations.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable

from fastapi import APIRouter
from sqlalchemy import func, case, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import DBSession
from app.models.database import Investigation, Evidence

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_stats(session: DBSession):
    """Return aggregated dashboard statistics."""

    # ── Total investigations ──
    total_result = await session.execute(
        func.count(Investigation.id).select()
    )
    total_investigations = total_result.scalar() or 0

    # ── Classification breakdown (concluded only) ──
    class_result = await session.execute(
        Investigation.__table__.select()
        .with_only_columns(
            Investigation.classification,
            func.count().label("count"),
        )
        .where(Investigation.state == "concluded")
        .where(Investigation.classification.isnot(None))
        .group_by(Investigation.classification)
    )
    classification_breakdown = {
        row.classification: row.count for row in class_result
    }

    # ── Risk score distribution (buckets of 20) ──
    risk_result = await session.execute(
        Investigation.__table__.select()
        .with_only_columns(
            case(
                (Investigation.risk_score <= 20, "0-20"),
                (Investigation.risk_score <= 40, "21-40"),
                (Investigation.risk_score <= 60, "41-60"),
                (Investigation.risk_score <= 80, "61-80"),
                else_="81-100",
            ).label("bucket"),
            func.count().label("count"),
        )
        .where(Investigation.state == "concluded")
        .where(Investigation.risk_score.isnot(None))
        .group_by("bucket")
    )
    risk_distribution = [
        {"bucket": row.bucket, "count": row.count} for row in risk_result
    ]
    # Ensure all buckets exist
    bucket_order = ["0-20", "21-40", "41-60", "61-80", "81-100"]
    existing_buckets = {r["bucket"] for r in risk_distribution}
    for b in bucket_order:
        if b not in existing_buckets:
            risk_distribution.append({"bucket": b, "count": 0})
    risk_distribution.sort(key=lambda x: bucket_order.index(x["bucket"]))

    # ── Timeline (last 30 days, daily counts by classification) ──
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    timeline_result = await session.execute(
        Investigation.__table__.select()
        .with_only_columns(
            func.date_trunc("day", Investigation.created_at).label("day"),
            Investigation.classification,
            func.count().label("count"),
        )
        .where(Investigation.created_at >= thirty_days_ago)
        .where(Investigation.state == "concluded")
        .group_by("day", Investigation.classification)
        .order_by("day")
    )
    timeline: list[dict] = []
    for row in timeline_result:
        timeline.append({
            "date": row.day.isoformat() if row.day else None,
            "classification": row.classification or "inconclusive",
            "count": row.count,
        })

    # ── Top registrars (from evidence JSONB, malicious/suspicious only) ──
    top_registrars = await _get_top_evidence_field(
        session, "whois_registrar", ["malicious", "suspicious"]
    )

    # ── Top hosting providers ──
    top_hosting = await _get_top_evidence_field(
        session, "hosting_asn_org", ["malicious", "suspicious"]
    )

    # ── Recent malicious investigations ──
    recent_result = await session.execute(
        Investigation.__table__.select()
        .with_only_columns(
            Investigation.id,
            Investigation.domain,
            Investigation.risk_score,
            Investigation.classification,
            Investigation.created_at,
        )
        .where(Investigation.classification == "malicious")
        .order_by(Investigation.created_at.desc())
        .limit(100)
    )
    recent_malicious = _build_recent_malicious(recent_result)

    return {
        "total_investigations": total_investigations,
        "classification_breakdown": classification_breakdown,
        "risk_distribution": risk_distribution,
        "timeline": timeline,
        "top_registrars": top_registrars,
        "top_hosting_providers": top_hosting,
        "recent_malicious": recent_malicious,
    }


def _build_recent_malicious(rows: Iterable) -> list[dict]:
    recent_malicious: list[dict] = []
    seen_domains: set[str] = set()

    for row in rows:
        normalized_domain = (row.domain or "").strip().lower()
        if not normalized_domain or normalized_domain in seen_domains:
            continue
        seen_domains.add(normalized_domain)
        recent_malicious.append(
            {
                "id": str(row.id),
                "domain": row.domain,
                "risk_score": row.risk_score,
                "classification": row.classification,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        )
        if len(recent_malicious) == 10:
            break

    return recent_malicious


# The evidence columns this may group by. An allowlist rather than an arbitrary
# column name, because the value is interpolated into SQL — these are generated
# columns maintained by Postgres (migration 019), not caller input.
_TOP_FIELD_COLUMNS = {"whois_registrar", "hosting_asn_org"}


async def _get_top_evidence_field(
    session: AsyncSession,
    column: str,
    classifications: list[str],
    limit: int = 10,
) -> list[dict]:
    """
    Most common values of one evidence field, for the given classifications.

    Reads a stored generated column rather than digging into `evidence_json`.
    The JSONB averages ~300 KB per row, so extracting one string from it made
    Postgres detoast the entire value — this query took 3 seconds, and the two
    panels that use it accounted for most of a 6-second dashboard. Off the JSON
    it is ~1 ms.
    """
    if column not in _TOP_FIELD_COLUMNS:
        raise ValueError(f"Unsupported evidence column: {column}")

    try:
        result = await session.execute(
            text(f"""
                SELECT e.{column} AS field_value, COUNT(*) AS count
                FROM evidence e
                JOIN investigations i ON i.id = e.investigation_id
                WHERE i.classification = ANY(:classifications)
                  AND i.state = 'concluded'
                  AND e.{column} IS NOT NULL
                  AND e.{column} != ''
                GROUP BY field_value
                ORDER BY count DESC
                LIMIT :limit
            """),
            {"classifications": classifications, "limit": limit},
        )
        return [{"name": row.field_value, "count": row.count} for row in result]
    except Exception:
        return []
