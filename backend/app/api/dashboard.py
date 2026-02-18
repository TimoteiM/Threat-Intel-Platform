"""
Dashboard analytics endpoint — aggregated stats across all investigations.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
    top_registrars = await _get_top_jsonb_field(
        session, "whois", "registrar", ["malicious", "suspicious"]
    )

    # ── Top hosting providers (from evidence JSONB) ──
    top_hosting = await _get_top_jsonb_field(
        session, "hosting", "asn_org", ["malicious", "suspicious"]
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
        .limit(10)
    )
    recent_malicious = [
        {
            "id": str(row.id),
            "domain": row.domain,
            "risk_score": row.risk_score,
            "classification": row.classification,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in recent_result
    ]

    return {
        "total_investigations": total_investigations,
        "classification_breakdown": classification_breakdown,
        "risk_distribution": risk_distribution,
        "timeline": timeline,
        "top_registrars": top_registrars,
        "top_hosting_providers": top_hosting,
        "recent_malicious": recent_malicious,
    }


async def _get_top_jsonb_field(
    session: AsyncSession,
    evidence_key: str,
    field_name: str,
    classifications: list[str],
    limit: int = 10,
) -> list[dict]:
    """
    Extract top values from a JSONB field within evidence,
    filtered to specific classifications.
    """
    try:
        result = await session.execute(
            text("""
                SELECT
                    e.evidence_json->:evidence_key->>:field_name AS field_value,
                    COUNT(*) AS count
                FROM evidence e
                JOIN investigations i ON i.id = e.investigation_id
                WHERE i.classification = ANY(:classifications)
                  AND i.state = 'concluded'
                  AND e.evidence_json->:evidence_key->>:field_name IS NOT NULL
                  AND e.evidence_json->:evidence_key->>:field_name != ''
                GROUP BY field_value
                ORDER BY count DESC
                LIMIT :limit
            """),
            {
                "evidence_key": evidence_key,
                "field_name": field_name,
                "classifications": classifications,
                "limit": limit,
            },
        )
        return [{"name": row.field_value, "count": row.count} for row in result]
    except Exception:
        return []
