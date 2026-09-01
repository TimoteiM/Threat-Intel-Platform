"""
Detection quality, ATT&CK coverage and analyst feedback.

GET  /api/detections/quality        -> per-rule signal-to-noise, ATT&CK confirm rate
GET  /api/detections/attack-coverage-> what detections claim vs what evidence shows
GET  /api/detections/attack-coverage/tactic-alerts -> the alerts behind one tactic
GET  /api/detections/attack-coverage/mismatch-alerts -> the alerts behind one claim/evidence mismatch
POST /api/detections/feedback       -> record an analyst's true/false positive call
GET  /api/detections/feedback       -> list feedback, newest first
GET  /api/detections/feedback/accuracy -> how often the platform agreed with analysts
GET  /api/detections/feedback/{type}/{id} -> the standing judgement on one subject

Feedback is what makes the decision engine measurable: without it, every tuning
decision is a guess about whether a classification was right.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from app.dependencies import DBSession
from app.models.database import AlertBodyInvestigationRun, AnalystFeedback, Investigation
from app.models.schemas import AnalystFeedbackCreate
from app.services.attack_coverage_service import attack_coverage, mismatch_alerts, tactic_alerts
from app.services.detection_quality_service import detection_quality

router = APIRouter(prefix="/api/detections", tags=["detections"])

SUBJECT_TYPES = ("investigation", "alert_run")
VERDICTS = ("true_positive", "false_positive", "unclear")

# The platform's classifications, split into what an analyst calling something a
# true positive would expect to see. Used only to measure agreement.
ACTIONABLE = frozenset({"malicious", "suspicious"})


@router.get("/quality")
async def get_detection_quality(
    db: DBSession,
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Per-rule quality, worst signal-to-noise first."""
    return await detection_quality(db, days=days, limit=limit)


@router.get("/attack-coverage")
async def get_attack_coverage(
    db: DBSession,
    days: int = Query(default=90, ge=1, le=365),
) -> dict[str, Any]:
    """Which ATT&CK techniques the detections claim, and which the evidence shows."""
    return await attack_coverage(db, days=days)


@router.get("/attack-coverage/tactic-alerts")
async def get_tactic_alerts(
    db: DBSession,
    tactic: str = Query(min_length=1, max_length=120),
    days: int = Query(default=90, ge=1, le=365),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """The alerts whose assessment touched one tactic, newest first."""
    return await tactic_alerts(db, tactic=tactic, days=days, limit=limit)


@router.get("/attack-coverage/mismatch-alerts")
async def get_mismatch_alerts(
    db: DBSession,
    rule_name: str = Query(min_length=1, max_length=512),
    technique: str = Query(min_length=2, max_length=20),
    rule_id: str | None = Query(default=None, max_length=120),
    days: int = Query(default=90, ge=1, le=365),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """The alerts where this rule claimed one technique and the evidence showed another."""
    return await mismatch_alerts(
        db, rule_name=rule_name, technique=technique, rule_id=rule_id, days=days, limit=limit
    )


@router.post("/feedback", status_code=201)
async def create_feedback(request: AnalystFeedbackCreate, db: DBSession) -> dict[str, Any]:
    """
    Record (or change) the analyst's call on one investigation or alert run.

    Re-submitting replaces the previous judgement rather than adding a second —
    an analyst changing their mind is a correction, not another data point.
    """
    if request.subject_type not in SUBJECT_TYPES:
        raise HTTPException(400, f"subject_type must be one of {', '.join(SUBJECT_TYPES)}")
    if request.verdict not in VERDICTS:
        raise HTTPException(400, f"verdict must be one of {', '.join(VERDICTS)}")
    try:
        subject_id = uuid.UUID(request.subject_id)
    except ValueError as exc:
        raise HTTPException(400, "subject_id must be a UUID") from exc

    snapshot = await _subject_snapshot(db, request.subject_type, subject_id)
    if snapshot is None:
        raise HTTPException(404, f"No {request.subject_type} with id {request.subject_id}")

    existing = (
        await db.execute(
            select(AnalystFeedback).where(
                AnalystFeedback.subject_type == request.subject_type,
                AnalystFeedback.subject_id == subject_id,
            )
        )
    ).scalars().first()

    if existing is not None:
        existing.verdict = request.verdict
        existing.note = (request.note or "").strip() or None
        if request.analyst:
            existing.analyst = request.analyst
        await db.commit()
        await db.refresh(existing)
        return {**_serialize(existing), "replaced_previous": True}

    row = AnalystFeedback(
        subject_type=request.subject_type,
        subject_id=subject_id,
        verdict=request.verdict,
        note=(request.note or "").strip() or None,
        analyst=(request.analyst or "").strip() or None,
        **snapshot,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return {**_serialize(row), "replaced_previous": False}


@router.get("/feedback")
async def list_feedback(
    db: DBSession,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    verdict: str | None = Query(default=None),
) -> dict[str, Any]:
    query = select(AnalystFeedback)
    count_query = select(func.count(AnalystFeedback.id))
    if verdict:
        if verdict not in VERDICTS:
            raise HTTPException(400, f"verdict must be one of {', '.join(VERDICTS)}")
        query = query.where(AnalystFeedback.verdict == verdict)
        count_query = count_query.where(AnalystFeedback.verdict == verdict)

    rows = (
        await db.execute(query.order_by(AnalystFeedback.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    total = (await db.execute(count_query)).scalar() or 0
    return {"items": [_serialize(row) for row in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/feedback/accuracy")
async def feedback_accuracy(
    db: DBSession,
    days: int = Query(default=90, ge=1, le=365),
) -> dict[str, Any]:
    """
    How often the platform's classification matched the analyst's call.

    Only feedback where the analyst committed either way is counted — `unclear`
    is reported separately rather than folded in as a miss.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        await db.execute(
            select(AnalystFeedback).where(AnalystFeedback.created_at >= cutoff)
        )
    ).scalars().all()

    agreed = disagreed = unclear = 0
    missed: list[dict[str, Any]] = []          # platform said benign, analyst said real
    over_flagged: list[dict[str, Any]] = []    # platform said bad, analyst said no

    for row in rows:
        if row.verdict == "unclear":
            unclear += 1
            continue
        platform_says_bad = str(row.platform_classification or "") in ACTIONABLE
        analyst_says_bad = row.verdict == "true_positive"
        if platform_says_bad == analyst_says_bad:
            agreed += 1
            continue
        disagreed += 1
        (missed if analyst_says_bad else over_flagged).append(_serialize(row))

    judged = agreed + disagreed
    return {
        "window_days": days,
        "feedback_total": len(rows),
        "judged": judged,
        "unclear": unclear,
        "agreed": agreed,
        "disagreed": disagreed,
        "agreement_rate": round(agreed / judged, 3) if judged else None,
        # The asymmetry matters far more than the headline rate: a missed
        # detection and an over-flag cost a SOC very different things.
        "missed_by_platform": missed[:25],
        "over_flagged_by_platform": over_flagged[:25],
        "note": (
            "No analyst feedback yet — accuracy cannot be measured until calls are recorded."
            if not judged
            else f"{agreed} of {judged} judged subjects matched the analyst's call."
        ),
    }


@router.get("/feedback/{subject_type}/{subject_id}")
async def get_feedback_for(subject_type: str, subject_id: str, db: DBSession) -> dict[str, Any]:
    """The standing judgement on one subject, so the UI can show its current state."""
    if subject_type not in SUBJECT_TYPES:
        raise HTTPException(400, f"subject_type must be one of {', '.join(SUBJECT_TYPES)}")
    try:
        parsed = uuid.UUID(subject_id)
    except ValueError as exc:
        raise HTTPException(400, "subject_id must be a UUID") from exc

    row = (
        await db.execute(
            select(AnalystFeedback).where(
                AnalystFeedback.subject_type == subject_type,
                AnalystFeedback.subject_id == parsed,
            )
        )
    ).scalars().first()
    return {"feedback": _serialize(row) if row else None}


# ── Internals ─────────────────────────────────────────────────────────────────


async def _subject_snapshot(db: DBSession, subject_type: str, subject_id) -> dict[str, Any] | None:
    """
    What the platform concluded, copied onto the feedback row.

    Copied rather than joined because a run can be re-analysed later: the
    feedback is about the answer as it was given, not as it now stands.
    """
    if subject_type == "investigation":
        investigation = await db.get(Investigation, subject_id)
        if investigation is None:
            return None
        return {
            "platform_classification": investigation.classification,
            "platform_risk_score": investigation.risk_score,
            "detection_rule_id": None,
        }

    run = await db.get(AlertBodyInvestigationRun, subject_id)
    if run is None:
        return None
    return {
        "platform_classification": run.overall_verdict,
        "platform_risk_score": run.highest_risk_score,
        "detection_rule_id": run.detection_rule_id,
    }


def _serialize(row: AnalystFeedback) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "subject_type": row.subject_type,
        "subject_id": str(row.subject_id),
        "verdict": row.verdict,
        "platform_classification": row.platform_classification,
        "platform_risk_score": row.platform_risk_score,
        "detection_rule_id": row.detection_rule_id,
        "note": row.note,
        "analyst": row.analyst,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
