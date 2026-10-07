"""
Detection quality, ATT&CK coverage and analyst feedback.

GET  /api/detections/devices        -> one row per machine: volume, verdicts, users
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
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import case as sql_case
from sqlalchemy import func, select

from app.dependencies import DBSession
from app.models.database import AlertBodyInvestigationRun, AnalystFeedback, Investigation
from app.models.schemas import AnalystFeedbackCreate
from app.models.database import AlertCaseSpine
from app.services.alert_correlation_service import case_by_key, correlate_alerts
from app.services.alert_entity_profile_service import build_entity_profile
from app.services.alert_tuning_service import build_tuning_recommendations
from app.services.attack_coverage_service import attack_coverage, mismatch_alerts, tactic_alerts
from app.services.detection_quality_service import detection_quality
from app.services import tenant_scope
# The client selector, shared with the Alerts page rather than written twice.
from app.api.alert_investigations import _selectable_tenants

router = APIRouter(prefix="/api/detections", tags=["detections"])

# Identity, read exactly as the alert-run routes read it. A second way to
# decide who is calling is a second way to get it wrong, and this module is
# about to start scoping reads with it.
_IN_PROCESS = {"kind": "internal", "all_tenants": True, "tenant_ids": []}


def _identity(request: Request | None) -> dict[str, Any] | None:
    """The authenticated caller, as the auth middleware left it."""
    if request is None:
        return dict(_IN_PROCESS)
    state = getattr(request, "state", None)
    if state is None:
        return dict(_IN_PROCESS)
    return getattr(state, "identity", None)


def _scope(request: Request | None) -> "tenant_scope.TenantScope":
    return tenant_scope.scope_of(_identity(request))


def _filtered(request: Request | None, tenant: str | None) -> "tenant_scope.TenantScope":
    """The caller's scope, optionally narrowed to the one client they picked.

    The filter can only narrow. Naming a tenant the caller may not read is
    refused rather than ignored — a filter that silently falls back to
    "everything you can see" is how a client-restricted account learns that
    another client exists.
    """
    scope = _scope(request)
    if not tenant:
        return scope
    try:
        return tenant_scope.requested_scope(scope, tenant)
    except tenant_scope.TenantForbidden as exc:
        raise HTTPException(403, str(exc)) from None


def _as_utc(value: str | None, *, end_of_day: bool) -> datetime | None:
    """Parse an ISO date or datetime into UTC, or refuse it.

    A bare `2026-09-01` as an upper bound means the end of that day, not its
    first instant — otherwise picking the same day for both bounds returns
    nothing, which reads as "no cases" rather than "you asked for no time".
    """
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, f"Not a date: {text[:40]!r}") from None
    if len(text) == 10 and end_of_day:
        parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# Correlated cases, keyed by what they were computed from.
#
# A case is a function of the alerts that exist and the question asked. Nothing
# else moves it, so recomputing on every page load — and on every 30-second
# refresh the list performs by itself — re-derives an identical answer at a
# measured 3.2s a time.
#
# The key carries the newest alert's timestamp, so this is not a staleness
# window: an entry is served only while no alert has been ingested since it was
# built, and the arrival of one alert invalidates every entry. That check is a
# single indexed max().
#
# Scope is in the key because a cached answer computed for one client must
# never be served to another — a cache is the one place a leak can happen with
# no query behind it to notice.
_CASES_CACHE: "OrderedDict[tuple, dict[str, Any]]" = OrderedDict()
_CASES_CACHE_MAX = 16


async def _ingest_watermark(db: DBSession) -> str:
    """The newest alert we hold, used as a cache generation."""
    newest = (
        await db.execute(select(func.max(AlertBodyInvestigationRun.created_at)))
    ).scalar()
    return newest.isoformat() if newest else "empty"


SUBJECT_TYPES = ("investigation", "alert_run")
VERDICTS = ("true_positive", "false_positive", "unclear")

# The platform's classifications, split into what an analyst calling something a
# true positive would expect to see. Used only to measure agreement.
ACTIONABLE = frozenset({"malicious", "suspicious"})


# Worst first. A machine with a malicious conclusion outranks one with fifty
# benign alerts, because volume is a workload measure and this list is read to
# decide where to look.
_VERDICT_RANK = sql_case(
    (AlertBodyInvestigationRun.overall_verdict == "malicious", 3),
    (AlertBodyInvestigationRun.overall_verdict == "suspicious", 2),
    (AlertBodyInvestigationRun.overall_verdict == "benign", 1),
    else_=0,
)


@router.get("/devices")
async def list_devices(
    db: DBSession,
    # Plain defaults, not Query(...): this handler is called directly in tests
    # and a Query object reaches SQLAlchemy as a non-integer. Clamped below
    # instead, which also bounds what a URL can ask for.
    days: int = 30,
    search: str | None = None,
    verdict: str | None = None,
    tenant: str | None = None,
    limit: int = 100,
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """One row per machine that has produced an alert in the window.

    The estate seen device-first. Each row is what the per-host panels used to
    say inside every case — how much, how bad, whose account — which described
    the machine rather than the case it was printed in.

    Scoped to the caller's tenants like every other alert-run read. This is a
    new aggregate over the same rows, and an aggregate leaks just as precisely
    as a list: a count of malicious alerts on a named host is exactly the fact
    a client-restricted caller must not learn about another client.
    """
    scope = _scope(request)
    days = max(1, min(365, int(days)))
    limit = max(1, min(500, int(limit)))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    query = (
        select(
            AlertBodyInvestigationRun.entity_host.label("host"),
            AlertBodyInvestigationRun.tenant_id.label("tenant_id"),
            func.count(AlertBodyInvestigationRun.id).label("alerts"),
            func.max(AlertBodyInvestigationRun.created_at).label("last_seen"),
            func.max(_VERDICT_RANK).label("worst_rank"),
            func.count(func.distinct(AlertBodyInvestigationRun.entity_user)).label("users"),
            func.count(func.distinct(AlertBodyInvestigationRun.detection_rule_id)).label("rules"),
        )
        .where(
            AlertBodyInvestigationRun.entity_host.is_not(None),
            AlertBodyInvestigationRun.entity_host != "",
            AlertBodyInvestigationRun.created_at >= since,
        )
        .group_by(AlertBodyInvestigationRun.entity_host, AlertBodyInvestigationRun.tenant_id)
    )
    query = tenant_scope.apply(query, AlertBodyInvestigationRun.tenant_id, scope)
    if tenant:
        tenant_scope.assert_can_read(scope, tenant)
        query = query.where(AlertBodyInvestigationRun.tenant_id == tenant)
    if search:
        query = query.where(AlertBodyInvestigationRun.entity_host.ilike(f"%{search.strip()}%"))
    if verdict:
        query = query.having(
            func.max(_VERDICT_RANK) == {"malicious": 3, "suspicious": 2, "benign": 1}.get(verdict, 0)
        )

    rows = (
        await db.execute(query.order_by(func.max(_VERDICT_RANK).desc(),
                                        func.count(AlertBodyInvestigationRun.id).desc())
                         .limit(limit))
    ).all()

    worst = {3: "malicious", 2: "suspicious", 1: "benign", 0: None}
    return {
        "items": [
            {
                "host": r.host,
                "tenant_id": r.tenant_id,
                "alerts": int(r.alerts or 0),
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "worst_verdict": worst.get(int(r.worst_rank or 0)),
                "users": int(r.users or 0),
                "rules": int(r.rules or 0),
            }
            for r in rows
        ],
        "days": days,
        "scope": scope.describe(),
        # The clients this caller may filter to. Built by the same helper the
        # Alerts page uses, so the two selectors cannot come to offer different
        # answers about who exists.
        "available_tenants": await _selectable_tenants(db, request),
    }


@router.get("/quality")
async def get_detection_quality(
    db: DBSession,
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=100, ge=1, le=500),
    tenant: str | None = None,
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Per-rule quality, worst signal-to-noise first.

    Scoped to the caller's tenants. `tenant` narrows further to one client and
    is refused if the caller may not read it.
    """
    result = await detection_quality(
        db, scope=_filtered(request, tenant), days=days, limit=limit
    )
    # The same selector the other pages carry, so Rules and ATT&CK coverage can
    # be read one client at a time rather than as an estate-wide average that
    # belongs to nobody.
    result["available_tenants"] = await _selectable_tenants(db, request)
    return result


@router.get("/attack-coverage")
async def get_attack_coverage(
    db: DBSession,
    days: int = Query(default=90, ge=1, le=365),
    tenant: str | None = None,
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Which ATT&CK techniques the detections claim, and which the evidence shows.

    Scoped to the caller's tenants. `tenant` narrows further to one client and
    is refused if the caller may not read it.
    """
    return await attack_coverage(db, scope=_filtered(request, tenant), days=days)


@router.get("/attack-coverage/tactic-alerts")
async def get_tactic_alerts(
    db: DBSession,
    tactic: str = Query(min_length=1, max_length=120),
    days: int = Query(default=90, ge=1, le=365),
    limit: int = Query(default=100, ge=1, le=500),
    tenant: str | None = None,
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """The alerts whose assessment touched one tactic, newest first.

    Scoped to the caller's tenants. `tenant` narrows further to one client and
    is refused if the caller may not read it.
    """
    return await tactic_alerts(
        db, scope=_filtered(request, tenant), tactic=tactic, days=days, limit=limit
    )


@router.get("/attack-coverage/mismatch-alerts")
async def get_mismatch_alerts(
    db: DBSession,
    rule_name: str = Query(min_length=1, max_length=512),
    technique: str = Query(min_length=2, max_length=20),
    rule_id: str | None = Query(default=None, max_length=120),
    days: int = Query(default=90, ge=1, le=365),
    limit: int = Query(default=100, ge=1, le=500),
    tenant: str | None = None,
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """The alerts where this rule claimed one technique and the evidence showed another.

    Scoped to the caller's tenants. `tenant` narrows further to one client and
    is refused if the caller may not read it.
    """
    return await mismatch_alerts(
        db, scope=_filtered(request, tenant), rule_name=rule_name, technique=technique,
        rule_id=rule_id, days=days, limit=limit,
    )


@router.get("/correlated-cases")
async def get_correlated_cases(
    db: DBSession,
    # Up to two years, so "all cases" is a real option rather than a 30-day
    # cap wearing that name. Retention decides what it actually reaches.
    hours: int = Query(default=48, ge=1, le=17520),
    # One, because a case is now the unit of coverage: every ingested alert
    # belongs to one, and the score separates the interesting from the
    # routine. At the previous default of 2 this endpoint hid 97% of the
    # clusters it computed and 55% of all alerts had no case at all.
    min_rules: int = Query(default=1, ge=1, le=10),
    min_score: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=50, ge=1, le=500),
    tenant: str | None = None,
    # An explicit range, for an analyst who picked dates. ISO-8601; a bare date
    # is read as midnight UTC.
    since: str | None = None,
    until: str | None = None,
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Entities carrying more than one independent detection inside the window.

    Scoped to the caller's tenants. `tenant` narrows further to one client and
    is refused if the caller may not read it.
    """
    scope = _scope(request)
    if tenant:
        # Refused, not ignored: naming a client you may not read must not
        # quietly fall back to the ones you can.
        tenant_scope.assert_can_read(scope, tenant)

    # Correlated once, across everything this caller may read, so the client
    # selector can report a real count per client. Narrowing the *query* first
    # would make every other client's count unknowable, and the selector used
    # to paper over that by counting alert rows instead — which is why Cases
    # offered "Expertware (C00) (13,729)" next to a list of 33 cases.
    since_at = _as_utc(since, end_of_day=False)
    until_at = _as_utc(until, end_of_day=True)
    if since_at and until_at and since_at > until_at:
        raise HTTPException(400, "`since` is after `until`.")
    if since_at:
        # The scan has to reach back at least as far as the range being listed,
        # or a case inside it is filtered out of a window that never held it.
        span = (datetime.now(timezone.utc) - since_at).total_seconds() / 3600.0
        hours = max(hours, int(span) + 1)

    cache_key = (
        await _ingest_watermark(db),
        scope.cache_key(),
        hours, min_rules, min_score, limit,
        since_at.isoformat() if since_at else None,
        until_at.isoformat() if until_at else None,
    )
    cached = _CASES_CACHE.get(cache_key)
    if cached is not None:
        _CASES_CACHE.move_to_end(cache_key)
        # Copied, because the tenant filter below replaces `cases` and the next
        # reader must still see the whole answer.
        result = {**cached, "cases": list(cached.get("cases") or [])}
    else:
        result = await correlate_alerts(
            db, scope=scope, hours=hours, min_rules=min_rules,
            min_score=min_score, limit=limit, since=since_at, until=until_at,
        )
        _CASES_CACHE[cache_key] = {**result, "cases": list(result.get("cases") or [])}
        while len(_CASES_CACHE) > _CASES_CACHE_MAX:
            _CASES_CACHE.popitem(last=False)

    cases = list(result.get("cases") or [])
    counts: dict[str | None, int] = defaultdict(int)
    for case in cases:
        counts[case.get("tenant_id")] += 1

    if tenant:
        cases = [case for case in cases if case.get("tenant_id") == tenant]
        result["cases"] = cases
        result["total_cases"] = len(cases)

    options = await _selectable_tenants(db, request)
    for option in options:
        # Cases, not alert runs. On this page the alert count is a different
        # number about a different thing, and putting it in a case selector
        # read as a case count.
        option["run_count"] = counts.get(option["tenant_id"], 0)
    result["available_tenants"] = options
    return result


@router.get("/entity/{host}")
async def get_entity_profile(
    host: str,
    db: DBSession,
    days: int = Query(default=30, ge=1, le=365),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Everything stored about one machine, assembled for a single view.

    A profile is every alert a host has produced, so it is scoped like any
    other alert-run read. A host belonging to another client simply has no
    alerts here, which is the same answer as a host that does not exist.
    """
    return await build_entity_profile(db, host=host, scope=_scope(request), days=days)


@router.get("/tuning-recommendations")
async def get_tuning_recommendations(
    db: DBSession,
    days: int = Query(default=90, ge=1, le=365),
    min_alerts: int = Query(default=5, ge=2, le=50),
    tenant: str | None = None,
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Rules that have never produced an actionable verdict, and how to silence them.

    Nothing is created here. Every condition is replayed against the rule's whole
    stored history first, and any candidate that would have silenced an alert
    concluding malicious or suspicious is discarded rather than reported.
    """
    return await build_tuning_recommendations(
        db, scope=_filtered(request, tenant), days=days, min_alerts=min_alerts
    )


@router.get("/case/{case_key}")
async def get_case(
    case_key: str,
    db: DBSession,
    hours: int = Query(default=720, ge=1, le=8760),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Everything one case page needs, in a single call.

    The case itself, the full analysis, and the profile of the machine it
    happened on — assembled here rather than left to the page to fetch in three
    round trips, because they are read together every time.
    """
    scope = _scope(request)
    case = await case_by_key(db, case_key, scope=scope, hours=hours)
    spine = await db.get(AlertCaseSpine, case_key)
    if case is None and spine is None:
        raise HTTPException(404, "No such case")

    # A case that does not form for this caller is not theirs to read. The spine
    # alone would otherwise still answer who owned it and what it reached — a
    # 404 for the case body and a full header for another client's incident.
    if case is None and spine is not None and not scope.all_tenants:
        raise HTTPException(404, "No such case")

    host = (case or {}).get("entity_host") or (spine.entity_host if spine else None)
    profile = await build_entity_profile(db, host=host, scope=scope) if host else None

    return {
        "case_key": case_key,
        # None when the case no longer forms — its alerts may have aged out of
        # the window, or a late arrival may have re-anchored it under a new key.
        # The spine still answers who owned it and what it reached.
        "case": case,
        "spine": {
            "status": spine.status,
            "assignee": spine.assignee,
            "peak_score": spine.peak_score,
            # The lifecycle an analyst reads: the handle they say out loud,
            # whether it has been answered, and what it was answered as.
            "case_number": spine.case_number,
            "title": spine.title,
            "closed_at": spine.closed_at.isoformat() if spine.closed_at else None,
            "closure_kind": spine.closure_kind,
            "resolution": spine.resolution,
            "alerts_at_close": spine.alerts_at_close,
            "continues_case_key": spine.continues_case_key,
            # When the activity began, and separately when this platform first
            # recorded the case. They differ whenever alerts arrive replayed,
            # which here is most of the time.
            "opened_at": spine.opened_at.isoformat() if spine.opened_at else None,
            "first_recorded_at": spine.created_at.isoformat() if spine.created_at else None,
            "last_activity_at": spine.last_activity_at.isoformat() if spine.last_activity_at else None,
            "superseded_by": spine.superseded_by_case_key,
        } if spine else None,
        "narrative": {
            "markdown": spine.narrative_markdown if spine else None,
            "status": spine.narrative_status if spine else None,
            "generated_at": (
                spine.narrative_generated_at.isoformat()
                if spine and spine.narrative_generated_at else None
            ),
            "assistant_session_id": spine.narrative_session_id if spine else None,
        },
        "profile": profile,
    }


@router.get("/case/{case_key}/narrative")
async def get_case_narrative(case_key: str, db: DBSession) -> dict[str, Any]:
    """The full case analysis. Kept out of the list response, which carries the lead."""
    row = await db.get(AlertCaseSpine, case_key)
    if row is None:
        raise HTTPException(404, "No such case")
    return {
        "case_key": row.case_key,
        "markdown": row.narrative_markdown,
        "status": row.narrative_status,
        "generated_at": row.narrative_generated_at.isoformat() if row.narrative_generated_at else None,
        "assistant_session_id": row.narrative_session_id,
        "error": row.narrative_error,
    }


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


@router.get("/sla")
async def case_sla_summary(
    db: DBSession,
    days: int = Query(default=30, ge=1, le=365),
    target_minutes: int | None = Query(default=None, ge=1, le=10_080),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """MTTD, MTTR and SLA attainment over closed cases.

    The numbers the manual job used to produce. They are computed from stored
    timestamps rather than stored as figures, so a definition that turns out
    to be wrong is a query away from being right instead of a backfill.

    Reported in two populations. 497 of 884 cases in this estate hold a single
    alert, and a mean that mixes them with multi-alert cases is mostly a
    measure of how many single alerts arrived — it would make the service look
    fastest in exactly the weeks it did least.

    Two exclusions, both stated in the response rather than applied silently:
    a case recorded long after its first alert is a backfill and has no
    detection time, and a case closed because it aged out of the correlation
    window was never answered, so counting it as a resolution would reward
    losing track of one.
    """
    from app.config import get_settings
    from app.models.database import AlertCaseSpine
    from app.services import alert_case_closure_service as closure

    scope = _scope(request)
    settings = get_settings()
    target = float(
        (target_minutes or int(getattr(settings, "case_sla_target_minutes", 60) or 60)) * 60
    )
    since = datetime.now(timezone.utc) - timedelta(days=days)

    rows = (
        await db.execute(
            select(AlertCaseSpine).where(AlertCaseSpine.opened_at >= since)
        )
    ).scalars().all()

    cases: list[dict[str, Any]] = []
    aged_out = 0
    for row in rows:
        if row.closure_kind == "aged_out":
            aged_out += 1
            continue
        metrics = closure.metrics(
            opened_at=row.opened_at, created_at=row.created_at, closed_at=row.closed_at,
        )
        cases.append({
            "alert_count": row.alerts_at_close or 1,
            **metrics,
        })

    summary = closure.summarise(cases, target_seconds=target)
    summary["window_days"] = days
    summary["cases_considered"] = len(cases)
    summary["excluded_aged_out"] = aged_out
    summary["excluded_backfilled_detection"] = sum(
        1 for c in cases if c.get("detect_excluded")
    )
    # Every tenant's cases are in one estate view; the scope is recorded so a
    # number can never be read as being about one client when it is not.
    summary["scope"] = "all tenants" if getattr(scope, "all_tenants", False) else "scoped"
    return summary


@router.get("/case/{case_key}/observables")
async def get_case_observables(
    case_key: str, db: DBSession, request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Every indicator the case's alerts carry, split by what is known of it.

    Two populations, because they answer different questions and merging them
    is how an analyst comes to believe an address was checked when it was only
    seen:

      verified    the platform looked it up and has a verdict for it
      identified  extracted from the alert, not investigated — a private
                  address, an internal domain, something the exclusions hold
                  back. Still worth showing: it is what the alert was about.

    Aggregated across the case's alerts, deduplicated by value, with the alert
    count so an indicator in nine alerts is visibly not the same as one in a
    single alert.
    """
    import json as _json

    from app.models.database import AlertBodyInvestigationRun

    scope = _scope(request)
    case = await case_by_key(db, case_key, scope=scope)
    if case is None:
        raise HTTPException(404, "No such case")

    run_ids = [
        str(m.get("run_id") or m.get("id") or "")
        for m in (case.get("alerts") or [])
    ]
    run_ids = [r for r in run_ids if r]
    if not run_ids:
        return {"case_key": case_key, "verified": [], "identified": [], "alerts": 0}

    rows = (
        await db.execute(
            select(AlertBodyInvestigationRun.id, AlertBodyInvestigationRun.result_json)
            .where(AlertBodyInvestigationRun.id.in_([uuid.UUID(r) for r in run_ids]))
        )
    ).all()

    verified: dict[str, dict[str, Any]] = {}
    identified: dict[str, dict[str, Any]] = {}
    for _run_id, result_json in rows:
        for report in ((result_json or {}).get("indicator_reports") or []):
            if not isinstance(report, dict):
                continue
            indicator = report.get("indicator") or {}
            value = str(indicator.get("value") or "").strip()
            if not value:
                continue
            skipped = bool(report.get("skip_reason"))
            bucket = identified if skipped else verified
            entry = bucket.setdefault(value, {
                "value": value,
                "type": str(indicator.get("type") or indicator.get("observable_type") or ""),
                "alerts": 0,
                "verdict": None,
                "risk_score": None,
                "sources": [],
                "reason": report.get("skip_reason") or None,
            })
            entry["alerts"] += 1
            verdict = (report.get("verdict") or {})
            classification = str(verdict.get("classification") or "")
            if classification and classification != "not_investigated":
                entry["verdict"] = classification
                entry["risk_score"] = verdict.get("risk_score")
                entry["sources"] = [str(x) for x in (verdict.get("sources") or [])][:5]

    def _rank(entry: dict[str, Any]) -> tuple:
        return (-(entry.get("risk_score") or 0), -entry["alerts"], entry["value"])

    return {
        "case_key": case_key,
        "alerts": len(run_ids),
        "verified": sorted(verified.values(), key=_rank),
        "identified": sorted(identified.values(), key=_rank),
    }


@router.post("/case/{case_key}/analyse")
async def analyse_case_now(
    case_key: str, db: DBSession, request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Answer this case now, without waiting for its quiet period.

    The automatic close waits ten minutes for the case to stop receiving
    alerts. An analyst who has already read it should not have to: this runs
    the same closing path immediately, on whatever the case holds right now.

    Closing early is a real decision, so it is recorded as one — `closure_kind`
    is 'analyst', not 'auto', and the resolution says who asked.
    """
    from app.config import get_settings as _settings
    from app.services import alert_case_closure_service as closure
    from app.services import alert_case_store as store
    from app.services.alert_case_narrative_service import narrative_fingerprint
    from app.tasks.case_narrative_task import dispatch as dispatch_narratives

    identity = _identity(request)
    scope = _scope(request)
    spine = await db.get(AlertCaseSpine, case_key)
    if spine is None:
        raise HTTPException(404, "No such case")
    if spine.closed_at is not None:
        raise HTTPException(409, "This case has already been answered.")

    case = await case_by_key(db, case_key, scope=scope)
    if case is None:
        raise HTTPException(
            409,
            "This case's alerts are outside the correlation window, so there is "
            "nothing to analyse. It can still be closed by hand.",
        )

    members = case.get("alerts") or []
    resolution = closure.resolution_for(
        verdict=case.get("verdict") or case.get("overall_verdict"),
        risk_score=case.get("score"),
    )
    await store.close_case(
        db,
        case_key=case_key,
        resolution=resolution,
        title=case.get("label") or spine.title,
        alerts_at_close=len(members),
        closure_kind="analyst",
    )
    await db.commit()

    dispatch_narratives([(
        case_key,
        case,
        narrative_fingerprint(
            score=int(case.get("score") or 0),
            member_count=len(members),
            tactics=case.get("tactics") or [],
        ),
    )])

    return {
        "case_key": case_key,
        "case_number": spine.case_number,
        "status": "closed",
        "resolution": resolution,
        "alerts": len(members),
        "closed_by": str((identity or {}).get("username") or "analyst"),
        "note": "Analysing now. The written resolution appears here when it lands.",
    }
