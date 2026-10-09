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

from pydantic import BaseModel
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import case as sql_case
from sqlalchemy import desc as sa_desc
from sqlalchemy import false as sa_false
from sqlalchemy import func, select, text

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

# How far back every single-case endpoint looks to re-derive its case.
#
# A case is derived from its alerts, not stored as a row, so the window is part
# of its identity: a case that forms over 720 hours does not form over 48. The
# detail call used 720 and the graph, observables, narrative, close and analyse
# calls used the service default of 48, so on any case older than two days the
# page rendered a full header and then four endpoints that answered "No such
# case" — an empty graph and no observables on a real incident, and a manual
# close that could not find the case the analyst was looking at. One constant,
# so the six cannot drift apart again.
#: How far back a single-case endpoint looks when it has nothing better.
#:
#: Superseded in intent by `OPEN_CASE_CEILING_HOURS` below, and kept only for
#: the endpoints that still take an explicit window. There is no fixed window
#: that is right: measured over 1,014 derived cases, 68.4% complete in a
#: single instant while multi-alert cases run to 28.5 hours at p99, so any
#: constant is wrong for one of the two modes.
CASE_LOOKUP_HOURS = 720

#: The only thing bounding how far back an open case derives.
#:
#: Not a belief about accretion — a guard against a runaway. The observed
#: maximum span of any case in this estate is 2.0 days (172,803s), measured as
#: max-min event_time over each case's own members via the derivation, so 72
#: hours clears it with a day of margin.
#:
#: When this clips a case, something upstream is wrong and it is logged rather
#: than absorbed: a case still accreting after three days is either a
#: host-wide bucket or a derivation defect, and both are findings.
OPEN_CASE_CEILING_HOURS = 72
# The widest window a single-case endpoint accepts. The cases list offers "All"
# — 17,520 hours — so a case found there links to a page that must be able to
# ask for the same window; at the previous ceiling of 8,760 every call from
# such a link was refused with a 422.
CASE_LOOKUP_MAX_HOURS = 17520

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
    hours: int = Query(default=CASE_LOOKUP_HOURS, ge=1, le=CASE_LOOKUP_MAX_HOURS),
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

    # When the case does not form, say why. The graph tab explains itself and
    # this endpoint did not, so the same case read two ways gave an analyst an
    # explanation on one tab and silence on the other.
    unreachable = None
    if case is None and spine is not None:
        from app.services.case_supersession_service import where_this_key_went
        from app.services.case_unreachable_service import why_unreachable

        unreachable = (
            await why_unreachable(
                db, spine=spine, hours=hours,
                pointer=await where_this_key_went(db, case_key),
            )
        ).as_json()

    return {
        "case_key": case_key,
        "unreachable": unreachable,
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
            # Who signed it off and why, when a person did.
            "closed_by": spine.closed_by,
            "closure_note": spine.closure_note,
            # True when the analysis on screen is no longer the one the
            # analyst closed on: correlation rewrites the narrative whenever
            # the case's shape moves, closed cases included.
            "analysis_changed_since_close": bool(
                spine.closed_narrative_fingerprint
                and spine.narrative_fingerprint
                and spine.closed_narrative_fingerprint != spine.narrative_fingerprint
            ),
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
async def get_case_narrative(
    case_key: str,
    db: DBSession,
    hours: int = Query(default=CASE_LOOKUP_HOURS, ge=1, le=CASE_LOOKUP_MAX_HOURS),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """The full case analysis. Kept out of the list response, which carries the lead.

    Scoped, which it was not. This fetched the spine by primary key and
    returned the whole write-up to any authenticated caller for any case key —
    so a client-restricted account could read another client's incident
    analysis in full, naming their hosts, accounts and what was done to them.
    It is the most sensitive single field on the row, and it was the only case
    endpoint with no tenant check at all.
    """
    scope = _scope(request)
    case = await case_by_key(db, case_key, scope=scope, hours=hours)
    row = await db.get(AlertCaseSpine, case_key)
    if row is None or (case is None and not scope.all_tenants):
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
        "platform_risk_score": run.indicator_risk_score,
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


def _case_tenant_clause(scope: "tenant_scope.TenantScope") -> tuple[Any, ...]:
    """Restrict cases to the clients this caller may read.

    A real filter, not a label. `/detections/sla` computed `scope` and then
    used it only to stamp the response `"scoped"` while the query selected
    every tenant's cases — so a client-restricted account was shown the whole
    estate's MTTR under a word asserting it was theirs, which is worse than
    not saying anything.
    """
    from app.models.database import AlertCaseSpine

    if getattr(scope, "all_tenants", False):
        return ()
    allowed = [t for t in (getattr(scope, "tenant_ids", None) or [])]
    permitted = AlertCaseSpine.tenant_id.in_(allowed) if allowed else sa_false()
    if getattr(scope, "include_unassigned", False):
        permitted = permitted | AlertCaseSpine.tenant_id.is_(None)
    return (permitted,)


def _severity_band(peak_score: int | None) -> str:
    """A case's severity, from the score it reached.

    The 75 and 40 boundaries are the ones the Cases table's own severity pill
    already uses, so a case does not change severity between two pages. The
    critical band is new and was chosen from the distribution rather than
    picked: of 1,098 cases, 924 score under 40, about 70 land in 40-74, 36 in
    75-89 and 79 at 90 or above — so 90 separates a real population instead of
    slicing one in half.
    """
    score = int(peak_score or 0)
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _as_utc_day(value: datetime | None) -> str:
    if value is None:
        return ""
    moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _case_detection(row: Any) -> str:
    """What the case was about, without the device it happened on.

    A case's title is the first linked alert's title, and those begin with the
    host — "EXP-BSFX014 - Multi-Stage Execution by Host". Grouping on the
    whole string would count the same detection once per machine and the top
    ten would be a list of hosts.

    Stripped by matching the row's own `entity_host` exactly, not by splitting
    on the first " - ". This repository has produced six delimiter-boundary
    bugs; the host is right there on the row, so there is no boundary to
    guess.
    """
    title = str(getattr(row, "title", "") or "").strip()
    host = str(getattr(row, "entity_host", "") or "").strip()
    if host and title.casefold().startswith(f"{host.casefold()} - "):
        title = title[len(host) + 3:].strip()
    # The composed form, for a case whose alerts carried no usable title.
    if host and title.casefold().startswith(f"{host.casefold()} \u2014 "):
        title = title[len(host) + 3:].strip()
    return title[:120]


def _month_bounds(month: str | None) -> tuple[datetime | None, datetime | None]:
    """`YYYY-MM` to a half-open UTC range, or no bound at all.

    Half-open so a case opened at the last microsecond of the month lands in
    that month and not in both. An unparseable or absent month means the whole
    history rather than an error: the page offers only months that exist, so a
    bad value is a stale bookmark, and showing everything is the harmless
    answer.
    """
    text = str(month or "").strip()
    if not text or text.lower() == "all":
        return None, None
    try:
        year_s, month_s = text.split("-", 1)
        year, mon = int(year_s), int(month_s)
        start = datetime(year, mon, 1, tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None, None
    end = datetime(year + (mon == 12), (mon % 12) + 1, 1, tzinfo=timezone.utc)
    return start, end


@router.get("/reports/options")
async def report_options(
    db: DBSession, request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """The clients and months the report can actually be run for.

    Built from the data rather than from a date picker, so a month with no
    cases is not offered as though it were empty when it is simply outside the
    estate's history. The client list is the same: only tenants this caller may
    read, and `__unassigned__` only when unassigned cases exist.
    """
    from app.models.database import AlertCaseSpine

    scope = _scope(request)
    months = (
        await db.execute(
            select(
                func.to_char(func.date_trunc("month", AlertCaseSpine.opened_at), "YYYY-MM").label("month"),
                func.count().label("cases"),
            )
            .where(*_case_tenant_clause(scope))
            .group_by("month")
            .order_by(sa_desc("month"))
        )
    ).all()

    tenants = (
        await db.execute(
            select(
                AlertCaseSpine.tenant_id,
                func.count().label("cases"),
            )
            .where(*_case_tenant_clause(scope))
            .group_by(AlertCaseSpine.tenant_id)
            .order_by(sa_desc("cases"))
        )
    ).all()

    return {
        "months": [{"month": m, "cases": int(c)} for m, c in months if m],
        "clients": [
            {
                "tenant_id": t or "__unassigned__",
                "label": t or "Unassigned",
                "cases": int(c),
            }
            for t, c in tenants
        ],
        "scope": {"all_tenants": bool(getattr(scope, "all_tenants", False))},
    }


@router.get("/reports")
async def case_report(
    db: DBSession,
    month: str | None = None,
    tenant: str | None = None,
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """One month of one client's work, in the shape a service review is read in.

    How many alerts arrived, how many cases they became, how many were closed
    and how many are still open; the same split by severity and by day; how
    long detection and response took for each severity; what the cases were
    resolved as; and which detections produced most of them.

    Computed from stored timestamps on request rather than kept as running
    totals, so a definition that turns out to be wrong is a query away from
    being right instead of a backfill.

    Scoped on `tenant_id`, which the case carries because the alerts carry it.
    Not on `alert_client`, the sender's own label, which reads "unknown" for
    1,079 of 1,098 cases and would make the client filter a control with one
    option.
    """
    from app.config import get_settings
    from app.models.database import AlertBodyInvestigationRun, AlertCaseSpine
    from app.services import alert_case_closure_service as closure

    scope = _scope(request)
    settings = get_settings()
    now = datetime.now(timezone.utc)

    clauses = list(_case_tenant_clause(scope))
    start, end = _month_bounds(month)
    if start is not None:
        clauses.append(AlertCaseSpine.opened_at >= start)
        clauses.append(AlertCaseSpine.opened_at < end)
    chosen_tenant = str(tenant or "").strip()
    if chosen_tenant and chosen_tenant != "all":
        if chosen_tenant == "__unassigned__":
            clauses.append(AlertCaseSpine.tenant_id.is_(None))
        else:
            # Asked for, and permitted. A caller may name only a client the
            # scope already lets them read.
            if not scope.may_read(chosen_tenant):
                raise HTTPException(404, "No such client")
            clauses.append(AlertCaseSpine.tenant_id == chosen_tenant)

    rows = (await db.execute(select(AlertCaseSpine).where(*clauses))).scalars().all()

    # How many alerts arrived, which is a different question from how many
    # ended up inside a closed case — most alerts never form a multi-alert
    # case at all, and reporting only the ones that did understates the volume
    # the service actually handled.
    alert_clauses: list[Any] = []
    occurred = func.coalesce(
        AlertBodyInvestigationRun.event_time, AlertBodyInvestigationRun.created_at
    )
    if start is not None:
        alert_clauses += [occurred >= start, occurred < end]
    if chosen_tenant and chosen_tenant != "all":
        if chosen_tenant == "__unassigned__":
            alert_clauses.append(AlertBodyInvestigationRun.tenant_id.is_(None))
        else:
            alert_clauses.append(AlertBodyInvestigationRun.tenant_id == chosen_tenant)
    elif not getattr(scope, "all_tenants", False):
        allowed = list(getattr(scope, "tenant_ids", None) or [])
        permitted = (
            AlertBodyInvestigationRun.tenant_id.in_(allowed) if allowed else sa_false()
        )
        if getattr(scope, "include_unassigned", False):
            permitted = permitted | AlertBodyInvestigationRun.tenant_id.is_(None)
        alert_clauses.append(permitted)

    alerts_ahead = int(
        (
            await db.execute(
                select(func.count())
                .select_from(AlertBodyInvestigationRun)
                .where(
                    *alert_clauses,
                    AlertBodyInvestigationRun.event_time.is_not(None),
                    AlertBodyInvestigationRun.event_time
                    > AlertBodyInvestigationRun.created_at + text("interval '2 minutes'"),
                )
            )
        ).scalar()
        or 0
    )

    alerts_triggered = int(
        (
            await db.execute(
                select(func.count()).select_from(AlertBodyInvestigationRun).where(*alert_clauses)
            )
        ).scalar()
        or 0
    )
    # Grouped by the label, not by the expression: the format string is a
    # bound parameter, so Postgres cannot match two copies of the call to each
    # other and rejects the GROUP BY.
    day_label = func.to_char(occurred, "YYYY-MM-DD").label("day")
    alerts_by_day = {
        str(day): int(count)
        for day, count in (
            await db.execute(
                select(day_label, func.count()).where(*alert_clauses).group_by("day")
            )
        ).all()
        if day
    }

    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    resolutions: dict[str, int] = {}
    by_day: dict[str, dict[str, Any]] = {}
    per_severity: dict[str, list[dict[str, Any]]] = {k: [] for k in severities}
    detections: dict[str, int] = {}
    cases_closed = 0
    cases_active = 0
    swept = 0

    for row in rows:
        band = _severity_band(row.peak_score)
        severities[band] += 1
        resolutions[str(row.resolution or "unresolved")] = (
            resolutions.get(str(row.resolution or "unresolved"), 0) + 1
        )
        if row.closed_at is None:
            cases_active += 1
        else:
            cases_closed += 1

        day = _as_utc_day(row.opened_at)
        bucket = by_day.setdefault(
            day, {"date": day, "cases": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        )
        bucket["cases"] += 1
        bucket[band] += 1

        detection = _case_detection(row)
        if detection:
            detections[detection] = detections.get(detection, 0) + 1

        # Never answered by anybody, so not a response time. Counted in the
        # totals and in the resolution breakdown — the month did produce them
        # — but kept out of the means, because counting a case that aged out
        # or was merged as a resolution rewards losing track of one.
        if str(row.closure_kind or "") in {"aged_out", "expired", "merged"}:
            continue

        measured = closure.metrics(
            opened_at=row.opened_at, created_at=row.created_at, closed_at=row.closed_at,
            last_activity_at=row.last_activity_at,
        )
        if measured.get("resolve_excluded"):
            swept += 1
        per_severity[band].append(measured)

    def _timing(entries: list[dict[str, Any]], key: str) -> dict[str, Any]:
        """The 50th percentile, and the arithmetic mean beside it.

        The median is the headline because that is the statistic the SIEMBIOT
        monthly report uses, so the two documents answer the same question and
        a client reading both is not comparing a percentile against an
        average. Verified against Postgres' own `percentile_cont(0.5)` over
        the same population — identical on all four severity bands, including
        the even-count interpolation.


        It is also the right statistic for this distribution regardless.
        Measured over October: median 173.9 minutes against a mean of 393.5,
        a p95 of 1,428 and a maximum of 1,488. One case that waited a day
        moves the mean by hours and the median not at all, so the mean of a
        tail like this reports the worst week rather than the usual one.

        Both travel. The median is what the chart draws; the mean is in the
        tooltip, because a service review is asked about both and dropping
        one invites the question being answered from the other.
        """
        values = sorted(e[key] for e in entries if e.get(key) is not None)
        if not values:
            return {"median": None, "mean": None, "count": 0}
        middle = len(values) // 2
        median = (
            values[middle]
            if len(values) % 2
            else (values[middle - 1] + values[middle]) / 2
        )
        return {
            "median": round(median / 60, 1),
            "mean": round(sum(values) / len(values) / 60, 1),
            "count": len(values),
        }

    return {
        "month": month or "all",
        "client": chosen_tenant or "all",
        "alerts_triggered": alerts_triggered,
        "cases_created": len(rows),
        "cases_closed": cases_closed,
        "cases_active": cases_active,
        "severity": severities,
        # Minutes, by severity, the way a service review reads them.
        "response_minutes": {
            band: _timing(entries, "detect_seconds")
            for band, entries in per_severity.items()
        },
        "resolution_minutes": {
            band: _timing(entries, "resolve_seconds")
            for band, entries in per_severity.items()
        },
        "resolutions": dict(sorted(resolutions.items(), key=lambda kv: -kv[1])),
        "by_day": [
            {**by_day.get(day, {"date": day, "cases": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}),
             "alerts": alerts_by_day.get(day, 0)}
            for day in sorted(set(by_day) | set(alerts_by_day))
        ],
        "top_detections": [
            {"detection": name, "cases": count}
            for name, count in sorted(detections.items(), key=lambda kv: -kv[1])[:10]
        ],
        # One line rather than a panel, because a mean over a filtered
        # population still has to say it was filtered. A case closed more than
        # six hours after its own last alert was swept up by a catch-up pass
        # rather than answered, and including it reported September as a mean
        # resolution of 21.8 days.
        "resolution_excludes_swept": swept,
        # Alerts whose own timestamp is later than the moment we received
        # them, which is a clock or timezone fault at the source. `metrics()`
        # clamps a negative detection time to zero, so each one silently
        # reports as "detected instantly" and pulls the figures down. Six
        # exist estate-wide, the worst ten hours ahead.
        "alerts_timestamped_ahead": alerts_ahead,
        "scope": {
            "all_tenants": bool(getattr(scope, "all_tenants", False)),
            "applied": "tenant_id",
        },
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


@router.get("/case/{case_key}/graph")
async def get_case_graph(
    case_key: str,
    db: DBSession,
    hours: int = Query(default=CASE_LOOKUP_HOURS, ge=1, le=CASE_LOOKUP_MAX_HOURS),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """The case drawn as what happened: entities, not alerts.

    The first version of this drew the case *record* — a hub, one box per
    alert, an account — and could not draw an attack, because the thing worth
    seeing only exists when two observations collapse onto one node. This
    serves the entity model instead: a join over the rows the extractor
    materialised per alert, merged, with the claimed-versus-corroborated
    distinction carried on every node and every edge.

    Scoped and windowed like every other single-case endpoint.
    """
    from app.models.database import AlertCaseSpine
    from app.services.asset_criticality_service import criticality_for
    from app.services.case_collision_service import shadow_payload, shadowing_keys
    from app.services.case_disposition_review_service import review_for
    from app.services.case_unreachable_service import why_unreachable
    from app.services.graph_draw_summary_service import summarise
    from app.services.case_supersession_service import (
        earlier_keys_for,
        where_this_key_went,
    )
    from app.services.alert_graph_store_service import graph_for_runs, pivots_for

    scope = _scope(request)
    case = await case_by_key(db, case_key, scope=scope, hours=hours)
    spine = await db.get(AlertCaseSpine, case_key)
    if case is None and spine is None:
        raise HTTPException(404, "No such case")
    if case is None and not scope.all_tenants:
        raise HTTPException(404, "No such case")

    if case is None:
        # The key no longer re-derives over this window. 842 of this estate's
        # 1,889 case rows were re-pointed at the live case covering the same
        # incident (migration 052), so the first thing to try is the pointer:
        # a dead key should redirect rather than render nothing.
        went = await where_this_key_went(db, case_key)
        # Why, measured. The sentence that used to stand here named the window
        # or a re-grouping in every case, and for 51 of the 61 live keys that
        # do not derive it was false in both halves: their host component uses
        # a retired composite form that no stored alert carries, so no window
        # can recover them and no pointer exists to follow.
        reason = await why_unreachable(db, spine=spine, hours=hours, pointer=went)
        return {
            "case_key": case_key,
            "case_number": spine.case_number,
            "nodes": [], "edges": [], "counts": {},
            "attack": {"corroborated": 0, "claimed": 0},
            "integrity": {},
            "sources": {"by_source": [], "unmapped": []},
            "over_cap": False,
            "continues": None,
            "supersession": went,
            "unreachable": reason.as_json(),
            "note": reason.note,
        }

    # The whole case, not the first hundred alerts of it.
    #
    # `case["alerts"]` caps at 100 and keeps the EARLIEST, so this endpoint had
    # been drawing the opening of a large incident and presenting it as the
    # incident: #1849 holds 1,889 alerts and the graph saw 100 of them,
    # spanning the first 0.68h of a 26.72h case. Worse, the 300-alert bound
    # inside `graph_for_runs` could never engage on this path, because its
    # input was never more than 100 — so the severity-ranked selection that
    # bound performs was dead code here while being exercised only by the CLI.
    full = await case_by_key(
        db, case_key, scope=scope, hours=hours, max_members=100000
    ) or case
    run_ids = [a.get("run_id") for a in (full.get("alerts") or []) if a.get("run_id")]
    graph = await graph_for_runs(db, run_ids)

    # Which machines matter, as a person recorded it. Absent means unknown,
    # never "not a crown jewel": this estate has no asset inventory, so an
    # empty table is an absence of opinion rather than a verdict.
    host_labels = [
        n["label"] for n in graph["nodes"] if n["kind"] == "host"
    ]
    tiers = await criticality_for(db, host_labels)
    for node in graph["nodes"]:
        if node["kind"] != "host":
            continue
        found = tiers.get(node["label"])
        node["criticality"] = found or {"tier": None, "state": "unknown"}

    # The pivot badge: how many other alerts touched this same entity. One
    # indexed select on merge_key over 56,321 stored entities.
    elsewhere = await pivots_for(
        db, [n["id"] for n in graph["nodes"]], exclude_runs=run_ids,
    )
    for node in graph["nodes"]:
        node["pivot_alerts"] = elsewhere.get(node["id"], 0)

    graph["continues"] = case.get("continues")
    graph["case_key"] = case_key
    graph["case_number"] = case.get("case_number")
    # Analyses written under earlier keys for this same incident, attributed
    # and dated. Never merged into this case's own verdict.
    graph["earlier_keys"] = await earlier_keys_for(db, case_key)

    # Whether this case's conclusion covers everything it now holds. 30 cases
    # in this estate carry a disposition formed on fewer alerts than they hold,
    # the worst judged on 2 of 57. Nothing is reopened and no resolution is
    # changed; the context is made visible and the decision stays with a person.
    if spine is not None:
        review = review_for(
            case_number=spine.case_number,
            resolution=spine.resolution,
            alerts_at_close=spine.alerts_at_close,
            current_run_ids=run_ids,
            closed_by=spine.closed_by,
            closed_at=spine.closed_at,
        )
        graph["disposition_review"] = review.as_json() if review else None

    # Why the drawing is this size. A two-node graph for a 1,889-alert case
    # reads as broken and is not: every one of its alerts comes from a source
    # with no field map. A correct graph that reads as a broken one is a defect
    # in the graph.
    graph["draw_summary"] = summarise(
        graph=graph,
        members=int(case.get("alert_count") or len(run_ids)),
        distinct_rules=len(
            {a.get("detection_rule_id") for a in (case.get("alerts") or [])
             if a.get("detection_rule_id")}
        ) or None,
    )

    # Earlier keys for this same incident. Matched on the weaker signal and
    # labelled as such, because a key that no longer re-derives has no alert
    # set to compare against.
    if spine is not None:
        shadows = await shadowing_keys(
            db, case_key=case_key, entity_host=spine.entity_host,
            opened_at=spine.opened_at, alert_count=spine.alerts_at_close,
        )
        graph["duplicate_keys"] = shadow_payload(shadows)

    return graph



@router.get("/case/{case_key}/observables")
async def get_case_observables(
    case_key: str,
    db: DBSession,
    hours: int = Query(default=CASE_LOOKUP_HOURS, ge=1, le=CASE_LOOKUP_MAX_HOURS),
    request: Request = None,  # type: ignore[assignment]
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
    case = await case_by_key(db, case_key, scope=scope, hours=hours)
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


class CaseCloseRequest(BaseModel):
    """An analyst's sign-off on a case."""

    resolution: str
    note: str | None = None


@router.post("/case/{case_key}/close")
async def close_case_manually(
    case_key: str,
    body: CaseCloseRequest,
    db: DBSession,
    hours: int = Query(default=CASE_LOOKUP_HOURS, ge=1, le=CASE_LOOKUP_MAX_HOURS),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Close a case by hand, once the analysis exists to close it on.

    An analyst signing a case off is recording a judgement, and a judgement
    needs something to have been read first. This platform spent 831 cases
    filing resolutions that nothing had assessed — derived from a correlation
    score that measures agreement between rules, not severity — so the
    precondition here is the point of the endpoint, not a formality.

    The gate is the written analysis, not the derived resolution. Measured
    across every spine row, those two disagree in both directions: 47 cases
    have an analysis and no resolution, and 11 have a resolution and no
    analysis at all. See `analysis_is_ready`.

    One case is let through without an analysis, and it is stated rather than
    silent: a case whose alerts no longer re-derive can never be analysed,
    because there is nothing left to send. Refusing those would leave them
    open for ever, and the analyse endpoint already tells the analyst they
    "can still be closed by hand". They close as `expired`, which is what they
    are — the analyst is acknowledging a dead case, not reaching a verdict on
    one, so their chosen resolution is not accepted for it.
    """
    from app.api.auth import ADMIN_ROLES, ROLE_ANALYST
    from app.models.enums import CaseClosureKind, CaseResolution
    from app.services import alert_case_closure_service as closure
    from app.services import alert_case_store as store

    # A person, not an ingest key. The Wazuh and TraceCat credentials reach
    # this API by design, and closing a case is a named human act — the same
    # reasoning, and the same shape, as sandbox submission in `cape.py`.
    identity = _identity(request) or {}
    if not identity:
        raise HTTPException(401, "Sign in first.")
    if identity.get("kind") != "user":
        raise HTTPException(403, "Closing a case requires a signed-in user account.")
    if str(identity.get("role") or "") not in ADMIN_ROLES + (ROLE_ANALYST,):
        raise HTTPException(403, "Your role may not close cases.")

    scope = _scope(request)
    case = await case_by_key(db, case_key, scope=scope, hours=hours)
    spine = await db.get(AlertCaseSpine, case_key)
    if spine is None or (case is None and not scope.all_tenants):
        raise HTTPException(404, "No such case")
    if spine.closed_at is not None:
        if spine.closure_kind == "merged" and spine.superseded_by_case_key:
            successor = await db.get(AlertCaseSpine, spine.superseded_by_case_key)
            raise HTTPException(
                409,
                "This case's alerts moved into "
                + (f"case #{successor.case_number}" if successor and successor.case_number
                   else "another case")
                + ", because its own key no longer forms a case. Nothing is left here "
                  "to answer.",
            )
        raise HTTPException(409, "This case has already been answered.")

    # Merged into another case, and not closeable on its own.
    #
    # A superseded case keeps `closed_at` NULL, so a precondition that only
    # asks whether a case is closed lets all 243 of them through. They then
    # failed on the closure claim — which requires status='open' — and the
    # analyst was told the case was "being answered right now", which is not
    # what happened and gives them nothing to do. Its alerts live in the case
    # that absorbed it, and that is the one to sign off.
    if spine.status == "superseded" or spine.superseded_by_case_key:
        successor = None
        if spine.superseded_by_case_key:
            successor = await db.get(AlertCaseSpine, spine.superseded_by_case_key)
        # Only reachable for a row left behind by the old absorption, which
        # claimed the other case "includes these" alerts. Measured over 320
        # such pointers, 171 absorbed a case that still held its own alerts
        # and in none of them had those alerts moved — so the claim was
        # false, and it is not made here.
        raise HTTPException(
            409,
            "This case is marked as merged into "
            + (f"case #{successor.case_number}" if successor and successor.case_number
               else "another case")
            + ", which is a relationship this platform no longer creates. It will "
              "be released on the next correlation pass and can be closed then.",
        )

    unanalysable = case is None
    if not unanalysable and not closure.analysis_is_ready(
        narrative_status=spine.narrative_status,
        narrative_markdown=spine.narrative_markdown,
    ):
        raise HTTPException(
            409,
            "This case has no analysis yet, so there is nothing to close it on. "
            "Send it to the AI first; you can close it once the analysis lands.",
        )

    if unanalysable:
        resolution = CaseResolution.EXPIRED.value
    else:
        try:
            resolution = CaseResolution(str(body.resolution or "").strip()).value
        except ValueError:
            raise HTTPException(
                400,
                "Unknown resolution. Choose one of: "
                + ", ".join(c.value for c in CaseResolution.analyst_choices()),
            )
        if resolution not in {c.value for c in CaseResolution.analyst_choices()}:
            # `expired`, `aged_out` and `awaiting_analysis` describe what
            # happened *to* a case rather than what anybody concluded about
            # it. Letting a person sign a case off as "expired" would put a
            # non-answer into the same column the answers live in.
            raise HTTPException(
                400,
                f"'{resolution}' is not a resolution a person can close a case under. "
                "Choose one of: "
                + ", ".join(c.value for c in CaseResolution.analyst_choices()),
            )

    # The closing job runs every minute and takes this claim before it writes.
    # Without it a manual close and an automatic one interleave on the same
    # row, and `close_case` is a blind overwrite with no history.
    now = datetime.now(timezone.utc)
    if not await store.claim_for_closure(db, case_key=case_key, now=now):
        raise HTTPException(409, "This case is being answered right now. Try again in a moment.")

    await store.close_case(
        db,
        case_key=case_key,
        resolution=resolution,
        title=(case or {}).get("label") or spine.title,
        alerts_at_close=len((case or {}).get("alerts") or []) or (spine.alerts_at_close or 0),
        closed_at=now,
        closure_kind=CaseClosureKind.ANALYST.value,
        closed_by=str(identity.get("username") or identity.get("email") or "analyst"),
        closure_note=(body.note or "").strip() or None,
        # Which analysis was in front of them. `narrative_fingerprint` is
        # rewritten whenever correlation commissions a fresh narrative — for
        # closed cases too — so without this frozen copy the sign-off silently
        # re-attaches to an analysis they never read.
        narrative_fingerprint=spine.narrative_fingerprint,
    )
    await db.commit()

    return {
        "case_key": case_key,
        "case_number": spine.case_number,
        "status": "closed",
        "resolution": resolution,
        "closed_by": str(identity.get("username") or identity.get("email") or "analyst"),
        "closed_at": now.isoformat(),
        "note": (
            "This case could no longer be re-derived, so it was closed as expired "
            "rather than under a verdict."
            if unanalysable
            else "Closed on the analysis shown."
        ),
    }


@router.post("/case/{case_key}/analyse")
async def analyse_case_now(
    case_key: str,
    db: DBSession,
    hours: int = Query(default=CASE_LOOKUP_HOURS, ge=1, le=CASE_LOOKUP_MAX_HOURS),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """Analyse this case now, without waiting for its quiet period.

    The analysis is normally commissioned when a case goes quiet. An analyst
    who is reading the case now should not have to wait ten minutes for it, so
    this commissions it immediately on whatever the case holds.

    It does not close the case. Closing is a separate act — either the quiet
    period, or a person, who may only sign a case off once this has produced
    something for them to agree with.
    """
    from app.services.alert_case_narrative_service import narrative_fingerprint
    from app.services.case_read_set_service import (
        NARRATIVE_REQUESTED,
        record_read_set,
    )
    from app.tasks.case_narrative_task import dispatch as dispatch_narratives

    scope = _scope(request)
    # Scoped first, and only then asked about.
    #
    # This used to answer from the spine — fetched by primary key, with no
    # tenant filter — before scoping: 404 for a key that does not exist and
    # 409 "already answered" for another client's closed case. That difference
    # is an existence oracle, and on an MSSP the thing it discloses is which
    # of your competitors' clients had an incident. `get_case` already states
    # the rule: a case that does not form for this caller is not theirs.
    case = await case_by_key(db, case_key, scope=scope, hours=hours)
    spine = await db.get(AlertCaseSpine, case_key)
    if spine is None or (case is None and not scope.all_tenants):
        raise HTTPException(404, "No such case")
    if spine.closed_at is not None:
        raise HTTPException(409, "This case has already been answered.")

    if case is None:
        raise HTTPException(
            409,
            "This case's alerts are outside the correlation window, so there is "
            "nothing to analyse. It can still be closed by hand.",
        )

    members = case.get("alerts") or []

    # Asking for the analysis does not close the case.
    #
    # It used to. That made the gated manual close below unreachable: the only
    # way to obtain an analysis was a button that closed the case for you, so
    # every case an analyst sent to the model came back "already answered" and
    # there was nothing left to sign off. Asking a question and recording a
    # decision are two acts, and this endpoint is the first one.
    fingerprint = narrative_fingerprint(
        score=int(case.get("score") or 0),
        member_count=len(members),
        tactics=case.get("tactics") or [],
    )

    # What this read covered, recorded but not frozen.
    #
    # Asking for an early read must not stop the case accepting alerts — that
    # would give this endpoint an invisible cost at the point of use. But the
    # conclusion it produces is about a specific set, and until now nothing
    # recorded which: of 1,698 narratives in this estate, zero name a single
    # alert. 23.3% of cases accrete after their conclusion is written, and
    # 95.5% of cases holding 21+ alerts do, so the set moving is the normal
    # case rather than an anomaly. Recorded here so the divergence is visible
    # instead of silent.
    identity = getattr(request.state, "identity", None) or {}
    await record_read_set(
        db,
        case_key=case_key,
        run_ids=[m.get("run_id") for m in members if m.get("run_id")],
        reason=NARRATIVE_REQUESTED,
        requested_by=str(identity.get("username") or identity.get("email") or "analyst"),
        narrative_fingerprint=fingerprint,
    )
    await db.commit()

    dispatch_narratives([(case_key, case, fingerprint)])

    return {
        "case_key": case_key,
        "case_number": spine.case_number,
        # Still open. The quiet period will close it with the model's verdict,
        # or a person can close it themselves once the analysis has landed.
        "status": spine.status,
        "narrative_status": "queued",
        "alerts": len(members),
        "note": (
            "Analysing now. The case stays open and keeps accepting alerts — "
            "asking for a read does not freeze it. The alerts this read covers "
            "are recorded, so if the case grows, the difference is visible."
        ),
    }
