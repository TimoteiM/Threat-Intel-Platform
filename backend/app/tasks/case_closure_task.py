"""Answering cases that have gone quiet, so an analyst does not have to.

The manual job this replaces is three acts: open a case, merge the alerts that
belong to it, close it with a resolution. Correlation does the first two. This
does the third — every minute, for every case that has stopped receiving
alerts.

Why every minute rather than hourly: the quiet period is ten minutes, and a
job that runs hourly would add up to an hour of dead time to every case's
MTTR. The scan is one indexed read of open cases ordered by last activity;
when nothing is due it does nothing, which is the common case.

A case is answered once. Closing stops the SLA clock, and a case that could
reopen hours later would make MTTR meaningless — a straggler at hour sixteen
turning a four-minute resolution into a sixteen-hour one. Alerts arriving
after the answer are appended when they add nothing (99% of them, measured)
and open a continuation case when they bring a detection the case never saw.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# One pass answers at most this many cases. A backlog is worked through over
# successive minutes rather than in one task that outlives its time limit.
MAX_PER_PASS = 25

# How long a closed case may wait for its analysis before it is recorded as
# unanswered. Generous on purpose: the narrative is a model call behind a
# queue, and a case that is merely slow must not be written off as
# inconclusive while the answer is still on its way.
_ANALYSIS_GRACE = timedelta(hours=2)

def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)



@celery_app.task(name="app.tasks.case_closure_task.close_quiet_cases", time_limit=240,
                 soft_time_limit=210)
def close_quiet_cases(limit: int | None = None) -> dict[str, Any]:
    """Close every case that has been quiet long enough to be finished."""
    import asyncio

    settings = get_settings()
    batch = int(limit or MAX_PER_PASS)

    # Imported at the enclosing level, not inside the coroutine: `_pass` is a
    # sibling closure and a name bound in a nested one is not in its scope.
    # That exact mistake stopped the correlation job for weeks.
    from app.services import alert_case_closure_service as closure
    from app.services import alert_case_store as store
    from app.services import tenant_scope
    from app.services.alert_correlation_service import case_by_key

    async def _run() -> dict[str, Any]:
        # A dedicated unpooled engine per invocation, as the neighbouring
        # scheduled tasks already do: Celery runs each task in a worker thread
        # and `asyncio.run` builds a fresh loop, so the app-wide pooled engine
        # hands the new loop connections bound to the previous one.
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        try:
            return await _pass(factory)
        finally:
            await engine.dispose()

    async def _pass(factory) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        answered: list[dict[str, Any]] = []
        skipped = 0
        unreadable = 0
        expired = 0
        backed_off = 0

        async with factory() as db:
            # Before anything else: cases closed but still waiting on an
            # answer that is never coming.
            #
            # A closed case carries `awaiting_analysis` until the narrative
            # task writes the verdict over it. If that task died, was dropped
            # by the broker, or failed every retry, the placeholder is
            # permanent — and a case with no resolution is invisible to every
            # report that counts them. After the grace period it becomes
            # `inconclusive`, which is what it is: nobody answered it.
            #
            # Never a positive, and never a false positive either. An
            # unanswered case must not improve a metric.
            stranded = await store.resolve_stranded(
                db, older_than=now - _ANALYSIS_GRACE, resolution="inconclusive",
            )

            # The quiet period goes into the query, so a case that cannot
            # possibly be due does not consume one of the limited slots.
            open_cases = await store.cases_awaiting_closure(
                db, limit=batch * 4, due_before=now - _quiet_period(settings),
            )
            if not open_cases:
                return {"ran": True, "open": 0, "closed": 0}

            # Each case is looked up on its own, scoped to its entity.
            #
            # It used to be one bulk correlation whose *listing* was then
            # searched for each key — and a listing filters on wall-clock
            # time, on score and on a row limit, while membership is relative
            # to each entity's own newest event. A case created seconds
            # earlier could be missing from it, which this job once read as
            # "unreadable" and closed unanswered. A scoped lookup asks the
            # question the job actually has, and costs about a second.
            window_hours = int(getattr(settings, "correlation_window_hours", 48) or 48)

            for row in open_cases:
                if len(answered) >= batch:
                    break

                # A case that failed to read a moment ago will fail again:
                # membership is re-derived from the same alerts by the same
                # code. Backing off geometrically, capped, keeps it in the
                # queue — it is never written off on absence — while freeing
                # the slot for a case that can actually be answered.
                if _still_backing_off(row, now):
                    backed_off += 1
                    continue
                # Reach back far enough to cover the case's own activity: an
                # old case is still readable, it is simply not in the last
                # 48 hours.
                age_hours = max(
                    window_hours,
                    int((now - _as_utc(row.last_activity_at)).total_seconds() // 3600) + 24,
                )
                case = await case_by_key(
                    db, row.case_key, scope=tenant_scope.INTERNAL, hours=age_hours,
                )
                if case is None:
                    # Genuinely unreadable: its alerts no longer form this
                    # case at all. A case that can never gain another member
                    # — its last activity is older than the session horizon —
                    # is finished whether or not we can answer it, and leaving
                    # it open for ever is an unbounded MTTR. It is closed as
                    # what it is, with no resolution invented from nothing.
                    if _as_utc(row.last_activity_at) < now - timedelta(hours=window_hours):
                        if await store.claim_for_closure(db, case_key=row.case_key, now=now):
                            await store.close_case(
                                db,
                                case_key=row.case_key,
                                resolution="expired",
                                title=row.title,
                                alerts_at_close=row.alerts_at_close or 0,
                                closed_at=now,
                                closure_kind="expired",
                            )
                            expired += 1
                        continue

                    # Not readable this pass. Recorded, so the next pass can
                    # skip it for a while rather than paying another full
                    # re-correlation to fail in the same way — and so a
                    # blocker is a number somebody can see.
                    await store.record_closure_attempt(db, case_key=row.case_key, now=now)

                    # Absence from the listing is never evidence about a case.
                    #
                    # The listing filters on wall-clock time, on score and on a
                    # row limit; membership is computed relative to each
                    # entity's own newest event, which is why a replayed chain
                    # forms a case at all. So a case created seconds ago, whose
                    # membership was read in this very call, can be missing
                    # from the listing because its alerts are old. Reading that
                    # as "unreadable" and closing it `aged_out` destroyed 575
                    # cases, 504 within two minutes of being created, every one
                    # with zero alerts and no resolution anybody computed.
                    #
                    # Nothing is closed on absence now. The case stays open and
                    # the count is reported, so a listing that has drifted from
                    # the membership is a number somebody can see rather than a
                    # silent cull.
                    unreadable += 1
                    continue

                members = case.get("alerts") or []
                decision = closure.decide(
                    members,
                    last_activity_at=row.last_activity_at,
                    opened_at=row.opened_at,
                    now=now,
                    quiet_period=_quiet_period(settings),
                )
                if not decision.due:
                    continue

                if not await store.claim_for_closure(db, case_key=row.case_key, now=now):
                    # Another pass is already answering it.
                    continue

                # A continuation that brought nothing its parent had not
                # already answered arrives with the answer on it. Asking a
                # model the same question again would cost a call to produce
                # the same sentence — 47% of continuations, measured.
                #
                # Anything else closes with no answer yet. The resolution is
                # whatever the analysis concludes, and the narrative task
                # writes it when the model returns; closing cannot wait for
                # that without making MTTR measure queue depth.
                #
                # A parent whose own answer is still pending is not an answer
                # to inherit, so the continuation waits for its own.
                inherited = bool(
                    row.resolution
                    and row.resolution != closure.AWAITING_ANALYSIS
                    and row.continues_case_key
                )
                resolution = row.resolution if inherited else closure.AWAITING_ANALYSIS
                await store.close_case(
                    db,
                    case_key=row.case_key,
                    resolution=resolution,
                    title=case.get("label") or row.title,
                    alerts_at_close=len(members) or int(case.get("alert_count") or 0),
                    closed_at=now,
                    closure_kind="inherited" if inherited else "auto",
                )
                answered.append({
                    "inherited": bool(inherited),
                    "case": case,
                    "case_key": row.case_key,
                    "case_number": row.case_number,
                    "resolution": resolution,
                    "alerts": len(members),
                    "reason": decision.reason,
                    "quiet_for_seconds": round(decision.quiet_for.total_seconds()),
                })
                logger.info(
                    "Closed case #%s (%s) as %s on %s alert(s) — %s",
                    row.case_number, row.case_key[:12], resolution, len(members),
                    decision.reason,
                )
            await db.commit()

        # The narrative is the resolution an analyst reads, and it costs a
        # model call — dispatched after the commit so a case is never left
        # claimed-but-unclosed if the dispatch fails. Reuses the correlation's
        # own dispatcher, which trims an oversized member list for the prompt.
        if answered:
            from app.services.alert_case_narrative_service import narrative_fingerprint
            from app.tasks.case_narrative_task import dispatch as dispatch_narratives

            dispatch_narratives([
                (
                    entry["case_key"],
                    entry["case"],
                    narrative_fingerprint(
                        score=int(entry["case"].get("score") or 0),
                        member_count=entry["alerts"],
                        tactics=entry["case"].get("tactics") or [],
                    ),
                )
                for entry in answered
                # Nothing new to say, so nothing is asked.
                if not entry["inherited"]
            ])

        return {
            "ran": True,
            "open": len(open_cases),
            "closed": len(answered),
            # Closed because no alert can ever join them again.
            "expired": expired,
            # Skipped this pass because reading them failed recently.
            "backed_off": backed_off,
            # Closed, never analysed, past the grace period.
            "stranded_resolved": stranded,
            # Open, in the window, but not in the listing. Reported rather
            # than closed: a number that stays high means the listing and the
            # membership have drifted apart.
            "not_in_listing": unreadable,
            "cases": [
                {k: v for k, v in entry.items() if k != "case"} for entry in answered[:10]
            ],
        }

    try:
        outcome = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001 — a scheduled pass never crashes the beat
        logger.exception("Case closure pass failed: %s", exc)
        return {"ran": False, "error": f"{type(exc).__name__}: {exc}"}
    return outcome


# A case that could not be read waits this long before the next attempt,
# doubling each time to a ceiling. Never permanent: the alerts it is built
# from can come back into the window, and closing a case on absence from a
# listing is what destroyed 575 of them.
_BACKOFF_BASE = timedelta(minutes=2)
_BACKOFF_CEILING = timedelta(hours=1)


def _still_backing_off(row: Any, now: datetime) -> bool:
    attempts = int(getattr(row, "closure_attempts", 0) or 0)
    last = getattr(row, "closure_attempted_at", None)
    if not attempts or last is None:
        return False
    wait = min(_BACKOFF_BASE * (2 ** min(attempts - 1, 6)), _BACKOFF_CEILING)
    return _as_utc(last) + wait > now


def _quiet_period(settings: Any):
    from datetime import timedelta

    minutes = int(getattr(settings, "case_quiet_period_minutes", 10) or 10)
    return timedelta(minutes=minutes)
