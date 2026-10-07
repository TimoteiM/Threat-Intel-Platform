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
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# One pass answers at most this many cases. A backlog is worked through over
# successive minutes rather than in one task that outlives its time limit.
MAX_PER_PASS = 25


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
    from app.services.alert_correlation_service import correlate_alerts

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
        aged = 0

        async with factory() as db:
            open_cases = await store.cases_awaiting_closure(db, limit=batch * 4)
            if not open_cases:
                return {"ran": True, "open": 0, "closed": 0}

            # One correlation read serves every case in the pass: membership is
            # recomputed, not stored, and doing it per case would re-derive the
            # same window once for each.
            window_hours = int(getattr(settings, "correlation_window_hours", 48) or 48)
            correlated = await correlate_alerts(
                db, scope=tenant_scope.INTERNAL, hours=window_hours, limit=2000,
            )
            by_key = {c.get("case_key"): c for c in (correlated.get("cases") or [])}

            for row in open_cases:
                if len(answered) >= batch:
                    break
                case = by_key.get(row.case_key)
                if case is None:
                    # Outside the correlation window, so its membership cannot
                    # be read and it cannot be answered on what it holds. It is
                    # still closed, because a case that stays open for ever is
                    # an unbounded MTTR and an SLA that can only get worse —
                    # but it is closed as what it is, with no model call and no
                    # resolution invented from nothing.
                    if await store.claim_for_closure(db, case_key=row.case_key, now=now):
                        await store.close_case(
                            db,
                            case_key=row.case_key,
                            resolution="aged_out",
                            title=row.title,
                            alerts_at_close=row.alerts_at_close or 0,
                            closed_at=now,
                            closure_kind="aged_out",
                        )
                        aged += 1
                    skipped += 1
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
                inherited = bool(row.resolution) and row.continues_case_key
                resolution = row.resolution if inherited else closure.resolution_for(
                    verdict=case.get("verdict") or case.get("overall_verdict"),
                    risk_score=case.get("score"),
                )
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
            "outside_window": skipped,
            "aged_out": aged,
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


def _quiet_period(settings: Any):
    from datetime import timedelta

    minutes = int(getattr(settings, "case_quiet_period_minutes", 10) or 10)
    return timedelta(minutes=minutes)
