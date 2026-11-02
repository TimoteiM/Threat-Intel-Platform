"""Keep the graph tables warm, instead of asking someone to remember.

`alert_graph_entity` and `alert_graph_edge` are a cache, and until now
`materialise_run` had exactly one caller: the `graph_backfill` CLI. So every
figure drawn from those tables was as of whenever a person last ran it, and
nothing said so. Two alerts on `exp-4lwk334` carry a corroborated ATT&CK
technique and have no graph rows at all, because they arrived after the last
backfill — the corroboration work is invisible until they are materialised.

Why a sweep and not a hook at ingest
------------------------------------
A hook lives at one call site, and this codebase has four separate writers of
`indicator_risk_score` and seven hand-maintained lists that have each swallowed
a feature silently. A hook on the analysis task would cover the path somebody
remembered and miss the recovery task, the callback, the manual re-analysis and
whatever is added next — and it would fail the way those failed, by producing
nothing and saying nothing.

The sweep asks the database what is missing. It cannot be bypassed by a new
writer, it repairs whatever a failed run left behind, and it is idempotent:
`materialise_run` replaces a run's rows rather than appending.

What "stale" means here
-----------------------
Two signals, because absence and change are different failures:

    graph_materialised_at IS NULL                    never materialised
    graph_materialised_at < completed_at             the analysis finished
                                                     after the graph was
                                                     written, so the rows
                                                     predate the assessment
                                                     they should reflect

The second closes the gap a sweep on absence alone leaves. `result_attack_assessment`
carries no timestamp of its own, so `completed_at` — when the analysis
finished — stands in for it: an assessment cannot be written after the run
completes without the run completing again, and when it does, `completed_at`
moves. It is the right column rather than a convenient one, and it is the only
one this table has.

What it still does not cover is an assessment rewritten *without* `completed_at`
moving. Nothing in this codebase does that today, and saying so is better than
a signal that implies more coverage than it has.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AlertBodyInvestigationRun, AlertLogContext
from app.services.alert_graph_store_service import materialise_run

logger = logging.getLogger(__name__)

#: How many runs one pass materialises. Sized against the measured backfill
#: rate of roughly 38 runs a second: a batch of 200 is about five seconds of
#: work, which keeps a two-minute schedule comfortably ahead of an estate
#: taking a few hundred alerts a day without ever holding a long transaction.
BATCH = 200


@dataclass
class SweepResult:
    considered: int
    materialised: int
    entities: int
    edges: int
    failed: int
    remaining: int

    def as_json(self) -> dict[str, Any]:
        return {
            "considered": self.considered,
            "materialised": self.materialised,
            "entities": self.entities,
            "edges": self.edges,
            "failed": self.failed,
            "remaining": self.remaining,
        }


def _stale() -> Any:
    """Never materialised, or materialised before the analysis finished."""
    return (
        AlertBodyInvestigationRun.graph_materialised_at.is_(None)
        | (
            AlertBodyInvestigationRun.completed_at.isnot(None)
            & (
                AlertBodyInvestigationRun.graph_materialised_at
                < AlertBodyInvestigationRun.completed_at
            )
        )
    )


async def pending_count(db: AsyncSession) -> int:
    """Runs whose graph rows are missing or older than their analysis."""
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(AlertBodyInvestigationRun)
                .where(_stale())
            )
        ).scalar()
        or 0
    )


async def sweep(db: AsyncSession, *, limit: int = BATCH) -> SweepResult:
    """Materialise the oldest stale runs.

    Oldest first, so a backlog drains in the order it arrived and a reader
    watching `remaining` sees it fall monotonically rather than jumping about.
    """
    rows = (
        await db.execute(
            select(
                AlertBodyInvestigationRun.id,
                AlertBodyInvestigationRun.alert_body,
                AlertBodyInvestigationRun.event_time,
                AlertBodyInvestigationRun.created_at,
                AlertBodyInvestigationRun.indicator_risk_score,
                AlertBodyInvestigationRun.result_attack_assessment,
                AlertLogContext.logs,
            )
            .outerjoin(
                AlertLogContext,
                AlertLogContext.run_id == AlertBodyInvestigationRun.id,
            )
            .where(_stale())
            .order_by(AlertBodyInvestigationRun.created_at)
            .limit(limit)
        )
    ).all()

    entities = edges = done = failed = 0
    for run_id, body, when, created, level, assessment, logs in rows:
        try:
            n_ent, n_edge = await materialise_run(
                db, run_id=run_id, alert_body=body,
                event_time=when or created, risk_score=level,
                assessment=assessment, log_events=logs,
            )
        except Exception as exc:  # one bad row must not stall the backlog
            failed += 1
            logger.warning(
                "graph_materialise_failed run_id=%s error=%s", run_id,
                type(exc).__name__,
            )
            continue
        entities += n_ent
        edges += n_edge
        done += 1
    if done:
        await db.commit()

    remaining = await pending_count(db)
    result = SweepResult(
        considered=len(rows), materialised=done, entities=entities,
        edges=edges, failed=failed, remaining=remaining,
    )
    if failed:
        logger.error(
            "graph_materialise_partial materialised=%d failed=%d remaining=%d "
            "— a run that cannot be materialised is invisible to every graph "
            "figure, so this is an error rather than a warning",
            done, failed, remaining,
        )
    elif done:
        logger.info(
            "graph_materialised runs=%d entities=%d edges=%d remaining=%d",
            done, entities, edges, remaining,
        )
    return result
