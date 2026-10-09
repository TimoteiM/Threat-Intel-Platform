"""Extract every stored alert into the graph tables.

    python -m app.cli.graph_backfill --limit 500      # a sample
    python -m app.cli.graph_backfill                  # the whole corpus

Idempotent: an alert's rows are replaced, not appended, so this is the command
to re-run whenever the extractor learns a new field shape.
"""

from __future__ import annotations

import argparse
import asyncio
import time

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.database import AlertBodyInvestigationRun, AlertLogContext
from app.services.alert_graph_store_service import materialise_run


async def run(limit: int | None, batch: int) -> None:
    started = time.perf_counter()
    entities = edges = done = empty = 0
    offset = 0
    while True:
        async with AsyncSessionLocal() as db:
            query = (
                select(
                    AlertBodyInvestigationRun.id,
                    AlertBodyInvestigationRun.alert_body,
                    AlertBodyInvestigationRun.event_time,
                    AlertBodyInvestigationRun.created_at,
                    AlertBodyInvestigationRun.highest_risk_score,
                    AlertBodyInvestigationRun.result_attack_assessment,
                    AlertLogContext.logs,
                )
                .outerjoin(
                    AlertLogContext,
                    AlertLogContext.run_id == AlertBodyInvestigationRun.id,
                )
                .order_by(AlertBodyInvestigationRun.created_at)
                .offset(offset)
                .limit(batch if limit is None else min(batch, limit - done))
            )
            rows = (await db.execute(query)).all()
            if not rows:
                break
            for run_id, body, when, created, level, assessment, logs in rows:
                n_ent, n_edge = await materialise_run(
                    db, run_id=run_id, alert_body=body,
                    event_time=when or created, rule_level=level,
                    assessment=assessment, log_events=logs,
                )
                entities += n_ent
                edges += n_edge
                done += 1
                if n_ent == 0:
                    empty += 1
            await db.commit()
        offset += len(rows)
        print(f"  {done} alerts, {entities} entities, {edges} edges", flush=True)
        if limit is not None and done >= limit:
            break
    seconds = time.perf_counter() - started
    print(
        f"{done} alerts in {seconds:.1f}s "
        f"({done / seconds:.0f}/s) -> {entities} entities, {edges} edges; "
        f"{empty} alerts yielded nothing ({100 * empty / max(done, 1):.1f}%)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--batch", type=int, default=500)
    args = parser.parse_args()
    asyncio.run(run(args.limit, args.batch))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
