"""
Fill entity_host / entity_user on alert runs already stored.

The columns arrived with migration 021, so everything investigated before it
has no entity — and correlation groups on exactly that. Without this pass the
feature can only see alerts that arrive from now on, which makes "what else
happened on this machine in the last 48 hours" unanswerable for the whole
existing history.

Pure parsing. No collector, no provider, no model: the alert bodies are already
stored and the entity is read out of them.

    python -m scripts.backfill_alert_entities            # dry run
    python -m scripts.backfill_alert_entities --apply
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from sqlalchemy import and_ as sa_and, select
from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun
from app.services.alert_field_service import entity_of, extract_alert_fields, source_of

sync_engine.echo = False
BATCH = 500


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    stats: Counter = Counter()
    with Session(sync_engine) as session:
        from sqlalchemy import or_

        # Anything missing an entity *or* a source. Source arrived later than
        # the entity columns, so runs backfilled once still have none — and
        # correlation partitions on it, so a null source would silently pool
        # every platform into one bucket.
        rows = session.execute(
            select(AlertBodyInvestigationRun).where(
                or_(
                    sa_and(
                        AlertBodyInvestigationRun.entity_host.is_(None),
                        AlertBodyInvestigationRun.entity_user.is_(None),
                    ),
                    AlertBodyInvestigationRun.alert_source.is_(None),
                )
            )
        ).scalars().all()

        print(f"{len(rows)} run(s) without an entity", flush=True)
        for index, run in enumerate(rows, start=1):
            if args.limit and stats["updated"] >= args.limit:
                break
            fields = extract_alert_fields(
                run.alert_body or "",
                rule_id=run.detection_rule_id,
                rule_name=run.detection_rule_name,
            )
            host, user = entity_of(fields)
            source = source_of(fields)
            if args.apply and run.alert_source is None:
                run.alert_source = source
                stats["source_set"] += 1
            if not host and not user:
                stats["no_entity_in_body"] += 1
                continue
            if run.entity_host or run.entity_user:
                stats["entity_already_set"] += 1
                continue

            stats["updated"] += 1
            if host:
                stats["with_host"] += 1
            if user:
                stats["with_user"] += 1
            if args.apply:
                run.entity_host = host
                run.entity_user = user
                if index % BATCH == 0:
                    session.commit()
                    print(f"  …{index}/{len(rows)}", flush=True)

        if args.apply:
            session.commit()

    print()
    print("DRY RUN — nothing written." if not args.apply else "APPLIED")
    for key in ("updated", "with_host", "with_user", "source_set",
                "entity_already_set", "no_entity_in_body"):
        print(f"  {key:20} {stats[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
