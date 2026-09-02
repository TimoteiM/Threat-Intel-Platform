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

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import AlertBodyInvestigationRun
from app.services.alert_field_service import entity_of, extract_alert_fields

sync_engine.echo = False
BATCH = 500


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    stats: Counter = Counter()
    with Session(sync_engine) as session:
        rows = session.execute(
            select(AlertBodyInvestigationRun).where(
                AlertBodyInvestigationRun.entity_host.is_(None),
                AlertBodyInvestigationRun.entity_user.is_(None),
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
            if not host and not user:
                stats["no_entity_in_body"] += 1
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
    for key in ("updated", "with_host", "with_user", "no_entity_in_body"):
        print(f"  {key:20} {stats[key]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
