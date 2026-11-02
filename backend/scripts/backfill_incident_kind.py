"""Re-kind stored runs whose tenant declares an incident feed.

Migration 075 records the declaration; ingest reads it from there for new
alerts. This applies it to runs already stored, which ingest cannot reach.

**Promote only, never demote.** A run is moved `alert` -> `incident` and never
the other way. A payload that declared itself pre-correlated is already an
incident and is left alone; demoting on a feed-level setting would discard a
statement the sender made about that specific payload.

**Re-runnable.** It selects on the current value, so a second run is a no-op.
That is the test for a migration-shaped change: the first run and the tenth
leave the same state.

Read-only unless `--apply` is given. The default prints what it would do.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.services import tenant_feed  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="write. Without it, this only reports.")
    args = ap.parse_args()

    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        tenants = [
            r.tenant_id for r in conn.execute(
                text("SELECT tenant_id FROM tenants WHERE feed_kind = :k"),
                {"k": tenant_feed.INCIDENTS},
            )
        ]
        if not tenants:
            print("No tenant declares an incident feed. Nothing to do.")
            return 0
        print(f"tenants declaring an incident feed: {tenants}")

        rows = conn.execute(
            text("""
                SELECT tenant_id AS tid,
                       count(*) AS total,
                       count(*) FILTER (WHERE COALESCE(alert_kind,'alert')='alert') AS to_promote,
                       count(*) FILTER (WHERE alert_kind='incident') AS already,
                       count(*) FILTER (WHERE entity_host IS NULL) AS hostless
                  FROM alert_body_investigation_runs
                 WHERE tenant_id = ANY(:t)
                 GROUP BY 1 ORDER BY 1
            """),
            {"t": tenants},
        ).all()

        print(f"\n{'tenant':8s} {'runs':>6s} {'to promote':>11s} "
              f"{'already':>8s} {'hostless':>9s}")
        total_to_promote = 0
        for r in rows:
            total_to_promote += int(r.to_promote)
            print(f"{r.tid:8s} {r.total:6d} {r.to_promote:11d} "
                  f"{r.already:8d} {r.hostless:9d}")
        print(f"\n{total_to_promote} run(s) would become alert_kind='incident'.")
        print("Each becomes a single-member case, keyed on its own row id, and")
        print("a missing entity_host no longer excludes it from correlation.")

        if not args.apply:
            print("\n(dry run — pass --apply to write)")
            return 0

    with engine.begin() as conn:
        result = conn.execute(
            text("""
                UPDATE alert_body_investigation_runs
                   SET alert_kind = 'incident'
                 WHERE tenant_id = ANY(:t)
                   AND COALESCE(alert_kind, 'alert') = 'alert'
            """),
            {"t": tenants},
        )
        print(f"\npromoted {result.rowcount} run(s) to alert_kind='incident'")

    with engine.connect() as conn:
        left = conn.execute(
            text("""
                SELECT count(*) FROM alert_body_investigation_runs
                 WHERE tenant_id = ANY(:t)
                   AND COALESCE(alert_kind,'alert') = 'alert'
            """),
            {"t": tenants},
        ).scalar()
        print(f"remaining on alert_kind='alert' for those tenants: {left} "
              f"(re-running now is a no-op)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
