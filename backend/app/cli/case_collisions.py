"""How many incidents in this estate exist under more than one case key.

    python -m app.cli.case_collisions
    python -m app.cli.case_collisions --hours 17520

Detection is on the alert-ID set, not on host plus opening minute: 59.1% of
this estate's cases hold a single alert, so a host-and-minute rule would merge
unrelated cases whenever two alerts landed in the same sixty seconds.
"""

from __future__ import annotations

import argparse
import asyncio

from app.db.session import AsyncSessionLocal
from app.services import tenant_scope
from app.services.alert_correlation_service import correlate_alerts
from sqlalchemy import text

from app.services.case_collision_service import detect, metric


async def run(hours: int, limit: int) -> None:
    async with AsyncSessionLocal() as db:
        out = await correlate_alerts(
            db, scope=tenant_scope.INTERNAL, hours=hours, limit=limit, persist=False
        )
    cases = out["cases"]
    found = detect(cases)
    stats = metric(found)
    print(f"cases derived: {len(cases)} over {hours}h")
    print(f"  incidents under several keys : {stats['incidents_with_several_keys']}")
    print(f"  surplus case rows            : {stats['surplus_case_rows']}")
    print(f"  largest group                : {stats['largest_group']} keys")
    if cases:
        print(
            f"  share of the case list that is duplicate: "
            f"{100 * stats['surplus_case_rows'] / len(cases):.1f}%"
        )
    for collision in found[:25]:
        numbers = ", ".join(f"#{n}" for n in collision.case_numbers)
        print(
            f"  {numbers}  — {collision.alerts} alerts compared, "
            f"overlap {collision.overlap:.2f}"
        )
    if len(found) > 25:
        print(f"  … and {len(found) - 25} more")

    # The other half, on the weaker signal. Reported separately on purpose.
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text(
            "select case_key, entity_host, opened_at, alerts_at_close, "
            "superseded_by_case_key is not null or continues_case_key is not null "
            "from alert_case_spine"
        ))).all()
    live = {c["case_key"] for c in cases}
    dead = [r for r in rows if r[0] not in live]
    marked = sum(1 for r in dead if r[4])
    print()
    print("keys that no longer re-derive at all:")
    print(f"  spine rows                   : {len(rows)}")
    print(f"  still derivable              : {len(rows) - len(dead)}")
    print(f"  dead keys                    : {len(dead)} "
          f"({100 * len(dead) / max(len(rows), 1):.1f}%)")
    print(f"  dead and already marked      : {marked}")
    print("  (a dead key has no alert set, so the alert-set test above cannot")
    print("   see it; #9 against #1440 is one of these, not a live collision)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=int, default=17520)
    parser.add_argument("--limit", type=int, default=5000)
    args = parser.parse_args()
    asyncio.run(run(args.hours, args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
