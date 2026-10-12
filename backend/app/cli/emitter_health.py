"""The list that goes to the people who own the agents.

One source of truth: the same `emitter_freshness_service` the shadow monitor
uses, so the list and the monitor cannot disagree. The first version of this
list was assembled by hand and reported a host at "21.1% of prior" by comparing
194 alerts over 24 days against 41 over 18 — unequal windows, and on equal ones
it is 37%, a decline rather than a collapse.

    python -m app.cli.emitter_health
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import date

from sqlalchemy import text

from app.db.session import AsyncSessionLocal
from app.services.emitter_freshness_service import HOST, SHADOW_RATIO, check

#: The estate collapse, excluded from baselines because it is not evidence
#: about any emitter's health.
COLLAPSE = (date(2026, 9, 25), date(2026, 10, 5))

_LAST_SEEN = """
select lower(split_part(entity_host, '.', 1)) as host,
       max(created_at) as last_seen, count(*) as lifetime
from alert_body_investigation_runs
where entity_host is not null
group by 1
"""


async def run(ratio: float) -> None:
    async with AsyncSessionLocal() as db:
        reports = await check(db, excluded_ranges=[COLLAPSE])
        seen = {
            r.host: (r.last_seen, r.lifetime)
            for r in (await db.execute(text(_LAST_SEEN))).all()
        }
        now = (await db.execute(text("select now()"))).scalar()

    report = reports[HOST]
    firing = sorted(
        (v for v in report.volumes if v.would_alarm(ratio)),
        key=lambda v: v.ratio or 0.0,
    )
    print("DEGRADED OR DARK — measured against each host's own demonstrated peak")
    print(f"  baseline excludes {len(report.excluded_zero_days)} zero-ingest days, "
          f"the collapse {report.excluded_ranges}, and "
          f"{len(report.excluded_emitters)} test host(s)")
    print(f"  both periods are {7} eligible days — equal lengths, stated")
    print()
    print(f"  {'host':22s} {'recent':>7s} {'peak':>8s} {'ratio':>7s}  last heard  days")
    for v in firing:
        last, _life = seen.get(v.emitter, (None, 0))
        days = (now - last).days if last else None
        print(f"  {v.emitter[:22]:22s} {v.recent:7d} {v.baseline:8.0f} "
              f"{v.ratio:7.3f}  {last:%Y-%m-%d}  {days:4d}")

    print()
    print("SILENT, BUT TOO SPARSE TO JUDGE BY RATE — a last-seen question, not a rate")
    quiet = [
        (h, s, life)
        for h, (s, life) in seen.items()
        if s and (now - s).days >= 14 and life >= 5
        and h not in {v.emitter for v in firing}
        and h not in set(report.excluded_emitters)
    ]
    for host, last, life in sorted(quiet, key=lambda x: -x[2])[:15]:
        print(f"  {host[:22]:22s} {life:7d} alerts ever          "
              f"  {last:%Y-%m-%d}  {(now - last).days:4d}")

    print()
    print(f"NOT COVERED: {len(report.volumes) - 11} of {len(report.volumes)} hosts "
          "never produced enough in any window to be judged by rate. Rate-based "
          "freshness covers the high-volume hosts; the rest need a last-seen "
          "instrument, which does not exist yet.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ratio", type=float, default=SHADOW_RATIO)
    asyncio.run(run(ap.parse_args().ratio))


if __name__ == "__main__":
    main()
