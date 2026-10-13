"""Has each enrichment source ever actually answered?

    python -m app.cli.source_answers

The companion to the watch heartbeat: that answers *did the task run*, this
answers *did the source answer*. A collector can run on schedule, succeed,
and record nothing from a provider that refused every request — which is what
ThreatFox did for seven months across 2,400 investigations.

A CLI rather than an endpoint because it takes about 98 seconds: a 90-day
aggregate extracting nested paths from large JSONB documents. The cost is
per-row extraction, not the number of scans — collapsing seven queries into
one changed the runtime by nothing — so it cannot be made fast enough for a
request. The right home is a scheduled task storing its result, exactly as
`watch_heartbeat` does, and that is not built.
"""

from __future__ import annotations

import argparse
import asyncio

from app.db.session import AsyncSessionLocal
from app.services.source_answer_rate_service import WINDOW_DAYS, answer_rates


async def run(days: int) -> int:
    async with AsyncSessionLocal() as db:
        out = await answer_rates(db, days=days)

    print(f"enrichment sources, last {out['window_days']} days\n")
    print(f"  {'source':20s} {'answered':>10s} {'of':>8s}   rate")
    for entry in out["sources"]:
        rate = entry["rate"]
        if isinstance(rate, dict):
            print(f"  {entry['source']:20s} {entry['answered']:>10d} "
                  f"{entry['observations']:>8d}   {rate['kind']}")
            continue
        flag = "   <-- NEVER ANSWERED" if entry["never_answered"] else ""
        print(f"  {entry['source']:20s} {entry['answered']:>10d} "
              f"{entry['observations']:>8d}   {rate * 100:5.1f}%{flag}")

    if out["never_answered"]:
        print(
            f"\n{len(out['never_answered'])} source(s) returned nothing at all: "
            f"{', '.join(out['never_answered'])}.\n"
            "A source at 0% over a window this size is broken, whatever it "
            "claims. ThreatFox read 0 of 2,174 here for seven months because "
            "it was sending the wrong auth header and reporting an empty list."
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=WINDOW_DAYS)
    return asyncio.run(run(parser.parse_args().days))


if __name__ == "__main__":
    raise SystemExit(main())
