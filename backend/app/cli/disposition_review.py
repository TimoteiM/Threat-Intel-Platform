"""List every case whose conclusion covers fewer alerts than it now holds.

    python -m app.cli.disposition_review

Read-only. Nothing is reopened and no resolution is changed — this is the
triage list for a person to re-read.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.db.session import AsyncSessionLocal
from app.services import tenant_scope
from app.services.alert_correlation_service import correlate_alerts
from app.services.case_disposition_review_service import review_for

_SPINE = """
select case_key, case_number, resolution, alerts_at_close, closed_by, closed_at
from alert_case_spine
"""


async def run() -> None:
    """List the cases and state the share plainly."""
    async with AsyncSessionLocal() as db:
        spine = {r[0]: r for r in (await db.execute(text(_SPINE))).all()}
        # The endpoint's own path, with the member cap lifted — without which
        # a case's membership is its earliest 100 alerts and this list is
        # wrong in the same direction as the defect it reports.
        out = await correlate_alerts(
            db, scope=tenant_scope.INTERNAL, hours=17520, limit=5000,
            persist=False, max_members=100000,
        )
        found = []
        with_disposition = 0
        for case in out["cases"]:
            row = spine.get(case["case_key"])
            if row is None:
                continue
            from app.services.case_disposition_review_service import DISPOSITIONS
            if row[2] in DISPOSITIONS and (row[3] or 0) > 0:
                with_disposition += 1
            review = review_for(
                case_number=row[1], resolution=row[2], alerts_at_close=row[3],
                current_run_ids=[
                    a.get("run_id") for a in (case.get("alerts") or []) if a.get("run_id")
                ],
                closed_by=row[4], closed_at=row[5],
            )
            if review:
                found.append(review)

    # Unknown first: a case whose judged-on count was never recorded is
    # less checkable than one judged on a known 4%.
    found.sort(key=lambda r: (r.judged_on_is_known, r.proportion if r.proportion is not None else -1))
    automatic = sum(1 for r in found if r.automatic)
    unknown = sum(1 for r in found if not r.judged_on_is_known)
    print(f"cases whose conclusion covers less than their full set: "
          f"{len(found)} of {with_disposition} with a disposition "
          f"({100 * len(found) / max(with_disposition, 1):.1f}%)")

    print(f"  whose judged-on count was never recorded (hit the 100 cap): {unknown}")
    print(f"  decided automatically, no analyst involved: {automatic}")
    print(f"  signed off by a person                    : {len(found) - automatic}")
    print()
    print(f"  {'case':<8}{'resolution':<16}{'judged':>7}{'holds':>7}{'covers':>8}  closed")
    for review in found:
        judged = str(review.judged_on) if review.judged_on_is_known else f">={review.judged_on}"
        covers = (
            f"{round((review.proportion or 0) * 100)}%"
            if review.proportion is not None else "unknown"
        )
        print(
            f"  #{str(review.case_number):<7}{review.resolution:<16}"
            f"{judged:>7}{review.holds_now:>7}{covers:>8}  "
            f"{(review.closed_at or '')[:10]} "
            f"{review.closed_by or '(automatic)'}"
        )
    if found:
        print()
        print("Nothing above has been reopened and no resolution has changed.")
        print(found[0].as_json()["whose_judgement"])


def main() -> int:
    asyncio.run(run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
