"""Reconnect case rows whose key no longer re-derives.

    python -m app.cli.case_supersession --dry-run          # counts + samples
    python -m app.cli.case_supersession --dry-run --samples 10
    python -m app.cli.case_supersession --apply

Writes a pointer and a reason, and nothing else. It does not copy resolutions
or narratives onto live rows: a resolution recorded under one key is a
judgement about that key's alerts, and overwriting a live case's own
conclusion with it would be rewriting one rather than recovering it.
"""

from __future__ import annotations

import argparse
import asyncio
import json

from datetime import datetime, timezone

from sqlalchemy import select, text

from app.db.session import AsyncSessionLocal
from app.models.database import AlertCaseSpine
from app.services import tenant_scope
from app.services.alert_correlation_service import correlate_alerts
from app.services.case_supersession_service import (
    ALREADY_MERGED,
    AMBIGUOUS,
    collapse_chains,
    EXPIRED,
    MAPPED,
    TARGET_UNKNOWN,
    DeadRow,
    LiveCase,
    plan,
    summarise,
)

# Whether a dead row's alerts are still in the store at all. Without them
# there is nothing left to re-derive the case from, and the row is expired
# rather than merely unreachable.
_ALERTS_PRESENT = """
select s.case_key, ex.n > 0
from alert_case_spine s
cross join lateral (
  select count(*) n from alert_body_investigation_runs r
  where r.entity_host = s.entity_host
    and coalesce(r.event_time, r.created_at)
        between s.opened_at - interval '10 minutes'
            and s.opened_at + interval '30 minutes'
) ex
"""


def _as_dt(value) -> datetime | None:
    """Alert times come back from the correlation service as ISO strings."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


async def build():
    async with AsyncSessionLocal() as db:
        derived = await correlate_alerts(
            db, scope=tenant_scope.INTERNAL, hours=17520, limit=5000, persist=False
        )
        live_keys = {c["case_key"] for c in derived["cases"]}
        live = []
        for case in derived["cases"]:
            times = [
                t for t in (_as_dt(a.get("event_time")) for a in (case.get("alerts") or []))
                if t is not None
            ]
            live.append(
                LiveCase(
                    case_key=case["case_key"],
                    case_number=case.get("case_number"),
                    entity_host=case.get("entity_host") or "",
                    first_event_at=min(times) if times else None,
                    alert_count=int(case.get("alert_count") or len(case.get("alerts") or [])),
                )
            )
        present = dict((await db.execute(text(_ALERTS_PRESENT))).all())
        rows = (await db.execute(select(AlertCaseSpine))).scalars().all()
        dead = [
            DeadRow(
                case_key=row.case_key,
                case_number=row.case_number,
                entity_host=row.entity_host,
                opened_at=row.opened_at,
                alerts_at_close=row.alerts_at_close,
                resolution=row.resolution,
                closed_at=row.closed_at,
                has_analysis=bool(row.narrative_markdown),
                alerts_still_present=bool(present.get(row.case_key)),
                closure_kind=row.closure_kind,
                # Only a pointer this migration did not write itself. The
                # discriminator is `supersession_state`: a row this migration
                # has already mapped carries its own pointer, and reading that
                # back as contemporaneous merge evidence re-labelled all 842
                # mapped rows as `merged` on the second run. Idempotence
                # matters here because this command will be run again.
                existing_pointer=(
                    row.superseded_by_case_key
                    if row.supersession_state in (None, ALREADY_MERGED)
                    else None
                ),
            )
            for row in rows
            if row.case_key not in live_keys
        ]
    return plan(dead, live), len(rows), len(live)


async def run(apply: bool, samples: int) -> None:
    decisions, total_rows, live_count = await build()
    stats = summarise(decisions)
    print(f"spine rows {total_rows} | derivable {live_count} | dead {len(decisions)}")
    for state in (MAPPED, ALREADY_MERGED, AMBIGUOUS, TARGET_UNKNOWN, EXPIRED):
        print(f"  {state:<16} {stats.get(state, 0)}")
    print(f"  of which carry a written analysis: {stats['carrying_analysis']}")
    print(f"  of which are true positives      : {stats['true_positive']}")

    print(f"\n{samples} sampled mappings, with the evidence for each:")
    shown = 0
    for decision in decisions:
        if decision.state != MAPPED or shown >= samples:
            continue
        shown += 1
        e = decision.evidence()
        print(
            f"  #{e['dead_case']} -> #{e['target_case']}  host={e['host']}\n"
            f"      dead row opened {e['dead_opened_at']} closing on "
            f"{e['dead_alerts_at_close']} alerts\n"
            f"      live case first alert {e['target_first_event_at']} holding "
            f"{e['target_alert_count']} alerts\n"
            f"      {e['seconds_apart']}s apart; "
            + (
                f"counts {'match' if e['dead_alerts_at_close'] == e['target_alert_count'] else 'DIFFER'}"
                if (e['dead_alerts_at_close'] or 0) > 0
                else "no count was ever recorded, matched on exact timestamp"
            )
            + f"; {len(e['candidates'])} candidate(s) considered"
        )
    ambiguous = [d for d in decisions if d.state == AMBIGUOUS]
    if ambiguous:
        print(f"\n{min(5, len(ambiguous))} sampled ambiguous rows, kept unresolved:")
        for decision in ambiguous[:5]:
            e = decision.evidence()
            print(
                f"  #{e['dead_case']}  host={e['host']}  candidates "
                f"{e['candidates']}\n      {e['reason']}"
            )

    async with AsyncSessionLocal() as db:
        chains = await collapse_chains(db, apply=False)
    if chains:
        print(f"\npointers that land on another superseded key: {len(chains)}")
        print("  (created by this migration: it re-pointed a middle row and did")
        print("   not follow back to the rows pointing at it)")
        for c in chains[:10]:
            print(f"    #{c['case_number']} -> #{c['was_pointing_at']} "
                  f"(superseded) -> #{c['now_points_at']}"
                  f"{' [live]' if c['end_is_live'] else ''}")

    if not apply:
        print("\n(dry run — nothing written)")
        return

    async with AsyncSessionLocal() as db:
        for decision in decisions:
            row = await db.get(AlertCaseSpine, decision.dead.case_key)
            if row is None:
                continue
            row.supersession_state = decision.state
            row.supersession_note = decision.reason
            if decision.state == MAPPED and decision.target is not None:
                row.superseded_by_case_key = decision.target.case_key
                row.supersession_candidates = None
            elif decision.state == ALREADY_MERGED:
                # Left exactly as the merge wrote it.
                row.supersession_candidates = None
            else:
                # Never a guessed pointer. A row in one of these states must
                # not be left carrying one either, or the state and the pointer
                # contradict each other and a reader believes the pointer.
                row.superseded_by_case_key = None
                row.supersession_candidates = {
                    "candidates": [
                        {"case_key": c.case_key, "case_number": c.case_number}
                        for c in decision.candidates
                    ]
                }
        await db.commit()
    async with AsyncSessionLocal() as db:
        collapsed = await collapse_chains(db, apply=True)
    if collapsed:
        print(f"{len(collapsed)} chained pointer(s) re-aimed at the live case "
              "they ultimately lead to; the state each was written under is kept.")

    print(f"\n{stats.get(MAPPED, 0)} pointers written; "
          f"{stats.get(AMBIGUOUS, 0)} left ambiguous with every candidate kept; "
          f"{stats.get(TARGET_UNKNOWN, 0)} target unknown; "
          f"{stats.get(EXPIRED, 0)} expired. "
          "No resolution or narrative was copied onto any live case.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--samples", type=int, default=10)
    args = parser.parse_args()
    if args.apply and args.dry_run:
        parser.error("pick one of --apply and --dry-run")
    asyncio.run(run(apply=args.apply, samples=args.samples))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
