"""Retire spine rows stranded by the incident re-kinding, each with the state
that is actually true of it.

When lin/pov/boc runs became `alert_kind='incident'`, the host-session
grouping that produced their old cases stopped re-deriving: those alerts are
now keyed on their own row ids. The old rows remain — correctly, they carry
analyses — but nothing recomputes them, and until they are marked they are
counted alongside the cases that replaced them. That is how `pov` came to
show 79 cases against 58 alerts.

**One blanket state would be a lie.** `case_supersession_service` already has
a vocabulary, and which value applies differs per row:

    expired    no alerts remain around this case's opening, so there is
               nothing to re-derive it from
    mapped     exactly one incident case now holds the alerts this case held,
               so a reader following the old number reaches the right place
    ambiguous  its alerts went to several incident cases — recorded as such
               rather than pointed at whichever one sorted first

Nothing is deleted and no resolution or narrative is copied: a judgement
recorded under one key is about that key's alerts.

Read-only unless `--apply`.
"""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.services import case_supersession_service as css  # noqa: E402

#: Tenants whose runs were re-kinded. Derived, not listed.
TENANT_SQL = "SELECT tenant_id FROM tenants WHERE feed_kind = 'incidents'"

#: A stranded row: one whose entity_host is a plain hostname while every run
#: for that tenant is now an incident. Incident cases carry the composite
#: `<host>\x1fincident:<id>`, so the absence of that marker identifies the old
#: grouping exactly, without guessing from dates.
STRANDED_SQL = """
    SELECT case_key, case_number, tenant_id, entity_host, alert_source,
           alert_client, session_started_at, opened_at, last_activity_at,
           alerts_at_close, supersession_state
      FROM alert_case_spine
     WHERE tenant_id = ANY(:tenants)
       AND entity_host NOT LIKE '%' || chr(31) || 'incident:%'
       AND supersession_state IS NULL
     ORDER BY tenant_id, case_number
"""

#: The incident cases now holding runs that sat on this host in this window.
#: Joined on the run's own id, which is what the incident key embeds.
TARGETS_SQL = """
    SELECT s.case_key, s.case_number
      FROM alert_body_investigation_runs r
      JOIN alert_case_spine s
        ON s.entity_host = r.entity_host || chr(31) || 'incident:' || r.id::text
     WHERE r.tenant_id = :tenant
       AND r.entity_host = :host
       AND r.event_time >= :start
       AND r.event_time <= :end
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        tenants = [r.tenant_id for r in conn.execute(text(TENANT_SQL))]
        if not tenants:
            print("No incident-feed tenants. Nothing to do.")
            return 0
        stranded = conn.execute(text(STRANDED_SQL), {"tenants": tenants}).all()
        print(f"incident-feed tenants: {tenants}")
        print(f"stranded spine rows  : {len(stranded)}\n")

        plan: list[tuple[str, int | None, str, str, str | None]] = []
        for row in stranded:
            targets = conn.execute(
                text(TARGETS_SQL),
                {"tenant": row.tenant_id, "host": row.entity_host,
                 "start": row.session_started_at or row.opened_at,
                 "end": row.last_activity_at or row.opened_at},
            ).all()
            if not targets:
                state, target, note = (
                    css.EXPIRED, None,
                    "Re-kinded to an incident feed 2026-10-26. No run remains "
                    "in this case's window to re-derive it from.",
                )
            elif len(targets) == 1:
                state, target = css.MAPPED, targets[0].case_key
                note = (
                    "Re-kinded to an incident feed 2026-10-26. Its alert is "
                    f"now its own case, #{targets[0].case_number}."
                )
            else:
                state, target = css.AMBIGUOUS, None
                note = (
                    "Re-kinded to an incident feed 2026-10-26. Its "
                    f"{len(targets)} alerts each became a case of their own "
                    f"(#{', #'.join(str(t.case_number) for t in targets)}), so "
                    "there is no single successor."
                )
            plan.append((row.case_key, row.case_number, state, note, target))

        counts = collections.Counter(state for _, _, state, _, _ in plan)
        print("plan:")
        for state, n in counts.most_common():
            print(f"   {state:14s} {n}")
        for key, num, state, _note, target in plan[:6]:
            print(f"   #{num} -> {state}" + (f" -> {target[:12]}…" if target else ""))
        if len(plan) > 6:
            print(f"   … and {len(plan) - 6} more")

        if not args.apply:
            print("\n(dry run — pass --apply to write)")
            return 0

    with engine.begin() as conn:
        for key, _num, state, note, target in plan:
            conn.execute(
                text("""
                    UPDATE alert_case_spine
                       SET supersession_state = :state,
                           supersession_note  = :note,
                           superseded_by_case_key = :target,
                           updated_at = now()
                     WHERE case_key = :key
                       AND supersession_state IS NULL
                """),
                {"state": state, "note": note, "target": target, "key": key},
            )
        print(f"\nretired {len(plan)} row(s)")

    with engine.connect() as conn:
        left = conn.execute(text(STRANDED_SQL), {"tenants": tenants}).all()
        print(f"stranded rows remaining: {len(left)} (re-running now is a no-op)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
