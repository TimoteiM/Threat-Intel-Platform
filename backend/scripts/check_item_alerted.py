"""Did item N reach the platform? Run this between items.

The gate in the middle of the exercise. Ten minutes between items is not
long, so this answers one question quickly: **did an alert for the activity
just performed arrive, and did its log context collect?**

Three outcomes, kept apart on purpose:

* `ARRIVED` — an alert exists in the window. Proceed to the next item.
* `NOTHING YET` — no alert yet. It may still be in flight; the ingest and
  analysis path is not instant. Wait and re-run before concluding.
* `NOTHING (settled)` — past the grace period with nothing. That is a
  **detection-coverage** result for this item, not a loop miss, and the next
  item can still proceed.

Read-only. It reads the runs table and the log-context table and writes
nothing.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.services.context_gathering import playbook as pb

#: Past this, "nothing arrived" stops being "not yet". Chosen from the
#: observed path: ingest writes the row, a Celery task analyses it, and the
#: log-context collection runs inside that. 20 minutes is the same grace the
#: comparison tool uses, so the two cannot disagree about attribution.
SETTLE = timedelta(minutes=20)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--since", required=True,
                    help="the item's started_utc, e.g. 2026-10-22T09:00:00Z")
    ap.add_argument("--expect-class", default=None,
                    help="the class the item should produce, e.g. 15")
    args = ap.parse_args()

    since = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    elapsed = now - since

    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT r.id::text AS run_id, r.event_time, r.created_at, r.status,
                   r.result_json->'alert_fields'->>'event_id' AS eid,
                   r.result_json->'alert_fields'->>'rule_name' AS rule_name,
                   r.entity_user,
                   COALESCE(r.overall_verdict, '(none)') AS verdict,
                   lc.status AS log_status, lc.reason AS log_reason
            FROM alert_body_investigation_runs r
            LEFT JOIN alert_log_context lc ON lc.run_id = r.id
            WHERE lower(r.entity_host) = lower(:host)
              AND r.created_at >= :since
            ORDER BY r.created_at"""),
            {"host": args.host, "since": since}).fetchall()

    print(f"host   : {args.host}")
    print(f"since  : {since:%Y-%m-%dT%H:%M:%SZ}  ({elapsed.total_seconds()/60:.0f} "
          f"minutes ago)")
    if args.expect_class:
        print(f"expect : class {args.expect_class}")
    print()

    if not rows:
        settled = elapsed > SETTLE
        print("  NOTHING (settled)" if settled else "  NOTHING YET")
        if settled:
            print(f"\n  No alert for this host since that time, and it is past the "
                  f"{int(SETTLE.total_seconds()//60)}-minute\n  settle window. Record "
                  f"this item as having produced no alert — that is a\n  "
                  f"DETECTION-COVERAGE result, not a gathering failure. The loop was\n"
                  f"  never handed anything.\n\n  You can proceed to the next item.")
        else:
            print(f"\n  Nothing yet, and only {elapsed.total_seconds()/60:.0f} minutes "
                  f"have passed. Ingest, analysis and\n  log collection are not instant. "
                  f"Re-run this in a few minutes before\n  concluding anything.")
        raise SystemExit(0)

    print(f"  ARRIVED — {len(rows)} alert(s)\n")
    for r in rows:
        cls = pb.event_class_of({"event_id": r.eid or ""}) or "(none)"
        mark = ""
        if args.expect_class:
            mark = ("  <-- matches" if cls == str(args.expect_class)
                    else f"  <-- EXPECTED {args.expect_class}, GOT {cls}")
        print(f"    run {r.run_id[:8]}  arrived {r.created_at:%H:%M:%S}  "
              f"class={cls:<6}{mark}")
        print(f"      rule      : {str(r.rule_name)[:78]}")
        print(f"      account   : {r.entity_user}")
        print(f"      status    : {r.status}   verdict: {r.verdict}")
        print(f"      log ctx   : {r.log_status or '(none yet)'}"
              + (f" — {str(r.log_reason)[:60]}" if r.log_reason else ""))
        if str(r.entity_user or "").upper().startswith("NT AUTHORITY"):
            print(f"      NOTE: the account is a built-in principal, so the "
                  f"user-side templates\n            cannot fire for this alert. "
                  f"If that was not intended, re-run the\n            item as a "
                  f"real account.")
        print()
    print("  Proceed to the next item.")


if __name__ == "__main__":
    main()
