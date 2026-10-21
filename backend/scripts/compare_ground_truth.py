"""Compare what the loop gathered against what we know we did.

Written **before** the exercise, deliberately. A comparison written after the
results exist is a comparison shaped by them — the same reason the protocol
insists its own notes are authored before execution.

Reads two things that are produced independently:

1. `protocol.json` — what the operator did, authored before and during the
   exercise, living under `~/evidence/` where nothing in `backend/` reads it
   except this script, by hand, after the replay has already run;
2. the platform's own records — alerts, their classes, their selectors, and
   what the gathering loop retrieved.

**Five columns per item, and no aggregation.** Four exercises is not a rate,
so this prints a row per item and refuses to summarise them into a
proportion. The fifth column is the one five historical false positives
cannot provide: what the loop failed to gather that we know happened.

**Items that produced no alert are reported as detection coverage, not loop
misses.** If nothing fired, nothing downstream means anything, and calling
that a gathering failure would blame the loop for a detection gap. The
replay is run only on items that alerted.

Read-only. Nothing is written back.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.services.context_gathering import playbook as pb

#: How far after `finished_utc` an alert may arrive and still be attributed.
#: Stated rather than assumed: the pipeline queues, and an alert that lands
#: two minutes later is the same event. Anything beyond this is not
#: attributable and is reported as such rather than counted.
ATTRIBUTION_GRACE = timedelta(minutes=20)


def load_protocol(path: pathlib.Path) -> list[dict]:
    """The operator's notes. Validated, because a silent miss here would be
    read as the loop's fault."""
    data = json.loads(path.read_text())
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise SystemExit(f"{path}: no `items` list found")
    required = ("item", "host", "account", "command",
                "started_utc", "finished_utc", "expected_class")
    for entry in items:
        # An item recorded as `untested` is a gap that was written down, and
        # it needs none of the execution fields. Dropping such an item from
        # the file instead would make a missing class look like a clean
        # result — the 1102 row has no other coverage.
        if str(entry.get("status") or "").lower() == "untested":
            continue
        missing = [f for f in required if not entry.get(f)]
        if missing:
            raise SystemExit(
                f"{path}: item {entry.get('item', '?')} is missing {missing}. "
                f"The protocol asks for these because the comparison cannot "
                f"infer them — an absent `account` in particular, since "
                f"running as SYSTEM makes the user-side templates unfirable."
            )
    return items


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def alerts_for(conn, item: dict) -> list[dict]:
    rows = conn.execute(text("""
        SELECT id::text AS run_id, event_time,
               result_json->'alert_fields' AS fields,
               result_json AS result_json,
               entity_host, entity_user
        FROM alert_body_investigation_runs
        WHERE lower(entity_host) = lower(:host)
          AND event_time BETWEEN :lo AND :hi
        ORDER BY event_time"""),
        {"host": item["host"],
         "lo": _utc(item["started_utc"]),
         "hi": _utc(item["finished_utc"]) + ATTRIBUTION_GRACE}).fetchall()
    return [dict(r._mapping) for r in rows]


def selectors_present(result_json: dict, fields: dict,
                      host: str, user: str | None) -> dict[str, str]:
    """The same extraction the replay uses, including the hash location.

    `alert_fields` carries no indicator; hashes live in
    `indicator_reports[].indicator`. Duplicated deliberately rather than
    imported: if the replay's extraction changes, this comparison should
    disagree with it loudly instead of inheriting the change silently.
    """
    out: dict[str, str] = {}
    if host:
        out["host"] = host
    principal = user or (fields or {}).get("user")
    if principal:
        out["user"] = str(principal)
    for report in (result_json or {}).get("indicator_reports") or []:
        indicator = (report or {}).get("indicator")
        if not isinstance(indicator, dict):
            continue
        kind, value = str(indicator.get("type") or ""), str(indicator.get("value") or "")
        if value and kind == "hash" and "hash" not in out:
            out["hash"] = value
        elif value and kind == "ip" and "ip" not in out:
            out["ip"] = value
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("protocol", type=pathlib.Path,
                    help="path to protocol.json under ~/evidence/")
    args = ap.parse_args()

    items = load_protocol(args.protocol)
    engine = create_engine(get_settings().database_sync_url)

    alerted: list[dict] = []
    not_alerted: list[dict] = []
    untested: list[dict] = []

    with engine.connect() as conn:
        for item in items:
            if str(item.get("status") or "").lower() == "untested":
                print("=" * 76)
                print(f"ITEM {item.get('item')}  expected class "
                      f"{item.get('expected_class')}  — UNTESTED")
                print(f"  reason: {item.get('reason') or '(none recorded)'}")
                print(f"\n  Not a result and not a miss. This class has no "
                      f"coverage from this exercise,\n  which is a gap in the "
                      f"exercise rather than a finding about the loop.\n")
                untested.append(item)
                continue
            runs = alerts_for(conn, item)
            print("=" * 76)
            print(f"ITEM {item['item']}  expected class {item['expected_class']}  "
                  f"host {item['host']}")
            print(f"  ran as   : {item['account']}")
            print(f"  command  : {item['command']}")
            print(f"  window   : {item['started_utc']} .. {item['finished_utc']} "
                  f"(+{int(ATTRIBUTION_GRACE.total_seconds() // 60)}m grace)")

            # ── column 1: alerted ──
            if not runs:
                not_alerted.append(item)
                print(f"\n  1 ALERTED    : NO")
                print(f"  2 CLASS      : n/a")
                print(f"  3 SELECTORS  : n/a")
                print(f"  4 TEMPLATES  : n/a")
                print(f"  5 MISSED     : n/a — nothing fired, so the loop was "
                      f"never given anything")
                print(f"\n  --> DETECTION COVERAGE, not a loop miss. No rule "
                      f"produced an alert for this\n      activity on this host. "
                      f"That is a finding about the ruleset.")
                print()
                continue

            alerted.append(item)
            print(f"\n  1 ALERTED    : YES — {len(runs)} alert(s) in the window")

            # ── column 2: class ──
            classes = []
            for run in runs:
                cls = pb.event_class_of(run["fields"] or {}) or "(none)"
                classes.append(cls)
            expected = str(item["expected_class"])
            matched = [c for c in classes if c == expected]
            print(f"  2 CLASS      : expected {expected!r} / observed "
                  f"{sorted(set(classes))}")
            if not matched:
                print(f"               -> MISMATCH. The playbook row that would "
                      f"have run is not the row that ran.")

            # ── column 3: selectors ──
            for run in runs[:3]:
                sel = selectors_present(run["result_json"], run["fields"] or {},
                                        run["entity_host"], run["entity_user"])
                cls = pb.event_class_of(run["fields"] or {}) or "(none)"
                chosen, skipped = pb.templates_for(cls, sel)
                print(f"  3 SELECTORS  : run {run['run_id'][:8]} class={cls} "
                      f"-> {sorted(sel)}")
                # ── column 4: templates ──
                print(f"  4 TEMPLATES  : would run {[t.name for t in chosen]}")
                for skip in skipped:
                    print(f"               skipped {skip.get('template')}: "
                          f"{skip.get('reason')}")

            # ── column 5: missed ──
            print(f"  5 MISSED     : fill from the replay record — the artefact "
                  f"the command named,\n               the account that ran it, "
                  f"the host state at the time. Compare against\n"
                  f"               the replay's own output for these run ids.")
            print()

    print("=" * 76)
    print("WHAT TO REPLAY")
    print("=" * 76)
    print(f"  items that alerted      : {[i['item'] for i in alerted]}")
    print(f"  items that did NOT      : {[i['item'] for i in not_alerted]}")
    print(f"  items UNTESTED          : {[i['item'] for i in untested]}")
    print()
    if not_alerted:
        print("  The non-firing items are DETECTION COVERAGE findings. Do not")
        print("  replay them and do not count them as loop misses: the loop was")
        print("  never handed an alert for them.")
    print()
    print("  **No aggregate is printed, deliberately.** Four exercises is not a")
    print("  rate, and a '3 of 4' line would be a proportion of a sample of")
    print("  four. Read the rows.")


if __name__ == "__main__":
    main()
