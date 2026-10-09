"""Dump one case's attack graph as JSON, so the model can be checked before
anything is rendered.

    python -m app.cli.case_graph 1440            # from the graph tables
    python -m app.cli.case_graph 1440 --live     # re-parse the alert bodies
    python -m app.cli.case_graph 1440 --json     # the graph itself

By default this reads the materialised tables, which is the path the page will
use. `--live` re-parses the bodies instead, and the two must agree: a stored
graph that merged differently from a freshly extracted one would let this CLI
pass the acceptance checks while the page quietly failed them.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

from sqlalchemy import text

from app.api.detections import CASE_LOOKUP_HOURS
from app.db.session import AsyncSessionLocal
from app.services import tenant_scope
from app.services.alert_correlation_service import case_by_key
from app.services.alert_graph_assembly_service import AlertEvidence, assemble
from app.services.alert_graph_extraction_service import extract
from app.services.alert_graph_store_service import graph_for_runs

# NO SQL OF ITS OWN.
#
# This file used to select a case's alerts with its own query — host plus the
# spine's window — and that is how it came to measure a path nobody was on.
# The endpoint resolves a case through `case_by_key` and hands the result to
# `graph_for_runs`; the CLI resolved it differently, so the CLI exercised the
# severity-ranked bound while the endpoint could never reach it (its input was
# capped at 100 and the bound triggers above 300). Eleven cases were re-run
# and timed through a path no user takes.
#
# So this command now calls exactly what the endpoint calls, and asserts that
# it does. A CLI that measures a parallel implementation is not a check on the
# system; it is a second system that happens to agree sometimes.
_SPINE = "select case_key, case_number from alert_case_spine where case_number = :number"


async def build(number: int, *, live: bool = False,
                hours: int = CASE_LOOKUP_HOURS) -> tuple[dict, float]:
    """Assemble a case graph through the endpoint's own call path.

    `assert_endpoint_path` below pins that this is the endpoint's path and not
    a reimplementation of it.
    """
    async with AsyncSessionLocal() as db:
        row = (await db.execute(text(_SPINE), {"number": number})).first()
        if row is None:
            raise SystemExit(f"No case #{number} in the spine.")
        case_key = row[0]

        # Exactly as app/api/detections.py:get_case_graph does it, including
        # the lifted member cap — without which the bound below cannot engage
        # and the graph draws the first 100 alerts of the case.
        case = await case_by_key(
            db, case_key, scope=tenant_scope.INTERNAL,
            hours=hours, max_members=100000,
        )
        if case is None:
            raise SystemExit(
                f"Case #{number} does not re-derive over {hours}h — the same "
                f"answer GET /api/detections/case/{{key}}/graph?hours={hours} "
                "gives. Pass --hours to widen it, as the case page does when "
                "the list was opened over a wider window."
            )
        run_ids = [a.get("run_id") for a in (case.get("alerts") or []) if a.get("run_id")]
        if live:
            started = time.perf_counter()
            evidence = []
            rows = (await db.execute(text(_RUNS), {"ids": [str(r) for r in run_ids]})).all()
            for run_id, rule_id, detection, when, body, score, assessment in rows:
                confirmed = [
                    t.get("id")
                    for t in ((assessment or {}).get("techniques") or [])
                    if isinstance(t, dict) and t.get("status") == "confirmed"
                ]
                evidence.append(
                    AlertEvidence(
                        run_id=str(run_id), rule_id=rule_id, detection=detection,
                        event_time=when, source_severity=None,
                        extracted=extract(body, risk_score=score,
                                          confirmed_techniques=confirmed),
                    )
                )
            graph = assemble(evidence)
            return graph, (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        graph = await graph_for_runs(db, run_ids)
        return graph, (time.perf_counter() - started) * 1000


_RUNS = """
select r.id, r.detection_rule_id, r.detection_name,
       coalesce(r.event_time, r.created_at), r.alert_body,
       r.indicator_risk_score, r.result_attack_assessment
from alert_body_investigation_runs r
where r.id::text = any(:ids)
order by coalesce(r.event_time, r.created_at)
"""


def assert_endpoint_path() -> None:
    """Fail if this command stops exercising the endpoint's own query.

    The guard exists because the previous version of this file had its own
    SQL, and the divergence was invisible: both produced a graph, both looked
    right, and only one was the path users take.
    """
    import inspect

    from app.api import detections

    endpoint = inspect.getsource(detections.get_case_graph)
    mine = inspect.getsource(build)
    for call in ("case_by_key(", "graph_for_runs(", "max_members=100000"):
        if call not in endpoint:
            raise SystemExit(
                f"The endpoint no longer calls {call!r}; this CLI is measuring "
                "something else. Update both together."
            )
        if call not in mine:
            raise SystemExit(
                f"This CLI no longer calls {call!r} while the endpoint does. "
                "A CLI that measures a parallel implementation is not a check "
                "on the system."
            )


def _checks(graph: dict) -> list[tuple[bool, str]]:
    """The six results case #1440 is supposed to produce."""
    nodes = graph["nodes"]
    by_kind = lambda k: [n for n in nodes if n["kind"] == k]
    label = lambda n: (n["label"] or "").lower()
    edges = graph["edges"]

    hosts = {label(n) for n in by_kind("host")}
    odsync = [n for n in nodes if "odsync.exe" in label(n)]
    into_odsync = {
        e["kind"] for e in edges
        if odsync and e["target"] == odsync[0]["id"]
    }
    ip = [n for n in by_kind("ip") if n["label"] == "185.220.101.47"]
    into_ip = {e["kind"] for e in edges if ip and e["target"] == ip[0]["id"]}
    pwsh = [
        n for n in by_kind("process")
        if label(n) == "powershell.exe" and n["attrs"].get("pid") == "6120"
    ]
    rules_on_pwsh = {
        w["rule_id"] for n in pwsh for w in n["witnesses"]
    }
    chain = {
        ("opened_file", "winword.exe", "invoice_aug.docm"),
        ("spawned", "winword.exe", "powershell.exe"),
        ("points_to", "onedrivesync", "odsync.exe"),
        ("opened_handle", "odsync.exe", "lsass.exe"),
        ("remote_exec_via", "ps.exe", "exp-dc-01"),
        ("created_service", "ps.exe", "updsvc"),
        ("service_binary", "updsvc", "odsvc.exe"),
    }
    ids = {n["id"]: label(n) for n in nodes}
    present = {
        (e["kind"], ids.get(e["source"], ""), ids.get(e["target"], ""))
        for e in edges
    }
    missing = chain - present

    return [
        ({"exp-fin-034", "exp-dc-01"} <= hosts,
         f"two hosts drawn: {sorted(hosts)}"),
        (not missing,
         "causal chain complete" if not missing else f"chain missing {sorted(missing)}"),
        (len(odsync) == 1 and {"points_to", "opened_handle"} <= into_odsync | {
            e["kind"] for e in edges if odsync and e["source"] == odsync[0]["id"]},
         f"odsync.exe is {len(odsync)} node(s), reached by {sorted(into_odsync)}"),
        (len(ip) == 1 and len(into_ip) >= 2,
         f"185.220.101.47 is {len(ip)} node(s), reached by {sorted(into_ip)}"
         + (" [reused infrastructure]" if ip and ip[0]["attrs"].get("reused_infrastructure") else "")),
        ({"100210", "92052"} <= rules_on_pwsh,
         f"PID 6120 carries rules {sorted(r for r in rules_on_pwsh if r)}"),
        (len(by_kind("technique")) >= 9,
         f"{len(by_kind('technique'))} ATT&CK techniques as nodes"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_number", type=int)
    parser.add_argument("--json", action="store_true", help="print the graph")
    parser.add_argument(
        "--hours", type=int, default=CASE_LOOKUP_HOURS,
        help="the lookback the endpoint would be called with (default "
             f"{CASE_LOOKUP_HOURS}, the endpoint's own default)",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="re-parse the alert bodies instead of reading the graph tables",
    )
    args = parser.parse_args()

    # Before measuring anything, prove this is the path the endpoint takes.
    assert_endpoint_path()
    graph, millis = asyncio.run(
        build(args.case_number, live=args.live, hours=args.hours)
    )
    if args.json:
        print(json.dumps(graph, indent=2, default=str))
        return 0

    source = "re-parsed" if args.live else "joined from tables"
    print(f"case #{args.case_number}: {len(graph['nodes'])} nodes, "
          f"{len(graph['edges'])} edges, {source} in {millis:.0f} ms")
    # Which entry point produced the number above. A timing without this is
    # not a measurement of the system — see the comment at the top of this
    # file and the 215-3,958 ms figures that described an unreachable path.
    coverage = graph.get("coverage") or {}
    print(f"  path    : case_by_key(hours={args.hours}, max_members=100000) -> "
          "graph_for_runs, as GET /api/detections/case/{key}/graph does")
    if coverage.get("alerts_dropped"):
        print(f"  coverage: read {coverage['alerts_read']} of "
              f"{coverage['alerts_read'] + coverage['alerts_dropped']} alerts, "
              f"{coverage.get('entity_rows_read')} entity rows")
    print(f"  by kind : {graph['counts']}")
    print(f"  attack  : {graph['attack']}")
    print(f"  integrity: {graph['integrity']}")
    print()
    ok = True
    for passed, description in _checks(graph):
        ok = ok and passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {description}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
