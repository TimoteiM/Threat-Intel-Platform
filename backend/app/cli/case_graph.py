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

from app.db.session import AsyncSessionLocal
from app.services.alert_graph_assembly_service import AlertEvidence, assemble
from app.services.alert_graph_extraction_service import extract
from app.services.alert_graph_store_service import graph_for_runs

# The case's alerts. Membership is derived from event time elsewhere; here the
# spine's own window is enough and keeps the CLI independent of correlation.
_ALERTS = """
select r.id::text, r.detection_rule_id, r.detection_name,
       coalesce(r.event_time, r.created_at), r.alert_body,
       r.indicator_risk_score, r.result_attack_assessment
from alert_body_investigation_runs r
join alert_case_spine s on s.case_number = :number
where r.entity_host = s.entity_host
  and coalesce(r.event_time, r.created_at) >= s.opened_at
  and coalesce(r.event_time, r.created_at) <= coalesce(s.closed_at, s.last_activity_at)
order by coalesce(r.event_time, r.created_at)
"""


async def build(number: int, *, live: bool = False) -> tuple[dict, float]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text(_ALERTS), {"number": number})).all()
        if not rows:
            raise SystemExit(f"No alerts found for case #{number}.")
        if not live:
            # The join: two indexed selects, no body read and no regex run.
            started = time.perf_counter()
            graph = await graph_for_runs(db, [r[0] for r in rows])
            return graph, (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    evidence = []
    for run_id, rule_id, detection, when, body, level, assessment in rows:
        confirmed = [
            t.get("id")
            for t in ((assessment or {}).get("techniques") or [])
            if isinstance(t, dict) and t.get("status") == "confirmed"
        ]
        evidence.append(
            AlertEvidence(
                run_id=run_id, rule_id=rule_id, detection=detection,
                event_time=when, rule_level=level,
                extracted=extract(body, risk_score=level, confirmed_techniques=confirmed),
            )
        )
    graph = assemble(evidence)
    return graph, (time.perf_counter() - started) * 1000


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
        "--live", action="store_true",
        help="re-parse the alert bodies instead of reading the graph tables",
    )
    args = parser.parse_args()

    graph, millis = asyncio.run(build(args.case_number, live=args.live))
    if args.json:
        print(json.dumps(graph, indent=2, default=str))
        return 0

    source = "re-parsed" if args.live else "joined from tables"
    print(f"case #{args.case_number}: {len(graph['nodes'])} nodes, "
          f"{len(graph['edges'])} edges, {source} in {millis:.0f} ms")
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
