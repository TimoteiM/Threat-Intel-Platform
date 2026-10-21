"""Replay the five analyst-closed cases through the playbook and the loop.

**Read-only. Nothing is written back and nothing is delivered.** No row is
updated, no health is stamped, no narrative is generated, no case is touched.
The only writes anywhere are the token map the boundary keeps in memory,
which dies with the process.

**The population is Expertware's own estate** — `c00`, CID
`eed7e41845d04c26b4198f4c85f6216e`, 176 of 176 devices on an
`expertware.net` domain. See `docs/measurements/POPULATION.md`. That is why
this is the right first connector and why nothing here is a client result.

**The answer key is five cases and it is thin in a specific way.** Of 2,526
closed cases, five were closed by an analyst. Four are `false_positive` and
one is `inconclusive` — **there are no true positives**. So this measures
whether the loop agrees that nothing happened. It cannot measure whether the
loop finds something that did. Two of the five also have no analyst recorded
in `closed_by`, leaving three attributable to one person over two days.

Budget is deliberately low: these are real API calls against a real tenant.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.services import token_boundary as tb
from app.services.context_gathering import loop as gl
from app.services.context_gathering import playbook as pb
from app.services.context_gathering.falcon_source import FalconSource

TENANT = "c00"


def answer_key(conn) -> list[dict]:
    rows = conn.execute(text("""
        SELECT case_number, entity_host, session_started_at, last_activity_at,
               alerts_at_close, resolution, peak_score, closed_by
        FROM alert_case_spine
        WHERE closure_kind = 'analyst' AND tenant_id = :t
        ORDER BY case_number"""), {"t": TENANT}).fetchall()
    return [dict(r._mapping) for r in rows]


def alerts_of(conn, case: dict) -> list[dict]:
    """The case's alerts, reconstructed.

    Membership is **not stored** — `alert_case_spine` holds the overlay and
    `correlate_alerts` recomputes which alerts belong together on every read
    (`docs/problems/derived-case-membership.md`). `case_read_set` has no row
    for any of these five, so the reconstruction here is host plus session
    window, which is the same pair the case key is built from.

    That is an approximation and it is visible in the output: `reconstructed`
    is printed next to `alerts_at_close` so the two can disagree where they
    do.
    """
    rows = conn.execute(text("""
        SELECT id::text AS run_id, event_time,
               result_json->'alert_fields' AS fields,
               result_json AS result_json,
               entity_host, entity_user
        FROM alert_body_investigation_runs
        WHERE entity_host = :h AND event_time BETWEEN :a AND :b
        ORDER BY event_time"""),
        {"h": case["entity_host"], "a": case["session_started_at"],
         "b": case["last_activity_at"]}).fetchall()
    return [dict(r._mapping) for r in rows]


def selectors_from(result_json: dict, fields: dict, host: str,
                  user: str | None) -> dict[str, str]:
    """Real selector values for this alert. Tokenised inside `gather`.

    **The hash does not live in `alert_fields`.** The first version of this
    function looked there for `sha256`/`hash`/`file_hash` and found nothing,
    so every `hash_prevalence` template skipped with "no hash on this alert"
    — an absence produced by looking in the wrong place, which would have
    been reported as a property of the alerts.

    Measured: `alert_fields` carries agent, event_id, rule_id/name, manager,
    agent_ip, user and severities, and no indicator at all. The extracted
    indicators are in `indicator_reports[].indicator`, typed `ip`, `domain`
    or `hash` — 168 hash indicators across 300 sampled runs on the
    answer-key hosts.
    """
    out: dict[str, str] = {}
    if host:
        out["host"] = str(host)
    principal = user or (fields or {}).get("user")
    if principal:
        out["user"] = str(principal)
    for report in (result_json or {}).get("indicator_reports") or []:
        indicator = (report or {}).get("indicator")
        if not isinstance(indicator, dict):
            continue
        kind = str(indicator.get("type") or "")
        value = str(indicator.get("value") or "")
        if not value:
            continue
        # The first of each kind. A template takes one selector, and
        # "whichever hash came first" is a choice, so it is stated rather
        # than left to dict ordering downstream.
        if kind == "hash" and "hash" not in out:
            out["hash"] = value
        elif kind == "ip" and "ip" not in out:
            out["ip"] = value
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-queries", type=int, default=4,
                    help="per alert; these are real API calls")
    ap.add_argument("--alerts-per-case", type=int, default=2,
                    help="how many alerts of each case to replay")
    ap.add_argument("--dry-run", action="store_true",
                    help="plan only: no API calls, just what WOULD be asked")
    args = ap.parse_args()

    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        cases = answer_key(conn)
        print(f"answer key: {len(cases)} analyst-closed cases on {TENANT} "
              f"(Expertware's own estate)\n")
        resolutions = Counter(c["resolution"] for c in cases)
        print(f"  resolutions: {dict(resolutions)}")
        print(f"  attributable to a named analyst: "
              f"{sum(1 for c in cases if c['closed_by'])} of {len(cases)}")
        print(f"  true positives in the key: "
              f"{resolutions.get('true_positive', 0)}  <-- the limit of what "
              f"this can measure\n")

        registry = {
            pb.EDR: FalconSource(tenant_id=TENANT),
            # No SIEM source yet. The loop will record `check_failed` naming
            # the absent kind rather than reporting an empty SIEM answer.
            pb.SIEM: None,
        }
        registry = {k: v for k, v in registry.items() if v is not None}

        for case in cases:
            alerts = alerts_of(conn, case)
            classes = Counter(
                pb.event_class_of({"event_id": (a["fields"] or {}).get("event_id", "")})
                or "(none)" for a in alerts)
            print("=" * 74)
            print(f"CASE #{case['case_number']}  resolution={case['resolution']}  "
                  f"peak_score={case['peak_score']}  "
                  f"closed_by={case['closed_by'] or '(not recorded)'}")
            print(f"  alerts_at_close={case['alerts_at_close']}  "
                  f"reconstructed={len(alerts)}  classes={dict(classes.most_common(6))}")
            covered = [c for c in classes if c in pb.PLAYBOOK]
            print(f"  classes with a playbook row: {covered or 'NONE'}")

            for alert in alerts[: args.alerts_per_case]:
                fields = alert["fields"] or {}
                event_class = pb.event_class_of(fields) or "(none)"
                sel = selectors_from(alert["result_json"], fields,
                                     alert["entity_host"],
                                     alert["entity_user"])
                chosen, skipped = pb.templates_for(event_class, sel)
                print(f"\n    alert {alert['run_id'][:8]}  class={event_class:<6} "
                      f"selectors={sorted(sel)}")
                print(f"      would run : {[t.name for t in chosen]}")
                print(f"      skipped   : "
                      f"{[(s.get('template'), s.get('reason')) for s in skipped]}")
                if args.dry_run:
                    continue
                boundary = tb.in_memory(tenant_id=TENANT,
                                        investigation_id=f"replay-{alert['run_id']}")
                record = gl.gather(
                    tenant_id=TENANT,
                    investigation_id=f"replay-{alert['run_id']}",
                    alert_fields=fields,
                    selectors=sel,
                    registry=registry,
                    event_time=alert["event_time"],
                    boundary=boundary,
                    budget=gl.Budget(max_queries=args.max_queries),
                )
                js = record.as_json()
                print(f"      GATHERED  : {len(record.events)} event(s), "
                      f"{js['cost']['queries_run']} quer(ies), "
                      f"stop={js['cost']['stop_reason']}")
                for outcome in record.outcomes:
                    print(f"        {outcome.origin:8} {outcome.template:24} "
                          f"{outcome.status:12} kept={outcome.kept} "
                          f"{(outcome.reason or '')[:46]}")
                for note in record.notes:
                    print(f"        note: {note}")
            print()


if __name__ == "__main__":
    main()
