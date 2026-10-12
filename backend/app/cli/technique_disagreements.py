"""Alerts where the rule and the evidence name different techniques.

    python -m app.cli.technique_disagreements

Detection-engineering feedback, not noise. A model reading the telemetry
concluding T1036 (Masquerading) while the rule claims T1129 (Shared Modules)
means one of them is wrong, and keeping only the rule's answer guarantees a
wrong mapping stays wrong for ever.

Measured on `alert_body_investigation_runs.result_attack_assessment`, which is
the right table because it is where both namers' output is stored side by side.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter

from sqlalchemy import text

from app.db.session import AsyncSessionLocal
from app.analyst.attack_mapping import parent_technique
from app.services.technique_attribution_service import attribute
from app.services.technique_naming_service import name_technique


def _named(ids) -> str:
    """`T1059.001 (PowerShell)`, with retirement stated where it applies.

    The same resolver the graph, the panel and the exports read, so an id
    cannot be named one thing here and another there. A bare id in a terminal
    is the same problem as a bare id on a node: the reader has to go and look
    it up, and most do not.
    """
    out = []
    for tid in ids:
        found = name_technique(tid)
        name = found.get("name")
        if not isinstance(name, str):
            # Not in the catalogue. Printed as recorded, never guessed.
            out.append(f"{tid} (not in ATT&CK {found.get('attack_version')})")
            continue
        label = f"{tid} ({found.get('short_name') or name})"
        if found.get("retired"):
            label += f" [retired, now {found.get('current_equivalent')}]"
        out.append(label)
    return ", ".join(out)


async def run(limit: int, include_test: bool) -> None:
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                text(
                    "select id, lower(split_part(entity_host, '.', 1)) as host, "
                    "detection_rule_id, detection_name, "
                    "result_attack_assessment as a "
                    "from alert_body_investigation_runs "
                    "where result_attack_assessment is not null"
                )
            )
        ).all()
        from app.services.asset_criticality_service import test_hosts

        rigs = set() if include_test else await test_hosts(db)

    pairs: Counter = Counter()
    parent_level = 0
    runs_conflict = 0
    refined = 0
    refinements: Counter = Counter()
    by_rule: Counter = Counter()
    runs = 0
    for row in rows:
        host = row.host or ""
        if host in rigs:
            continue
        found = attribute(row.a)
        if not found.disagreement:
            continue
        runs += 1
        claimed, supported = found.disagreement
        # Agreement at the parent is not a conflict, and within it a
        # refinement is not the same statement as a plain agreement. A rule
        # claiming T1071 while the telemetry supports T1071.001 agrees about
        # Application Layer Protocol and the telemetry has made it *more
        # precise* — 193 of the 202, which is evidence the model's attribution
        # is competent at sub-technique depth and therefore that the genuine
        # conflicts are harder to dismiss as noise.
        shared = {parent_technique(t) for t in claimed} & {
            parent_technique(t) for t in supported
        }
        if shared:
            rule_depth = {t for t in claimed if parent_technique(t) in shared}
            model_depth = {t for t in supported if parent_technique(t) in shared}
            if any("." in t for t in model_depth) and not any(
                "." in t for t in rule_depth
            ):
                refined += 1
                refinements[(tuple(sorted(rule_depth)), tuple(sorted(model_depth)))] += 1
            else:
                parent_level += 1
            continue
        # One alert, one entry. Counting pairs turned a rule that asserts five
        # techniques into five disagreements for a single alert.
        runs_conflict += 1
        pairs[(claimed, supported)] += 1
        by_rule[(row.detection_rule_id, row.detection_name, claimed, supported)] += 1

    scope = "including test hosts" if include_test else f"excluding {len(rigs)} test host(s)"
    print(f"alerts where the rule and the evidence name different techniques: "
          f"{runs}  ({scope})")
    print(f"  the telemetry REFINED the rule (same parent, model more specific): {refined}")
    print(f"  otherwise agreeing at the parent technique:                        {parent_level}")
    print(f"  GENUINE CONFLICTS — this is the list to work through:              {runs_conflict}")
    if refinements:
        print("\n  refinements, commonest first — the rule is right and the "
              "telemetry made it precise:")
        for (r_ids, m_ids), n in refinements.most_common(6):
            print(f"    {n:5d} alerts  {_named(r_ids)} -> {_named(m_ids)}")
    from app.analyst.attack_reference import ATTACK_VERSION

    print(f"\nnames and retirement status from MITRE ATT&CK Enterprise "
          f"{ATTACK_VERSION}. 'retired' is a fact about the id in this "
          "release, not a judgement on the rule: a detection that mapped to "
          "an id mapped correctly for the ATT&CK of its day.")
    print("\nby what each side named (one row = one shape of disagreement):")
    for (claimed, supported), n in pairs.most_common(limit):
        print(f"  {n:5d} alerts")
        print(f"          rule claims       {_named(claimed)}")
        print(f"          evidence supports {_named(supported)}")
    print("\nby detection rule — this is the list to work through:")
    for (rule_id, name, claimed, supported), n in by_rule.most_common(limit):
        print(f"  {n:5d} alerts  rule {str(rule_id):8s} {str(name)[:46]}")
        print(f"          claims   {_named(claimed)}")
        print(f"          evidence {_named(supported)}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--include-test", action="store_true")
    args = ap.parse_args()
    asyncio.run(run(args.limit, args.include_test))


if __name__ == "__main__":
    main()
