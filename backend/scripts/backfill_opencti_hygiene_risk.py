"""
Recompute stored risk for observables OpenCTI labelled `hygiene`.

The aggregator used to score OpenCTI's warning-list matches and could floor
their risk at 70, so known-good infrastructure carried a high composite risk it
never earned. The collectors no longer do this; concluded investigations keep
the number they were given.

Only `final_risk` is rewritten, and only where the recomputed value differs.
The classification label is deliberately left alone: it comes from the analyst
and the report decision, not from this component, so changing it here would be
inventing a verdict rather than correcting a calculation. Runs that need a new
label need a real re-decide.

    python -m scripts.backfill_opencti_hygiene_risk            # dry run
    python -m scripts.backfill_opencti_hygiene_risk --apply
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.db.session import sync_engine
from app.models.database import Evidence, Investigation
from app.services.opencti_hygiene import is_hygiene_match
from app.services.risk_aggregator import aggregate_risk

sync_engine.echo = False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = parser.parse_args()

    changed = 0
    with Session(sync_engine) as session:
        rows = session.execute(
            select(Investigation, Evidence).join(Evidence, Evidence.investigation_id == Investigation.id)
        ).all()

        for investigation, evidence in rows:
            data = evidence.evidence_json or {}
            if not is_hygiene_match(data.get("opencti")):
                continue

            before = (data.get("final_risk") or {}).get("composite_risk_score")
            recomputed = aggregate_risk(dict(data))
            after = recomputed.get("risk_score")
            if before == after:
                continue

            print(
                f"  {str(investigation.domain)[:44]:44} composite {before} -> {after}"
                f"   (label stays {investigation.classification})"
            )
            changed += 1

            if args.apply:
                final_risk = dict(data.get("final_risk") or {})
                final_risk.update(recomputed)
                final_risk["composite_risk_score"] = after
                final_risk["composite_risk_level"] = recomputed.get("risk_level")
                data["final_risk"] = final_risk
                evidence.evidence_json = data
                flag_modified(evidence, "evidence_json")

        if args.apply:
            session.commit()

    print()
    print("DRY RUN — nothing written." if not args.apply else "APPLIED")
    print(f"investigations rescored: {changed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
