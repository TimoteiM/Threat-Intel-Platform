"""
Recompute stored verdicts from stored evidence.

The decision engine changed: signals that are true of most legitimate sites
(shared hosting, missing SPF/DMARC) no longer create suspicion on their own, a
registrant pivot must reach another domain, the benign path is reachable for a
site with a login page, and a score must sit inside its own label's band.

Concluded investigations keep whatever verdict they were given at the time, so
this script re-runs the engine over their evidence and writes back the canonical
decision fields — the investigation row, the latest report, and `final_risk` —
leaving every narrative the analyst wrote untouched.

    python -m scripts.backfill_decision_verdicts            # dry run
    python -m scripts.backfill_decision_verdicts --apply    # write
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

import logging

from app.db.session import sync_engine
from app.models.database import Evidence, Investigation, Report
from app.services.decision_engine import build_decision_report

RECOMPUTE_NOTE = "Verdict recomputed by the corroboration-rules update"


def _fixed_by_corroboration_rules(evidence: dict, before: str | None, after: str) -> bool:
    """
    Whether this verdict changed *because* of the corroboration rules.

    The signature of the bug: an established domain that nothing ever flagged,
    marked suspicious purely by observations that describe most of the legitimate
    web — shared hosting, a missing DMARC record, a registrant pivot that reached
    only itself — or by having a login page, which used to make the benign path
    unreachable no matter how clean everything else was.
    """
    if before != "suspicious" or after != "benign":
        return False

    vt = evidence.get("vt") or {}
    feeds = evidence.get("threat_feeds") or {}
    http = evidence.get("http") or {}
    infra = evidence.get("infrastructure_pivot") or {}
    whois = evidence.get("whois") or {}

    nothing_flagged_it = (
        int(vt.get("malicious_count") or 0) == 0
        and int(vt.get("suspicious_count") or 0) == 0
        and not feeds.get("openphish_listed")
        and not (feeds.get("phishtank") or {}).get("in_database")
        and not (feeds.get("threatfox_matches") or [])
        and not ((evidence.get("intel") or {}).get("blocklist_hits") or [])
    )
    if not nothing_flagged_it:
        return False

    # The clean path's own bar: a domain too young to have a track record is a
    # judgement call, not a false positive this change is entitled to overturn.
    if int(whois.get("domain_age_days") or 0) < 365:
        return False

    self_pivot = any(
        isinstance(pivot, dict)
        and not (
            {str(d).strip().lower() for d in (pivot.get("domains") or [])}
            - {
                str(evidence.get(key) or "").strip().lower()
                for key in ("domain", "target_domain", "observable")
            }
        )
        for pivot in (infra.get("registrant_pivots") or [])
    )
    return bool(
        infra.get("shared_hosting_detected")
        or str((evidence.get("email_security") or {}).get("spoofability_score") or "").lower() == "high"
        or self_pivot
        or http.get("has_login_form")
    )


def main() -> int:
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write the changes (default: dry run)")
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "re-adjudicate every concluded investigation with today's engine. The engine has "
            "moved on in more ways than the corroboration rules, so this also rewrites verdicts "
            "the analyst reached — including malicious ones. Off by default on purpose."
        ),
    )
    parser.add_argument("--backup", default="", help="where to write the previous values as JSON")
    args = parser.parse_args()

    changes: list[dict] = []
    transitions: Counter = Counter()
    skipped: Counter = Counter()

    with Session(sync_engine) as db:
        rows = db.execute(
            select(Investigation, Evidence)
            .join(Evidence, Evidence.investigation_id == Investigation.id)
            .where(Investigation.state == "concluded")
        ).all()

        for investigation, evidence in rows:
            try:
                decision = build_decision_report(
                    evidence.evidence_json or {}, investigation.observable_type or "domain"
                )
            except Exception as exc:  # a single bad record must not stop the pass
                print(f"  ! {investigation.domain}: {type(exc).__name__}: {exc}", file=sys.stderr)
                continue

            before = (investigation.classification, investigation.risk_score)
            after = (decision["classification"], decision["risk_score"])
            transitions[(before[0], after[0])] += 1
            if before == after:
                continue

            # Default scope: records these corroboration rules are responsible
            # for. Today's engine disagrees with plenty of old verdicts for other
            # reasons — a young domain, a sandbox result that arrived later — and
            # rewriting those would be re-adjudicating history, not fixing a bug.
            if not args.all and not _fixed_by_corroboration_rules(
                evidence.evidence_json or {}, before[0], after[0]
            ):
                skipped[(before[0], after[0])] += 1
                continue

            changes.append(
                {
                    "investigation_id": str(investigation.id),
                    "domain": investigation.domain,
                    "before": {
                        "classification": investigation.classification,
                        "risk_score": investigation.risk_score,
                        "confidence": investigation.confidence,
                        "recommended_action": investigation.recommended_action,
                    },
                    "after": {
                        "classification": decision["classification"],
                        "risk_score": decision["risk_score"],
                        "confidence": decision["confidence"],
                        "recommended_action": decision["recommended_action"],
                    },
                }
            )

            if not args.apply:
                continue

            investigation.classification = decision["classification"]
            investigation.risk_score = decision["risk_score"]
            investigation.confidence = decision["confidence"]
            investigation.recommended_action = decision["recommended_action"]

            report = db.execute(
                select(Report)
                .where(Report.investigation_id == investigation.id)
                .order_by(Report.iteration.desc(), Report.created_at.desc())
                .limit(1)
            ).scalars().first()
            if report is not None:
                payload = dict(report.report_json or {})
                payload.update(
                    {
                        "classification": decision["classification"],
                        "risk_score": decision["risk_score"],
                        "confidence": decision["confidence"],
                        "recommended_action": decision["recommended_action"],
                    }
                )
                rationale = str(payload.get("risk_rationale") or "").strip()
                stamp = datetime.now(timezone.utc).date().isoformat()
                note = f"{RECOMPUTE_NOTE} on {stamp}: was {before[0]} {before[1]}/100."
                if RECOMPUTE_NOTE not in rationale:
                    payload["risk_rationale"] = f"{rationale} {note}".strip()
                report.report_json = payload

            blob = dict(evidence.evidence_json or {})
            final_risk = dict(blob.get("final_risk") or {})
            if final_risk:
                final_risk["risk_score"] = decision["risk_score"]
                final_risk["risk_level"] = (
                    "high" if decision["risk_score"] >= 70
                    else "medium" if decision["risk_score"] >= 35
                    else "low"
                )
                blob["final_risk"] = final_risk
                evidence.evidence_json = blob

        if args.apply:
            db.commit()

    scope = "every classification change" if args.all else "only what the corroboration rules changed"
    print(f"{'APPLIED' if args.apply else 'DRY RUN'} — {len(changes)} record(s) rewritten "
          f"of {sum(transitions.values())} concluded ({scope})\n")
    for (was, now), count in sorted(transitions.items(), key=lambda kv: -kv[1]):
        mark = "" if was == now else ("   ← rewritten" if (args.all or (was == "suspicious" and now == "benign")) else "   ← left alone")
        print(f"   {str(was):>13} → {str(now):<13} {count:>4}{mark}")
    if skipped:
        print(f"\n{sum(skipped.values())} differing verdict(s) left untouched — today's engine "
              "disagrees with them for reasons beyond these rules; re-run those investigations "
              "individually if you want them re-adjudicated.")

    if args.backup and changes:
        Path(args.backup).write_text(json.dumps(changes, indent=2), encoding="utf-8")
        print(f"\nprevious values written to {args.backup}")

    print("\nsample:")
    for change in changes[:12]:
        b, a = change["before"], change["after"]
        print(f"   {change['domain'][:46]:48} {b['classification']} {b['risk_score']} → {a['classification']} {a['risk_score']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
