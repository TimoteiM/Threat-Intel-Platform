"""
Remove fabricated ANY.RUN threat labels from stored evidence, then re-decide.

Two collector defects put things in the evidence that ANY.RUN never said:

  1. Threat labels were scraped by substring-matching ANY.RUN's whole HTML
     report page. That page is a web application whose menus, filter lists and
     inline JS name every threat category it supports, so a generic word such as
     "phishing" matched on essentially every report — 99 of them here, 91 on
     tasks ANY.RUN had marked "No threats detected". The label then drove the
     verdict: reputation_component 0.90, final risk 72, "malicious".

  2. ANY.RUN forwards Suricata's informational tier in the same stream as real
     alerts. "INFO [ANY.RUN] Google Tag Manager analytics", classed literally
     "Not Suspicious Traffic", was counted as a network threat — and three of
     those were enough to corroborate the fabricated label.

The collector no longer produces either, but investigations already concluded
keep what they were given. This rewrites the stored ANY.RUN evidence to what the
fixed collector would have produced, then re-runs the decision engine over it.

Cleaning has to come first: the engine reads the label out of the evidence, so
re-deciding against uncleaned evidence just reproduces the same verdict.

What is removed is narrow on purpose. A generic label is deleted only where it
also appears in `html_threat_labels` — proof it came from the scraper. A label
ANY.RUN's API genuinely returned is real and is left alone; measured on this
corpus, of 103 records labelled phishing, 100 were scraped and 3 came from the
API, and all 3 of those were on non-clean verdicts.

    python -m scripts.backfill_anyrun_label_noise            # dry run
    python -m scripts.backfill_anyrun_label_noise --apply    # write
    python -m scripts.backfill_anyrun_label_noise --apply --limit 20
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from copy import deepcopy

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.db.session import sync_engine
from app.models.database import Evidence, Investigation, Report
from app.services.anyrun_service import (
    _GENERIC_LABEL_WORDS,
    _split_network_threats,
)
from app.services.decision_engine import build_decision_report

sync_engine.echo = False


def _scraped_generic_labels(raw: dict) -> set[str]:
    """
    The generic labels this record got from the HTML scraper.

    Membership in `html_threat_labels` is the evidence of provenance — without
    it we would be deleting labels ANY.RUN actually reported.
    """
    scraped = raw.get("html_threat_labels")
    if not isinstance(scraped, list):
        return set()
    return {
        str(label).strip().lower()
        for label in scraped
        if str(label).strip().lower() in _GENERIC_LABEL_WORDS
    }


def _strip_labels(values, drop: set[str]) -> tuple[list, int]:
    if not isinstance(values, list):
        return values, 0
    kept = [v for v in values if str(v).strip().lower() not in drop]
    return kept, len(values) - len(kept)


def _clean_anyrun_item(item: dict) -> dict[str, int]:
    """Rewrite one ANY.RUN evidence item in place; return what changed."""
    changed = Counter()
    raw = item.get("raw_summary")
    if not isinstance(raw, dict):
        return changed

    # ── 1. Fabricated labels ────────────────────────────────────────────────
    drop = _scraped_generic_labels(raw)
    if drop:
        for holder, key in ((raw, "html_threat_labels"), (raw, "threatName"),
                            (raw, "tags"), (item, "tags"), (item, "threat_names")):
            cleaned, removed = _strip_labels(holder.get(key), drop)
            if removed:
                holder[key] = cleaned
                changed["labels_removed"] += removed
        if changed["labels_removed"]:
            changed["items_relabelled"] += 1

    # ── 2. Informational Suricata events ────────────────────────────────────
    details = raw.get("behavior_details")
    if isinstance(details, dict) and isinstance(details.get("network_threats"), list):
        significant, informational = _split_network_threats(details["network_threats"])
        if informational:
            details["network_threats"] = significant
            details["network_informational_events"] = informational
            counts = raw.get("behavior_counts")
            if isinstance(counts, dict):
                counts["network_threats"] = len(significant)
                counts["network_informational_events"] = len(informational)
            changed["events_reclassified"] += len(informational)
            changed["items_reclassified"] += 1

    return changed


def _clean_evidence_row(evidence_json: dict) -> Counter:
    changed: Counter = Counter()
    items = ((evidence_json.get("hybrid_analysis") or {}).get("items"))
    if not isinstance(items, list):
        return changed
    for item in items:
        if not isinstance(item, dict):
            continue
        if (item.get("raw_summary") or {}).get("source") != "anyrun":
            continue
        changed.update(_clean_anyrun_item(item))
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    parser.add_argument("--limit", type=int, default=0, help="stop after N investigations")
    args = parser.parse_args()

    totals: Counter = Counter()
    verdict_moves: Counter = Counter()
    examples: list[str] = []

    with Session(sync_engine) as session:
        rows = session.execute(
            select(Investigation, Evidence)
            .join(Evidence, Evidence.investigation_id == Investigation.id)
        ).all()

        print(f"Scanning {len(rows)} investigations with evidence...", flush=True)

        for investigation, evidence in rows:
            if args.limit and totals["investigations_changed"] >= args.limit:
                break

            evidence_json = evidence.evidence_json or {}
            observable = investigation.observable_type or "domain"

            # Decide against the *uncleaned* evidence first. The stored verdict
            # was produced by an older engine, so comparing straight to it would
            # credit this fix with every unrelated rule change since. Only the
            # gap between these two decisions is attributable to the cleanup.
            pristine = deepcopy(evidence_json)
            try:
                drifted = build_decision_report(pristine, observable)
            except Exception as exc:
                print(f"  ! {investigation.domain}: {type(exc).__name__}: {exc}", file=sys.stderr)
                totals["decision_errors"] += 1
                continue

            changed = _clean_evidence_row(evidence_json)
            if not changed:
                continue

            totals.update(changed)
            totals["investigations_changed"] += 1

            before = investigation.classification
            try:
                decision = build_decision_report(evidence_json, observable)
            except Exception as exc:  # a single bad record must not stop the pass
                print(f"  ! {investigation.domain}: {type(exc).__name__}: {exc}", file=sys.stderr)
                totals["decision_errors"] += 1
                continue
            after = decision.get("classification")
            uncleaned = drifted.get("classification")

            if before != uncleaned:
                totals["drifted_without_cleanup"] += 1
            if uncleaned != after:
                totals["changed_by_cleanup"] += 1
                verdict_moves[f"{uncleaned} -> {after}"] += 1
                if len(examples) < 12:
                    examples.append(
                        f"  {investigation.domain[:52]:<52} {uncleaned} -> {after} "
                        f"({drifted.get('risk_score')} -> {decision.get('risk_score')})"
                    )

            if args.apply:
                # The cleaned evidence is always persisted: the fabricated label
                # and the misfiled events are wrong wherever they sit, and the
                # UI, reports and exports all read this blob.
                flag_modified(evidence, "evidence_json")

                # The verdict is only rewritten where the cleanup is what changed
                # it. Re-deciding the rest would quietly ship every unrelated
                # engine change made since those investigations ran — 63 records
                # here, including escalations this fix cannot explain. Those are
                # a separate decision, not a side effect of removing noise.
                if uncleaned != after:
                    investigation.classification = after
                    investigation.confidence = decision.get("confidence")
                    investigation.risk_score = decision.get("risk_score")
                    investigation.recommended_action = decision.get("recommended_action")

                    report = session.execute(
                        select(Report)
                        .where(Report.investigation_id == investigation.id)
                        .order_by(Report.created_at.desc())
                        .limit(1)
                    ).scalars().first()
                    if report is not None and isinstance(report.report_json, dict):
                        for field in ("classification", "confidence", "risk_score", "recommended_action"):
                            report.report_json[field] = decision.get(field)
                        flag_modified(report, "report_json")

        if args.apply:
            session.commit()

    print()
    print("=" * 72)
    print("DRY RUN — nothing written. Re-run with --apply." if not args.apply else "APPLIED")
    print("=" * 72)
    print(f"investigations with noise : {totals['investigations_changed']}")
    print(f"  verdict changed BY THIS FIX : {totals['changed_by_cleanup']}")
    print(f"  evidence cleaned (all)      : {totals['investigations_changed']}")
    print(f"  already drifted from stored : {totals['drifted_without_cleanup']}")
    print("      ^ unrelated engine changes since those runs. Their verdicts are")
    print("        left exactly as stored — this script only rewrites a verdict")
    print("        when removing the noise is what changed it.")
    print(f"fabricated labels removed: {totals['labels_removed']} across {totals['items_relabelled']} sandbox records")
    print(f"events reclassified      : {totals['events_reclassified']} across {totals['items_reclassified']} sandbox records")
    print()
    if verdict_moves:
        print("verdict changes:")
        for move, count in verdict_moves.most_common():
            print(f"  {move:<28} {count}")
        print()
        print("examples:")
        for line in examples:
            print(line)
    else:
        print("no verdict changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
