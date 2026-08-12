"""
Pre-render the report PDF for investigations that concluded before the cache existed.

New investigations get their PDF rendered by the worker as they finish, so Export
is a file download. Everything already in the database predates that and still
pays the full render — 16 seconds on a report with long tokenised URLs — on the
first click. This renders them ahead of time so no analyst ever waits.

Nothing here changes an investigation. It reads evidence and the latest report,
renders, and writes one artifact per investigation, keyed on the same fingerprint
the API checks. A run that is already cached and current is skipped, so this is
safe to re-run and cheap the second time.

    python -m scripts.backfill_report_pdfs                  # dry run — what would render
    python -m scripts.backfill_report_pdfs --apply          # render and store
    python -m scripts.backfill_report_pdfs --apply --limit 20
    python -m scripts.backfill_report_pdfs --apply --newest-first

Rendering is CPU-bound and single-threaded here on purpose: this runs against a
live platform, and saturating the box to save a few minutes is a bad trade.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import sync_engine
from app.models.database import Artifact, Evidence, Investigation, Report
from app.services.provider_branding import normalize_anyrun_branding
from app.services.report_pdf_cache import (
    ARTIFACT_NAME,
    pdf_fingerprint,
    render_and_store_sync,
)

logger = logging.getLogger("backfill_report_pdfs")


def _detail_dict(inv: Investigation) -> dict:
    """
    Field for field what `app/api/export.py` builds.

    The fingerprint is computed from this, so a dict that differs anywhere
    produces a file the API will never recognise as current — it would re-render
    on first export and the backfill would have achieved nothing.
    """
    return {
        "id": str(inv.id),
        "domain": inv.domain,
        "observable_type": getattr(inv, "observable_type", "domain"),
        "state": inv.state,
        "classification": inv.classification,
        "confidence": inv.confidence,
        "risk_score": inv.risk_score,
        "recommended_action": inv.recommended_action,
        "client_domain": inv.client_domain,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
        "concluded_at": inv.concluded_at.isoformat() if inv.concluded_at else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="render and store; otherwise dry run")
    parser.add_argument("--limit", type=int, default=0, help="stop after this many renders")
    parser.add_argument(
        "--newest-first",
        action="store_true",
        help="render recent investigations first — the ones most likely to be opened",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # The shared engine is built with echo=True, which prints every statement
    # and buries the progress lines this script exists to show. Turning it off
    # on the engine itself is the only thing that works — the echo handler is
    # attached at engine construction, so a logger level set afterwards is
    # ignored.
    sync_engine.echo = False
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    # WeasyPrint logs a line per page at INFO — 400 reports of that drowns
    # everything else in the log.
    logging.getLogger("weasyprint").setLevel(logging.ERROR)
    logging.getLogger("fontTools").setLevel(logging.ERROR)

    with Session(sync_engine) as session:
        order = Investigation.created_at.desc() if args.newest_first else Investigation.created_at.asc()
        investigations = session.execute(select(Investigation).order_by(order)).scalars().all()

        cached = {
            row.investigation_id: row.sha256_hash
            for row in session.execute(
                select(Artifact).where(Artifact.artifact_name == ARTIFACT_NAME)
            ).scalars()
        }

        pending: list[tuple[Investigation, dict, dict]] = []
        no_report = 0

        for inv in investigations:
            evidence = session.execute(
                select(Evidence).where(Evidence.investigation_id == inv.id)
            ).scalar_one_or_none()
            report = session.execute(
                select(Report)
                .where(Report.investigation_id == inv.id)
                .order_by(Report.created_at.desc())
            ).scalars().first()

            # No evidence and no report renders an empty shell nobody wants.
            if evidence is None and report is None:
                no_report += 1
                continue

            evidence_json = evidence.evidence_json if evidence else {}
            report_json = normalize_anyrun_branding(report.report_json) if report else {}
            detail = _detail_dict(inv)

            if cached.get(inv.id) == pdf_fingerprint(evidence_json, report_json, detail):
                continue
            pending.append((inv, evidence_json, report_json))

        total = len(pending)
        print(f"{len(investigations)} investigations")
        print(f"  {len(investigations) - total - no_report} already cached and current")
        print(f"  {no_report} skipped — no evidence or report to render")
        print(f"  {total} to render")

        if not total:
            return 0

        # Measured on this data: ~5s average, 16s worst case on a report
        # carrying long tokenised URLs.
        print(f"\nEstimated time: {total * 5 / 60:.0f}–{total * 8 / 60:.0f} minutes, one at a time.")

        if not args.apply:
            print("\nDry run. Re-run with --apply to render.")
            for inv, _, _ in pending[:10]:
                print(f"  would render  {inv.domain}")
            if total > 10:
                print(f"  … and {total - 10} more")
            return 0

        rendered = failed = 0
        started = time.perf_counter()

        for index, (inv, evidence_json, report_json) in enumerate(pending, start=1):
            if args.limit and rendered >= args.limit:
                print(f"\nStopping at --limit {args.limit}.")
                break

            began = time.perf_counter()
            ok = render_and_store_sync(
                session, str(inv.id), evidence_json, report_json, _detail_dict(inv)
            )
            took = time.perf_counter() - began
            if ok:
                rendered += 1
                print(f"[{index}/{total}] {inv.domain[:48]:<48} {took:5.1f}s", flush=True)
            else:
                failed += 1
                # render_and_store_sync logs the reason; a failure here is not
                # fatal — the API still renders that one on demand.
                print(f"[{index}/{total}] {inv.domain[:48]:<48} FAILED", flush=True)

        elapsed = time.perf_counter() - started
        print(f"\n{rendered} rendered, {failed} failed, in {elapsed / 60:.1f} minutes.")
        if failed:
            print("Failed investigations still export correctly — they render on demand.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
