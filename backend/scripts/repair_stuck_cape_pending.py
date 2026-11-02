"""Resolve investigations stuck on a CAPE detonation that already finished.

The CAPE collector attaches to an analysis already in flight for the same
target rather than detonating twice. The completion path then wrote the result
back to `SandboxAnalysis.investigation_id` **only** — so a second investigation
that attached kept a `cape.pending` pointer to an analysis that had finished
and belonged to someone else, and nothing ever cleared it:
`resume_sandbox_analyses` resumes non-terminal rows, and a reported analysis is
terminal.

`cape_task` now fans completion out to every referrer. That fixes the next one.
This fixes the ones already stuck, which no future completion will revisit.

The report is **re-fetched from CAPE and re-normalised**, not reconstructed
from the stored summary: `_store_cape_evidence` takes a normalised report
object, and inventing one from a JSON column would put evidence in an
investigation that never came from the sandbox.

Read-only unless `--apply`.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text  # noqa: E402

from app.config import get_settings  # noqa: E402

STUCK_SQL = """
    SELECT i.id::text          AS investigation_id,
           left(i.domain, 60)  AS observable,
           i.state             AS state,
           sa.id::text         AS analysis_id,
           sa.investigation_id::text AS owner_id,
           sa.status           AS analysis_status,
           sa.provider_task_id AS task_id
      FROM evidence e
      JOIN investigations i  ON i.id = e.investigation_id
      JOIN sandbox_analyses sa
        ON sa.id::text = e.evidence_json->'cape'->>'pending_analysis_id'
     WHERE e.evidence_json->'cape'->>'pending' = 'true'
       AND sa.status IN ('reported', 'failed', 'timed_out')
       AND sa.investigation_id IS DISTINCT FROM i.id
     ORDER BY i.created_at
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    engine = create_engine(get_settings().database_sync_url)
    with engine.connect() as conn:
        stuck = conn.execute(text(STUCK_SQL)).all()

    print(f"investigations stuck on a finished analysis owned by another run: "
          f"{len(stuck)}")
    for row in stuck:
        print(f"  {row.investigation_id[:8]} ({row.state}) -> analysis "
              f"{row.analysis_id[:8]} is {row.analysis_status}, owned by "
              f"{(row.owner_id or '-')[:8]}, CAPE task {row.task_id}")
        print(f"      {row.observable}")
    if not stuck:
        return 0
    if not args.apply:
        print("\n(dry run — pass --apply to re-fetch each report and annotate)")
        return 0

    # Imported here so a dry run needs no CAPE connectivity at all.
    from app.services.cape_client import CapeClient  # noqa: E402
    from app.services.cape_normalizer import normalize_report  # noqa: E402
    from app.tasks.cape_task import _annotate_investigation  # noqa: E402

    repaired = 0
    client = CapeClient()
    try:
        for row in stuck:
            if not row.task_id:
                print(f"  {row.investigation_id[:8]}: no CAPE task id — skipped")
                continue
            try:
                report = client.fetch_report(int(row.task_id))
            except Exception as exc:  # noqa: BLE001
                print(f"  {row.investigation_id[:8]}: could not fetch task "
                      f"{row.task_id} ({type(exc).__name__}) — left as is")
                continue
            payload = getattr(report, "payload", None) or getattr(report, "raw", None)
            if not isinstance(payload, dict):
                print(f"  {row.investigation_id[:8]}: task {row.task_id} returned "
                      f"no JSON report — left as is")
                continue
            normalized = normalize_report(
                payload,
                task_id=int(row.task_id),
                report_format=getattr(report, "fmt", None),
                report_size_bytes=getattr(report, "size_bytes", None),
            )
            import uuid as _uuid
            _annotate_investigation(_uuid.UUID(row.investigation_id), normalized)
            repaired += 1
            print(f"  {row.investigation_id[:8]}: annotated from CAPE task "
                  f"{row.task_id} and re-analysed")
    finally:
        client.close()

    print(f"\nrepaired {repaired} of {len(stuck)}")
    with engine.connect() as conn:
        left = conn.execute(text(STUCK_SQL)).all()
    print(f"still stuck: {len(left)} (re-running now is a no-op for the rest)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
