#!/usr/bin/env python3
"""
CLI tool — print a stored investigation as JSON, looked up by its run ID.

Usage:
    python -m scripts.get_investigation 3fa5f320-b3fd-4a6d-a1c2-d7046a234303
    python -m scripts.get_investigation <run_id> --output investigation.json

Output contains the investigation metadata, the latest structured analyst
report, the collected evidence and per-collector statuses.

Requires: Postgres reachable via DATABASE_URL (same settings as the API).
Read-only — never modifies the database.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.repository import (
    CollectorResultRepository,
    EvidenceRepository,
    InvestigationRepository,
    ReportRepository,
)
from app.db.session import AsyncSessionLocal, async_engine

EXIT_NOT_FOUND = 1
EXIT_INVALID_ID = 2


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


async def fetch_investigation(
    session: AsyncSession, investigation_id: uuid.UUID
) -> Optional[dict]:
    """Load an investigation with its report, evidence and collector results."""
    inv = await InvestigationRepository(session).get(investigation_id)
    if not inv:
        return None

    evidence = await EvidenceRepository(session).get(investigation_id)
    report = await ReportRepository(session).get_latest(investigation_id)
    collector_results = await CollectorResultRepository(
        session
    ).get_all_for_investigation(investigation_id)

    return {
        "investigation": {
            "id": str(inv.id),
            "domain": inv.domain,
            "state": inv.state,
            "context": inv.context,
            "classification": inv.classification,
            "confidence": inv.confidence,
            "risk_score": inv.risk_score,
            "recommended_action": inv.recommended_action,
            "analyst_iterations": inv.analyst_iterations,
            "created_at": _iso(inv.created_at),
            "updated_at": _iso(inv.updated_at),
            "concluded_at": _iso(inv.concluded_at),
        },
        "report": report.report_json if report else None,
        "report_iteration": report.iteration if report else None,
        "evidence": evidence.evidence_json if evidence else None,
        "collector_results": [
            {
                "collector": cr.collector_name,
                "status": cr.status,
                "duration_ms": cr.duration_ms,
                "error": cr.error,
                "completed_at": _iso(cr.completed_at),
            }
            for cr in collector_results
        ],
    }


async def _fetch_from_db(investigation_id: uuid.UUID) -> Optional[dict]:
    try:
        async with AsyncSessionLocal() as session:
            return await fetch_investigation(session, investigation_id)
    finally:
        await async_engine.dispose()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print a stored investigation (report + evidence) as JSON"
    )
    parser.add_argument("run_id", help="Investigation / run ID (UUID)")
    parser.add_argument("--output", "-o", help="Save JSON to file instead of stdout")
    args = parser.parse_args(argv)

    try:
        investigation_id = uuid.UUID(args.run_id.strip())
    except ValueError:
        print(f"❌ Invalid run ID (expected a UUID): {args.run_id}", file=sys.stderr)
        return EXIT_INVALID_ID

    result = asyncio.run(_fetch_from_db(investigation_id))
    if result is None:
        print(f"❌ Investigation not found: {investigation_id}", file=sys.stderr)
        return EXIT_NOT_FOUND

    result["exported_at"] = datetime.now(timezone.utc).isoformat()
    output = json.dumps(result, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Saved to {args.output}", file=sys.stderr)
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
