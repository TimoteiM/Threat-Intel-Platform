"""A case closed with more than 100 alerts records how many it had.

`alerts_at_close` was recorded from the case's member list, which
`case_by_key` caps at 100 by default. Measured on 2026-10-09: 31 closed cases
read exactly 100 and not one had ever recorded more — the cap was live on both
writers, the closing job and an analyst's close, so every case that outgrew it
was stored as a floor and later reported as "judged on 100".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from tests.integration._scratch_db import scratch_database

ALERTS = 120


@pytest.mark.asyncio
async def test_the_closing_job_records_the_full_count(monkeypatch):
    from app.models.database import AlertBodyInvestigationRun, AlertCaseSpine
    from app.services import tenant_scope
    from app.services.alert_correlation_service import correlate_alerts
    from app.tasks import case_closure_task, case_narrative_task

    async with scratch_database() as (url, factory):
        # One host, one detection, alerts a few seconds apart: a single case
        # well past the member-list cap, and quiet for an hour.
        start = datetime.now(timezone.utc) - timedelta(hours=2)
        async with factory() as db:
            for i in range(ALERTS):
                at = start + timedelta(seconds=10 * i)
                db.add(AlertBodyInvestigationRun(
                    title=f"alert {i}", alert_body="x", status="completed",
                    entity_host="host-a", alert_source="wazuh", alert_client="c1",
                    event_time=at, created_at=at,
                    detection_rule_id=str(100 + i % 2), detection_name="detection",
                    ioc_values=["evil.example"],
                ))
            await db.commit()
            # The case comes into being the way it does in production.
            out = await correlate_alerts(db, scope=tenant_scope.INTERNAL, hours=48, min_rules=1)
        sizes = [c["alert_count"] for c in out["cases"]]
        assert ALERTS in sizes, f"fixture did not form one {ALERTS}-alert case: {sizes}"

        monkeypatch.setattr(
            case_closure_task.get_settings(), "database_url",
            url.render_as_string(hide_password=False),
        )
        monkeypatch.setattr(case_narrative_task, "dispatch", lambda jobs: None)
        monkeypatch.setattr(case_closure_task, "_record_read_sets", lambda jobs: None)

        # The task calls asyncio.run itself, so it runs off this test's loop.
        import asyncio
        result = await asyncio.to_thread(case_closure_task.close_quiet_cases)
        assert result.get("ran") is not False, result

        async with factory() as db:
            closed = (await db.execute(
                select(AlertCaseSpine.alerts_at_close).where(AlertCaseSpine.closed_at.isnot(None))
            )).scalars().all()
        assert ALERTS in closed, f"closed with {closed}, expected {ALERTS}"
