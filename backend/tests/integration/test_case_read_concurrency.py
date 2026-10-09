"""The cases page under concurrent load, against a real Postgres.

The race this guards is invisible to a dict-backed fake: two requests that both
find no spine row both INSERT, and the second raises on the primary key. Before
the fix, 7 of 8 concurrent `GET /detections/correlated-cases` raised
IntegrityError — each one a 500 on the page analysts keep open, which refreshes
every 30 seconds.

Each test creates a scratch database on the configured server and drops it
afterwards; nothing is written to the application database. Skipped, with the
reason, only when no Postgres is reachable.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select

from tests.integration._scratch_db import scratch_database

CONCURRENCY = 24
HOSTS = 6


@pytest_asyncio.fixture
async def scratch():
    """A throwaway database with the application schema and some alerts."""
    from app.models.database import AlertBodyInvestigationRun

    async with scratch_database() as (_url, factory):
        now = datetime.now(timezone.utc)
        async with factory() as db:
            for h in range(HOSTS):
                for i, rule in enumerate(("100", "200", "300")):
                    at = now - timedelta(minutes=30 - i)
                    db.add(AlertBodyInvestigationRun(
                        title=f"alert {h}/{i}", alert_body="x", status="completed",
                        entity_host=f"host-{h}", alert_source="wazuh", alert_client="c1",
                        event_time=at, created_at=at,
                        detection_rule_id=rule, detection_name=f"detection {rule}",
                    ))
            await db.commit()
        yield factory


async def _spine(factory):
    from app.models.database import AlertCaseSpine

    async with factory() as db:
        return (await db.execute(select(AlertCaseSpine.case_key, AlertCaseSpine.case_number))).all()


@pytest.mark.asyncio
async def test_concurrent_case_list_reads_neither_fail_nor_double_number(scratch):
    from app.api import detections

    detections._CASES_CACHE.clear()
    barrier = asyncio.Barrier(CONCURRENCY)

    async def read(k: int):
        async with scratch() as db:
            await barrier.wait()
            return await detections.get_correlated_cases(
                db=db,
                # Two windows, because the key depends on the window and two
                # analysts on different presets are the realistic collision.
                hours=48 if k % 2 else 96,
                min_rules=1, min_score=0, limit=50,
                tenant=None, since=None, until=None, request=None,
            )

    results = await asyncio.gather(*(read(k) for k in range(CONCURRENCY)), return_exceptions=True)

    failures = [r for r in results if isinstance(r, BaseException)]
    assert not failures, f"{len(failures)} of {CONCURRENCY} reads raised: {failures[0]!r}"

    rows = await _spine(scratch)
    assert rows, "the read path formed no case at all, so this proved nothing"
    keys = [key for key, _ in rows]
    numbers = [number for _, number in rows]
    assert len(keys) == len(set(keys))
    assert None not in numbers
    assert len(numbers) == len(set(numbers)), "two cases share a case number"

    # Every concurrent reader was told the same number for the same case.
    told = defaultdict(set)
    for result in results:
        for case in result["cases"]:
            told[case["case_key"]].add(case.get("case_number"))
    stored = dict(rows)
    for key, seen in told.items():
        assert seen == {stored[key]}, f"{key[:12]} reported as {seen}, stored as {stored[key]}"


@pytest.mark.asyncio
async def test_the_alert_page_lookup_writes_no_case(scratch):
    """`GET /alert-investigations/{id}/case` is a lookup at a caller-chosen window.

    The key depends on the window, so a lookup that persisted minted a row for
    every window an analyst picked.
    """
    from app.api import alert_investigations
    from app.models.database import AlertBodyInvestigationRun

    async with scratch() as db:
        run_id = (await db.execute(select(AlertBodyInvestigationRun.id).limit(1))).scalar_one()

    async def look(hours: int):
        async with scratch() as db:
            return await alert_investigations.get_run_case(
                run_id=run_id, db=db, hours=hours, request=None,
            )

    found = await asyncio.gather(*(look(h) for h in (24, 48, 72, 168, 720)))
    assert all(f.get("case") is not None for f in found), "the lookup found no case, so this proved nothing"
    assert await _spine(scratch) == []
