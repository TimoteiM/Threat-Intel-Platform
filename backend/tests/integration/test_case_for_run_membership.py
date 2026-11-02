"""The alert page's "which case is this in?" lookup, on a case over the cap.

`case["alerts"]` stops at `max_members` (100) and keeps the EARLIEST, so
scanning it answers membership only for the first hundred. An alert at
position 101 of its own case was told it had no case at all — and on #1849
that is 1,789 of 1,889 alerts. A degraded view would be acceptable; "no case"
is wrong, and the alert page is exactly where an analyst learns that the alert
in front of them is one of many.

This is the fourth place in this codebase a capped collection has been read as
if it were whole, so the fix is a membership index rather than a bigger cap:
raising the cap would leave the fifth.

Against a real Postgres because the behaviour lives in the correlation pass,
which a dict-backed fake does not run. Skipped, with the reason, when no
server is reachable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from tests.integration._scratch_db import scratch_database

#: Comfortably over `max_members`, and over it by more than one alert so the
#: test cannot pass by an off-by-one.
MEMBERS = 240
CAP = 100


@pytest_asyncio.fixture
async def scratch():
    """One host, one long case, with the alerts ordered in time.

    Every alert carries the same `entity_user`, which is what makes them one
    case rather than three. Without it the cluster splits per detection name —
    the first version of this fixture produced 3 case keys and the test was
    measuring its own setup. Real large cases look like this: #71's 1,217
    members share `user:int\\tradoi`, #1833's 28 share `user:int\\tradoi` and
    one detection.
    """
    from app.models.database import AlertBodyInvestigationRun

    async with scratch_database() as (_url, factory):
        now = datetime.now(timezone.utc)
        ids: list[str] = []
        async with factory() as db:
            rows = []
            for i in range(MEMBERS):
                # Inside SESSION_GAP of each other so they stay one session,
                # and three distinct rules so the cluster forms at all.
                at = now - timedelta(hours=3) + timedelta(seconds=i * 30)
                rule = ("100", "200", "300")[i % 3]
                row = AlertBodyInvestigationRun(
                    title=f"alert {i}", alert_body="x", status="completed",
                    entity_host="host-long", alert_source="wazuh",
                    alert_client="c1", event_time=at, created_at=at,
                    detection_rule_id=rule, detection_name=f"detection {rule}",
                    entity_user="CORP\\jdoe",
                )
                rows.append(row)
                db.add(row)
            await db.commit()
            ids = [str(r.id) for r in rows]
        yield factory, ids


@pytest.mark.asyncio
async def test_an_alert_past_the_cap_still_finds_its_case(scratch):
    from app.services import tenant_scope
    from app.services.alert_correlation_service import case_for_run

    factory, ids = scratch
    # Position 0 was always found; the ones past the cap are the regression.
    for index in (0, CAP, CAP + 1, MEMBERS - 1):
        async with factory() as db:
            case = await case_for_run(
                db, ids[index], scope=tenant_scope.INTERNAL, hours=720,
            )
        assert case is not None, (
            f"alert at position {index} of a {MEMBERS}-alert case was told it "
            "has no case"
        )
        assert case["entity_host"] == "host-long"
        # And the count it reports is the real one, not the shown slice.
        assert case["alert_count"] == MEMBERS
        assert case["alerts_truncated"] is True


@pytest.mark.asyncio
async def test_every_member_resolves_to_the_same_case(scratch):
    """All 240 belong to one case, so the lookup must not depend on position."""
    from app.services import tenant_scope
    from app.services.alert_correlation_service import correlate_alerts

    factory, ids = scratch
    async with factory() as db:
        result = await correlate_alerts(
            db, scope=tenant_scope.INTERNAL, hours=720, persist=False,
            member_index=True,
        )
    index = result["case_key_by_run"]
    assert len(index) == MEMBERS, "the index is capped"
    assert len(set(index.values())) == 1
    assert set(index) == set(ids)


@pytest.mark.asyncio
async def test_the_index_is_absent_rather_than_empty_when_not_requested(scratch):
    """So a caller cannot read "no membership" from "not built" — the
    blank-as-measurement failure this codebase keeps paying for."""
    from app.services import tenant_scope
    from app.services.alert_correlation_service import correlate_alerts

    factory, _ids = scratch
    async with factory() as db:
        result = await correlate_alerts(
            db, scope=tenant_scope.INTERNAL, hours=720, persist=False,
        )
    assert "case_key_by_run" not in result


@pytest.mark.asyncio
async def test_the_lookup_still_writes_nothing(scratch):
    """It is a lookup, and the window is the caller's: persisting minted a
    spine row per window an analyst happened to pick."""
    from sqlalchemy import select

    from app.models.database import AlertCaseSpine
    from app.services import tenant_scope
    from app.services.alert_correlation_service import case_for_run

    factory, ids = scratch
    for hours in (1, 24, 168, 720):
        async with factory() as db:
            await case_for_run(db, ids[-1], scope=tenant_scope.INTERNAL, hours=hours)
    async with factory() as db:
        rows = (await db.execute(select(AlertCaseSpine.case_key))).all()
    assert rows == [], f"the alert-page lookup minted {len(rows)} spine rows"
