"""Every supersession pointer says who wrote it.

Two rows in 866 carried a pointer and no state (#1866, #1973). Both were written
by `absorb_superseded`, the live correlation pass, which set the pointer and
nothing else. A real Postgres, because the guarantee is a CHECK constraint and
a fake would only model whatever the test author believed about it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from tests.integration._scratch_db import scratch_database

T0 = datetime(2026, 10, 9, 14, 28, 57, tzinfo=timezone.utc)


def _spine(key: str, started: datetime, **extra):
    from app.models.database import AlertCaseSpine

    return AlertCaseSpine(
        case_key=key, alert_source="wazuh", alert_client="c1", entity_host="host-a",
        session_started_at=started, session_seq=0, opened_at=started,
        last_activity_at=started + timedelta(seconds=30), status="open",
        peak_score=10, peak_score_version="v", peak_at=started,
        created_at=started, updated_at=started, **extra,
    )


@pytest.mark.asyncio
async def test_absorption_records_who_wrote_the_pointer():
    from app.models.database import AlertCaseSpine
    from app.services.alert_case_store import absorb_superseded

    live, dead = "l" * 64, "d" * 64
    async with scratch_database() as (_url, factory):
        async with factory() as db:
            # The shape of #1973: a session starting inside the live one's.
            db.add(_spine(live, T0))
            db.add(_spine(dead, T0 + timedelta(milliseconds=685)))
            await db.commit()
            absorbed = await absorb_superseded(
                db, live_case_key=live, source="wazuh", client="c1", host="host-a",
                session_started_at=T0, session_ended_at=T0 + timedelta(minutes=1),
            )
            await db.commit()
        assert absorbed == [dead]
        async with factory() as db:
            row = await db.get(AlertCaseSpine, dead)
        assert row.superseded_by_case_key == live
        assert row.supersession_state == "merged"
        assert "correlation pass" in row.supersession_note


@pytest.mark.asyncio
async def test_the_database_refuses_a_pointer_without_a_state():
    from app.models.database import AlertCaseSpine

    async with scratch_database() as (_url, factory):
        async with factory() as db:
            db.add(_spine("a" * 64, T0))
            db.add(_spine("b" * 64, T0 + timedelta(seconds=1)))
            await db.commit()
        async with factory() as db:
            with pytest.raises(IntegrityError, match="ck_case_spine_pointer_has_provenance"):
                await db.execute(
                    update(AlertCaseSpine)
                    .where(AlertCaseSpine.case_key == "b" * 64)
                    .values(superseded_by_case_key="a" * 64)
                )


@pytest.mark.asyncio
async def test_a_released_pointer_takes_its_state_with_it_and_keeps_its_history():
    """A row pointing at a key that dies, and not eligible to follow it, is a
    live case again. `mapped` or `merged` with no pointer would contradict
    itself, so the state goes; the note records that it happened."""
    from app.models.database import AlertCaseSpine
    from app.services.alert_case_store import absorb_superseded

    live, dying, earlier = "l" * 64, "d" * 64, "e" * 64
    async with scratch_database() as (_url, factory):
        async with factory() as db:
            db.add(_spine(live, T0))
            db.add(_spine(dying, T0 + timedelta(seconds=1)))
            # Starts before the live case, so it may not follow the pointer.
            db.add(_spine(
                earlier, T0 - timedelta(seconds=1), superseded_by_case_key=dying,
                supersession_state="mapped", supersession_note="Mapped by the migration.",
            ))
            await db.commit()
            await absorb_superseded(
                db, live_case_key=live, source="wazuh", client="c1", host="host-a",
                session_started_at=T0, session_ended_at=T0 + timedelta(minutes=1),
            )
            await db.commit()
        async with factory() as db:
            row = await db.get(AlertCaseSpine, earlier)
        assert row.superseded_by_case_key is None
        assert row.supersession_state is None
        assert row.supersession_note.startswith("Mapped by the migration. Released")
