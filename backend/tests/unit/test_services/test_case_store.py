"""The overlay: what survives a read, and what a read must never overwrite.

Two failures these guard against, both silent. A snapshot per recompute records
how often the page was opened rather than what the case did. And a recompute
that writes status or assignee undoes an analyst's work every time someone
looks at the page.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.database import AlertCaseSnapshot, AlertCaseSpine
from app.services.alert_case_store import (
    absorb_superseded,
    live_case_key,
    reset_supersession_stats,
    snapshot_if_changed,
    supersession_stats,
    upsert_spine,
)

T0 = datetime(2026, 8, 1, tzinfo=timezone.utc)
KEY = "a" * 64


class _FakeDB:
    """A dict-backed stand-in that answers the store's two reads honestly."""

    def __init__(self):
        self.spine: dict[str, AlertCaseSpine] = {}
        self.snapshots: list[AlertCaseSnapshot] = []
        self.sequence = 0

    async def get(self, _model, pk):
        return self.spine.get(pk)

    def add(self, row):
        if isinstance(row, AlertCaseSpine):
            self.spine[row.case_key] = row
        else:
            self.snapshots.append(row)

    async def execute(self, query):
        name = (query.get_execution_options() or {}).get("query_name")
        db = self

        class _R:
            # The case-number sequence. A spine row now takes its number from
            # `nextval`, so a stub without this models a schema that no longer
            # exists — and every test here would fail on a method, not on what
            # it is about.
            def scalar_one(self):
                db.sequence += 1
                return db.sequence

            # Absorption issues bulk UPDATEs for the chain collapse and for
            # the release, and reads `rowcount` from each. A stub without it
            # models a driver that does not exist, and the tests fail on the
            # attribute instead of on the behaviour they are about.
            rowcount = 0

            def scalar_one_or_none(self):
                if name != "snapshot_previous":
                    return None
                rows = [s for s in db.snapshots if s.score_version == db._want_version]
                return rows[-1] if rows else None

            def scalars(self):
                return self

            def all(self):
                return []

        return _R()

    _want_version = "v1"


async def _snap(db, **kw):
    db._want_version = kw.get("score_version", "v1")
    kw.setdefault("case_key", KEY)
    kw.setdefault("raw_score", None)
    kw.setdefault("surprise", None)
    kw.setdefault("tactics", ["Execution"])
    kw.setdefault("score_version", "v1")
    return await snapshot_if_changed(db, **kw)


# —— snapshot on change ————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_the_first_snapshot_is_a_baseline():
    db = _FakeDB()
    out = await _snap(db, score=60, member_count=4)
    assert out.snapshot is not None and out.is_baseline and out.previous_score is None


@pytest.mark.asyncio
async def test_an_unchanged_case_appends_nothing():
    db = _FakeDB()
    await _snap(db, score=60, member_count=4)
    out = await _snap(db, score=60, member_count=4)
    assert out.snapshot is None and len(db.snapshots) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"score": 75}, {"member_count": 9}, {"tactics": ["Execution", "Stealth"]},
])
async def test_any_of_the_three_tracked_fields_moving_appends(change):
    db = _FakeDB()
    base = {"score": 60, "member_count": 4, "tactics": ["Execution"]}
    await _snap(db, **base)
    out = await _snap(db, **{**base, **change})
    assert out.snapshot is not None and not out.is_baseline
    assert out.previous_score == 60
    assert len(db.snapshots) == 2


@pytest.mark.asyncio
async def test_tactic_order_is_not_a_change():
    db = _FakeDB()
    await _snap(db, score=60, member_count=4, tactics=["Stealth", "Execution"])
    out = await _snap(db, score=60, member_count=4, tactics=["Execution", "Stealth"])
    assert out.snapshot is None


@pytest.mark.asyncio
async def test_a_new_score_version_writes_a_baseline_not_a_change():
    """The deploy-time flood this exists to prevent.

    Without version-filtered comparison, the first recompute after new weights
    marks every open case as changed at once — indistinguishable from mass
    escalation. The first row under a version is a comparison point.
    """
    db = _FakeDB()
    await _snap(db, score=60, member_count=4)
    out = await _snap(db, score=95, member_count=4, score_version="v2")
    assert out.snapshot is not None
    assert out.is_baseline, "a version change must not read as a case getting worse"
    assert out.previous_score is None, "nothing to delta against across a formula change"


# —— the spine ——————————————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_a_recompute_never_overwrites_human_fields():
    db = _FakeDB()
    row = await upsert_spine(
        db, case_key=KEY, source="s", client="c", host="h",
        session_started_at=T0, session_seq=0, last_activity_at=T0,
        score=40, score_version="v1",
    )
    row.status = "acknowledged"
    row.assignee = "an-analyst"
    await upsert_spine(
        db, case_key=KEY, source="s", client="c", host="h",
        session_started_at=T0, session_seq=1, last_activity_at=T0 + timedelta(hours=1),
        score=55, score_version="v1",
    )
    assert row.status == "acknowledged"
    assert row.assignee == "an-analyst"
    assert row.peak_score == 55


@pytest.mark.asyncio
async def test_a_peak_never_falls_within_one_version():
    db = _FakeDB()
    for score in (80, 30, 45):
        await upsert_spine(
            db, case_key=KEY, source="s", client="c", host="h",
            session_started_at=T0, session_seq=0, last_activity_at=T0,
            score=score, score_version="v1",
        )
    assert db.spine[KEY].peak_score == 80


@pytest.mark.asyncio
async def test_a_peak_is_rebased_across_a_scoring_change():
    """75 -> 100 came from fixing Stealth, not from the case getting worse."""
    db = _FakeDB()
    await upsert_spine(
        db, case_key=KEY, source="s", client="c", host="h",
        session_started_at=T0, session_seq=0, last_activity_at=T0,
        score=100, score_version="v1",
    )
    await upsert_spine(
        db, case_key=KEY, source="s", client="c", host="h",
        session_started_at=T0, session_seq=0, last_activity_at=T0,
        score=60, score_version="v2",
    )
    assert db.spine[KEY].peak_score == 60
    assert db.spine[KEY].peak_score_version == "v2"


@pytest.mark.asyncio
async def test_last_activity_never_moves_backwards():
    db = _FakeDB()
    await upsert_spine(
        db, case_key=KEY, source="s", client="c", host="h",
        session_started_at=T0, session_seq=0, last_activity_at=T0 + timedelta(hours=5),
        score=40, score_version="v1",
    )
    await upsert_spine(
        db, case_key=KEY, source="s", client="c", host="h",
        session_started_at=T0, session_seq=0, last_activity_at=T0,
        score=40, score_version="v1",
    )
    assert db.spine[KEY].last_activity_at == T0 + timedelta(hours=5)


# —— supersession ————————————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_a_live_key_resolves_to_itself():
    db = _FakeDB()
    await upsert_spine(
        db, case_key=KEY, source="s", client="c", host="h",
        session_started_at=T0, session_seq=0, last_activity_at=T0,
        score=10, score_version="v1",
    )
    assert await live_case_key(db, KEY) == KEY


@pytest.mark.asyncio
async def test_a_dead_key_resolves_forward_in_one_hop():
    db = _FakeDB()
    live = "b" * 64
    for key in (KEY, live):
        await upsert_spine(
            db, case_key=key, source="s", client="c", host="h",
            session_started_at=T0, session_seq=0, last_activity_at=T0,
            score=10, score_version="v1",
        )
    db.spine[KEY].superseded_by_case_key = live
    assert await live_case_key(db, KEY) == live


def test_the_supersession_counter_starts_clean():
    reset_supersession_stats()
    assert supersession_stats() == {"superseded": 0, "chains_collapsed": 0}


# —— a case is never absorbed into another case ———————————————————————————
#
# Reported as: closing case #132 answered "This case was merged into case
# #133. Close that one instead — its alerts include these." It did not. #132
# held two Kerberoasting RC4 alerts, #133 four Computer-account-changed
# alerts, and they share not one alert. Measured over all 320 pointers in the
# database, 171 had absorbed a case that still holds its own alerts and in
# none of them had those alerts moved.

@pytest.mark.asyncio
async def test_a_case_this_pass_is_producing_is_never_absorbed():
    """The invariant that replaces the session arithmetic.

    Supersession was written when one session meant one case. A session now
    yields several, grouped by shared evidence, and they all carry the same
    `session_started_at` — so "another key inside this session's span" came to
    mean "a sibling case about something else". A key the current pass is
    producing is a case that exists, with its own alerts, and no arithmetic
    may override that.
    """
    db = _FakeDB()
    live = "b" * 64
    sibling = "c" * 64
    for key in (live, sibling):
        await upsert_spine(
            db, case_key=key, source="s", client="c", host="h",
            session_started_at=T0, session_seq=0, last_activity_at=T0,
            score=10, score_version="v1",
        )
    # The sibling starts later, so the session rule alone would absorb it.
    db.spine[sibling].session_started_at = T0 + timedelta(hours=1)

    absorbed = await absorb_superseded(
        db, live_case_key=live, source="s", client="c", host="h",
        session_started_at=T0, session_ended_at=T0 + timedelta(hours=6),
        known=dict(db.spine), protected_keys=frozenset({live, sibling}),
    )
    assert absorbed == []
    assert db.spine[sibling].superseded_by_case_key is None
    assert db.spine[sibling].status == "open"


@pytest.mark.asyncio
async def test_a_genuinely_dead_key_is_still_followed_forward():
    """The thing absorption is for, kept. A late alert closes a gap, the
    merged session starts earlier and hashes to a new key, and the old row
    would otherwise be unreachable along with its assignee and history."""
    db = _FakeDB()
    live = "b" * 64
    dead = "c" * 64
    for key in (live, dead):
        await upsert_spine(
            db, case_key=key, source="s", client="c", host="h",
            session_started_at=T0, session_seq=0, last_activity_at=T0,
            score=10, score_version="v1",
        )
    db.spine[dead].session_started_at = T0 + timedelta(hours=1)

    absorbed = await absorb_superseded(
        db, live_case_key=live, source="s", client="c", host="h",
        session_started_at=T0, session_ended_at=T0 + timedelta(hours=6),
        known=dict(db.spine), protected_keys=frozenset({live}),
    )
    assert absorbed == [dead]
    assert db.spine[dead].superseded_by_case_key == live


@pytest.mark.asyncio
async def test_an_absorbed_case_is_closed_and_not_left_open_for_ever():
    """The other half of the report — "case #132 remained opened".

    A superseded row kept `closed_at` NULL, and the Cases table reads
    `closed_at`, so 242 of them showed as Open for ever: the closing job
    skipped them because their status is not 'open', and a manual close failed
    on the closure claim for the same reason. There was no exit from the
    state. Its alerts are in the live case now, so there is nothing left to
    judge — it is recorded as merged, which is what happened, and never as a
    finding.
    """
    db = _FakeDB()
    live = "b" * 64
    dead = "c" * 64
    for key in (live, dead):
        await upsert_spine(
            db, case_key=key, source="s", client="c", host="h",
            session_started_at=T0, session_seq=0, last_activity_at=T0,
            score=10, score_version="v1",
        )
    db.spine[dead].session_started_at = T0 + timedelta(hours=1)

    await absorb_superseded(
        db, live_case_key=live, source="s", client="c", host="h",
        session_started_at=T0, session_ended_at=T0 + timedelta(hours=6),
        known=dict(db.spine), protected_keys=frozenset({live}),
    )
    row = db.spine[dead]
    assert row.closed_at is not None, "a merged case must not stay open for ever"
    assert row.closure_kind == "merged"
    assert row.resolution == "merged"

    from app.models.enums import CaseResolution

    # Not a finding, and not something a person may sign a case off as.
    assert "merged" not in {c.value for c in CaseResolution.analyst_choices()}
