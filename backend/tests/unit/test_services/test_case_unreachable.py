"""Why a key cannot be re-derived, named rather than guessed.

The sentence this replaces named the window or a re-grouping in every case.
Measured on `alert_case_spine`, for 51 of the 61 live keys that do not derive
at the endpoint's default it was false in both halves.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from app.services.case_unreachable_service import (
    AGED_OUT,
    COMPOSITE_SEPARATOR,
    NO_ALERTS_REMAIN,
    REGROUPED,
    RETIRED_KEY_FORMAT,
    UNDETERMINED,
    why_unreachable,
)

NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)


@dataclass
class _Spine:
    entity_host: str | None = "exp-fin-034"
    alert_source: str | None = "Siembiot"
    alert_client: str | None = "unknown"
    opened_at: datetime | None = None
    case_number: int | None = 1234


class _Row:
    def __init__(self, runs, newest=None):
        self.runs = runs
        self.newest = newest


class _FakeDB:
    """Only `execute(text(...))` is used, and only for the triple count."""

    def __init__(self, runs: int, newest=None):
        self._row = _Row(runs, newest)
        self.calls = 0

    async def execute(self, *_args, **_kwargs):
        self.calls += 1
        row = self._row

        class _Result:
            def first(self_inner):
                return row

        return _Result()


@pytest.mark.asyncio
async def test_a_pointer_is_the_first_answer_and_no_window_helps():
    out = await why_unreachable(
        _FakeDB(0), spine=_Spine(), hours=720, now=NOW,
        pointer={"state": "mapped", "note": "went to #1440"},
    )
    assert out.reason == REGROUPED
    assert out.window_cannot_help is True
    assert out.note == "went to #1440"


@pytest.mark.asyncio
async def test_the_retired_composite_host_form_is_named_as_itself():
    """54 cases are keyed this way and 0 alert runs still carry the form, so
    the old note's "aged out of the window" was wrong twice over."""
    db = _FakeDB(999)
    spine = _Spine(
        entity_host=f"mvapsupm01{COMPOSITE_SEPARATOR}incident:7e0559e6-0100-41"
    )
    out = await why_unreachable(db, spine=spine, hours=720, now=NOW)
    assert out.reason == RETIRED_KEY_FORMAT
    assert out.window_cannot_help is True
    assert "widening the window will not change that" in out.note
    assert "mvapsupm01" in out.note
    assert db.calls == 0, "the host form settles it; no query needed"


@pytest.mark.asyncio
async def test_it_does_not_invite_a_retry_that_cannot_work():
    """The failure being fixed is an explanation that sends an analyst to do
    something futile."""
    for spine, pointer in (
        (_Spine(entity_host=f"h{COMPOSITE_SEPARATOR}incident:x"), None),
        (_Spine(), {"state": "merged"}),
    ):
        out = await why_unreachable(_FakeDB(0), spine=spine, hours=720,
                                    now=NOW, pointer=pointer)
        assert out.window_cannot_help is True
        assert "wider window" not in out.note or "will not help" in out.note


@pytest.mark.asyncio
async def test_no_alerts_left_on_the_triple_is_its_own_reason():
    out = await why_unreachable(_FakeDB(0), spine=_Spine(), hours=720, now=NOW)
    assert out.reason == NO_ALERTS_REMAIN
    assert out.window_cannot_help is True
    assert out.detail["runs_on_triple"] == 0


@pytest.mark.asyncio
async def test_age_is_reported_as_age_and_a_window_could_still_help():
    out = await why_unreachable(
        _FakeDB(12), spine=_Spine(opened_at=NOW - timedelta(days=54)),
        hours=720, now=NOW,
    )
    assert out.reason == AGED_OUT
    assert out.window_cannot_help is False
    assert out.detail["opened_hours_ago"] == pytest.approx(1296.0, abs=1.0)
    # And it points at the real suspect rather than blaming the window alone:
    # the window stretches to a case's own opening, so if age bit, the stored
    # opening time is what to check.
    assert "stored opening time" in out.note


@pytest.mark.asyncio
async def test_a_recent_case_with_alerts_that_still_fails_says_it_is_undiagnosed():
    """The honest fourth state. Calling this "aged out" is the guess that the
    whole module exists to stop."""
    out = await why_unreachable(
        _FakeDB(64, newest=NOW - timedelta(hours=2)),
        spine=_Spine(opened_at=NOW - timedelta(hours=54)), hours=720, now=NOW,
    )
    assert out.reason == UNDETERMINED
    assert "has not been" in out.note
    assert out.detail["runs_on_triple"] == 64


@pytest.mark.asyncio
async def test_a_naive_opened_at_is_read_as_utc():
    out = await why_unreachable(
        _FakeDB(5), spine=_Spine(opened_at=datetime(2026, 8, 16, 9, 2, 11)),
        hours=720, now=NOW,
    )
    assert out.reason == AGED_OUT
