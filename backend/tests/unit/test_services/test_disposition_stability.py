"""A verdict must not be formed on evidence that keeps arriving.

`case_disposition_review_service` used to claim in its docstring that the two
close-anchor fixes "stop the thirty becoming thirty-one". The flagged
population has since gone 30 -> 56 -> 60 -> 61, so the claim was false, and a
false claim in a docstring is worse than none: it is the next reader's
starting point.

This file is that claim turned into assertions, so it cannot quietly stay
false. Measured on `alert_case_spine`, live rows with a disposition and a close
time, 2026-10-12, using `last_activity_at > closed_at`:

    auto         0 of 1,063   the two fixes govern this path, and it holds
    inherited   20 of    45   every accretion in the estate
    analyst      0 of     4
    unreadable   0 of     4
    expired      0 of    15

And they are real arrivals: of the 1,654 alerts that joined those 20 cases
after their close, 1,654 were ingested after it and 0 were already stored, so
this is not a wider re-derivation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.alert_case_closure_service import (
    ANSWERS_AT_CLOSE,
    CASE_WINDOW,
    accreted_after_close,
    decide,
)
from app.services.case_disposition_review_service import review_for

NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)


class TestTheInvariant:
    def test_accretion_after_a_close_is_detected_from_stored_columns(self):
        assert accreted_after_close(
            closed_at=NOW, last_activity_at=NOW + timedelta(hours=6)
        ) is True
        assert accreted_after_close(
            closed_at=NOW, last_activity_at=NOW - timedelta(hours=6)
        ) is False

    def test_an_absent_timestamp_is_not_read_as_accretion(self):
        """A missing value is an absence, not a False measurement — but the
        caller must not be able to read "no accretion" as "checked and none"."""
        assert accreted_after_close(closed_at=None, last_activity_at=NOW) is False
        assert accreted_after_close(closed_at=NOW, last_activity_at=None) is False

    def test_a_naive_timestamp_is_read_as_utc(self):
        assert accreted_after_close(
            closed_at=datetime(2026, 10, 12, 12, 0, 0),
            last_activity_at=NOW + timedelta(minutes=1),
        ) is True


class TestTheQuietPeriodPathStillHolds:
    """The two fixes' own guarantee: a case is not answered while it is still
    receiving alerts. 0 of 1,063 `auto` closes accreted, and this is what keeps
    that true."""

    def _members(self, count: int, *, last: datetime):
        return [{"event_time": last - timedelta(minutes=i)} for i in range(count)]

    def test_a_case_still_receiving_alerts_is_not_due(self):
        decision = decide(
            self._members(3, last=NOW - timedelta(minutes=5)),
            last_activity_at=NOW - timedelta(minutes=5),
            opened_at=NOW - timedelta(days=2),
            created_at=NOW - timedelta(days=2),
            now=NOW,
            quiet_period=CASE_WINDOW,
        )
        assert decision.due is False
        assert "still receiving alerts" in decision.reason

    def test_a_case_quiet_for_its_full_window_is_due(self):
        decision = decide(
            self._members(3, last=NOW - CASE_WINDOW - timedelta(minutes=1)),
            last_activity_at=NOW - CASE_WINDOW - timedelta(minutes=1),
            opened_at=NOW - timedelta(days=2),
            created_at=NOW - timedelta(days=2),
            now=NOW,
            quiet_period=CASE_WINDOW,
        )
        assert decision.due is True

    def test_the_anchor_is_last_activity_not_the_opening(self):
        """The regression that stranded 80.7% of memberships outside their own
        case: a window run from the opening closes a case that is still live."""
        decision = decide(
            self._members(3, last=NOW),
            last_activity_at=NOW,
            opened_at=NOW - timedelta(days=30),
            created_at=NOW - timedelta(days=30),
            now=NOW,
            quiet_period=CASE_WINDOW,
        )
        assert decision.due is False, (
            "a 30-day-old case receiving alerts right now must not be due"
        )


class TestInheritanceIsTheOpenDefect:
    def test_inheritance_writes_a_disposition_at_close_time(self):
        """Which is why it is the only path that can be wrong on arrival: an
        `auto` close writes `awaiting_analysis` and is answered later."""
        assert "inherited" in ANSWERS_AT_CLOSE
        assert "auto" not in ANSWERS_AT_CLOSE

    def test_a_continuation_answered_then_accreting_is_flagged(self):
        """#1908 is this: judged on one alert, 125 arrived afterwards."""
        review = review_for(
            case_number=1908, resolution="false_positive", alerts_at_close=1,
            current_run_ids=[f"run-{i}" for i in range(126)],
            closed_by=None, closed_at=NOW,
        )
        assert review is not None
        assert review.judged_on == 1
        assert review.holds_now == 126

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "The open design defect, kept executable rather than described. "
            "20 of 45 `inherited` closes in this estate have "
            "last_activity_at > closed_at, so a continuation that inherits a "
            "verdict can still accrete — 1,654 alerts across those 20, every "
            "one ingested after the close. Fixing it means freezing membership "
            "on judgement, not moving a clock. This marker is strict: the day "
            "the behaviour changes, this test XPASSes and the suite fails, so "
            "nobody can quietly fix or re-break it without saying so here."
        ),
    )
    def test_a_case_answered_at_close_does_not_accrete(self):
        # The shape of #2021: inherited a verdict on 8 alerts, then 299 more
        # arrived over the following hours.
        closed_at = NOW
        last_activity_at = NOW + timedelta(hours=6, minutes=16)
        assert not accreted_after_close(
            closed_at=closed_at, last_activity_at=last_activity_at
        ), (
            "a case whose verdict was written at close has gained members "
            "since; the verdict describes less evidence than the case holds"
        )


class TestQuietMeansQuietInBothClocks:
    """The third clock defect in this file's history, after the close anchor
    running from the opening and `opened_at` holding the session's origin.

    Measured by splitting the 71 flagged dispositions on `created_at` rather
    than `event_time`: 22 had a member ingested after the verdict was written,
    and not all are continuations — #2083 closed on 2 alerts and holds 54, with
    52 ingested afterwards; #2007 on 4 holding 103, with 17 after.
    """

    def _args(self, **over):
        base = dict(
            last_activity_at=NOW - CASE_WINDOW - timedelta(minutes=1),
            opened_at=NOW - timedelta(days=2),
            created_at=NOW - timedelta(days=2),
            now=NOW,
            quiet_period=CASE_WINDOW,
        )
        base.update(over)
        return base

    def test_a_case_quiet_in_event_time_but_still_receiving_is_not_due(self):
        """#2083's shape: nothing new happened for six hours, but evidence
        about what did happen is still landing."""
        decision = decide([], **self._args(
            last_ingest_at=NOW - timedelta(minutes=2)
        ))
        assert decision.due is False
        assert "arrived more recently" in decision.reason

    def test_quiet_in_both_clocks_is_due_and_says_so(self):
        decision = decide([], **self._args(
            last_ingest_at=NOW - CASE_WINDOW - timedelta(minutes=1)
        ))
        assert decision.due is True
        assert "both clocks" in decision.reason

    def test_the_event_clock_still_gates_on_its_own(self):
        """Adding a second condition must not weaken the first."""
        decision = decide([], **self._args(
            last_activity_at=NOW - timedelta(minutes=1),
            last_ingest_at=NOW - timedelta(days=5),
        ))
        assert decision.due is False
        assert decision.reason == "still receiving alerts"

    def test_a_missing_ingest_time_falls_back_and_names_the_fallback(self):
        """An absence is reported, not read as "nothing arrived"."""
        decision = decide([], **self._args(last_ingest_at=None))
        assert decision.due is True
        assert "no ingest time was supplied" in decision.reason

    def test_the_reported_quiet_period_is_the_shorter_of_the_two(self):
        decision = decide([], **self._args(
            last_ingest_at=NOW - CASE_WINDOW - timedelta(hours=3)
        ))
        assert decision.quiet_for == CASE_WINDOW + timedelta(minutes=1)


class TestTheGateReadsTheWholeMembership:
    def test_the_closure_task_asks_for_an_uncapped_member_list(self):
        """Reading the newest ingest from a list capped at 100 that keeps the
        EARLIEST would answer with the oldest hundred — the capped-collection
        mistake, committed inside the fix for it."""
        import pathlib

        task = (
            pathlib.Path(__file__).resolve().parents[3]
            / "app" / "tasks" / "case_closure_task.py"
        ).read_text()
        assert "max_members=100_000" in task
        assert "last_ingest_at=_newest_ingest(members)" in task

    def test_the_newest_receipt_wins_whatever_the_event_order(self):
        from app.tasks.case_closure_task import _newest_ingest

        members = [
            {"created_at": (NOW - timedelta(hours=9)).isoformat()},
            {"created_at": NOW - timedelta(minutes=3)},
            {"created_at": (NOW - timedelta(days=2)).isoformat()},
        ]
        assert _newest_ingest(members) == NOW - timedelta(minutes=3)

    def test_members_without_a_receipt_time_yield_an_absence(self):
        from app.tasks.case_closure_task import _newest_ingest

        assert _newest_ingest([]) is None
        assert _newest_ingest([{"event_time": NOW}, {"created_at": None}]) is None
        assert _newest_ingest([{"created_at": "not a date"}]) is None

    def test_a_naive_receipt_time_is_read_as_utc(self):
        from app.tasks.case_closure_task import _newest_ingest

        assert _newest_ingest([{"created_at": "2026-10-12T11:00:00"}]) == (
            datetime(2026, 10, 12, 11, 0, tzinfo=timezone.utc)
        )
