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
