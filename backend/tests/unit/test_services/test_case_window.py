"""An open case derives from its own first alert, bounded only by a runaway guard."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.services.alert_case_window_service import (
    OPEN_CASE_CEILING,
    window_for_open_case,
)

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def test_a_case_derives_from_its_own_first_alert_not_a_fixed_window():
    """The distribution is the argument: 68.4% of cases complete in a single
    instant while multi-alert cases reach 28.5 hours at p99, so any constant
    is wrong for one of the two modes."""
    first = NOW - timedelta(hours=5)
    start, clipped = window_for_open_case(first, now=NOW)
    assert start == first
    assert clipped is False


def test_the_widest_case_this_estate_has_ever_produced_is_not_clipped():
    """Measured as max-min event_time over each case's own members: 172,803s,
    2.0 days. The ceiling clears it with a day of margin."""
    first = NOW - timedelta(seconds=172803)
    start, clipped = window_for_open_case(first, now=NOW)
    assert start == first
    assert clipped is False


def test_the_ceiling_clips_and_says_so(caplog):
    """A clip is reported, never absorbed. A case still accreting after three
    days is either a host-wide bucket — 24 cases hold 74.5% of all alert
    memberships — or a derivation defect."""
    first = NOW - timedelta(hours=100)
    with caplog.at_level(logging.WARNING):
        start, clipped = window_for_open_case(first, now=NOW, case_number=61)
    assert clipped is True
    assert start == NOW - OPEN_CASE_CEILING
    assert "open_case_window_clipped" in caplog.text
    assert "case=61" in caplog.text
    assert "host-wide bucket or a derivation defect" in caplog.text


def test_an_unknown_first_alert_falls_back_without_claiming_a_clip():
    """No first alert is not the same as a case that outran the ceiling, and
    logging it as one would make the clip metric useless."""
    start, clipped = window_for_open_case(None, now=NOW)
    assert start == NOW - OPEN_CASE_CEILING
    assert clipped is False


def test_a_naive_timestamp_is_read_as_utc():
    first = (NOW - timedelta(hours=3)).replace(tzinfo=None)
    start, clipped = window_for_open_case(first, now=NOW)
    assert start.tzinfo is not None
    assert clipped is False


def test_the_ceiling_is_a_guard_not_a_belief_about_accretion():
    assert OPEN_CASE_CEILING == timedelta(hours=72), (
        "Changing this changes a runaway guard, not a statement about how long "
        "cases accrete. The observed maximum is 2.0 days; if that figure moves, "
        "re-measure before moving this."
    )
