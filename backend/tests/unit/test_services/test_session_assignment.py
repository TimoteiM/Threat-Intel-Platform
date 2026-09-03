"""Session assignment must be a pure function of event time, read at any window.

The property under test is not "the code runs" but "two readers looking at the
same host through different windows agree on what a case is". Every test here
exists because a plausible implementation fails it.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.services.alert_session_service import (
    SESSION_GAP,
    SESSION_GAP_HOURS,
    SESSION_MAX_HOURS,
    anchor_index,
    assign_sessions,
    case_key_for,
    session_starts,
)

T0 = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
SCOPE = {"source": "Siembiot", "client": "acme", "host": "exphost01"}


def at(*hours: float) -> list[datetime]:
    return [T0 + timedelta(hours=h) for h in hours]


def events(times):
    return [(i, t) for i, t in enumerate(times)]


def keys(times, start_index=0):
    """Assignment as a reader with a window starting at start_index sees it."""
    anchored = anchor_index(times, start_index)
    assigned = assign_sessions(events(times)[anchored:], **SCOPE)
    return {a.run_id: a.case_key for a in assigned if a.run_id >= start_index}


# —— the boundary property ———————————————————————————————————————————————

def test_every_window_start_yields_the_same_keys():
    # Three sessions: a burst, a 12h gap, a pair, a 20h gap, a burst.
    times = at(0, 0.5, 1, 13, 13.5, 34, 34.2, 34.4)
    truth = keys(times, 0)
    for start in range(len(times)):
        assert keys(times, start) == {
            k: v for k, v in truth.items() if k >= start
        }, f"window starting at index {start} disagreed"


def test_a_window_cutting_mid_session_still_agrees():
    times = at(0, 1, 2, 3)          # one continuous session, no gap anywhere
    # index 2 is squarely inside it; the reader must walk back to index 0.
    assert keys(times, 2) == {2: truth_key(times, 0), 3: truth_key(times, 0)}


def truth_key(times, idx):
    return assign_sessions(events(times), **SCOPE)[idx].case_key


def test_without_the_walk_a_mid_session_cut_invents_a_start():
    """The failure the anchor walk exists to prevent."""
    times = at(0, 1, 2, 3)
    naive = assign_sessions(events(times)[2:], **SCOPE)[0].case_key
    assert naive != truth_key(times, 2)


# —— identity is the start, not the ordinal ——————————————————————————————

def test_ordinal_is_not_part_of_the_key():
    times = at(0, 13, 26)          # three separate sessions
    full = assign_sessions(events(times), **SCOPE)
    tail = assign_sessions(events(times)[2:], **SCOPE)
    assert full[2].session_seq == 2 and tail[0].session_seq == 0
    assert full[2].case_key == tail[0].case_key


def test_seq_still_numbers_sessions_for_a_reader():
    times = at(0, 0.5, 13, 26, 26.1)
    assigned = assign_sessions(events(times), **SCOPE)
    assert [a.session_seq for a in assigned] == [0, 0, 1, 2, 2]


# —— the boundary rules themselves ————————————————————————————————————————

def test_a_gap_exactly_at_the_timeout_does_not_split():
    times = [T0, T0 + SESSION_GAP]
    assert len(set(session_starts(times))) == 1


def test_a_gap_one_second_over_the_timeout_splits():
    times = [T0, T0 + SESSION_GAP + timedelta(seconds=1)]
    assert len(set(session_starts(times))) == 2


def test_identical_stamps_stay_in_one_session():
    times = [T0, T0, T0]
    assert len(set(session_starts(times))) == 1


def test_the_hard_cap_cuts_a_session_that_never_falls_quiet():
    # An alert every 5h forever: no gap ever exceeds 6h, so only the cap splits.
    times = at(*[5 * i for i in range(40)])
    starts = session_starts(times)
    assert len(set(starts)) > 1
    for start, when in zip(starts, times):
        assert (when - start) <= timedelta(hours=SESSION_MAX_HOURS)


def test_cap_splits_are_why_the_walk_cannot_stop_at_the_cap():
    """A chain with no gap runs further back than SESSION_MAX."""
    times = at(*[5 * i for i in range(40)])       # 195h of unbroken activity
    walked = anchor_index(times, len(times) - 1)
    assert walked == 0
    span = times[-1] - times[walked]
    assert span > timedelta(hours=SESSION_MAX_HOURS)


# —— purity ————————————————————————————————————————————————————————————

def test_assignment_does_not_depend_on_when_it_is_computed():
    times = at(0, 1, 20, 21)
    first = assign_sessions(events(times), **SCOPE)
    second = assign_sessions(events(times), **SCOPE)
    assert [a.case_key for a in first] == [a.case_key for a in second]


def test_naive_stamps_are_read_as_utc():
    naive = datetime(2026, 8, 1, 0, 0)
    assert case_key_for("s", "c", "h", naive) == case_key_for("s", "c", "h", T0)


def test_scope_separates_keys_that_share_a_start():
    assert case_key_for("Siembiot", "a", "h", T0) != case_key_for("Siembiot", "b", "h", T0)
    assert case_key_for("Siembiot", "a", "h", T0) != case_key_for("Tracecat", "a", "h", T0)


def test_separator_cannot_be_forged_from_scope_text():
    assert case_key_for("a|b", "c", "h", T0) != case_key_for("a", "b|c", "h", T0)


def test_empty_history_assigns_nothing():
    assert assign_sessions([], **SCOPE) == []
