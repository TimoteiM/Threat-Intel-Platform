"""Reconnecting case rows whose key no longer re-derives.

The rule this file exists to hold: never guess a pointer. A wrong one silently
attributes one incident's analysis to another, which is worse than no pointer,
because the reader cannot tell it is wrong.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.case_supersession_service import (
    ALREADY_MERGED,
    AMBIGUOUS,
    EXPIRED,
    MAPPED,
    TARGET_UNKNOWN,
    DeadRow,
    LiveCase,
    decide,
    plan,
    summarise,
)

T = datetime(2026, 8, 16, 9, 2, 11, 482000, tzinfo=timezone.utc)


def _dead(**over) -> DeadRow:
    base = dict(
        case_key="d" * 64, case_number=9, entity_host="EXP-FIN-034.corp.local",
        opened_at=T, alerts_at_close=8, resolution="true_positive",
        closed_at=T + timedelta(minutes=10), has_analysis=True,
        alerts_still_present=True, closure_kind="auto",
    )
    base.update(over)
    return DeadRow(**base)


def _live(**over) -> LiveCase:
    base = dict(
        case_key="l" * 64, case_number=1440,
        entity_host="EXP-FIN-034.corp.local", first_event_at=T, alert_count=8,
    )
    base.update(over)
    return LiveCase(**base)


def test_the_9_1440_pair_resolves():
    """Case #9 is the only resolved true positive among the 880 dead rows, and
    #1440 is the same eight alerts under the key that still derives."""
    decision = decide(_dead(), [_live()])
    assert decision.state == MAPPED
    assert decision.target is not None
    assert decision.target.case_number == 1440
    assert "to the microsecond" in decision.reason


def test_an_exact_opening_timestamp_outranks_a_changed_count():
    """`opened_at` was copied from the first alert's event time, and that time
    is an input to the key, so agreement to the microsecond is identity. The
    count is not: a cluster that closed on three alerts derives five today
    because two more arrived afterwards."""
    decision = decide(_dead(alerts_at_close=3), [_live(alert_count=5)])
    assert decision.state == MAPPED
    assert "joined the cluster after this row closed" in decision.reason


def test_a_count_of_one_hundred_is_read_as_a_floor():
    """The old member list capped at 100, so a row closing on exactly 100 never
    recorded a total."""
    decision = decide(_dead(alerts_at_close=100), [_live(alert_count=561)])
    assert decision.state == MAPPED
    assert "capped at 100" in decision.reason
    assert "floor rather than a total" in decision.reason


def test_zero_alerts_at_close_means_never_counted_not_none_found():
    """Every row in this estate holding 0 has a `closure_kind` of `expired`
    (149) or `unreadable` (25): the case was closed *because* it could not be
    read back. Reading 0 as "this case had no alerts" rejected 209 matches that
    each had exactly one candidate agreeing to the microsecond."""
    dead = _dead(alerts_at_close=0, closure_kind="unreadable")
    assert dead.counted_its_alerts is False
    decision = decide(dead, [_live(alert_count=2)])
    assert decision.state == MAPPED
    assert "without ever counting its alerts" in decision.reason


def test_several_candidates_and_no_distinguishing_evidence_stays_ambiguous():
    candidates = [
        _live(case_key="a" * 64, case_number=892, first_event_at=T + timedelta(seconds=30)),
        _live(case_key="b" * 64, case_number=895, first_event_at=T + timedelta(seconds=60)),
        _live(case_key="c" * 64, case_number=897, first_event_at=T + timedelta(seconds=90)),
    ]
    decision = decide(_dead(alerts_at_close=0, closure_kind="expired"), candidates)
    assert decision.state == AMBIGUOUS
    assert decision.target is None, "an ambiguous row must never carry a pointer"
    assert {c.case_number for c in decision.candidates} == {892, 895, 897}
    assert "may not describe" in decision.reason


def test_a_count_can_break_a_tie_between_candidates_sharing_a_moment():
    candidates = [
        _live(case_key="a" * 64, case_number=892, first_event_at=T, alert_count=4),
        _live(case_key="b" * 64, case_number=895, first_event_at=T, alert_count=8),
    ]
    decision = decide(_dead(alerts_at_close=8), candidates)
    assert decision.state == MAPPED
    assert decision.target is not None and decision.target.case_number == 895


def test_no_live_case_on_that_host_is_target_unknown_not_a_404():
    """Same principle as a case naming the source it has no field map for: the
    row says what happened to it rather than disappearing."""
    decision = decide(_dead(), [_live(entity_host="somewhere-else")])
    assert decision.state == TARGET_UNKNOWN
    assert decision.target is None
    assert "no case derives from" in decision.reason


def test_a_row_whose_alerts_have_aged_out_is_expired():
    decision = decide(_dead(alerts_still_present=False), [_live()])
    assert decision.state == EXPIRED
    assert "nothing left to re-derive it from" in decision.reason
    assert "analysis is kept" in decision.reason


def test_a_different_host_is_never_a_candidate():
    """Host is the one input to the key that a person would notice being
    wrong, so it is matched exactly rather than loosely."""
    decision = decide(_dead(), [_live(entity_host="exp-fin-035.corp.local")])
    assert decision.state == TARGET_UNKNOWN


def test_the_tolerance_does_not_stretch_to_an_unrelated_case():
    decision = decide(_dead(), [_live(first_event_at=T + timedelta(minutes=20))])
    assert decision.state == TARGET_UNKNOWN


def test_the_summary_counts_what_is_at_stake():
    decisions = plan(
        [
            _dead(case_key="1" * 64, case_number=1),
            _dead(case_key="2" * 64, case_number=2, alerts_still_present=False,
                  resolution="false_positive", has_analysis=False),
        ],
        [_live()],
    )
    stats = summarise(decisions)
    assert stats[MAPPED] == 1
    assert stats[EXPIRED] == 1
    assert stats["carrying_analysis"] == 1
    assert stats["true_positive"] == 1


def test_a_pointer_the_merge_wrote_is_reported_not_re_decided():
    """All 13 rows in this state carry a `closure_kind` of `merged` or `auto`
    and a pointer written by the merge logic as it ran. That is a record of
    what happened; overriding it with a timestamp heuristic would replace it
    with a guess about what probably happened."""
    target = _live(case_key="m" * 64, case_number=895)
    dead = _dead(
        case_number=891, closure_kind="merged", existing_pointer="m" * 64,
        alerts_at_close=0,
    )
    decision = decide(dead, [target, _live(case_number=897)])
    assert decision.state == ALREADY_MERGED
    assert decision.target is not None and decision.target.case_number == 895
    assert "written by the merge itself" in decision.reason


def test_a_merge_pointer_into_another_dead_row_says_the_trail_continues():
    dead = _dead(closure_kind="merged", existing_pointer="z" * 64)
    decision = decide(dead, [_live()])
    assert decision.state == ALREADY_MERGED
    assert decision.target is None
    assert "continues through that row" in decision.reason
