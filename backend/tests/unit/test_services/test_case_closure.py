"""When a case stops waiting, and what happens to alerts that arrive after.

Every number in these tests came from replaying the real estate — 11,376
alerts, 884 cases — before any of it was built:

  * closing ten minutes after a case *opens* strands 9,244 alerts outside
    their own case (81% of everything); ten minutes after its *last* alert
    strands 821. The clock runs on last activity, and that is an 11x
    difference, not a preference.
  * gaps between consecutive alerts in one case: p50 0.0, p75 0.7, p90 8.8,
    p95 29.4, p99 186 minutes. Ten minutes covers 90% of arrivals.
  * of 821 late alerts, 811 (99%) repeated a detection the case already held
    and 10 brought a new one. So a straggler appends and nothing is
    re-answered unless it is one of the 10.

Replayed with these rules, 884 cases produce 911 model calls and 27
continuations, against 1,705 if every straggler re-answered.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services import alert_case_closure_service as closure

T0 = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def alert(detection, *, minutes=0):
    return SimpleNamespace(
        detection_name=detection,
        detection_rule_id=None,
        detection_rule_name=None,
        event_time=T0 + timedelta(minutes=minutes),
        id=f"{detection}-{minutes}",
    )


def _decide(members, *, last_minutes, now_minutes, opened_minutes=0):
    return closure.decide(
        members,
        last_activity_at=T0 + timedelta(minutes=last_minutes),
        opened_at=T0 + timedelta(minutes=opened_minutes),
        now=T0 + timedelta(minutes=now_minutes),
    )


# --- the window --------------------------------------------------------------
#
# A case is answered once it has been QUIET for CASE_WINDOW, measured from its
# last alert. The window is six hours, equal to SESSION_GAP.
#
# This is what the module did originally, and the header above is the
# measurement that chose it. It was changed to a fixed window from the opening
# and then changed back, and the second measurement reproduced the first on a
# different corpus: over 1,015 derived cases and 12,061 memberships, anchoring
# at the opening left 9,731 of 12,064 memberships (80.7%) arriving after their
# case had closed; anchoring at the last alert at the same ten minutes left
# 897 (7.4%); and widening to SESSION_GAP left 31 (0.3%). Against the original
# replay's 9,244 (81%) and 821, on 11,376 alerts rather than 12,064. Two
# corpora, the same factor of eleven.
#
# The first attempt at the re-measurement read the `alerts` payload, which
# caps at 100 per case and keeps the EARLIEST, so it hid 6,533 of the 12,064
# memberships — all of them in the 24 largest cases, and all of them the late
# arrivals being counted. It reported 57.9% where the answer is 80.7%.
#
# The concern that motivated the fixed window is real and is still answered.
# An idle timer that STRETCHED with novelty never answered a host alerting
# every nine minutes. This does not stretch: the period is identical for every
# case, so a busy host is answered one window after its last alert.
#
# And it cannot run forever. SESSION_GAP starts a new case after six hours of
# silence, and SESSION_MAX caps a session at three days, so a case is bounded
# at three days plus one window rather than being open-ended.

def test_a_case_inside_its_window_is_not_answered():
    members = [alert("A"), alert("A", minutes=3)]
    assert not _decide(members, last_minutes=3, now_minutes=8).due


def test_a_case_is_answered_once_it_has_been_quiet_for_its_window():
    members = [alert("A"), alert("A", minutes=3)]
    decision = _decide(members, last_minutes=3, now_minutes=3 + 361)
    assert decision.due
    assert decision.reason == "quiet for its full window"


def test_the_clock_runs_from_the_last_alert_not_from_the_opening():
    """A case still receiving alerts is not quiet, and must not be answered.

    Anchoring at the opening answered a case while the alerts the correlation
    would still give it were arriving: 9,731 of 12,064 memberships (80.7%)
    landed after their case had closed. 30 cases now carry a disposition
    formed on fewer alerts than they hold, the worst judged on 2 of 57.
    """
    busy = [alert("A", minutes=m) for m in range(0, 60, 5)]
    decision = _decide(busy, last_minutes=59, now_minutes=60, opened_minutes=0)
    assert not decision.due, "an alert a minute ago means the case is not quiet"
    assert decision.reason == "still receiving alerts"
    assert decision.quiet_for == timedelta(minutes=1)


def test_a_case_that_went_silent_immediately_still_waits_its_full_window():
    """The window is a floor as well as a ceiling: a lone alert gets the whole
    period to collect what follows, which is what the quiet period is for."""
    assert not _decide([alert("A")], last_minutes=0, now_minutes=359).due
    assert _decide([alert("A")], last_minutes=0, now_minutes=361).due


def test_a_busy_case_cannot_stay_open_forever():
    """The fixed window was introduced because an idle timer that stretched
    with novelty never answered a host alerting every nine minutes. This
    period does not stretch — but it does wait, so the bound comes from
    elsewhere: SESSION_GAP starts a new case after six hours of silence and
    SESSION_MAX caps a session at three days, so a case is bounded at three
    days plus one window rather than being open-ended.
    """
    from app.services.alert_session_service import SESSION_GAP, SESSION_MAX

    assert closure.CASE_WINDOW == SESSION_GAP, (
        "the close window must be at least SESSION_GAP, or a case can close "
        "while the correlation is still right to give it alerts"
    )
    assert SESSION_MAX <= timedelta(days=3)


# --- escalation no longer extends the window ---------------------------------

def test_a_case_still_producing_new_detections_is_answered_anyway():
    """It used to earn a thirty-minute silence before being answered, which is
    the protection a fixed window gives up. What replaces it is the
    continuation: the next alert opens its own case with its own window, so a
    multi-stage attack is a chain of answered cases rather than one held open
    while an analyst waits for it."""
    members = [alert("recon"), alert("credential access", minutes=8)]
    # Quiet since minute 8, answered one window later and not one minute later
    # for having escalated.
    assert not _decide(members, last_minutes=8, now_minutes=12).due
    decision = _decide(members, last_minutes=8, now_minutes=8 + 361)
    assert decision.due
    assert decision.reason == "quiet for its full window"
    # The escalation itself is still detectable; it simply does not extend the
    # period, which is what "does not stretch" means.
    assert closure.is_escalating(members, now=T0 + timedelta(minutes=12))


def test_the_window_is_the_same_for_a_noisy_case_and_an_escalating_one():
    """One rule for every case, which is the point of a fixed window: the
    answer does not depend on a judgement about what the case is doing."""
    noisy = [alert("A", minutes=m) for m in range(0, 30, 2)]
    escalating = [alert("stage-1"), alert("stage-2", minutes=8)]
    for members in (noisy, escalating):
        # Same period, measured from the same instant, for both.
        assert not _decide(members, last_minutes=0, now_minutes=359).due
        assert _decide(members, last_minutes=0, now_minutes=361).due


def test_a_long_case_is_answered_one_window_after_its_last_alert():
    """Not after its opening. A case whose second alert lands six hours in is
    answered six hours after THAT, because until then the correlation is still
    right to give it alerts — a six-hour gap is exactly the boundary at which
    SESSION_GAP would have started a new case instead."""
    members = [alert("stage-1"), alert("stage-2", minutes=370)]
    assert not _decide(members, last_minutes=370, now_minutes=385).due
    decision = _decide(members, last_minutes=370, now_minutes=370 + 361)
    assert decision.due
    assert decision.reason == "quiet for its full window"


# --- what happens to late alerts ---------------------------------------------

def test_a_closed_case_stops_taking_alerts():
    """The regression this replaced. An earlier rule appended a late alert to
    the closed case whenever its detection was already known — which read well
    against the measurement (99% of late alerts are repeats) but the
    measurement was about minutes, not hours. In production case #117 closed
    at 09:48 and was still taking alerts at 10:59, so a morning of real alerts
    produced no case an analyst could see and no SLA clock that was running."""
    members = [alert("A"), alert("A", minutes=71)]
    answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=90),
    )
    assert len(answered) == 1, "the case keeps only what it was answered on"
    assert len(late.continuation) == 1, "the rest is a new episode"
    assert late.needs_continuation


def test_a_continuation_bringing_nothing_new_inherits_the_answer():
    """Membership and cost are separate questions. Every post-closure alert
    gets a case; only one bringing a detection the parent never answered
    costs a model call. Measured: 915 calls for 1,728 cases."""
    members = [alert("A"), alert("A", minutes=71)]
    _answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=90),
    )
    assert late.inherits
    assert late.new_detections == set()


def test_a_straggler_with_a_new_detection_starts_a_continuation():
    """The other 1%, and the only case worth paying for."""
    members = [alert("A"), alert("lateral movement", minutes=30)]
    answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=40),
    )
    assert late.needs_continuation
    assert [m.detection_name for m in late.continuation] == ["lateral movement"]
    assert late.new_detections == {"lateral movement"}


def test_everything_after_the_answer_goes_into_the_continuation():
    """Including repeats of a detection the parent already held — once a case
    is answered, what follows is one episode, not two."""
    members = [
        alert("A"), alert("lateral movement", minutes=30), alert("A", minutes=35),
    ]
    _answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=40),
    )
    assert len(late.continuation) == 2
    assert not late.inherits, "a new detection is present, so it is answered afresh"


def test_nothing_arriving_after_closure_means_nothing_to_do():
    members = [alert("A"), alert("A", minutes=3)]
    answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=20),
    )
    assert len(answered) == 2
    assert not late.needs_continuation


# --- resolutions and metrics -------------------------------------------------

def test_a_resolution_is_how_an_analyst_closes_a_case():
    assert closure.resolution_for(verdict="malicious") == "true_positive"
    assert closure.resolution_for(verdict="benign") == "false_positive"
    assert closure.resolution_for(verdict="suspicious") == "needs_review"


def test_unknown_is_not_quietly_recorded_as_either():
    """"Inconclusive" is a real outcome. Filing it as a false positive is how
    a metric starts to look good by losing the cases it could not answer."""
    assert closure.resolution_for(verdict=None) == "inconclusive"
    assert closure.resolution_for(verdict="unknown") == "inconclusive"


def test_the_score_is_not_an_input_to_the_resolution():
    """The defect this function was rewritten for.

    The resolution was a band of the correlation score — true_positive was
    exactly 76-100 across 831 closed cases — and that score measures how much
    independent agreement there is between rules, not severity: four distinct
    rules and nothing else scores 90. Case #61 was filed as a confirmed
    detection while its own report opened "Verdict: Inconclusive".

    Pinned on the signature, because the old code reached the score branch
    only when `verdict` was None, which was *always* — the correlated case
    dict has no `verdict` key at all, so every verdict branch above was dead
    code that had never run in production.
    """
    import inspect

    parameters = inspect.signature(closure.resolution_for).parameters
    assert "risk_score" not in parameters
    assert "score" not in parameters


def test_the_verdicts_the_model_actually_writes_all_map():
    """Taken verbatim from stored narratives. The model qualifies its verdict
    in prose and the qualifier is for the analyst, not for the parser."""
    assert closure.resolution_for(verdict="Benign operational denial") == "false_positive"
    assert closure.resolution_for(verdict="Benign managed detection-validation") == "false_positive"
    assert closure.resolution_for(verdict="Suspicious authentication activity") == "needs_review"
    assert closure.resolution_for(
        verdict="Inconclusive, with a benign operational explanation more strongly supported"
    ) == "inconclusive"
    assert closure.resolution_for(verdict="Likely benign") == "false_positive"


def test_a_verdict_nobody_can_read_is_never_a_positive():
    """Scanning the line for a frightening word read "No malicious activity
    confirmed" as a confirmed intrusion — the same error as reading the score:
    a conclusion drawn from something that was never a conclusion."""
    for unreadable in (
        "No malicious activity confirmed",
        "nothing suspicious was found",
        "The host was fine",
        "",
        None,
    ):
        assert closure.resolution_for(verdict=unreadable) == "inconclusive"


def test_a_case_closed_before_its_analysis_says_so_rather_than_guessing():
    """490 of 794 cases were closed before their analysis existed. Closing has
    to happen when the case goes quiet or MTTR measures queue depth, so the
    resolution is deferred — and the placeholder is not a finding."""
    assert closure.AWAITING_ANALYSIS == "awaiting_analysis"
    assert closure.AWAITING_ANALYSIS not in {
        "true_positive", "false_positive", "needs_review", "inconclusive",
    }


def test_a_failed_analysis_reads_as_unanswered():
    assert closure.resolution_from_analysis(None) == "inconclusive"
    assert closure.resolution_from_analysis("") == "inconclusive"
    assert closure.resolution_from_analysis(
        "# Executive Summary\n\n**Verdict: Benign, routine update traffic**\n\nNothing."
    ) == "false_positive"


def test_mttr_runs_from_the_first_alert_not_from_when_we_noticed():
    """An alert that sat in a queue for an hour is an hour of exposure
    whatever the ingest clock says."""
    m = closure.metrics(
        opened_at=T0, created_at=T0 + timedelta(minutes=2), closed_at=T0 + timedelta(minutes=12),
    )
    assert m["detect_seconds"] == 120.0
    assert m["resolve_seconds"] == 720.0
    assert m["open"] is False


def test_a_backfilled_case_is_excluded_from_detection_time():
    """Every case predating this feature has a row written when correlation
    first ran over history. Reporting that arithmetic would put eighteen-day
    "detections" into the average."""
    m = closure.metrics(
        opened_at=T0 - timedelta(days=18), created_at=T0, closed_at=None,
    )
    assert m["detect_seconds"] is None
    assert "backfilled" in m["detect_excluded"]


def test_single_and_multi_alert_cases_are_reported_apart():
    """497 of 884 cases hold one alert. A mean including them is mostly a
    measure of how many single alerts arrived."""
    cases = [
        {"alert_count": 1, "detect_seconds": 10, "resolve_seconds": 60},
        {"alert_count": 1, "detect_seconds": 10, "resolve_seconds": 60},
        {"alert_count": 9, "detect_seconds": 10, "resolve_seconds": 6000},
    ]
    out = closure.summarise(cases, target_seconds=3600)

    assert out["single_alert"]["cases"] == 2
    assert out["single_alert"]["mttr_seconds"] == 60.0
    assert out["multi_alert"]["mttr_seconds"] == 6000.0
    assert out["single_alert"]["sla_met"] == 2
    assert out["multi_alert"]["sla_breached"] == 1


def test_an_open_case_can_already_be_breaching():
    assert closure.sla_state(None, target_seconds=3600, now_open_seconds=4000) == "breached"
    assert closure.sla_state(None, target_seconds=3600, now_open_seconds=3000) == "at_risk"
    assert closure.sla_state(None, target_seconds=3600, now_open_seconds=100) == "open"
    assert closure.sla_state(60, target_seconds=3600) == "met"


# --- the gate on a manual close ---------------------------------------------

def test_the_gate_is_the_written_analysis_not_the_derived_resolution():
    """Measured across all 1,051 spine rows, the candidate conditions disagree
    in both directions: 47 cases have an analysis and no resolution (the
    write-back only fires once a case is closed), and 11 have a resolution and
    no analysis at all (continuations inherit their parent's answer). Gating on
    the resolution would refuse the first set and wave through the second."""
    assert closure.analysis_is_ready(
        narrative_status="completed", narrative_markdown="# Executive Summary\n\nreal text"
    )
    # An analysis that is still being written is not one to sign off on.
    assert not closure.analysis_is_ready(
        narrative_status="running", narrative_markdown="partial"
    )
    assert not closure.analysis_is_ready(
        narrative_status="failed", narrative_markdown="whatever was left"
    )
    assert not closure.analysis_is_ready(narrative_status=None, narrative_markdown="text")


def test_a_completed_analysis_with_no_text_is_not_an_analysis():
    """Both halves are required. A row marked completed whose markdown is empty
    is a write that half-happened, and it must not read as something a person
    can agree with."""
    for empty in ("", "   ", "\n\n", None):
        assert not closure.analysis_is_ready(
            narrative_status="completed", narrative_markdown=empty
        )


def test_a_person_may_not_close_a_case_under_a_non_answer():
    """`expired`, `aged_out` and `awaiting_analysis` say what happened *to* a
    case, not what anyone concluded about it. Offering them as a choice would
    put a non-answer in the same column the answers live in."""
    from app.models.enums import CaseResolution

    choices = {c.value for c in CaseResolution.analyst_choices()}
    assert choices == {"true_positive", "false_positive", "needs_review", "inconclusive"}
    for not_a_verdict in ("expired", "aged_out", "awaiting_analysis"):
        assert CaseResolution(not_a_verdict).value not in choices


def test_the_resolution_vocabulary_has_one_home():
    """It lived as bare strings across the closing job, the API, two migrations
    and the Cases table, which is how `needs_review` came to be reachable in
    the backend with no label anywhere in the UI."""
    from app.models.enums import CaseResolution

    assert CaseResolution.AWAITING_ANALYSIS.value == closure.AWAITING_ANALYSIS
    # The str/value trap: these inherit `str, enum.Enum`, so `str(member)` is
    # the member name. Equality is by value, and `.value` is what reaches a
    # column.
    assert CaseResolution.TRUE_POSITIVE == "true_positive"
    assert str(CaseResolution.TRUE_POSITIVE) != "true_positive"


def test_a_sender_whose_clock_runs_ahead_cannot_open_a_case_that_never_closes():
    """A case opens at its first alert's own event time, and some senders are
    wrong about what time it is.

    Six alerts in this estate are timestamped after the moment we received
    them, the worst ten hours ahead, and case #1127 opened 213 minutes in the
    future. Under a fixed window that case can never become due, because its
    window has not started — the idle timer hid the same fault behind a
    different arithmetic.

    The window runs from the earlier of when the alert says it happened and
    when we recorded the case.
    """
    ahead = T0 + timedelta(hours=3, minutes=30)
    decision = closure.decide(
        [], last_activity_at=ahead, opened_at=ahead,
        created_at=T0 - timedelta(hours=7), now=T0,
    )
    assert decision.due, "a future-dated case must still be answerable"

    # And it is not answered early either: the fallback is a real window, not
    # an escape hatch.
    assert not closure.decide(
        [], last_activity_at=ahead, opened_at=ahead,
        created_at=T0 - timedelta(minutes=2), now=T0,
    ).due


def test_without_a_recorded_time_the_alerts_own_time_is_used():
    """`created_at` is optional, so a caller that does not have it keeps the
    behaviour it had."""
    assert closure.decide(
        [], last_activity_at=T0, opened_at=T0, now=T0 + timedelta(minutes=361),
    ).due
    assert not closure.decide(
        [], last_activity_at=T0, opened_at=T0, now=T0 + timedelta(minutes=359),
    ).due


# --- the anchor, made enforceable --------------------------------------------

def test_the_anchor_is_last_activity_and_moving_it_back_fails_here():
    """This file's header recorded the measurement that chose the anchor —
    "the clock runs on last activity, and that is an 11x difference, not a
    preference" — and the code was later changed to do the opposite while the
    header stayed. The only artefact that knew was a comment, and a comment
    cannot fail.

    So the knowledge is a test. Re-measured on 12,064 memberships against the
    original 11,376: anchoring at the opening stranded 9,731 (80.7%) against
    9,244 (81%); anchoring at the last alert stranded 897 against 821.

    Two assertions, because either alone can be satisfied by the wrong code.
    """
    import inspect

    # Behavioural: a case whose last alert was a minute ago is not quiet,
    # however long it has existed. Under the opening anchor it was due.
    busy = [alert("A", minutes=m) for m in range(0, 600, 5)]
    assert not _decide(busy, last_minutes=599, now_minutes=600).due

    # Structural: the window must be computed from the last alert. A
    # behavioural test alone passes if someone widens the opening window
    # instead of moving the anchor, which is the same bug with a bigger number.
    source = inspect.getsource(closure.decide)
    assert "quiet_for < quiet_period" in source, (
        "the decision must compare the QUIET duration against the window. "
        "Comparing (now - opened_at) is the anchor this test exists to stop "
        "coming back — see the 11x measurement in this file's header."
    )
    assert "open_for < quiet_period" not in source, (
        "that is the opening anchor. It stranded 80.7% of alert memberships "
        "outside their own case and it is why 30 cases carry a disposition "
        "formed on fewer alerts than they hold."
    )


def test_the_window_is_not_shorter_than_the_correlation_gap():
    """The ordering rule, as a test rather than a comment: a case must not be
    able to close while the correlation is still right to give it alerts.
    Below SESSION_GAP, it can."""
    from app.services.alert_session_service import SESSION_GAP

    assert closure.CASE_WINDOW >= SESSION_GAP, (
        f"CASE_WINDOW is {closure.CASE_WINDOW} and SESSION_GAP is "
        f"{SESSION_GAP}. A case closing before the gap that would start a new "
        "one means alerts arrive for a case that is already answered: at ten "
        "minutes against six hours, 9,731 of 12,064 memberships did."
    )
