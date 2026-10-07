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


# --- the timer ---------------------------------------------------------------

def test_a_case_still_receiving_alerts_is_not_answered():
    members = [alert("A"), alert("A", minutes=3)]
    assert not _decide(members, last_minutes=3, now_minutes=8).due


def test_a_case_quiet_for_the_period_is_answered():
    members = [alert("A"), alert("A", minutes=3)]
    decision = _decide(members, last_minutes=3, now_minutes=14)
    assert decision.due
    assert decision.reason == "quiet for the standard period"


def test_the_clock_runs_on_the_last_alert_not_the_first():
    """The 11x finding. A case open for an hour but active two minutes ago is
    not finished; one open for twelve minutes and quiet for eleven is."""
    busy = [alert("A", minutes=m) for m in range(0, 60, 5)]
    assert not _decide(busy, last_minutes=55, now_minutes=57, opened_minutes=0).due

    brief = [alert("A")]
    assert _decide(brief, last_minutes=0, now_minutes=11).due


# --- the escalation hold -----------------------------------------------------

def test_a_case_still_producing_new_detections_is_held():
    """The protection for multi-stage attacks: p95 of within-case gaps is 29
    minutes, so ten minutes of quiet is not evidence that an attack is over
    while it is still producing kinds of activity it had not produced."""
    members = [alert("recon"), alert("credential access", minutes=8)]
    decision = _decide(members, last_minutes=8, now_minutes=20)
    assert not decision.due
    assert decision.reason == "still producing new detections"
    assert decision.quiet_period == closure.ESCALATING_QUIET_PERIOD


def test_the_hold_ends_once_it_has_been_quiet_for_the_longer_period():
    members = [alert("recon"), alert("credential access", minutes=8)]
    assert _decide(members, last_minutes=8, now_minutes=45).due


def test_repeating_one_detection_is_noise_and_earns_no_hold():
    """A host firing the same rule three hundred times is noisy, not
    escalating. Holding its case open would hold it open for ever."""
    members = [alert("A", minutes=m) for m in range(0, 30, 2)]
    decision = _decide(members, last_minutes=28, now_minutes=40)
    assert decision.due
    assert decision.reason == "quiet for the standard period"


def test_a_case_cannot_be_held_open_for_ever_by_escalation():
    """Still escalating — a new detection fifteen minutes ago — and quiet for
    longer than the base period, but open past the maximum hold. It is
    answered on what it has, and whatever comes next continues it."""
    members = [alert("stage-1"), alert("stage-2", minutes=370)]
    decision = _decide(members, last_minutes=370, now_minutes=385, opened_minutes=0)

    assert closure.is_escalating(members, now=T0 + timedelta(minutes=385))
    assert decision.quiet_for < closure.ESCALATING_QUIET_PERIOD
    assert decision.due
    assert "maximum" in decision.reason


def test_a_single_alert_case_is_never_escalating():
    assert not closure.is_escalating([alert("A")], now=T0)


# --- what happens to late alerts ---------------------------------------------

def test_a_straggler_repeating_a_known_detection_is_appended_silently():
    """99% of late alerts. Re-answering would spend a model call to produce
    the same sentence."""
    members = [alert("A"), alert("A", minutes=30)]
    answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=40),
    )
    assert len(answered) == 1
    assert len(late.appended) == 1
    assert not late.needs_continuation


def test_a_straggler_with_a_new_detection_starts_a_continuation():
    """The other 1%, and the only case worth paying for."""
    members = [alert("A"), alert("lateral movement", minutes=30)]
    answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=40),
    )
    assert late.needs_continuation
    assert [m.detection_name for m in late.continuation] == ["lateral movement"]
    assert late.new_detections == {"lateral movement"}


def test_everything_after_the_new_detection_goes_with_it():
    """Once a case has moved on, its later activity belongs to the part that
    moved — including repeats of the original detection."""
    members = [
        alert("A"), alert("lateral movement", minutes=30), alert("A", minutes=35),
    ]
    _answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=40),
    )
    assert len(late.continuation) == 2
    assert late.appended == []


def test_nothing_arriving_after_closure_means_nothing_to_do():
    members = [alert("A"), alert("A", minutes=3)]
    answered, late = closure.split_after_closure(
        members, closed_at=T0 + timedelta(minutes=10), now=T0 + timedelta(minutes=20),
    )
    assert len(answered) == 2
    assert late.appended == [] and not late.needs_continuation


# --- resolutions and metrics -------------------------------------------------

def test_a_resolution_is_how_an_analyst_closes_a_case():
    assert closure.resolution_for(verdict="malicious", risk_score=90) == "true_positive"
    assert closure.resolution_for(verdict="benign", risk_score=5) == "false_positive"
    assert closure.resolution_for(verdict="suspicious", risk_score=50) == "needs_review"


def test_unknown_is_not_quietly_recorded_as_either():
    """"Inconclusive" is a real outcome. Filing it as a false positive is how
    a metric starts to look good by losing the cases it could not answer."""
    assert closure.resolution_for(verdict=None, risk_score=None) == "inconclusive"
    assert closure.resolution_for(verdict="unknown", risk_score=40) == "inconclusive"


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
