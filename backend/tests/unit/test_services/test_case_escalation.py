"""Which crossings speak, and which stay quiet.

Escalation fires once and then never re-examines itself, so a wrong decision
here is permanent and invisible. Every test names the specific way a plausible
implementation would page someone for nothing, or say nothing when it should.
"""

from __future__ import annotations

import pytest

from app.services.alert_case_escalation import (
    EVENT_ESCALATED,
    EVENT_OPENED_HIGH,
    decide_emission,
    record_emission,
)
from app.services.alert_case_store import SnapshotOutcome

KEY = "a" * 64
THRESHOLDS = {
    "escalation_delta": 20,
    "escalation_min_score": 50,
    "opened_high_min_score": 50,
}


class _Snapshot:
    def __init__(self):
        self.escalated = False
        self.emitted_event = None
        self.escalated_from_score = None
        self.escalated_to_score = None
        self.escalated_delta_config = None
        self.escalated_min_score_config = None


class _DB:
    """Answers only the one query the decision makes: is this key a survivor?"""

    def __init__(self, reborn=False):
        self.reborn = reborn

    async def execute(self, _query):
        reborn = self.reborn

        class _R:
            def scalar_one_or_none(self):
                return ("dead" * 16) if reborn else None

        return _R()


def _outcome(**kw):
    kw.setdefault("snapshot", _Snapshot())
    kw.setdefault("is_baseline", False)
    kw.setdefault("previous_score", None)
    kw.setdefault("had_prior_any_version", False)
    kw.setdefault("version_baseline_score", None)
    kw.setdefault("last_emission_score", None)
    return SnapshotOutcome(**kw)


async def _decide(outcome, score, db=None, **over):
    return await decide_emission(
        db or _DB(), case_key=KEY, outcome=outcome, score=score,
        score_version="v1", **{**THRESHOLDS, **over},
    )


# —— nothing moved ————————————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_an_unchanged_case_says_nothing():
    """A recompute that emitted here would be reporting a page load."""
    assert await _decide(_outcome(snapshot=None), 95) is None


# —— opened_high: the three exclusions ————————————————————————————————————

@pytest.mark.asyncio
async def test_a_genuinely_new_high_case_opens_high():
    event = await _decide(_outcome(is_baseline=True), 96)
    assert event is not None and event.event == EVENT_OPENED_HIGH
    assert event.reference_score is None, "arrival is not a comparison"
    assert event.delta_config is None


@pytest.mark.asyncio
async def test_a_new_case_below_the_arrival_bar_stays_quiet():
    assert await _decide(_outcome(is_baseline=True), 40) is None


@pytest.mark.asyncio
async def test_a_version_rebaseline_never_opens_high():
    """The deploy flood, coming through the other door.

    A score_version bump writes one baseline per existing case, each of which is
    a first snapshot *at that version* carrying a high score. Gating on the
    version-scoped question would page once per existing high case the first
    time new weights ship.
    """
    outcome = _outcome(is_baseline=True, had_prior_any_version=True)
    assert await _decide(outcome, 96) is None


@pytest.mark.asyncio
async def test_a_reborn_key_never_opens_high():
    """Supersession is a new identity, not a new incident.

    A late arrival that re-anchors a session produces a case_key with no prior
    snapshot at any version — passing the first gate — while being the same
    intrusion the consumer already knows about under its old key.
    """
    outcome = _outcome(is_baseline=True)
    assert await _decide(outcome, 96, db=_DB(reborn=True)) is None


@pytest.mark.asyncio
async def test_the_arrival_bar_is_its_own_lever():
    """opened_high must not read the escalation floor."""
    outcome = _outcome(is_baseline=True)
    assert await _decide(outcome, 70, opened_high_min_score=90) is None
    assert await _decide(outcome, 70, opened_high_min_score=60) is not None


# —— escalated: measured from the last emission ———————————————————————————

@pytest.mark.asyncio
async def test_a_climb_past_the_delta_escalates():
    outcome = _outcome(version_baseline_score=40)
    event = await _decide(outcome, 75)
    assert event is not None and event.event == EVENT_ESCALATED
    assert event.reference_score == 40


@pytest.mark.asyncio
async def test_a_climb_under_the_delta_stays_quiet():
    assert await _decide(_outcome(version_baseline_score=40), 55) is None


@pytest.mark.asyncio
async def test_a_low_case_never_escalates_however_far_it_climbed():
    """5 -> 45 is arithmetic, not an incident."""
    assert await _decide(_outcome(version_baseline_score=5), 45) is None


@pytest.mark.asyncio
async def test_the_reference_is_the_last_emission_not_the_last_snapshot():
    outcome = _outcome(version_baseline_score=40, last_emission_score=90)
    assert await _decide(outcome, 100) is None, "10 above the last emission is not 60 above the baseline"


@pytest.mark.asyncio
async def test_emitting_twice_at_the_same_score_is_impossible():
    """Idempotency comes from a stored score, never from a flag."""
    outcome = _outcome(version_baseline_score=40, last_emission_score=90)
    assert await _decide(outcome, 90) is None


@pytest.mark.asyncio
async def test_lowering_the_delta_surfaces_a_missed_crossing():
    """The reason the provenance columns exist.

    40 -> 70 happened while the delta was 40, so nothing was emitted. Comparing
    against the previous snapshot afterwards would measure 70 against 70 and
    stay silent for ever. Measuring from the last emission — here, none, so the
    version's baseline — surfaces it once the threshold is lowered.
    """
    outcome = _outcome(version_baseline_score=40, last_emission_score=None)
    assert await _decide(outcome, 70, escalation_delta=40) is None
    event = await _decide(outcome, 70, escalation_delta=20)
    assert event is not None and event.reference_score == 40


@pytest.mark.asyncio
async def test_no_comparison_point_means_no_escalation():
    assert await _decide(_outcome(), 95) is None


# —— the record ————————————————————————————————————————————————————————————

@pytest.mark.asyncio
async def test_an_emission_records_what_it_was_measured_against():
    outcome = _outcome(version_baseline_score=40)
    event = await _decide(outcome, 75)
    record_emission(outcome, event)
    row = outcome.snapshot
    assert row.escalated is True
    assert row.emitted_event == EVENT_ESCALATED
    assert (row.escalated_from_score, row.escalated_to_score) == (40, 75)
    # The thresholds in force, so a later config edit can still answer
    # "have we already fired for this crossing".
    assert row.escalated_delta_config == 20
    assert row.escalated_min_score_config == 50


@pytest.mark.asyncio
async def test_an_arrival_is_recorded_as_an_arrival():
    outcome = _outcome(is_baseline=True)
    event = await _decide(outcome, 96)
    record_emission(outcome, event)
    assert outcome.snapshot.emitted_event == EVENT_OPENED_HIGH
    assert outcome.snapshot.escalated_from_score is None
    assert outcome.snapshot.escalated_delta_config is None
