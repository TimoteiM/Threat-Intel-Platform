"""What may be proposed as an exclusion, and what may never be.

Every test here names a way a plausible implementation silences a real
detection. The feature's whole value is that an analyst can accept a
recommendation without re-deriving it, which only holds if the unsafe
candidates were removed rather than ranked lower.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.services.alert_tuning_service import (
    CONDITION_FIELDS,
    clear_tuning_cache,
    MAX_VALUE_PREVALENCE,
    _Alert,
    _best_conditions,
    _prevalence,
    wazuh_rule_xml,
)

ANCHOR = {"rule_id": "60104"}


def alert(actionable: bool, **fields: str) -> _Alert:
    return _Alert(
        run_id=f"r{len(fields)}{actionable}{fields}",
        verdict="malicious" if actionable else "benign",
        actionable=actionable,
        when=datetime(2026, 8, 1, tzinfo=timezone.utc),
        fields={"rule_id": "60104", **fields},
    )


# —— what may never appear in a condition ————————————————————————————————

def test_severity_is_never_a_condition_field():
    """The sender's severity is wrong in both directions on this estate."""
    for name in ("event_priority", "event_severity", "event_log_level"):
        assert name not in CONDITION_FIELDS


def test_rule_name_is_never_a_condition_field():
    """One-to-one with rule_id, so it reads as narrowing while adding nothing."""
    assert "rule_name" not in CONDITION_FIELDS
    assert "rule_id" in CONDITION_FIELDS


def test_a_condition_that_would_silence_an_actionable_alert_is_discarded():
    noise = [alert(False, agent="A", event_id="4825") for _ in range(4)]
    actionable = [alert(True, agent="A", event_id="4825")]
    found = _best_conditions(noise, actionable, anchor=ANCHOR)
    assert found == [], "a leaking candidate must be removed, not ranked lower"


def test_a_leak_on_one_value_does_not_block_a_clean_one():
    noise = [
        alert(False, agent="A", event_id="4825"),
        alert(False, agent="B", event_id="4825"),
    ]
    actionable = [alert(True, agent="A", event_id="4825")]
    found = _best_conditions(noise, actionable, anchor=ANCHOR)
    assert found, "agent B is clean and should still be offered"
    for condition in found:
        assert condition.match_fields.get("agent") != "A"
        assert condition.leaked == 0


# —— narrowest, not broadest ——————————————————————————————————————————————

def test_the_narrowest_condition_wins_over_the_bare_rule():
    """The bug this ranking was written to fix.

    Sorting by "covers most, fewest fields" makes muting the whole rule win
    every time, because a rule always covers all of its own noise with one
    field. That produced "mute Kerberoasting everywhere" off five benign alerts.
    """
    noise = [alert(False, agent="ExpDC001") for _ in range(5)]
    found = _best_conditions(noise, [], anchor=ANCHOR)
    best = found[0]
    assert best.match_fields == {"rule_id": "60104", "agent": "ExpDC001"}
    assert best.covered == 5


def test_the_bare_rule_is_still_offered_last():
    noise = [alert(False, agent="ExpDC001") for _ in range(5)]
    found = _best_conditions(noise, [], anchor=ANCHOR)
    bare = [c for c in found if c.match_fields == ANCHOR]
    assert bare, "the broadest option should remain available"
    assert found.index(bare[0]) > 0, "but never as the proposal"
    assert bare[0].notes, "and it must say what it costs"


def test_a_value_common_across_the_estate_cannot_narrow_anything():
    """`manager = Siembiot` is true of every alert ever received here."""
    noise = [alert(False, manager="Siembiot", agent="A") for _ in range(4)]
    prevalence = {("manager", "Siembiot"): 1.0, ("agent", "A"): 0.01}
    found = _best_conditions(noise, [], anchor=ANCHOR, prevalence=prevalence)
    for condition in found:
        assert "manager" not in condition.match_fields


def test_a_selective_value_is_allowed():
    noise = [alert(False, agent="A") for _ in range(4)]
    prevalence = {("agent", "A"): MAX_VALUE_PREVALENCE - 0.01}
    found = _best_conditions(noise, [], anchor=ANCHOR, prevalence=prevalence)
    assert any("agent" in c.match_fields for c in found)


def test_no_noise_produces_no_recommendation():
    assert _best_conditions([], [alert(True, agent="A")], anchor=ANCHOR) == []


# —— prevalence ————————————————————————————————————————————————————————————

def test_prevalence_is_measured_across_the_whole_corpus():
    corpus = [{"manager": "S", "agent": "A"}, {"manager": "S", "agent": "B"}]
    result = _prevalence(corpus)
    assert result[("manager", "S")] == 1.0
    assert result[("agent", "A")] == 0.5


def test_prevalence_of_nothing_is_empty():
    assert _prevalence([]) == {}


# —— the generated Wazuh rule ——————————————————————————————————————————————

def test_the_generated_rule_id_is_inside_wazuh_local_range():
    for rule_id in ("1002", "110400", "60104", "9"):
        xml = wazuh_rule_xml(rule_id, {"rule_id": rule_id}, reason="x")
        generated = int(xml.split('<rule id="')[1].split('"')[0])
        assert 100000 <= generated <= 120000, generated


def test_the_generated_rule_id_is_stable_across_calls():
    """hash() is randomised per process; a regenerated rule must not move."""
    first = wazuh_rule_xml("110400", {"rule_id": "110400"}, reason="x")
    second = wazuh_rule_xml("110400", {"rule_id": "110400"}, reason="x")
    assert first == second


def test_the_rule_silences_rather_than_drops():
    xml = wazuh_rule_xml("110400", {"rule_id": "110400", "agent": "DC1"}, reason="x")
    assert 'level="0"' in xml, "level 0 keeps the event searchable in the archive"
    assert "<if_sid>110400</if_sid>" in xml
    assert "<hostname>DC1</hostname>" in xml


def test_the_reason_is_escaped_into_the_xml():
    xml = wazuh_rule_xml("1", {"rule_id": "1"}, reason='a & b <c> "d"')
    assert "&amp;" in xml and "&lt;c&gt;" in xml


# —— the sampling and caching that made this endpoint usable ——————————————

def test_prevalence_separates_a_constant_from_a_specific_value():
    """What the sample size actually has to decide.

    The threshold only has to tell `manager = Siembiot` (true of nearly every
    alert) from a specific event_id (true of a handful). Three hundred
    observations settle that far more tightly than the 40% line needs, which is
    why the sample was cut from the whole corpus — each parse is regex over raw
    log text, so the sample size is the cost.
    """
    corpus = [{"manager": "S", "event_id": str(n)} for n in range(300)]
    result = _prevalence(corpus)
    assert result[("manager", "S")] > MAX_VALUE_PREVALENCE
    assert result[("event_id", "7")] < MAX_VALUE_PREVALENCE


def test_the_cache_can_be_cleared():
    """The TTL cache must be droppable, or tests read each other's answers."""
    clear_tuning_cache()
    from app.services.alert_tuning_service import _CACHE
    assert _CACHE == {}
