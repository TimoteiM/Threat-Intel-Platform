"""
Alert-level suppression: matching an alert by what it is, not what it contains.
"""

from __future__ import annotations

from app.services.exclusion_service import ExclusionMatcher

NOISY = {
    "id": "e1", "indicator_type": "alert", "reason": "Wazuh 1002 status noise",
    "match_fields": {"rule_id": "1002", "agent": "exprevpxy002", "event_priority": "Low"},
}


def test_all_fields_must_match():
    """
    A partial match is not a match. "rule 1002 AND this agent AND Low" exists
    precisely so the same rule from another agent is still investigated, and
    honouring part of it would silence exactly what the analyst kept.
    """
    matcher = ExclusionMatcher([NOISY])
    assert matcher.match_alert(
        {"rule_id": "1002", "agent": "exprevpxy002", "event_priority": "Low"}
    ) is not None
    # Same rule, different agent — still investigated.
    assert matcher.match_alert(
        {"rule_id": "1002", "agent": "OTHER-HOST", "event_priority": "Low"}
    ) is None
    # Same rule and agent, escalated priority — still investigated.
    assert matcher.match_alert(
        {"rule_id": "1002", "agent": "exprevpxy002", "event_priority": "High"}
    ) is None


def test_extra_fields_on_the_alert_do_not_prevent_a_match():
    """The exclusion names conditions, not the whole alert."""
    matcher = ExclusionMatcher([NOISY])
    assert matcher.match_alert(
        {"rule_id": "1002", "agent": "exprevpxy002", "event_priority": "Low",
         "manager": "Siembiot", "event_name": "Web Request"}
    ) is not None


def test_matching_ignores_case_and_padding():
    """A rule id arrives as "1002" or 1002; an agent's case is nobody's decision."""
    matcher = ExclusionMatcher([NOISY])
    assert matcher.match_alert(
        {"rule_id": " 1002 ", "agent": "EXPREVPXY002", "event_priority": "low"}
    ) is not None


def test_a_missing_field_never_matches():
    """Absent is not equal to anything, or an exclusion would widen silently."""
    matcher = ExclusionMatcher([NOISY])
    assert matcher.match_alert({"rule_id": "1002", "agent": "exprevpxy002"}) is None


def test_alert_rows_survive_the_matcher_being_built():
    """
    An alert exclusion has no normalized_value, and the loader dropped every row
    without one — so the whole type was silently discarded at construction.
    """
    matcher = ExclusionMatcher([NOISY])
    assert bool(matcher) is True
    assert len(matcher) == 1


def test_indicator_exclusions_are_unaffected():
    rows = [NOISY, {"id": "e2", "indicator_type": "domain", "normalized_value": "corp.test",
                    "reason": "ours", "match_subdomains": True}]
    matcher = ExclusionMatcher(rows)
    assert matcher.match_alert({"rule_id": "1002", "agent": "exprevpxy002", "event_priority": "Low"})
    assert len(matcher) == 2


def test_an_exclusion_with_no_conditions_matches_nothing():
    """A blank predicate would otherwise silence every alert on the platform."""
    matcher = ExclusionMatcher([{"id": "e3", "indicator_type": "alert", "match_fields": {}}])
    assert matcher.match_alert({"rule_id": "1002"}) is None


def test_the_row_adapter_carries_the_predicate():
    """
    _as_dict names its fields explicitly, so a new column is invisible to the
    matcher until it is added there. When match_fields was missing, every alert
    exclusion loaded from the database was dropped at construction: the row
    existed, the UI listed it, and it silenced nothing.
    """
    from types import SimpleNamespace
    from app.services.exclusion_service import _as_dict

    row = SimpleNamespace(
        id="e9", indicator_type="alert", value="rule_id=1002",
        normalized_value='{"rule_id":"1002"}', reason="noise", added_by=None,
        match_subdomains=False, match_fields={"rule_id": "1002"},
    )
    assert _as_dict(row)["match_fields"] == {"rule_id": "1002"}
    # ...and the matcher built from that row actually matches.
    assert ExclusionMatcher([row]).match_alert({"rule_id": "1002"}) is not None
