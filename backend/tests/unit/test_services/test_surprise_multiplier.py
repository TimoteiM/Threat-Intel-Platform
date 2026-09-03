"""
Familiarity as a multiplier: how ordinary is this combination on this host.

The raw score asks how alarming a case's shape is. It cannot ask whether that
shape is ordinary here — and two rules that co-fire on a host every day are a
property of the estate, not evidence about tonight.
"""

from __future__ import annotations

from datetime import date

from app.services.alert_baseline_service import (
    SURPRISE_FLOOR,
    aggregate_surprise,
    case_surprise,
    pair_surprise,
)

DAY = date(2026, 8, 20)
SCOPE = {"source": "Siembiot", "client": "unknown", "host": "SRV-01"}


def test_a_never_seen_pairing_is_fully_surprising():
    assert pair_surprise(0) == 1.0


def test_familiarity_decays_with_the_days_seen():
    assert pair_surprise(1) == 0.5
    assert pair_surprise(29) < 0.05


def test_the_multiplier_never_reaches_zero():
    """
    A pure 1/(1+n) drives a pair seen fifty times to 0.02 and erases any case
    built on familiar rules. But an attacker using the tools already on the box
    produces exactly that — boring rules in an alarming sequence — so the floor
    keeps it heavily discounted rather than silenced.
    """
    assert aggregate_surprise([0.02, 0.02, 0.02]) == SURPRISE_FLOOR
    assert aggregate_surprise([0.0]) == SURPRISE_FLOOR
    assert SURPRISE_FLOOR > 0


def test_one_novel_pair_is_not_averaged_into_oblivion():
    """
    The arithmetic mean would bury it at 0.29 and `max` would declare the whole
    case novel at 1.0. The generalised mean puts it between, nearer the
    surprising end, because that pair may be the entire signal.
    """
    mixed = aggregate_surprise([1.0, 0.05, 0.05, 0.05])
    assert 0.55 < mixed < 0.75
    assert mixed > sum([1.0, 0.05, 0.05, 0.05]) / 4     # beats the plain mean
    assert mixed < 1.0                                   # but is not `max`


def test_an_all_novel_case_is_undiscounted():
    assert aggregate_surprise([1.0, 1.0]) == 1.0


def test_no_pairs_is_neutral_not_zero():
    """One rule cannot form a case; this is absence of evidence about
    familiarity, not evidence of familiarity."""
    assert aggregate_surprise([]) == 1.0


def test_a_case_is_not_measured_against_itself():
    """
    The alerts being scored sit in the baseline they are scored against. Without
    subtracting the case's own days, a burst would quietly make itself look
    familiar — and the more alerts an incident generated, the less surprising it
    would appear.
    """
    baseline = {("Siembiot", "unknown", "SRV-01", "rule-a", "rule-b"): {DAY}}
    included, detail = case_surprise(
        baseline, **SCOPE, rules=["rule-a", "rule-b"], own_days={DAY}
    )
    assert detail[0]["cooccurrence_days"] == 0
    assert included == 1.0

    # The same pair with genuine prior history is discounted.
    baseline[("Siembiot", "unknown", "SRV-01", "rule-a", "rule-b")] = {
        DAY, date(2026, 8, 1), date(2026, 8, 2), date(2026, 8, 3)
    }
    discounted, detail = case_surprise(
        baseline, **SCOPE, rules=["rule-a", "rule-b"], own_days={DAY}
    )
    assert detail[0]["cooccurrence_days"] == 3
    assert discounted < 0.3


def test_familiarity_is_scoped_to_the_host():
    """A pairing routine on a build server says nothing about a domain
    controller."""
    baseline = {("Siembiot", "unknown", "OTHER-HOST", "rule-a", "rule-b"): {DAY, date(2026, 8, 1)}}
    value, _ = case_surprise(baseline, **SCOPE, rules=["rule-a", "rule-b"], own_days=set())
    assert value == 1.0


def test_every_pair_in_a_multi_rule_case_is_considered():
    baseline: dict = {}
    _value, detail = case_surprise(
        baseline, **SCOPE, rules=["a", "b", "c"], own_days=set()
    )
    assert len(detail) == 3      # ab, ac, bc
