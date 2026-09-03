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


# ── The baseline must always dwarf the window it judges ──────────────────────

from app.services.alert_baseline_service import (
    BASELINE_WINDOW_MULTIPLE,
    SURPRISE_BASELINE_DAYS,
    PairBaseline,
    baseline_window_days,
)


def test_the_baseline_widens_with_the_query_window():
    """
    A case is excluded from its own history, so it eats a slice of its baseline
    sized by the query window. Fixed at 30 days that is fine at 48h and inert at
    30d — and it degrades continuously between, so the failure is silent.
    """
    assert baseline_window_days(48) == SURPRISE_BASELINE_DAYS
    assert baseline_window_days(24 * 7) == 7 * BASELINE_WINDOW_MULTIPLE
    assert baseline_window_days(24 * 30) == 30 * BASELINE_WINDOW_MULTIPLE


def test_a_case_never_owns_much_of_its_own_baseline():
    """The invariant, asserted at every window someone might query."""
    for hours in (1, 24, 48, 24 * 7, 24 * 30, 24 * 90):
        query_days = max(1, -(-hours // 24))
        assert query_days / baseline_window_days(hours) <= 1 / 10


def test_the_floor_still_applies_at_short_windows():
    assert baseline_window_days(1) == SURPRISE_BASELINE_DAYS


# ── A cold baseline says so ──────────────────────────────────────────────────

def test_a_baseline_of_single_day_pairs_is_not_mature():
    """
    A pair seen on exactly one day discounts nothing once that day is excluded
    as the case's own — so however many such pairs exist, no score can fall.
    """
    cold = PairBaseline(
        pairs={("s", "c", "h", "a", "b"): {DAY}},
        window_days=30, runs_considered=100, observed_days=12,
    )
    assert cold.pairs_with_history == 0
    assert cold.is_mature is False
    assert "young baseline" in cold.as_dict()["note"]


def test_a_baseline_with_repeat_pairings_is_mature_and_says_nothing():
    warm = PairBaseline(
        pairs={("s", "c", "h", "a", "b"): {DAY, date(2026, 8, 1)}},
        window_days=30, runs_considered=100, observed_days=12,
    )
    assert warm.is_mature is True
    assert warm.as_dict()["note"] is None


def test_rules_that_never_pair_are_named():
    """
    A rule that fires regularly and never once alongside another on the same
    host and day can never contribute to a correlated case — a case needs two
    distinct rules. Every investigation it triggers is collector budget spent on
    something correlation will never read, which makes it the first candidate
    for suppression. On this estate that is rule 1002, two-thirds of all volume.
    """
    baseline = PairBaseline(
        pairs={}, window_days=30, runs_considered=500, observed_days=6,
        non_pairing_rules=(("1002", 6), ("60104", 5)),
    )
    named = baseline.as_dict()["non_pairing_rules"]
    assert named[0] == {"rule": "1002", "days_seen": 6}
    assert len(named) == 2
