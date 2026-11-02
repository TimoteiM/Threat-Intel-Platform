"""
Direction and pace: what a case's members did, and how fast.

Both modulate the movement a case already earned. Neither adds points of its
own — pace alone means nothing, and a fast pair of noisy rules is still noise.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.alert_correlation_service import (
    MIN_MEMBERS_FOR_TEMPO,
    SIMULTANEITY_SECONDS,
    progression_of,
    score_case,
    shape_factor,
    tempo_of,
)

T0 = datetime(2026, 8, 20, 9, 0, tzinfo=timezone.utc)


class _Member:
    """A run carrying an event time and evidenced tactics."""

    def __init__(self, offset_seconds: float, tactics: list[str] | None = None):
        self.event_time = T0 + timedelta(seconds=offset_seconds)
        self.created_at = self.event_time
        self.result_attack_assessment = (
            {"additional_techniques": [{"id": "T1", "tactics": tactics}]} if tactics else None
        )


# ── Progression ──────────────────────────────────────────────────────────────

def test_a_forward_chain_scores_near_one():
    members = [
        _Member(0, ["Execution"]),
        _Member(600, ["Persistence"]),
        _Member(1200, ["Impact"]),
    ]
    result = progression_of(members, T0)
    assert result["ratio"] == 1.0
    assert result["transitions"] == 2


def test_the_same_tactics_backwards_score_zero():
    """Order is the whole point: the reverse sequence is not the same case."""
    members = [
        _Member(0, ["Impact"]),
        _Member(600, ["Persistence"]),
        _Member(1200, ["Execution"]),
    ]
    assert progression_of(members, T0)["ratio"] == 0.0


def test_staying_in_one_tactic_counts_as_forward():
    """Two alerts in the same stage are not evidence of going backwards."""
    members = [_Member(0, ["Execution"]), _Member(600, ["Execution"])]
    assert progression_of(members, T0)["ratio"] == 1.0


def test_near_simultaneous_members_are_unordered_not_penalised():
    """
    Sensors batch and clocks drift by more than a minute between hosts. Scoring
    a sub-minute pair either way turns jitter into a claim about the attacker.
    """
    members = [
        _Member(0, ["Impact"]),
        _Member(SIMULTANEITY_SECONDS - 1, ["Execution"]),   # unordered, skipped
        _Member(3600, ["Impact"]),                          # ordered, forward
    ]
    result = progression_of(members, T0)
    assert result["unordered"] == 1
    assert result["transitions"] == 1
    assert result["ratio"] == 1.0


def test_members_without_evidenced_tactics_carry_no_direction():
    """
    A claimed tactic has never been corroborated here, so a direction computed
    from one would be a direction through the rules' imagination.
    """
    members = [_Member(0), _Member(600), _Member(1200)]
    result = progression_of(members, T0)
    assert result["ratio"] is None
    assert result["staged_members"] == 0


# ── Tempo ────────────────────────────────────────────────────────────────────

def test_tempo_is_unknown_below_the_member_floor():
    """
    Two alerts produce one interval, and one interval is not a pace. A confident
    "tight burst" read off a single gap is a number that looks like measurement.
    """
    members = [_Member(0), _Member(30)]
    result = tempo_of(members, T0)
    assert result["kind"] == "unknown"
    assert result["median_gap_seconds"] is None
    assert str(MIN_MEMBERS_FOR_TEMPO) in result["reason"]


def test_a_tight_burst_is_recognised():
    members = [_Member(i * 20) for i in range(5)]
    assert tempo_of(members, T0)["kind"] == "burst"


def test_a_slow_case_reads_as_dwell():
    members = [_Member(i * 6 * 3600) for i in range(4)]
    assert tempo_of(members, T0)["kind"] == "dwell"


def test_one_long_pause_does_not_turn_a_burst_into_a_dwell():
    """The median is used precisely so an overnight gap cannot rewrite the pace."""
    members = [_Member(0), _Member(20), _Member(40), _Member(60), _Member(20 * 3600)]
    assert tempo_of(members, T0)["kind"] == "burst"


# ── The interaction ──────────────────────────────────────────────────────────

def test_burst_and_forward_progression_compound():
    fast_forward = shape_factor({"ratio": 1.0}, {"kind": "burst"})
    slow_forward = shape_factor({"ratio": 1.0}, {"kind": "dwell"})
    assert fast_forward > slow_forward
    assert fast_forward > 1.5


def test_low_and_slow_is_never_penalised_for_being_slow():
    """A chain that advances over three days is still a chain."""
    assert shape_factor({"ratio": 1.0}, {"kind": "dwell"}) > 1.0
    assert shape_factor({"ratio": 1.0}, {"kind": "dwell"}) >= shape_factor(
        {"ratio": 1.0}, {"kind": "steady"}
    )


def test_unknown_direction_is_neutral_not_a_penalty():
    """An absence of direction is not evidence of a bad one."""
    assert shape_factor({"ratio": None}, {"kind": "unknown"}) == 1.0


def test_a_burst_of_noise_gains_nothing():
    """
    Pace scales movement, never the total — so two rules firing fast with no
    tactics between them multiply a movement of zero and stay as boring as they
    were. This is why tempo is not an additive bonus.
    """
    noisy_fast, _ = score_case(
        distinct_rules=2, tactics=set(), max_risk=0, verdicts=[],
        shape=shape_factor({"ratio": None}, {"kind": "burst"}),
    )
    noisy_slow, _ = score_case(
        distinct_rules=2, tactics=set(), max_risk=0, verdicts=[],
        shape=shape_factor({"ratio": None}, {"kind": "dwell"}),
    )
    assert noisy_fast == noisy_slow


def test_a_fast_forward_chain_outscores_the_same_chain_shuffled():
    tactics = {"Execution", "Persistence", "Credential Access", "Impact"}
    directed, _ = score_case(
        distinct_rules=2, tactics=tactics, max_risk=0, verdicts=[],
        shape=shape_factor({"ratio": 1.0}, {"kind": "burst"}),
    )
    shuffled, _ = score_case(
        distinct_rules=2, tactics=tactics, max_risk=0, verdicts=[],
        shape=shape_factor({"ratio": 0.0}, {"kind": "steady"}),
    )
    assert directed > shuffled


# ── The kill chain must know the vocabulary ATT&CK actually emits ────────────

from app.services.alert_correlation_service import TACTIC_ORDER, _TACTIC_RANK


def test_the_current_attack_tactic_names_all_rank():
    """
    ATT&CK v19.2 split Defense Evasion into Stealth and Defense Impairment, and
    the generated catalogue emits the new names. While only the old spelling
    ranked, every Stealth tactic was invisible to movement and to progression —
    a real case reached Execution and Stealth and scored as though it had
    reached one tactic. Nothing failed; the score was just quietly lower.
    """
    for name in ("Stealth", "Defense Impairment", "Execution", "Impact"):
        assert name.casefold() in _TACTIC_RANK, name


def test_retired_spellings_still_rank_where_their_replacement_sits():
    """Assessments stored before the rename still carry the old name."""
    assert _TACTIC_RANK["defense evasion"] == _TACTIC_RANK["stealth"]


def test_stealth_ranks_between_privilege_escalation_and_credential_access():
    assert (
        _TACTIC_RANK["privilege escalation"]
        < _TACTIC_RANK["stealth"]
        < _TACTIC_RANK["credential access"]
    )


def test_an_unranked_tactic_is_counted_and_named():
    """
    The alias table patches the past; it does not protect the future. MITRE will
    revise the taxonomy again and the failure is silent — a new name ranks
    nowhere and zeroes movement for every case reaching it, which is how the
    Stealth rename cost a real case 25 points for a month without one error.
    """
    from app.services.alert_correlation_service import (
        _UNRANKED_TACTICS,
        unranked_tactics_seen,
    )

    _UNRANKED_TACTICS.clear()
    score_case(
        distinct_rules=2, tactics={"Execution", "Tactic MITRE Invents In 2027"},
        max_risk=0, verdicts=[],
    )
    assert unranked_tactics_seen() == {"Tactic MITRE Invents In 2027": 1}


def test_known_tactics_are_not_reported_as_unranked():
    from app.services.alert_correlation_service import _UNRANKED_TACTICS, unranked_tactics_seen

    _UNRANKED_TACTICS.clear()
    score_case(distinct_rules=2, tactics={"Execution", "Stealth", "Defense Evasion"},
               max_risk=0, verdicts=[])
    assert unranked_tactics_seen() == {}
