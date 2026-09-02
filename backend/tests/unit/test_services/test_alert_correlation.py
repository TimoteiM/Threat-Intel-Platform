"""
Case scoring: what makes several alerts one event worth raising.
"""

from __future__ import annotations

from app.services.alert_correlation_service import _tactics_of, score_case


def test_volume_alone_does_not_make_a_case():
    """Forty repeats of one noisy rule is one noisy rule."""
    score, reasons = score_case(distinct_rules=1, tactics=set(), max_risk=10, verdicts=["suspicious"])
    assert score == 0
    assert reasons == []


def test_independent_detections_agreeing_is_the_strongest_signal():
    """
    It is the one signal that does not depend on ATT&CK data being right — and
    in this deployment no ATT&CK claim has ever been corroborated.
    """
    score, reasons = score_case(distinct_rules=2, tactics=set(), max_risk=0, verdicts=[])
    assert score >= 30
    assert any("independent detections" in r for r in reasons)


def test_travelling_across_the_kill_chain_scores_above_sitting_still():
    near, _ = score_case(distinct_rules=2, tactics={"Execution", "Persistence"}, max_risk=0, verdicts=[])
    far, reasons = score_case(distinct_rules=2, tactics={"Execution", "Impact"}, max_risk=0, verdicts=[])
    assert far > near
    assert any("advances from" in r for r in reasons)


def test_claimed_tactics_are_worth_less_than_evidenced_ones():
    """
    A rule's mapping is its author's hypothesis, and the mismatch view shows
    rules claiming Valid Accounts where the evidence is PowerShell. Worth
    something — it is the only ATT&CK signal for attacks the collectors cannot
    reach — but never as much as a technique the investigation established.
    """
    evidenced, _ = score_case(
        distinct_rules=2, tactics={"Execution", "Credential Access", "Impact"}, max_risk=0, verdicts=[]
    )
    claimed, reasons = score_case(
        distinct_rules=2, tactics=set(), max_risk=0, verdicts=[],
        claimed_only={"Execution", "Credential Access", "Impact"},
    )
    assert evidenced > claimed
    assert any("not evidenced here" in r for r in reasons)


def test_a_case_the_platform_cannot_evidence_still_ranks():
    """
    Kerberoasting plus an account change on a domain controller is the most
    interesting thing on this estate, and this platform can evidence none of it
    — its collectors answer questions about domains, addresses and files.
    Scoring only what can be evidenced would rank it last.
    """
    score, _ = score_case(
        distinct_rules=2, tactics=set(), max_risk=0, verdicts=["suspicious"],
        claimed_only={"Credential Access", "Persistence", "Privilege Escalation"},
    )
    assert score >= 40


def test_confirmed_claims_count_as_evidence_and_bare_claims_do_not():
    assessment = {
        "techniques": [
            {"id": "T1059", "status": "confirmed", "tactics": ["Execution"]},
            {"id": "T1078", "status": "not_corroborated", "tactics": ["Defense Evasion"]},
        ],
        "additional_techniques": [{"id": "T1027", "tactics": ["Stealth"]}],
    }
    evidenced, claimed = _tactics_of(assessment)
    assert evidenced == {"Execution", "Stealth"}
    assert claimed == {"Defense Evasion"}


def test_unmapped_tactics_are_dropped():
    evidenced, claimed = _tactics_of(
        {"additional_techniques": [{"id": "T1", "tactics": ["Unmapped", "Execution"]}]}
    )
    assert evidenced == {"Execution"}
    assert claimed == set()
