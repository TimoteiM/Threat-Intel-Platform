"""
The coverage payload must answer the two questions an analyst starts with:
what has the evidence borne out, and what is the AI finding that no rule claims.
Both were already computed per technique; neither had a name in the response.
"""

from __future__ import annotations

from app.services.attack_coverage_service import _by_tactic


def _row(tid, tactic, *, claimed=0, confirmed=0, observed=0, uncorroborated=0, ai=0):
    return {
        "id": tid, "name": tid, "tactic": tactic, "tactics": [tactic], "url": None,
        "evidenceable": True, "deprecated": False,
        "claimed": claimed, "confirmed": confirmed, "uncorroborated": uncorroborated,
        "observed": observed, "ai_suggested": ai, "confirm_rate": None,
    }


def test_tactic_rollup_carries_every_lens():
    rows = [
        _row("T1059", "Execution", claimed=4, confirmed=2, observed=2),
        _row("T1027", "Execution", observed=3, ai=3),
    ]
    execution = {t["tactic"]: t for t in _by_tactic(rows)}["Execution"]
    assert execution["claimed"] == 4
    assert execution["confirmed"] == 2
    assert execution["ai_suggested"] == 3


def test_rollup_counts_distinct_techniques_not_occurrences():
    """
    "3 confirmed techniques" is what a tactic row is read for. One technique
    confirmed forty times is one technique, not forty.
    """
    rows = [
        _row("T1059", "Execution", claimed=40, confirmed=40, observed=40),
        _row("T1027", "Execution", observed=1, ai=1),
    ]
    execution = {t["tactic"]: t for t in _by_tactic(rows)}["Execution"]
    assert execution["confirmed"] == 40           # occurrences, unchanged
    assert execution["confirmed_techniques"] == 1  # distinct
    assert execution["ai_suggested_techniques"] == 1


def test_a_multi_tactic_technique_counts_under_each():
    """ATT&CK lists T1547 under Persistence and Privilege Escalation, and an
    analyst reading either column expects to find it there."""
    row = _row("T1547", "Persistence", claimed=1, confirmed=1)
    row["tactics"] = ["Persistence", "Privilege Escalation"]
    by = {t["tactic"]: t for t in _by_tactic([row])}
    assert by["Persistence"]["confirmed_techniques"] == 1
    assert by["Privilege Escalation"]["confirmed_techniques"] == 1


def test_a_tactic_with_nothing_confirmed_reports_zero():
    """The lens filters on this, so it must not fall back to claimed."""
    rows = [_row("T1078", "Defense Evasion", claimed=2224, confirmed=0, uncorroborated=2224)]
    tactic = _by_tactic(rows)[0]
    assert tactic["claimed"] == 2224
    assert tactic["confirmed_techniques"] == 0
    assert tactic["uncorroborated"] == 2224
