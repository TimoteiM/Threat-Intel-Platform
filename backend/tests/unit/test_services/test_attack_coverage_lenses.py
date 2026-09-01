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


# ── Mapping mismatches ───────────────────────────────────────────────────────

from app.services.attack_coverage_service import _mapping_mismatches


def _run(rule, claims, found):
    return (
        {"techniques": claims, "additional_techniques": found},
        "rule-1",
        rule,
    )


def test_pairs_a_rules_claim_with_what_the_evidence_found():
    rows = [
        _run(
            "PowerShell encoded command",
            [{"id": "T1078", "name": "Valid Accounts", "status": "not_corroborated"}],
            [{"id": "T1059.001", "name": "PowerShell"}, {"id": "T1027", "name": "Obfuscation"}],
        )
    ] * 3
    group = _mapping_mismatches(rows)[0]
    assert group["rule_name"] == "PowerShell encoded command"
    assert group["runs"] == 3
    assert [c["id"] for c in group["claimed"]] == ["T1078"]
    assert {e["id"] for e in group["evidenced_instead"]} == {"T1059.001", "T1027"}


def test_a_run_with_no_evidence_is_not_a_mismatch():
    """
    A claim with nothing found either way is what "claimed but never
    corroborated" already reports. Counting it here would drown the rules whose
    mapping is actually contradicted.
    """
    rows = [_run("Quiet rule", [{"id": "T1078", "status": "not_corroborated"}], [])]
    assert _mapping_mismatches(rows) == []


def test_a_confirmed_run_is_not_a_mismatch():
    """The rule was right; whatever else the alert also showed is not a disagreement."""
    rows = [
        _run(
            "Good rule",
            [{"id": "T1059", "status": "confirmed"}],
            [{"id": "T1027", "name": "Obfuscation"}],
        )
    ]
    assert _mapping_mismatches(rows) == []


def test_ai_only_evidence_is_marked_as_such():
    """A model's lead and a deterministic signal are different grounds for
    rewriting a rule, so the UI has to be able to tell them apart."""
    rows = [
        _run(
            "Rule",
            [{"id": "T1078", "status": "not_corroborated"}],
            [
                {"id": "T1105", "name": "Ingress Tool Transfer", "source": "ai_suggested"},
                {"id": "T1059", "name": "Scripting"},
            ],
        )
    ]
    found = {e["id"]: e for e in _mapping_mismatches(rows)[0]["evidenced_instead"]}
    assert found["T1105"]["ai_only"] is True
    assert found["T1059"]["ai_only"] is False


def test_deterministic_evidence_outranks_an_ai_suggestion_for_the_same_technique():
    """Seen once by a signal means it is not AI-only, whatever else proposed it."""
    rows = [
        _run("Rule", [{"id": "T1078", "status": "not_corroborated"}],
             [{"id": "T1059", "source": "ai_suggested"}, {"id": "T1059"}]),
    ]
    found = {e["id"]: e for e in _mapping_mismatches(rows)[0]["evidenced_instead"]}
    assert found["T1059"]["ai_only"] is False


def test_groups_are_ordered_by_how_often_the_rule_misfires():
    rows = [_run("Loud rule", [{"id": "T1078"}], [{"id": "T1059"}])] * 5
    rows += [_run("Quiet rule", [{"id": "T1082"}], [{"id": "T1027"}])]
    assert [g["rule_name"] for g in _mapping_mismatches(rows)] == ["Loud rule", "Quiet rule"]


# ── Drill-down into one mismatch cell ────────────────────────────────────────

import pytest

from app.services.attack_coverage_service import mismatch_alerts


class _Row:
    def __init__(self, assessment, rule_name, rule_id="r1", title="alert"):
        from uuid import uuid4
        from datetime import datetime, timezone
        self.id = uuid4()
        self.title = title
        self.created_at = datetime.now(timezone.utc)
        self.overall_verdict = "suspicious"
        self.highest_risk_score = 50
        self.detection_rule_id = rule_id
        self.detection_rule_name = rule_name
        self.result_attack_assessment = assessment


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _DB:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, _query):
        return _Result(self._rows)


MISMATCH = {
    "techniques": [{"id": "T1078", "name": "Valid Accounts", "status": "not_corroborated"}],
    "additional_techniques": [{
        "id": "T1059.001", "name": "PowerShell", "source": None,
        "explanation": "matched a literal command line",
        "evidence": [{"matched": "-EncodedCommand"}, {"matched": "-NoProfile"}],
    }],
}


@pytest.mark.asyncio
async def test_drilldown_returns_the_runs_and_the_quote():
    """
    The quote is why the technique was accepted, so it is what an analyst reads
    before trusting the row — especially for an AI proposal.
    """
    db = _DB([_Row(MISMATCH, "PowerShell rule")])
    out = await mismatch_alerts(db, rule_name="PowerShell rule", technique="T1059.001")
    assert out["total"] == 1
    alert = out["alerts"][0]
    assert [c["id"] for c in alert["claimed"]] == ["T1078"]
    assert alert["evidenced"]["quotes"] == ["-EncodedCommand", "-NoProfile"]
    assert alert["evidenced"]["ai_suggested"] is False


@pytest.mark.asyncio
async def test_drilldown_only_returns_the_rule_that_was_clicked():
    db = _DB([_Row(MISMATCH, "PowerShell rule"), _Row(MISMATCH, "Some other rule")])
    out = await mismatch_alerts(db, rule_name="PowerShell rule", technique="T1059.001")
    assert out["total"] == 1


@pytest.mark.asyncio
async def test_drilldown_matches_the_unnamed_rule_placeholder():
    """The aggregate groups a nameless rule under a placeholder; clicking it
    has to find the same runs."""
    db = _DB([_Row(MISMATCH, None)])
    out = await mismatch_alerts(db, rule_name="(unnamed rule)", technique="T1059.001")
    assert out["total"] == 1


@pytest.mark.asyncio
async def test_drilldown_excludes_runs_that_confirmed_something():
    """Same definition as the aggregate, so the count reconciles with the chip."""
    confirmed = {
        "techniques": [{"id": "T1078", "status": "confirmed"}],
        "additional_techniques": MISMATCH["additional_techniques"],
    }
    db = _DB([_Row(confirmed, "PowerShell rule")])
    out = await mismatch_alerts(db, rule_name="PowerShell rule", technique="T1059.001")
    assert out["total"] == 0


@pytest.mark.asyncio
async def test_drilldown_ignores_a_different_technique():
    db = _DB([_Row(MISMATCH, "PowerShell rule")])
    out = await mismatch_alerts(db, rule_name="PowerShell rule", technique="T1027")
    assert out["total"] == 0
