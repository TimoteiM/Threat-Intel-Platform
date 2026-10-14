"""A changed verdict must not read as a stable one.

`ReportRepository.get_latest` returns one row ordered by iteration, so every
surface served the newest and none said the verdict had moved. `live.com`
went malicious/high/90/block -> suspicious/low/40/monitor in two and a half
hours on 2026-10-13 and the only trace was a report row nothing reads.

The dangerous direction here is *false stability*: reporting `flipped: False`
on a verdict that changed. Every test below is written against that, and the
controls check a genuinely stable verdict still reads as stable — a function
that called everything flipped would pass the first set and be useless.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services.verdict_history_service import (
    from_reports,
    of_alert_run,
    withdrawal,
)

T0 = datetime(2026, 10, 13, 12, 5, tzinfo=timezone.utc)


def _report(iteration, created, **verdict):
    body = {"classification": "benign", "confidence": "high",
            "risk_score": 15, "recommended_action": "monitor"}
    body.update(verdict)
    return SimpleNamespace(iteration=iteration, created_at=created,
                           report_json=body)


# ─── the live.com case ────────────────────────────────────────────────────

def test_the_live_com_history_reports_the_flip():
    rows = [
        _report(0, T0, classification="malicious", confidence="high",
                risk_score=90, recommended_action="block"),
        _report(1, T0 + timedelta(hours=2, minutes=36),
                classification="suspicious", confidence="low",
                risk_score=40, recommended_action="monitor"),
        _report(2, T0 + timedelta(hours=2, minutes=36, seconds=5),
                classification="suspicious", confidence="low",
                risk_score=40, recommended_action="monitor"),
    ]
    s = from_reports(rows)
    assert s.flipped is True
    assert s.current["classification"] == "suspicious"
    assert len(s.superseded) == 1
    assert s.superseded[0]["classification"] == "malicious"
    assert s.superseded[0]["risk_score"] == 90
    assert s.superseded[0]["recommended_action"] == "block"
    # The duplicate re-analysis agreed with the current verdict, so it is
    # counted rather than listed as a change.
    assert s.unchanged_iterations == 1
    assert "changed" in s.headline()
    assert "malicious" in s.headline()


# ─── false stability, in each of its forms ────────────────────────────────

def test_a_change_of_confidence_alone_is_still_a_change():
    """Comparing only `classification` would call this stable.
    malicious/high becoming malicious/low is a different assessment and an
    analyst should see it."""
    rows = [
        _report(0, T0, classification="malicious", confidence="high",
                risk_score=90, recommended_action="block"),
        _report(1, T0 + timedelta(hours=1), classification="malicious",
                confidence="low", risk_score=55,
                recommended_action="investigate"),
    ]
    s = from_reports(rows)
    assert s.flipped is True
    assert s.superseded[0]["confidence"] == "high"


def test_ordering_decides_which_verdict_is_current():
    """The rows arrive unordered from the database. If the history is
    assembled in arrival order it names the wrong verdict as current, and
    then reports the real current verdict as superseded — a flip inverted
    rather than missed."""
    newest = _report(1, T0 + timedelta(hours=2), classification="suspicious",
                     confidence="low", risk_score=40)
    oldest = _report(0, T0, classification="malicious", confidence="high",
                     risk_score=90, recommended_action="block")
    s = from_reports([newest, oldest])          # deliberately reversed
    assert s.current["classification"] == "suspicious"
    assert s.superseded[0]["classification"] == "malicious"


def test_same_iteration_falls_back_to_created_at():
    """Two rows at iteration 0 — which happens, `live.com` has three rows
    and the two re-analyses are five seconds apart."""
    a = _report(0, T0, classification="malicious", risk_score=90)
    b = _report(0, T0 + timedelta(seconds=5), classification="benign",
                risk_score=15)
    s = from_reports([a, b])
    assert s.current["classification"] == "benign"
    assert s.superseded[0]["classification"] == "malicious"


# ─── the controls: stable must stay stable ───────────────────────────────

def test_a_single_report_is_not_a_flip():
    s = from_reports([_report(0, T0)])
    assert s.flipped is False
    assert s.superseded == []
    assert s.headline() is None


def test_repeated_identical_verdicts_are_not_a_flip():
    """A re-analysis that reached the same answer is corroboration. Calling
    it a change would make the field noise and teach readers to skip it —
    the failure the source-coverage work already hit once."""
    rows = [_report(i, T0 + timedelta(hours=i)) for i in range(4)]
    s = from_reports(rows)
    assert s.flipped is False
    assert s.unchanged_iterations == 3
    assert s.headline() is None


def test_no_reports_is_not_a_flip():
    s = from_reports([])
    assert s.flipped is False
    assert s.current == {}


# ─── the alert-run store, which has no history to derive from ────────────

def test_a_recorded_withdrawal_reads_like_a_derived_one():
    """A reader must not need to know which store it came from."""
    rec = withdrawal(
        classification="malicious", confidence="high", risk_score=90,
        recommended_action="block",
        reason="25 ThreatFox indicators, none about this observable",
        at="2026-10-13T12:03:46+00:00", by="maintenance pass",
    )
    s = of_alert_run({"overall_verdict": "suspicious", "superseded": rec})
    assert s.flipped is True
    assert s.superseded[0]["classification"] == "malicious"
    assert s.superseded[0]["reason"].startswith("25 ThreatFox")
    assert s.current["classification"] == "suspicious"


def test_an_alert_run_with_no_record_is_not_a_flip():
    s = of_alert_run({"overall_verdict": "malicious"})
    assert s.flipped is False
    assert s.current["classification"] == "malicious"


@pytest.mark.parametrize("junk", [None, [], "superseded", {"superseded": "yes"}])
def test_a_malformed_record_is_not_a_flip(junk):
    """The dangerous direction is the other way for this one: junk must not
    be read as a withdrawal, or a corrupt row would retract a live verdict."""
    s = of_alert_run(junk)
    assert s.flipped is False
