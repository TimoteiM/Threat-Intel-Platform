"""A verdict records which code produced it.

On 2026-10-13 a `malicious/high/risk-90/block` verdict on `live.com` had to
be attributed to a specific build by three inferences:

  1. its `key_evidence` said `ThreatFox matches: 25`;
  2. the scoped version of `build_decision_report` builds that line from the
     scoped list, so it would not have emitted the line at all;
  3. the worker process had started at 09:21:06 and the fix was committed at
     10:53, and Celery does not reload.

All three were needed to answer "which code decided this". Nobody should ever
have to make them, so the fingerprint now travels with the verdict.

Companion to `source_coverage_service`: that says which sources answered,
this says which code decided.
"""

from __future__ import annotations

from app.services.decision_engine import (
    apply_decision_to_report,
    build_decision_report,
)


def _clean_evidence() -> dict:
    return {
        "domain": "example.com",
        "observable_type": "domain",
        "vt": {"found": True, "meta": {"status": "completed"},
               "malicious_count": 0, "suspicious_count": 0, "total_vendors": 70},
        "threat_feeds": {"feeds_checked": ["threatfox", "google_safe_browsing"]},
        "whois": {"domain_age_days": 4000},
        "http": {},
        "intel": {"blocklist_hits": [], "sources_checked": ["SURBL"],
                  "sources_skipped": {}},
        "urlscan": {},
        "hybrid_analysis": {},
    }


def test_a_verdict_carries_the_fingerprint_of_the_code_that_decided_it():
    engine = build_decision_report(_clean_evidence(), "domain")["decision_engine"]
    fingerprint = (engine.get("code") or {}).get("fingerprint")
    assert isinstance(fingerprint, str) and len(fingerprint) == 64, (
        "the verdict does not say which code produced it"
    )


def test_the_fingerprint_matches_this_process():
    """It must identify the *running process*, not the source on disk — that
    is the whole distinction, because the worker does not reload."""
    from app.code_version import code_version

    engine = build_decision_report(_clean_evidence(), "domain")["decision_engine"]
    assert engine["code"]["fingerprint"] == code_version()["code_fingerprint"]


def test_the_canonical_overlay_does_not_drop_the_provenance():
    """`apply_decision_to_report` rebuilds the `decision_engine` block when it
    adopts the analyst's reading. The fingerprint has to survive that, or a
    verdict reached through the fallback path loses the one field that says
    where it came from."""
    decision = build_decision_report(_clean_evidence(), "domain")
    merged = apply_decision_to_report(
        {"classification": "malicious", "confidence": "high", "risk_score": 90},
        decision,
    )
    assert merged["decision_engine"]["code"]["fingerprint"] == (
        decision["decision_engine"]["code"]["fingerprint"]
    )


def test_the_analyst_fallback_path_also_keeps_it():
    """The one branch that overwrites classification with the analyst's."""
    decision = dict(build_decision_report(_clean_evidence(), "domain"))
    decision["classification"] = "inconclusive"
    decision["risk_score"] = None
    merged = apply_decision_to_report(
        {"classification": "malicious", "confidence": "high", "risk_score": 90},
        decision,
    )
    assert merged["decision_engine"].get("source") == "analyst_fallback"
    assert merged["decision_engine"]["code"]["fingerprint"]


def test_provenance_failure_never_blocks_a_verdict(monkeypatch):
    """Best effort. A verdict must not fail to be produced because its
    provenance could not be computed — the dangerous direction here is an
    exception in a field nobody asked for taking down the decision."""
    import app.code_version as cv

    def _boom():
        raise RuntimeError("fingerprint unavailable")

    # Patch the module object, not a dotted string: the string form needs
    # `app.code_version` to already be imported, which it is when this file
    # runs alone and is not when the whole suite runs. The test passed in
    # isolation and failed in the suite — the harness, not the subject.
    monkeypatch.setattr(cv, "code_version", _boom)
    report = build_decision_report(_clean_evidence(), "domain")
    assert report["classification"] == "benign"
    code = report["decision_engine"]["code"]
    assert code["fingerprint"] is None
    # And it says why, rather than leaving a blank.
    assert "RuntimeError" in code["error"]
