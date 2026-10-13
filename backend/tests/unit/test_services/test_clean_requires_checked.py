"""A feed that did not answer must not permit a benign verdict.

Written before the fix, against the dangerous direction, because fixing an
absence bug puts you in a filtering mindset and filtering is the operation
that creates absences — twice today the fix for an absence bug contained one.

The shape: `decision_engine` reaches benign through

    observable_clean = (... and not tf_matches and not intel_hits ...)

`not tf_matches` is true both when the feed answered "nothing" and when it
never answered. For seven months it was the second, and the branch stayed
open on nothing. Granularity does not fix this — the next 401 empties the
list again — so the precondition has to require *checked and not listed*,
which is what the Google Safe Browsing handling twelve lines above already
does.

The flag is not new. `feeds_checked` has excluded threatfox and
`feeds_skipped` has recorded `threatfox (error: HTTPError)` on every row
since March. Nothing read them.
"""

from __future__ import annotations

from app.services.decision_engine import build_decision_report


def _clean_evidence(**feeds) -> dict:
    """An observable that is clean on every other axis, so the feed decides."""
    return {
        "domain": "example-unlisted.test",
        "observable_type": "domain",
        "vt": {"found": True, "meta": {"status": "completed"},
               "malicious_count": 0, "suspicious_count": 0, "total_vendors": 70},
        "threat_feeds": {
            "threatfox_matches": [],
            "feeds_checked": [],
            "feeds_skipped": [],
            "phishtank": {},
            "abuseipdb": {},
            **feeds,
        },
        "whois": {"domain_age_days": 4000},
        "intel": {"blocklist_hits": []},
        "http": {},
        "urlscan": {},
        "hybrid_analysis": {},
    }


def test_a_feed_that_answered_nothing_permits_benign():
    """The legitimate case: asked, and genuinely not listed."""
    decision = build_decision_report(
        _clean_evidence(feeds_checked=["threatfox"]), "domain"
    )
    assert decision["classification"] == "benign"
    assert decision["confidence"] == "high"


def test_a_feed_that_never_answered_does_not_permit_benign():
    """The dangerous direction, and the state of this platform for seven
    months: threatfox absent from feeds_checked, present in feeds_skipped
    with an HTTPError, and an empty match list that reads as "not listed"."""
    decision = build_decision_report(
        _clean_evidence(feeds_skipped=["threatfox (error: HTTPError)"]), "domain"
    )
    assert decision["confidence"] != "high" or decision["classification"] != "benign", (
        "an unchecked feed unlocked the high-confidence benign branch — this "
        "is the condition that made seven months of silence invisible"
    )


def test_a_feed_missing_entirely_does_not_permit_benign():
    """No feeds_checked key at all — older evidence, or a collector that
    never ran. Unknown is not the same as clean."""
    evidence = _clean_evidence()
    evidence["threat_feeds"].pop("feeds_checked")
    decision = build_decision_report(evidence, "domain")
    assert decision["confidence"] != "high" or decision["classification"] != "benign"
