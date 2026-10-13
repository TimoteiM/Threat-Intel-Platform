"""Per-verdict source coverage, against the directions that do damage.

The dangerous direction here is *reassurance*: a coverage report that says
"all sources answered" when they did not is worse than no report, because an
analyst would then read a thin verdict as a well-supported one. So every
test below is written against a false all-clear, and the controls check the
report can still say "fine" when things are.

The second dangerous direction is scope: the expected set is derived from
`COLLECTOR_REGISTRY`, and a registry that silently stops covering a source
is the defect this service exists to report on. One test asserts the
derivation, so adding a collector cannot leave it uncounted.
"""

from __future__ import annotations

import pytest

from app.collectors.registry import COLLECTOR_REGISTRY
from app.services.absence import is_absent
from app.services.source_coverage_service import (
    UNKNOWN,
    ANSWERED,
    FAILED,
    NOT_APPLICABLE,
    NOT_ATTEMPTED,
    coverage,
)

ALL_FEEDS = ("threatfox", "otx", "abuseipdb", "phishtank", "openphish",
             "google_safe_browsing")
INTEL_SOURCES = ("SURBL", "Spamhaus DBL", "URLhaus (abuse.ch)", "Spamhaus SIA")


def _ok(**extra) -> dict:
    """Evidence where every collector completed and every feed answered."""
    base = {
        name: {"meta": {"status": "completed"}}
        for name in COLLECTOR_REGISTRY
    }
    base["threat_feeds"] = {
        "meta": {"status": "completed"},
        "feeds_checked": list(ALL_FEEDS),
        "feeds_skipped": [],
    }
    base["intel"] = {
        "meta": {"status": "completed"},
        "sources_checked": list(INTEL_SOURCES),
        "sources_skipped": {},
    }
    base.update(extra)
    return base


def _state(cov, source: str) -> str:
    return next(s.state for s in cov.sources if s.source == source)


# ─── the control: it must be able to say "fine" ───────────────────────────

def test_a_fully_covered_verdict_reports_no_gap():
    cov = coverage(_ok(), "domain")
    assert cov.unavailable == []
    assert "All" in cov.headline()
    assert cov.as_json()["unavailable"] == 0


# ─── the live 2026-09-15 state, which is the reason this exists ───────────

def test_the_two_bad_days_report_four_unavailable():
    """VirusTotal rate-limited, intel dead, ThreatFox 401, OTX erroring —
    all four at once, which is what 2026-09-15 looked like."""
    ev = _ok(
        vt={"meta": {"status": "failed",
                     "error": "ValueError: VirusTotal API rate limit exceeded "
                              "on all configured keys."}},
        intel={"meta": {"status": "failed",
                        "error": "RuntimeError: Spamhaus SIA login failed: HTTP 401"}},
        threat_feeds={
            "meta": {"status": "completed"},
            "feeds_checked": ["abuseipdb", "phishtank", "openphish",
                              "google_safe_browsing"],
            "feeds_skipped": ["threatfox (error: HTTPError)",
                              "otx (error: HTTPError)"],
        },
    )
    cov = coverage(ev, "domain")
    names = {s.source for s in cov.unavailable}
    assert "vt" in names
    assert "threatfox" in names
    assert "otx" in names
    # All four intel sources are gone, because the collector never ran.
    assert set(INTEL_SOURCES) <= names
    assert _state(cov, "vt") == FAILED
    assert _state(cov, "threatfox") == FAILED
    assert _state(cov, "SURBL") == FAILED
    # The sentence an analyst reads.
    assert "unavailable when this verdict was reached" in cov.headline()


def test_a_dead_collector_marks_every_feed_behind_it():
    """The 2,198-run case. `blocklist_hits: []` on a row where `_collect`
    raised read downstream as four blocklists clearing the domain; the
    coverage report must name all four as unanswered, not omit them."""
    ev = _ok(intel={"meta": {"status": "failed", "error": "HTTP 401"},
                    "blocklist_hits": []})
    cov = coverage(ev, "domain")
    for src in INTEL_SOURCES:
        assert _state(cov, src) == FAILED, src
        assert "did not complete" in next(
            s.detail for s in cov.sources if s.source == src
        )


# ─── the false all-clear, in each of its forms ────────────────────────────

def test_an_empty_result_is_not_an_answer():
    """A collector that completed but recorded no asked/skipped list at all.

    Every threat_feeds row written before `feeds_checked` existed is in this
    state. It is genuinely *unknown* rather than known-bad, so it must not
    inflate the gap count — but it must not count as an answer either, and
    that is the direction that does damage.
    """
    ev = _ok(threat_feeds={"meta": {"status": "completed"}})
    cov = coverage(ev, "domain")
    for feed in ALL_FEEDS:
        assert _state(cov, feed) == UNKNOWN, feed
    answered = {s.source for s in cov.answered}
    assert not (set(ALL_FEEDS) & answered), "an unrecorded feed read as answered"
    assert set(ALL_FEEDS) <= {s.source for s in cov.unknown}
    for feed in ALL_FEEDS:
        payload = next(s.as_json() for s in cov.sources if s.source == feed)
        assert is_absent(payload["absence"])


def test_a_missing_collector_key_is_not_attempted_not_a_gap():
    """No block at all means the collector was not in the selection. Real on
    most rows for asn, cape, brave_osint and opencti — counting those as
    gaps produced a 47-50% baseline on every single day in the window, which
    is a field analysts would learn to skip."""
    ev = _ok()
    del ev["urlscan"]
    cov = coverage(ev, "domain")
    assert _state(cov, "urlscan") == NOT_ATTEMPTED
    assert "urlscan" not in {s.source for s in cov.unavailable}
    assert "urlscan" in {s.source for s in cov.not_attempted}
    assert "urlscan" not in {s.source for s in cov.answered}


def test_empty_evidence_does_not_produce_an_all_clear():
    """The degenerate case, and the one a reassurance bug gets wrong. With
    nothing asked there are no *gaps*, so the headline must say nothing was
    asked rather than that everything answered."""
    cov = coverage({}, "domain")
    assert cov.answered == []
    assert cov.asked == []
    assert "No external source was asked" in cov.headline()
    assert "answered" not in cov.headline().replace("was asked", "")


def test_none_evidence_does_not_produce_an_all_clear():
    cov = coverage(None, "domain")
    assert cov.answered == []
    assert cov.asked == []
    assert "No external source was asked" in cov.headline()


# ─── the one state that is not a gap ──────────────────────────────────────

def test_an_unsupported_observable_type_is_out_of_scope_not_a_gap():
    """`http` does not support `ip`. Reporting that as a missing source
    would manufacture gaps on every IP investigation and train analysts to
    ignore the field."""
    cov = coverage(_ok(), "ip")
    assert _state(cov, "http") == NOT_APPLICABLE
    assert "http" not in {s.source for s in cov.unavailable}
    assert "http" not in {s.source for s in cov.applicable}
    payload = next(s.as_json() for s in cov.sources if s.source == "http")
    assert payload["absence"]["kind"] == "out_of_scope"


def test_skipped_is_not_attempted_rather_than_failed():
    """`hybrid_analysis` emits `meta.status = "skipped"` because it is
    opt-in, on 1,214 of 2,221 rows. Filing that as a failure would report a
    broken platform; filing it as an answer would be the absence-as-value
    bug. It is its own state."""
    ev = _ok(hybrid_analysis={"meta": {"status": "skipped"}})
    cov = coverage(ev, "domain")
    assert _state(cov, "hybrid_analysis") == NOT_ATTEMPTED
    # Reported, but not a gap: nothing broke. 1,214 of 2,221 rows are in
    # this state because the collector is opt-in, and counting them as gaps
    # is what buried the two days the VirusTotal quota blew.
    assert "hybrid_analysis" not in {s.source for s in cov.unavailable}
    assert "hybrid_analysis" in {s.source for s in cov.not_attempted}
    # And still not an answer.
    assert "hybrid_analysis" not in {s.source for s in cov.answered}


# ─── every unavailable source carries a sentence, not a blank ─────────────

@pytest.mark.parametrize("state_setter,source", [
    ({"vt": {"meta": {"status": "failed", "error": "boom"}}}, "vt"),
    ({"hybrid_analysis": {"meta": {"status": "skipped"}}}, "hybrid_analysis"),
    ({"threat_feeds": {"meta": {"status": "completed"}}}, "threatfox"),
])
def test_an_unavailable_source_carries_an_absence(state_setter, source):
    cov = coverage(_ok(**state_setter), "domain")
    payload = next(s.as_json() for s in cov.sources if s.source == source)
    assert is_absent(payload["absence"])
    assert payload["absence"]["reason"]


# ─── scope: the expected set is derived, not listed ───────────────────────

def test_every_registered_collector_is_accounted_for():
    """A collector added to the registry and not to this service would be a
    source missing from the check that reports missing sources — which is
    exactly what happened to `otx` in the answer-rate check. Derivation is
    what makes that impossible, and this asserts the derivation."""
    cov = coverage(_ok(), "domain")
    reported = {s.collector for s in cov.sources}
    assert reported == set(COLLECTOR_REGISTRY), (
        "a registered collector is absent from the coverage report: "
        f"{set(COLLECTOR_REGISTRY) - reported}"
    )


def test_the_report_names_what_is_missing_not_just_how_many():
    """A count tells nobody which one to go and fix."""
    ev = _ok(vt={"meta": {"status": "failed", "error": "rate limit"}})
    payload = coverage(ev, "domain").as_json()
    assert payload["unavailable_sources"] == ["vt"]
    assert payload["unavailable"] == 1


# ─── new exposure: meta.error reaches an API response for the first time ──

@pytest.mark.parametrize("error,secret", [
    ("HTTPError 401 for https://api.example/v1?apikey=s3cr3t-value-here",
     "s3cr3t-value-here"),
    ("HTTPError for https://x.example/?auth_token=abcdef123456&q=1",
     "abcdef123456"),
    ("RuntimeError: Authorization: Bearer eyJhbGciOi.payload.sig",
     "eyJhbGciOi.payload.sig"),
    ("ValueError: API-KEY=plaintextkey rejected", "plaintextkey"),
])
def test_a_secret_in_a_collector_error_never_reaches_the_payload(error, secret):
    """`meta.error` was stored but never returned by an application API
    before this service. All 774 distinct stored errors were scanned and
    none carried a key — but the redaction guards the next collector to put
    a signed URL in an exception, not today's corpus."""
    ev = _ok(vt={"meta": {"status": "failed", "error": error}})
    payload = coverage(ev, "domain").as_json()
    blob = str(payload)
    assert secret not in blob, "a key-shaped value reached the API payload"
    assert "[redacted]" in blob


def test_the_error_is_bounded():
    """The longest stored error is 2,321 characters. A page is not a log."""
    ev = _ok(vt={"meta": {"status": "failed", "error": "x" * 4000}})
    entry = next(
        s for s in coverage(ev, "domain").as_json()["sources"]
        if s["source"] == "vt"
    )
    assert len(entry["detail"]) < 400
    assert entry["detail"].endswith("...")


def test_an_ordinary_error_survives_redaction_intact():
    """The control. A redactor that mangles every message would pass the
    tests above and destroy the field's only purpose."""
    msg = "ValueError: VirusTotal API rate limit exceeded on all configured keys."
    ev = _ok(vt={"meta": {"status": "failed", "error": msg}})
    entry = next(
        s for s in coverage(ev, "domain").as_json()["sources"]
        if s["source"] == "vt"
    )
    assert entry["detail"] == msg
