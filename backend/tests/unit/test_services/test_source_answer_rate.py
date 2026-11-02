"""Has each enrichment source ever actually answered?

Built 2026-10-13 after ThreatFox spent seven months returning an empty list
on every investigation because it was never asked. Zero non-empty results in
2,400 rows is not a quiet estate; it is a signature, and nothing was watching
for it. On its first run this check found a second one.
"""

from __future__ import annotations

import pytest

from app.services.source_answer_rate_service import (
    MIN_OBSERVATIONS,
    SOURCES,
    SourceAnswers,
)


def test_a_source_that_never_answered_is_named():
    report = SourceAnswers("threatfox", observations=2174, answered=0).as_json()
    assert report["never_answered"] is True
    assert report["rate"] == 0.0


def test_the_denominator_travels_with_the_rate():
    """"0%" and "0 of 2,400" carry different information, and only one of
    them is a finding."""
    report = SourceAnswers("threatfox", observations=2174, answered=0).as_json()
    assert report["observations"] == 2174
    assert report["answered"] == 0


def test_too_few_observations_yields_an_absence_not_a_zero():
    """A 0% from three observations is not evidence of a broken feed, and
    reporting it as 0% is the blank-as-measurement bug."""
    report = SourceAnswers("subdomains", observations=3, answered=0).as_json()
    assert report["rate"]["kind"] == "too_little_history"
    assert "never_answered" not in report


def test_the_boundary_is_inclusive_in_the_safe_direction():
    below = SourceAnswers("x", observations=MIN_OBSERVATIONS - 1, answered=0).as_json()
    at = SourceAnswers("x", observations=MIN_OBSERVATIONS, answered=0).as_json()
    assert isinstance(below["rate"], dict)
    assert at["rate"] == 0.0


def test_a_working_source_is_not_flagged():
    report = SourceAnswers("virustotal", observations=2203, answered=2203).as_json()
    assert report["never_answered"] is False
    assert report["rate"] == 1.0


def test_one_answer_in_thousands_is_still_not_never():
    """The check is "never answered", not "answers rarely". Most domains are
    in no blocklist, and a low rate is ordinary."""
    report = SourceAnswers("intel_blocklists", observations=2168, answered=1).as_json()
    assert report["never_answered"] is False


@pytest.mark.parametrize("source,path", sorted(SOURCES.items()))
def test_every_declared_source_reads_a_plausible_path(source, path):
    """The source list is hand-maintained — the failure this codebase has had
    seven times — so at minimum the paths must be well formed and rooted in
    evidence_json."""
    assert path.startswith("evidence_json->")
    assert "'" in path


def test_the_sources_cover_the_feed_that_caused_this():
    assert "threatfox" in SOURCES
    assert "threatfox_matches" in SOURCES["threatfox"]


# ─── the check's own scope, and whether that guard can fail ───────────────

def test_no_registered_collector_is_silently_uncovered():
    """Every collector is either measured by SOURCES or exempt in UNMEASURED.

    `otx` was neither for 90 days while being 70% dead — the check built to
    find sources that stopped answering did not cover one that had.
    """
    from app.services.source_answer_rate_service import uncovered_collectors

    assert uncovered_collectors() == {}


def test_the_coverage_guard_can_actually_fail(monkeypatch):
    """What this check would print if the answer were bad.

    A guard that passes because it cannot fail is decoration — three such
    checks in a row reported "fine" on 2026-10-12. So: register a collector
    and assert the guard notices.
    """
    from app.collectors import registry
    from app.collectors.base import BaseCollector
    from app.services.source_answer_rate_service import uncovered_collectors

    class _Newcomer(BaseCollector):
        name = "brand_new_feed"
        supported_types = frozenset({"domain"})

    monkeypatch.setitem(registry.COLLECTOR_REGISTRY, "brand_new_feed", _Newcomer)
    assert "brand_new_feed" in uncovered_collectors()


def test_nothing_is_both_measured_and_exempt():
    """A contradiction would make the guard pass while the exemption claimed
    the source needs no measuring."""
    from app.services.source_answer_rate_service import (
        COLLECTOR_OF,
        UNMEASURED,
    )

    assert not (set(COLLECTOR_OF.values()) & set(UNMEASURED)), (
        "a collector is both measured and exempt"
    )
