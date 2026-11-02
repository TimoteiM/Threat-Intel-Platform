"""A feed that has never answered must not report a zero.

ThreatFox failed at `debug` level for 6,259 consecutive lookups and surfaced
as `threatfox_count = 0` — indistinguishable from "checked, nothing found".
This generalises that: no successes in the recent window means the source is
reporting on its own availability, not on the indicator.
"""

from __future__ import annotations

import pytest

from app.services.absence import CHECK_FAILED, is_absent
from app.services.enrichment_health_service import (
    MIN_SUCCESSES,
    WINDOW,
    is_unavailable,
    record,
    reset,
    result_or_absence,
    snapshot,
)


@pytest.fixture(autouse=True)
def _clean():
    reset()
    yield
    reset()


def test_a_source_that_has_never_answered_reports_an_absence_not_a_zero():
    for _ in range(WINDOW):
        record("threatfox", ok=False, error="HTTPError")
    assert is_unavailable("threatfox")
    reported = result_or_absence("threatfox", 0)
    assert is_absent(reported)
    assert reported["kind"] == CHECK_FAILED
    assert "not a clean result" in reported["reason"]
    assert reported["raw"] == "HTTPError"


def test_a_zero_from_a_working_source_is_a_real_negative_result():
    """The asymmetry that matters. A feed with successes returning nothing for
    this indicator has genuinely found nothing, and substituting an absence
    would destroy a real finding."""
    record("urlhaus", ok=True)
    for _ in range(WINDOW):
        record("urlhaus", ok=False, error="timeout")
    # One success inside the window is enough to prove the integration works.
    record("urlhaus", ok=True)
    assert not is_unavailable("urlhaus")
    assert result_or_absence("urlhaus", 0) == 0


def test_too_few_calls_to_judge_is_not_an_outage():
    """Two timeouts in a row must not condemn a feed. ThreatFox failed 800
    consecutive times, so any window in this range catches a real outage."""
    for _ in range(WINDOW - 1):
        record("newfeed", ok=False, error="timeout")
    assert not is_unavailable("newfeed")


def test_a_finding_from_an_unavailable_source_still_wins():
    """The point is to stop a zero reading as a finding, not to suppress a
    finding. A source contradicting its own health record is reporting data,
    and data beats bookkeeping."""
    for _ in range(WINDOW):
        record("threatfox", ok=False)
    assert result_or_absence("threatfox", [{"malware": "something"}]) == [
        {"malware": "something"}
    ]


def test_recovery_clears_the_alarm_so_the_next_outage_is_visible():
    for _ in range(WINDOW):
        record("threatfox", ok=False, error="HTTPError")
    assert snapshot()["threatfox"]["unavailable"] is True
    for _ in range(WINDOW):
        record("threatfox", ok=True)
    assert snapshot()["threatfox"]["unavailable"] is False
    assert not is_unavailable("threatfox")


def test_the_snapshot_separates_the_window_from_all_time():
    record("vt", ok=True)
    record("vt", ok=False, error="429")
    state = snapshot()["vt"]
    assert state["total_successes"] == 1
    assert state["total_failures"] == 1
    assert state["successes_in_window"] == 1
    assert state["last_error"] == "429"


def test_min_successes_is_one_so_a_sometimes_working_feed_is_trusted():
    assert MIN_SUCCESSES == 1, (
        "Raising this would let a feed that answers occasionally be reported "
        "as unavailable, suppressing its real negative results."
    )
