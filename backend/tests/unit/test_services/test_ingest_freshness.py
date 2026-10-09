"""The ingest freshness alarm.

Written against the shape that let two sources go silent for weeks: the queue
watchdog is downstream of ingest, so an alert that never arrives is never
queued and a dead feed produces the same queue as a healthy quiet one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.absence import KINDS, TOO_LITTLE_HISTORY, absent
from app.services.ingest_freshness_service import (
    MIN_RUNS_FOR_CADENCE,
    MIN_SILENCE,
    STALE_AT_GAPS,
    IngestFreshness,
    SourceFreshness,
    _typical_gap,
)

NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)


def _source(**kw) -> SourceFreshness:
    base = dict(
        source="fortigate-firewall-v5",
        runs=2533,
        last_seen=NOW - timedelta(days=22),
        recent_runs=0,
        typical_gap=timedelta(minutes=30),
        now=NOW,
    )
    base.update(kw)
    return SourceFreshness(**base)


class TestTheFaultThisWasWrittenFor:
    def test_a_source_silent_far_beyond_its_own_cadence_is_stale(self):
        """Fortigate: 2,533 runs, last seen 22 days ago. 16.6% of alert
        volume, and nothing in the platform could say it had stopped."""
        assert _source().stale is True

    def test_a_chatty_source_still_delivering_is_not_stale(self):
        assert _source(
            source="windows_eventchannel", runs=9102,
            last_seen=NOW - timedelta(minutes=3), recent_runs=762,
        ).stale is False

    def test_recent_arrivals_outrank_a_stale_looking_last_seen(self):
        """`graph_source_type` is written at materialise time, so a live
        source's newest runs carry none and the column reports it as stopped.
        It did exactly that for PAN-OS: 0 runs in 7 days by the column, 20 by
        the bodies. The recent count comes from the bodies and wins."""
        assert _source(
            source="palo_alto_panos", runs=224,
            last_seen=NOW - timedelta(days=8), recent_runs=20,
        ).stale is False


class TestItRefusesToJudgeWhatItCannotMeasure:
    def test_too_little_history_is_an_absence_not_a_clean_bill(self):
        source = _source(
            source="macOS_loginwindow", runs=10, typical_gap=None,
            unjudgeable=absent(TOO_LITTLE_HISTORY, "only 10 runs", raw="10"),
        )
        assert source.stale is False
        assert source.as_json()["unjudgeable"]["kind"] == TOO_LITTLE_HISTORY
        assert source.as_json()["stale"] is False

    def test_the_new_absence_kind_is_registered(self):
        """An unregistered kind degrades to `unrecognised_absence`, which would
        hide the reason behind a bucket."""
        assert TOO_LITTLE_HISTORY in KINDS
        assert absent(TOO_LITTLE_HISTORY, "x").kind == TOO_LITTLE_HISTORY

    def test_a_source_with_no_measurable_gap_is_never_stale(self):
        assert _source(typical_gap=None).stale is False

    def test_the_cadence_floor_matters_for_more_than_one_source(self):
        assert MIN_RUNS_FOR_CADENCE >= 2


class TestTheCadenceItself:
    def test_the_median_is_used_so_a_past_outage_cannot_raise_the_bar(self):
        """A mean would let one three-week gap in the history drag the
        threshold far enough that the source could never be late again — the
        outage raising the bar meant to catch it."""
        normal = [1800.0] * 40
        with_outage = normal + [22 * 24 * 3600.0]
        assert _typical_gap(with_outage) == timedelta(seconds=1800)

    def test_zero_and_negative_gaps_are_discarded(self):
        assert _typical_gap([0.0, -5.0, 600.0, 600.0]) == timedelta(seconds=600)

    def test_no_usable_gaps_yields_no_cadence(self):
        assert _typical_gap([]) is None
        assert _typical_gap([0.0, 0.0]) is None

    def test_a_weekly_source_is_allowed_a_skipped_week(self):
        """Three of its own gaps, so a weekly feed that misses a holiday week
        does not alarm. The cost of a late alarm here is days, not minutes."""
        weekly = _source(
            source="weekly-feed", runs=60, typical_gap=timedelta(days=7),
            last_seen=NOW - timedelta(days=15), recent_runs=0,
        )
        assert weekly.stale is False
        assert weekly.allowed_silence == timedelta(days=21)
        assert STALE_AT_GAPS == 3.0

    def test_a_short_cadence_cannot_alarm_inside_the_floor(self):
        """A source arriving every minute must not be called stale after an
        hour of calm."""
        chatty = _source(
            source="chatty", runs=5000, typical_gap=timedelta(minutes=1),
            last_seen=NOW - timedelta(hours=2), recent_runs=0,
        )
        assert chatty.allowed_silence == MIN_SILENCE
        assert chatty.stale is False


class TestTheReport:
    def test_stale_sources_are_named(self):
        health = IngestFreshness(sources=[
            _source(),
            _source(source="appsec-agent", runs=2685,
                    last_seen=NOW - timedelta(days=17)),
            _source(source="windows_eventchannel", runs=9102,
                    last_seen=NOW - timedelta(minutes=1), recent_runs=762),
        ])
        payload = health.as_json()
        assert payload["stale"] == ["fortigate-firewall-v5", "appsec-agent"]
        assert payload["watched"] == 3

    def test_an_unjudgeable_source_is_listed_separately_from_fresh_ones(self):
        health = IngestFreshness(sources=[
            _source(source="json", runs=5, typical_gap=None,
                    unjudgeable=absent(TOO_LITTLE_HISTORY, "only 5 runs")),
        ])
        payload = health.as_json()
        assert payload["stale"] == []
        assert payload["unjudgeable"] == ["json"]

    def test_a_naive_timestamp_is_read_as_utc_rather_than_crashing(self):
        source = _source(last_seen=datetime(2026, 9, 17, 12, 0, 0))
        assert source.silent_for == timedelta(days=22)


class TestTheRecentWindowIsPerSource:
    def test_a_frequent_source_is_judged_in_hours_not_in_a_week(self):
        """Counting every source over the whole seven-day window would mean a
        source can only be stale after seven days of silence, so for
        `windows_eventchannel` — a median gap of about a minute — the cadence
        logic would never bind. Per-source, the floor is 12 hours."""
        from app.services.ingest_freshness_service import arrivals_within

        arrivals = [NOW - timedelta(days=3), NOW - timedelta(days=5)]
        # Nothing in the last 12 hours, though plenty inside seven days.
        assert arrivals_within(arrivals, now=NOW, window=MIN_SILENCE) == 0
        assert arrivals_within(arrivals, now=NOW, window=timedelta(days=7)) == 2

    def test_a_slow_source_keeps_a_window_wide_enough_for_its_cadence(self):
        from app.services.ingest_freshness_service import arrivals_within

        # syscheck_integrity_changed: a 74-hour median gap, so 9.26 days
        # allowed. An arrival 5 days ago still counts as recent for it.
        arrivals = [NOW - timedelta(days=5)]
        slow = _source(
            source="syscheck_integrity_changed", runs=53,
            typical_gap=timedelta(hours=74), last_seen=NOW - timedelta(days=5),
            recent_runs=0,
        )
        window = slow.allowed_silence
        assert window is not None and window > timedelta(days=9)
        assert arrivals_within(arrivals, now=NOW, window=window) == 1

    def test_the_window_is_reported_because_zero_means_nothing_without_it(self):
        source = _source(recent_window=MIN_SILENCE)
        assert source.as_json()["recent_window_hours"] == 12.0

    def test_a_naive_arrival_timestamp_does_not_crash_the_comparison(self):
        from app.services.ingest_freshness_service import recent_arrivals_by_source

        assert callable(recent_arrivals_by_source)
