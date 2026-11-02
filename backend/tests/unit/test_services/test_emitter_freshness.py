"""Volume against an emitter's own baseline, in shadow.

One implementation, two groupings: a source and a host are both emitters, and
two implementations of the same question would drift — the host one is where
the value is, and it is the one that would have caught `expdc002` at 4.1% of
normal for three weeks.
"""

from __future__ import annotations

from datetime import date, timedelta

from app.services.emitter_freshness_service import (
    HOST,
    MIN_BASELINE_VOLUME,
    SHADOW_RATIO,
    SOURCE,
    WINDOW_DAYS,
    EmitterVolume,
    summarise,
)

DAYS = [date(2026, 8, 20) + timedelta(days=i) for i in range(56)]


def _flat(per_day: int, days=DAYS):
    return {d: per_day for d in days}


class TestRateNotTimeSinceLast:
    def test_one_alert_cannot_clear_a_collapse(self):
        """The defect this replaces: Fortigate delivered a single alert after
        26.3 days of silence and the time-since-last alarm went fresh on it."""
        counts = {d: 60 for d in DAYS[:-WINDOW_DAYS]}
        counts[DAYS[-1]] = 1  # the one alert
        out = summarise(grouping=SOURCE, per_emitter={"fortigate": counts},
                        eligible=DAYS)[0]
        assert out.judgeable
        assert out.ratio is not None and out.ratio < SHADOW_RATIO
        assert out.would_alarm()

    def test_a_healthy_emitter_does_not_fire(self):
        out = summarise(grouping=SOURCE, per_emitter={"windows": _flat(100)},
                        eligible=DAYS)[0]
        assert out.ratio == 1.0
        assert not out.would_alarm()

    def test_degradation_fires_as_well_as_silence(self):
        """The six worst hosts are not silent — they are at 1-21% of normal
        and still sending just enough to look alive."""
        counts = _flat(100, DAYS[:-WINDOW_DAYS])
        counts.update({d: 4 for d in DAYS[-WINDOW_DAYS:]})
        out = summarise(grouping=HOST, per_emitter={"expdc002": counts},
                        eligible=DAYS)[0]
        assert out.would_alarm()

    def test_a_burst_does_not_trip_it(self):
        """The baseline is a distribution, not a gap, so a quiet stretch
        inside an otherwise busy history does not fire."""
        counts = _flat(100)
        counts.update({d: 500 for d in DAYS[-WINDOW_DAYS:]})
        out = summarise(grouping=SOURCE, per_emitter={"busy": counts},
                        eligible=DAYS)[0]
        assert not out.would_alarm()


class TestTooLittleHistoryIsNotHealth:
    def test_a_genuinely_sparse_emitter_is_unjudgeable(self):
        """The floor is on demonstrated history, not on recent activity. A
        blank must not read as a clean bill."""
        counts = {d: 1 for d in DAYS[:4]}
        out = summarise(grouping=HOST, per_emitter={"tiny": counts},
                        eligible=DAYS)[0]
        assert not out.judgeable
        assert out.ratio is None
        assert not out.would_alarm(), "unjudgeable must never alarm"

    def test_a_dark_host_does_not_disqualify_itself_from_judgement(self):
        """The version this replaces counted recent active days, so a host
        dark for 38 days had too few of them to judge — the metric got
        blinder the worse the problem was. History cannot be eroded by the
        failure being detected."""
        counts = {d: 60 for d in DAYS[:14]}      # a busy past
        # ...then nothing at all for the rest of the window.
        out = summarise(grouping=HOST, per_emitter={"expsql003": counts},
                        eligible=DAYS)[0]
        assert out.judgeable, "a dark host must still be judgeable"
        assert out.ratio == 0.0
        assert out.would_alarm()

    def test_a_ramp_up_in_the_history_does_not_excuse_a_decline(self):
        """`expdc001`'s windows were [36, 97, 54, 27, 16, 1] newest-first. A
        median of the prior five is 27, so a recent 36 read as 1.333 —
        healthy — while it was at 37% of the week before."""
        days = DAYS[:42]
        counts = {}
        # Oldest-to-newest ramp: 1, 16, 27, 54, 97, then a drop to 36.
        for i, volume in enumerate([1, 16, 27, 54, 97, 36]):
            for d in days[i * 7:(i + 1) * 7]:
                counts[d] = volume // 7 + (1 if volume % 7 else 0)
        out = summarise(grouping=HOST, per_emitter={"expdc001": counts},
                        eligible=days)[0]
        assert out.judgeable
        # Measured against the most it has been seen to do, not the middle.
        assert out.baseline is not None and out.baseline >= 91

    def test_it_is_reported_rather_than_dropped(self):
        out = summarise(grouping=HOST, per_emitter={"quiet": {DAYS[0]: 1}},
                        eligible=DAYS)[0]
        assert out.as_json()["judgeable"] is False
        assert out.as_json()["active_days"] == 1


class TestTheWindowIsEligibleDaysNotCalendarDays:
    def test_the_payload_says_so(self):
        """17 of the last 60 calendar days are excluded, so a window of 7
        eligible days can span a fortnight. The first version of this file
        labelled the figure `recent_7d`, which it is not."""
        out = EmitterVolume(SOURCE, "x", 70, 70.0, 20, 1.0, 8).as_json()
        assert out["window_is_eligible_days_not_calendar_days"] is True
        assert "recent_7d" not in out
        assert out["recent_window"] == 70
        assert out["recent_per_eligible_day"] == round(70 / WINDOW_DAYS, 2)
    # There is no test here for `expdc001` reading 1.333 while running at 21%
    # of its pre-collapse volume. I could not reproduce that shape
    # synthetically — a busy-then-quiet series fires correctly at 0.2 — which
    # means I do not understand the mechanism well enough to assert it. A test
    # tuned until it matched a number I cannot explain would be worse than
    # none, so the observation stays in the service's own notes and in the
    # decision it is waiting on.


class TestItIsShadow:
    def test_nothing_calls_it_an_alarm(self):
        import pathlib

        task = (
            pathlib.Path(__file__).resolve().parents[3]
            / "app" / "tasks" / "pipeline_watch_task.py"
        ).read_text()
        assert "emitter_freshness_shadow" in task
        # Logged at info, never error: an error line is what a pager watches.
        src = (
            pathlib.Path(__file__).resolve().parents[3]
            / "app" / "services" / "emitter_freshness_service.py"
        ).read_text()
        assert "logger.info(\n            \"emitter_freshness_shadow" in src
        assert "logger.error" not in src

    def test_the_threshold_is_marked_provisional(self):
        assert SHADOW_RATIO == 0.25
