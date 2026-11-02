"""
Event time: when it happened on the host, not when we were told.

Correlation ordered members by created_at. On this deployment those differ by
13.8 hours on average and by as much as 323 days, and 76% of alerts change
position when sorted by one rather than the other — so every sequence question
asked of ingest order was answering about the pipeline, not the attack.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.alert_field_service import event_time_of

INGEST = datetime(2026, 8, 16, 16, 6, 47, tzinfo=timezone.utc)

WAZUH_WINDOWS = """Agent: EXP-D0MY264 | 1757
data.win.system.systemTime: 2026-08-11T08:45:55.4464718Z
data.win.system.eventID: 1
"""

WAZUH_HEADER = """Agent: exprevpxy002 | 1445
Time: 2026-08-16T07:29:13.311+0000 | 2026-08-16T07:28:30.948Z UTC
"""

APPSEC_JSON = '{"eventTime": "2026-08-16T03:46:30.948","eventName": "Web Request"}'

FIM = 'syscheck.mtime: 2026-08-14T05:00:00Z'


def test_windows_systemtime_wins_and_survives_seven_digit_fractions():
    """
    systemTime carries 100-nanosecond FILETIME resolution — seven fractional
    digits, which datetime will not parse as it arrives.
    """
    found = event_time_of(WAZUH_WINDOWS, fallback=INGEST)
    assert found == datetime(2026, 8, 11, 8, 45, 55, 446471, tzinfo=timezone.utc)


def test_the_earliest_stamp_in_a_two_valued_header_wins():
    """
    Wazuh's header carries two timestamps and does not say which is which.
    Taking the earlier is a rule, not a guess about field order: an event
    cannot postdate its own processing, so the earlier one is nearer the host.
    """
    found = event_time_of(WAZUH_HEADER, fallback=INGEST)
    assert found == datetime(2026, 8, 16, 7, 28, 30, 948000, tzinfo=timezone.utc)


def test_a_naive_stamp_is_read_as_utc():
    """One scale matters more to ordering than a timezone nobody declared."""
    found = event_time_of(APPSEC_JSON, fallback=INGEST)
    assert found == datetime(2026, 8, 16, 3, 46, 30, 948000, tzinfo=timezone.utc)
    assert found.tzinfo is not None


def test_fim_mtime_is_accepted():
    assert event_time_of(FIM, fallback=INGEST) == datetime(2026, 8, 14, 5, 0, tzinfo=timezone.utc)


def test_the_host_clock_outranks_the_alert_header():
    """Both present: the host's own clock is the more authoritative source."""
    body = WAZUH_WINDOWS + WAZUH_HEADER
    assert event_time_of(body, fallback=INGEST).day == 11


def test_an_unparseable_body_falls_back_to_ingest():
    """Never None when a fallback is given — a caller must always be able to sort."""
    assert event_time_of("nothing resembling a timestamp here", fallback=INGEST) == INGEST


def test_a_far_future_stamp_is_refused():
    """
    A clock-skewed endpoint stamping next year would otherwise sort itself to
    the end of every case it appears in, permanently.
    """
    skewed = "data.win.system.systemTime: 2031-01-01T00:00:00Z"
    assert event_time_of(skewed, fallback=INGEST) == INGEST


def test_a_slightly_future_stamp_is_kept():
    """Modest skew is normal; only the implausible is refused."""
    soon = datetime.now(timezone.utc) + timedelta(hours=6)
    body = f"data.win.system.systemTime: {soon.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    assert event_time_of(body, fallback=INGEST) != INGEST


# ── The heuristics are instrumented, not trusted ─────────────────────────────

from app.services.alert_field_service import (
    reset_stamp_heuristic_stats,
    stamp_heuristic_stats,
)


def test_two_stamp_disagreement_is_counted():
    """
    "Take the earlier" is defensible on today's data and is not a law. On 2,961
    stored runs the two stamps disagree 89.6% of the time but by at most 57.5
    seconds — one tight mode, which is processing lag. A flipped field order
    would show a second cluster, so the counter is what makes that visible.
    """
    reset_stamp_heuristic_stats()
    event_time_of(WAZUH_HEADER, fallback=INGEST)
    stats = stamp_heuristic_stats()
    assert stats["headers_with_multiple_stamps"] == 1
    assert stats["disagreed_notably"] == 1          # 42.4s apart
    assert stats["disagreed_implausibly"] == 0
    assert 40 < stats["max_delta_seconds"] < 45


def test_an_implausible_disagreement_is_flagged_separately():
    """Beyond processing lag, picking the earlier is picking arbitrarily."""
    reset_stamp_heuristic_stats()
    event_time_of("Time: 2026-08-16T00:00:00+0000 | 2026-08-16T09:00:00Z UTC", fallback=INGEST)
    assert stamp_heuristic_stats()["disagreed_implausibly"] == 1


def test_naive_stamps_are_counted_where_they_are_used():
    """
    Zero of the chosen stamps in stored history are naive — the offset-bearing
    header outranks the naive field on every body carrying both. This counter is
    what will say when that stops being true, because tempo breaks under a
    timezone shift in a way ordering does not.
    """
    reset_stamp_heuristic_stats()
    event_time_of(APPSEC_JSON, fallback=INGEST)
    assert stamp_heuristic_stats()["naive_stamps_chosen"] == 1
