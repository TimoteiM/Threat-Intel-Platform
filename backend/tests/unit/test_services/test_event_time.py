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
