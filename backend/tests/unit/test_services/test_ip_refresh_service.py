"""What the refresh selects, and what it refuses to select.

The behaviours pinned here are the ones the measurement on 2026-10-12 showed
were wrong in the shipped panel, plus the two cap/scope mistakes this project
has made before and does not want to make again.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.services.ip_refresh_service import PER_RUN, Selection, _routable, select

NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)


@dataclass
class Row:
    value: str
    draws: int
    mentions: int
    queried_at: datetime


def row(value: str, *, draws: int = 0, mentions: int = 1, age_days: int = 60) -> Row:
    return Row(value, draws, mentions, NOW - timedelta(days=age_days))


def test_private_space_is_never_refreshed() -> None:
    """1,040 of 1,173 drawn ip nodes are RFC1918 and no feed has an opinion."""
    picked = select(
        [row("10.1.1.4"), row("192.168.0.9"), row("127.0.0.1"),
         row("169.254.1.1"), row("8.8.8.8")],
        now=NOW,
    )
    assert [d.value for d in picked.due] == ["8.8.8.8"]
    assert picked.not_routable == 4


def test_a_value_that_is_not_an_address_is_not_refreshed() -> None:
    picked = select([row("exp-dc-01"), row(""), row("8.8.8.8")], now=NOW)
    assert [d.value for d in picked.due] == ["8.8.8.8"]
    assert picked.not_routable == 2


def test_addresses_on_a_case_page_come_first() -> None:
    """A drawn verdict is one an analyst reads; a mention is one nobody sees."""
    picked = select(
        [row("1.1.1.1", draws=0, mentions=900),
         row("2.2.2.2", draws=1, mentions=1)],
        now=NOW,
    )
    assert [d.value for d in picked.due] == ["2.2.2.2", "1.1.1.1"]


def test_among_undrawn_addresses_the_most_referenced_comes_first() -> None:
    picked = select(
        [row("1.1.1.1", mentions=2), row("2.2.2.2", mentions=50)], now=NOW
    )
    assert [d.value for d in picked.due] == ["2.2.2.2", "1.1.1.1"]


def test_age_breaks_a_tie() -> None:
    picked = select(
        [row("1.1.1.1", mentions=5, age_days=31),
         row("2.2.2.2", mentions=5, age_days=68)],
        now=NOW,
    )
    assert [d.value for d in picked.due] == ["2.2.2.2", "1.1.1.1"]


def test_what_the_cap_left_behind_is_carried_not_dropped() -> None:
    """The bug this project has shipped twice: a slice reporting its own length.

    `total_due` has to be the number due, not the number taken, or a run that
    covered 150 of 800 reads as having covered everything.
    """
    picked = select([row(f"8.8.8.{i}") for i in range(10)], now=NOW, limit=4)
    assert len(picked.due) == 4
    assert picked.skipped_for_cap == 6
    assert picked.total_due == 10


def test_nothing_due_is_distinguishable_from_a_full_run() -> None:
    picked = select([], now=NOW)
    assert picked == Selection(due=[], skipped_for_cap=0, not_routable=0)
    assert picked.total_due == 0


def test_age_days_is_computed_from_the_stored_stamp() -> None:
    picked = select([row("8.8.8.8", age_days=56)], now=NOW)
    assert picked.due[0].age_days == 56


def test_a_naive_timestamp_is_read_as_utc_not_rejected() -> None:
    naive = Row("8.8.8.8", 0, 1, datetime(2026, 8, 17))
    picked = select([naive], now=NOW)
    assert picked.due[0].age_days == 56


def test_routable_matches_the_panels_own_test() -> None:
    """Both modules decide 'could a feed know this' and must decide it alike."""
    from app.services.indicator_enrichment_service import _routable as panel_routable

    for value in ("10.1.1.4", "192.168.1.1", "127.0.0.1", "169.254.0.1",
                  "224.0.0.1", "8.8.8.8", "185.220.101.47", "not-an-ip", ""):
        assert _routable(value) == panel_routable(value), value


def test_per_run_stays_within_one_abuseipdb_key() -> None:
    """1,000 checks a day per key, and interactive lookups have first claim."""
    assert PER_RUN <= 250
