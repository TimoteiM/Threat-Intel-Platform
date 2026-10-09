"""Absence is reported, never rendered as zero.

Five places had independently reached this answer and each implemented it
separately; a sixth would have been a blank. The type exists so the renderer
cannot distinguish them, and so "we did not look" cannot be written as 0.
"""

from __future__ import annotations

import pytest

from app.services.absence import (
    CHECK_FAILED,
    KINDS,
    NO_FIELD_MAP,
    UNPARSED,
    UNRATED,
    UNRECOGNISED,
    Absent,
    absent,
    is_absent,
    reason_of,
    value_or_absence,
)


def test_an_absence_is_not_a_number_and_cannot_be_mistaken_for_one():
    """The whole point. Every one of the five cases came from a defect where a
    blank was read as a measurement: 7,260 unscored alerts ranking as least
    severe, 175 cases whose `alerts_at_close = 0` meant "never counted"."""
    missing = absent(UNRATED, "The source states no severity.")
    assert missing != 0
    assert missing is not None
    payload = value_or_absence(missing)
    assert payload["absent"] is True
    assert payload["kind"] == UNRATED
    assert payload["reason"]


def test_every_absence_carries_a_reason_a_person_can_read():
    for kind in KINDS:
        value = absent(kind, "Something specific did not happen.")
        assert reason_of(value) == "Something specific did not happen."


def test_an_unanticipated_kind_gets_its_own_bucket_not_a_meaningful_one():
    """Raising would turn "we could not describe why" into a 500, which is a
    worse answer than an imprecise one — so it degrades.

    But not into `unparsed`. Filing an unrecognised kind under a kind that
    *means* something is this convention's own failure mode committed inside
    the convention: a reader would see "a value was present and failed its
    shape check" when in fact nothing is known about why it is missing. It
    gets `unrecognised_absence`, and the original string survives as `raw` so
    the gap is traceable.
    """
    value = Absent(kind="something-nobody-anticipated", reason="x")
    assert value.kind == UNRECOGNISED
    assert value.kind != UNPARSED
    assert value.raw == "something-nobody-anticipated"
    assert is_absent(value)


def test_an_unrecognised_kind_does_not_overwrite_a_raw_value_it_was_given():
    value = Absent(kind="mystery", reason="x", raw="the actual bad value")
    assert value.kind == UNRECOGNISED
    assert value.raw == "the actual bad value"


def test_the_raw_value_survives_so_a_parser_bug_stays_visible():
    """The one-character account name is kept. Dropping it is how six
    delimiter bugs stayed hidden until a seeding helper printed a host called
    `program`."""
    value = absent(UNPARSED, "One character is not an identifier.", raw="P")
    assert value.as_json()["raw"] == "P"


def test_a_real_value_passes_through_untouched():
    assert value_or_absence(0) == 0
    assert value_or_absence(42) == 42
    assert value_or_absence("ok") == "ok"
    assert not is_absent(0), "zero is a measurement, not an absence"


def test_a_plain_none_is_not_an_absence():
    """A null in a payload is indistinguishable from a field the caller forgot
    to set, which is how each of the five became a blank in the first place."""
    assert not is_absent(None)
    assert reason_of(None) is None


@pytest.mark.parametrize(
    "kind,expected",
    [(NO_FIELD_MAP, NO_FIELD_MAP), (CHECK_FAILED, CHECK_FAILED)],
)
def test_the_kinds_the_platform_actually_uses_round_trip(kind, expected):
    assert value_or_absence(absent(kind, "why"))["kind"] == expected
