"""The case key formula is pinned, so changing it cannot silently orphan rows.

On 2026-10-07 the formula changed and no migration followed. Of 1,889 spine
rows, 881 stopped resolving: 855 still had their alerts and 811 carried a
written AI analysis, so 811 investigations became unreachable. Nothing failed,
nothing warned, and the only symptom was a case list where nearly half the
rows rendered nothing.

This test is the warning that was missing. It fails when the formula's output
changes for fixed inputs, and the fix is not to update the expected digest on
its own — it is to bump CASE_KEY_VERSION and write a migration that re-points
the rows keyed under the previous one.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.services.alert_session_service import CASE_KEY_VERSION, case_key_for

# Fixed inputs, and the digest the current formula produces for them.
FIXTURE = dict(
    source="Siembiot",
    client="Expertware",
    host="EXP-FIN-034.corp.local",
    session_started_at=datetime(2026, 8, 16, 9, 2, 11, 482000, tzinfo=timezone.utc),
)


def test_the_case_key_formula_has_not_changed_without_a_version_bump():
    without = case_key_for(**FIXTURE)
    with_discriminator = case_key_for(**FIXTURE, discriminator="run-1")

    assert CASE_KEY_VERSION == 2, (
        "CASE_KEY_VERSION changed. That is fine — but the digests below and the "
        "migration that re-points rows keyed under the previous version have to "
        "change with it. Last time this happened without a migration, 881 of "
        "1,889 case rows stopped resolving and 811 AI analyses became unreachable."
    )
    assert without == (
        "f09bc7852275d05a9dd731bbbc9a47c1fd44393df76895b4f99d35962cbd880e"
    ), (
        "The case key formula changed. Every stored row keyed under the old one "
        "will stop resolving. Bump CASE_KEY_VERSION, write a migration that "
        "maps the old keys onto the new ones (see migration 052 and "
        "app/services/case_supersession_service.py), then update this digest."
    )
    assert with_discriminator != without, (
        "The discriminator must still separate two cases that begin in the same "
        "session; without it they share an identity because they shared an "
        "afternoon."
    )


def test_a_naive_timestamp_is_read_as_utc():
    """Event times are stored naive-UTC in places, and a key that differed by
    tzinfo alone would split one case in two."""
    naive = dict(FIXTURE)
    naive["session_started_at"] = FIXTURE["session_started_at"].replace(tzinfo=None)
    assert case_key_for(**naive) == case_key_for(**FIXTURE)


def test_the_separator_cannot_be_forged_from_a_field_value():
    """("a|b", "c") and ("a", "b|c") must not collide, which is why the parts
    are joined on a unit separator rather than a printable character."""
    one = case_key_for("a|b", "c", "h", FIXTURE["session_started_at"])
    two = case_key_for("a", "b|c", "h", FIXTURE["session_started_at"])
    assert one != two
