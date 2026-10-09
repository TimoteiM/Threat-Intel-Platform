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
    # Whatever is passed here, the digest is the same — see
    # test_the_key_no_longer_depends_on_the_client.
    client="unknown",
    host="EXP-FIN-034.corp.local",
    session_started_at=datetime(2026, 8, 16, 9, 2, 11, 482000, tzinfo=timezone.utc),
)


def test_the_case_key_formula_has_not_changed_without_a_version_bump():
    without = case_key_for(**FIXTURE)
    with_discriminator = case_key_for(**FIXTURE, discriminator="run-1")

    assert CASE_KEY_VERSION == 3, (
        "CASE_KEY_VERSION changed. That is fine — but the digests below and the "
        "migration that re-points rows keyed under the previous version have to "
        "change with it. Last time this happened without a migration, 881 of "
        "1,889 case rows stopped resolving and 811 AI analyses became unreachable."
    )
    assert without == (
        "2b9d4e6a85bf9da17613711c5cdb1a39721ada3f93689b67a321ddcb6dc5a781"
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


def test_the_key_no_longer_depends_on_the_client():
    """`alert_client` reads 'unknown' on 15,234 of 15,255 alerts, so it could
    not distinguish one case from another — and for the 38 rows that did carry
    a value it changed the key for a reason that had nothing to do with the
    incident. It is pinned rather than removed: removing the component changes
    the joined string for every row and would renumber the entire case list,
    while pinning it to the value 1,851 of 1,889 rows already carry leaves
    those keys byte-identical."""
    baseline = case_key_for(**FIXTURE)
    for client in ("unknown", "LIN", "Codex Desktop", "", None, "Expertware"):
        altered = dict(FIXTURE)
        altered["client"] = client
        assert case_key_for(**altered) == baseline, client


def test_the_other_inputs_still_discriminate():
    """Pinning one component must not flatten the rest: a different host, a
    different source or a different opening still has to be a different case."""
    baseline = case_key_for(**FIXTURE)
    for field, value in (
        ("source", "other-manager"),
        ("host", "EXP-FIN-035.corp.local"),
    ):
        altered = dict(FIXTURE)
        altered[field] = value
        assert case_key_for(**altered) != baseline, field
    later = dict(FIXTURE)
    later["session_started_at"] = FIXTURE["session_started_at"].replace(microsecond=0)
    assert case_key_for(**later) != baseline


def test_every_key_component_that_claims_to_separate_actually_can():
    """A sweep, because the last instance of this was found by accident.

    `test_separator_cannot_be_forged_from_scope_text` used to forge a
    collision through `client` — a field that reads 'unknown' on 99.9% of
    rows. Once the component was pinned, the test still passed, but it was
    passing because both sides were identical rather than because the
    separator held. A test asserting separation across a component that cannot
    vary proves nothing, and nothing warned.

    So this states which components are load-bearing and checks each one
    separately. A future pin that empties one of these fails here.
    """
    separating = {
        "source": "other-manager",
        "host": "a-different-host",
    }
    pinned = {"client"}

    baseline = case_key_for(**FIXTURE)
    for field, value in separating.items():
        altered = dict(FIXTURE)
        altered[field] = value
        assert case_key_for(**altered) != baseline, (
            f"{field} is listed as separating but changing it does not change "
            "the key. Either the component was pinned without updating this "
            "list, or a test elsewhere is asserting separation it no longer has."
        )
    for field in pinned:
        altered = dict(FIXTURE)
        altered[field] = "something-else-entirely"
        assert case_key_for(**altered) == baseline, (
            f"{field} is listed as pinned but changing it changes the key. If "
            "it has been reinstated deliberately, bump CASE_KEY_VERSION and "
            "write the migration — see migration 053."
        )
    # The opening time, which is the component the whole supersession migration
    # leans on for identity.
    later = dict(FIXTURE)
    later["session_started_at"] = FIXTURE["session_started_at"].replace(microsecond=0)
    assert case_key_for(**later) != baseline
    # And the discriminator, which separates two cases inside one session.
    assert case_key_for(**FIXTURE, discriminator="run-1") != baseline
