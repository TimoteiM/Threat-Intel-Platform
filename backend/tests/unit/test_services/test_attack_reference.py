"""The ATT&CK catalogue's retirement flags, and which one goes on the wire.

ATT&CK distinguishes two kinds of retirement and the generator used to collapse
them: `"deprecated": bool(revoked or x_mitre_deprecated)`. The catalogue could
therefore say a technique had been retired but never which technique replaced
it, and "retired, current equivalent T1685" is the whole of what an analyst
needs to search current ATT&CK.

Now there are three flags — `revoked` (149 in 19.2, each with a successor),
`deprecated` (12, retired with no replacement) and `retired` (the union, 161).
That is a trap as well as a fix: a precise `deprecated` of 12 now sits beside a
union of 161, and wiring the outbound key to the wrong one would drop the
number by an order of magnitude while breaking nothing loudly. These tests
exist so that happens as a failure instead of as a quiet regression.
"""

from __future__ import annotations

import pytest

from app.analyst.attack_mapping import describe_technique
from app.analyst.attack_reference import ATTACK_VERSION, TECHNIQUE_REFERENCE

#: What `revoked`/`deprecated` are on the pinned release. If a regeneration
#: moves these, that is a real change in ATT&CK and the new numbers belong in
#: the places that quote them, starting with the outbound documents.
EXPECTED = {"techniques": 858, "revoked": 149, "deprecated": 12, "retired": 161}


def test_the_pinned_version_is_recorded_not_remembered() -> None:
    assert ATTACK_VERSION == "19.2"


def test_the_counts_on_the_pinned_release() -> None:
    counts = {
        "techniques": len(TECHNIQUE_REFERENCE),
        "revoked": sum(1 for e in TECHNIQUE_REFERENCE.values() if e["revoked"]),
        "deprecated": sum(1 for e in TECHNIQUE_REFERENCE.values() if e["deprecated"]),
        "retired": sum(1 for e in TECHNIQUE_REFERENCE.values() if e["retired"]),
    }
    assert counts == EXPECTED


def test_retired_is_exactly_the_union() -> None:
    for tid, entry in TECHNIQUE_REFERENCE.items():
        assert entry["retired"] == (entry["revoked"] or entry["deprecated"]), tid


def test_revoked_and_deprecated_are_disjoint_on_this_release() -> None:
    """Not a law of ATT&CK, but true in 19.2 — so the union being 161 rather
    than something smaller is itself a check that neither flag is doubled."""
    both = [t for t, e in TECHNIQUE_REFERENCE.items()
            if e["revoked"] and e["deprecated"]]
    assert both == []
    assert EXPECTED["revoked"] + EXPECTED["deprecated"] == EXPECTED["retired"]


def test_every_revoked_technique_names_its_successor() -> None:
    """Without this the label cannot say "current equivalent T1685", which is
    the only part of it an analyst can act on."""
    missing = [t for t, e in TECHNIQUE_REFERENCE.items()
               if e["revoked"] and not e["revoked_by"]]
    assert missing == []


def test_a_successor_is_itself_a_real_technique() -> None:
    for tid, entry in TECHNIQUE_REFERENCE.items():
        if entry["revoked_by"]:
            assert entry["revoked_by"] in TECHNIQUE_REFERENCE, tid


def test_nothing_retired_points_at_itself() -> None:
    for tid, entry in TECHNIQUE_REFERENCE.items():
        assert entry["revoked_by"] != tid


def test_revocation_chains_resolve_to_something_current() -> None:
    """Written to assert chains did not exist. Three do.

    T1073 -> T1574.002 -> T1574.001, and T1150 and T1162 both run through
    T1547.011 to T1647. So `revoked_by` alone would have told an analyst to
    search a technique that is itself retired — the equivalent as of some
    intermediate release rather than as of this one.
    """
    chained = [
        t for t, e in TECHNIQUE_REFERENCE.items()
        if e["revoked_by"] and TECHNIQUE_REFERENCE[e["revoked_by"]]["revoked"]
    ]
    assert sorted(chained) == ["T1073", "T1150", "T1162"]
    for tid in chained:
        current = TECHNIQUE_REFERENCE[tid]["current_equivalent"]
        assert current != TECHNIQUE_REFERENCE[tid]["revoked_by"]
        assert TECHNIQUE_REFERENCE[current]["revoked"] is False


def test_every_current_equivalent_is_current() -> None:
    """The property the label depends on, across all 149, not just the three."""
    for tid, entry in TECHNIQUE_REFERENCE.items():
        current = entry["current_equivalent"]
        if current is None:
            assert not entry["revoked"], tid
            continue
        assert current in TECHNIQUE_REFERENCE, tid
        assert TECHNIQUE_REFERENCE[current]["revoked"] is False, tid
        assert current != tid


# --- the wire key -----------------------------------------------------------

def test_the_outbound_deprecated_key_is_wired_to_the_union() -> None:
    """`describe_technique`'s `deprecated` feeds attack_coverage_service and
    the UI. It has always meant the union; both readers document it as "ATT&CK
    retired it". Pointing it at the 12-entry precise field would silently take
    the number from 161 to 12.
    """
    on_the_wire = sum(
        1 for tid in TECHNIQUE_REFERENCE
        if (describe_technique(tid) or {}).get("deprecated")
    )
    assert on_the_wire == EXPECTED["retired"]
    assert on_the_wire != EXPECTED["deprecated"]


@pytest.mark.parametrize(
    "tid,successor",
    [("T1562", "T1685"), ("T1562.001", "T1685"),
     ("T1562.002", "T1685.001"), ("T1070.001", "T1685.005")],
)
def test_the_four_revoked_techniques_present_in_this_estate(tid, successor) -> None:
    """488 technique nodes carry these four. ATT&CK 19 reorganised Impair
    Defenses into the T1685 family; the ruleset maps to a pre-19 ATT&CK and so,
    on 117 of those nodes, does this platform's own attribution.
    """
    described = describe_technique(tid)
    assert described["revoked"] is True
    assert described["revoked_by"] == successor
    assert described["deprecated"] is True      # the union, on the wire
    assert described["retired"] is True


def test_a_sub_technique_carries_both_a_full_and_a_short_name() -> None:
    """The node has room for one and the panel wants the other."""
    described = describe_technique("T1059.001")
    assert described["name"] == "Command and Scripting Interpreter: PowerShell"
    assert described["short_name"] == "PowerShell"


def test_a_parent_technique_s_short_name_is_its_name() -> None:
    described = describe_technique("T1059")
    assert described["name"] == "Command and Scripting Interpreter"
    assert described["short_name"] == "Command and Scripting Interpreter"


def test_case_is_normalised_on_lookup() -> None:
    assert describe_technique("t1098")["name"] == describe_technique("T1098")["name"]


def test_an_id_that_is_not_attacks_resolves_to_nothing() -> None:
    """Not a guess and not a blank: the caller renders an absence."""
    assert describe_technique("T9999") is None
    assert describe_technique("{0=T1098}") is None
    assert describe_technique("") is None
