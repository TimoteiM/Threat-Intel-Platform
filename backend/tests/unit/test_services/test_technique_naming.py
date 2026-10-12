"""Resolving an ATT&CK id for display: the three cases, and the absence.

The wording tests are not decoration. 273 technique nodes on a single case
carry one retired id, so a sentence implying the detection got it wrong is
repeated 273 times at an analyst who would then reasonably conclude their
ruleset is broken. The status is a fact about ATT&CK; the detection mapped
correctly for the ATT&CK of its day.
"""

from __future__ import annotations

import pytest

from app.analyst.attack_reference import ATTACK_VERSION
from app.services.technique_naming_service import annotate, name_technique


# --- the three resolutions --------------------------------------------------

def test_a_parent_technique_resolves_to_its_name() -> None:
    found = name_technique("T1059")
    assert found["name"] == "Command and Scripting Interpreter"
    assert found["short_name"] == "Command and Scripting Interpreter"
    assert found["retired"] is False


def test_a_sub_technique_carries_the_short_and_the_full_form() -> None:
    """The node has ~96px; the panel has a line."""
    found = name_technique("T1059.001")
    assert found["short_name"] == "PowerShell"
    assert found["name"] == "Command and Scripting Interpreter: PowerShell"


def test_a_retired_id_says_so_and_names_what_to_search_instead() -> None:
    found = name_technique("T1562.001")
    assert found["retired"] is True
    assert found["revoked"] is True
    assert found["current_equivalent"] == "T1685"
    assert "Retired in ATT&CK 19.2" in found["retirement"]
    assert "Current equivalent T1685" in found["retirement"]
    assert "Disable or Modify Tools" in found["retirement"]


def test_a_retired_id_does_not_quietly_show_the_successors_name() -> None:
    """The failure mode the explicit label exists to prevent: an id presented
    under a name it does not have."""
    found = name_technique("T1562.002")
    assert found["name"] == "Impair Defenses: Disable Windows Event Logging"
    assert found["short_name"] == "Disable Windows Event Logging"
    assert found["current_equivalent"] == "T1685.001"


# --- the wording ------------------------------------------------------------

@pytest.mark.parametrize("tid", ["T1562", "T1562.001", "T1562.002", "T1070.001"])
def test_the_wording_blames_nobody(tid: str) -> None:
    sentence = name_technique(tid)["retirement"].lower()
    assert "mapped correctly for the att&ck of its day" in sentence
    for blame in ("wrong", "incorrect", "mistake", "error", "should have",
                  "misattributed", "bad mapping", "invalid"):
        assert blame not in sentence, f"{tid}: {blame!r} reads as a judgement"


@pytest.mark.parametrize("tid", ["T1562", "T1562.001", "T1562.002", "T1070.001"])
def test_the_wording_states_a_version_and_a_forward_pointer(tid: str) -> None:
    found = name_technique(tid)
    assert ATTACK_VERSION in found["retirement"]
    assert found["current_equivalent"] in found["retirement"]


def test_a_technique_retired_without_a_replacement_says_that(monkeypatch) -> None:
    """12 of 161 are deprecated with nothing to point at. Saying "current
    equivalent None" would be worse than saying there is not one."""
    import app.services.technique_naming_service as mod

    monkeypatch.setattr(mod, "describe_technique", lambda tid: {
        "name": "Data Compressed", "short_name": "Data Compressed",
        "tactic": "Exfiltration", "tactics": ["Exfiltration"], "url": "",
        "retired": True, "revoked": False, "revoked_by": None,
        "current_equivalent": None, "evidenceable": False,
    })
    found = mod.name_technique("T1002")
    assert found["deprecated_without_replacement"] is True
    assert "without a replacement" in found["retirement"]
    assert "Current equivalent" not in found["retirement"]


def test_an_unresolvable_chain_refuses_rather_than_naming_an_intermediate(
    monkeypatch,
) -> None:
    import app.services.technique_naming_service as mod

    monkeypatch.setattr(mod, "describe_technique", lambda tid: {
        "name": "Looped", "short_name": "Looped", "tactic": "Impact",
        "tactics": ["Impact"], "url": "", "retired": True, "revoked": True,
        "revoked_by": "T2000", "current_equivalent": None,
        "evidenceable": False,
    })
    found = mod.name_technique("T1000")
    assert "does not resolve" in found["retirement"]
    assert "T2000" not in found["retirement"]


# --- the absence ------------------------------------------------------------

def test_an_id_absent_from_the_catalogue_is_an_absence_not_a_blank() -> None:
    found = name_technique("T9999")
    assert found["id"] == "T9999"
    assert found["naming"]["absent"] is True
    assert found["naming"]["kind"] == "unrecognised_absence"
    assert found["naming"]["raw"] == "T9999"
    assert ATTACK_VERSION in found["naming"]["reason"]
    # No guessed name, and nothing borrowed from anywhere else.
    assert "name" not in found
    assert "short_name" not in found


def test_a_malformed_id_keeps_its_raw_value_for_the_finding() -> None:
    """Fixed at the extractor, but the renderer must still not be able to be
    handed one and silently draw nothing."""
    found = name_technique("{0=T1489}")
    assert found["naming"]["kind"] == "unrecognised_absence"
    assert found["naming"]["raw"] == "{0=T1489}"


def test_an_empty_id_does_not_throw() -> None:
    assert name_technique("")["naming"]["absent"] is True
    assert name_technique(None)["naming"]["absent"] is True


def test_case_is_normalised() -> None:
    assert name_technique("t1098")["name"] == name_technique("T1098")["name"]
    assert name_technique("t1098")["id"] == "T1098"


# --- the graph annotation ---------------------------------------------------

def _graph(*ids: str) -> dict:
    return {
        "nodes": [
            {"kind": "technique", "label": tid, "attrs": {"id": tid}}
            for tid in ids
        ] + [{"kind": "process", "label": "powershell.exe", "attrs": {}}],
        "attack": {"corroborated": 0, "claimed": len(ids)},
    }


def test_annotate_names_every_technique_node_and_leaves_others_alone() -> None:
    graph = annotate(_graph("T1059.001", "T1562.001"))
    techniques = [n for n in graph["nodes"] if n["kind"] == "technique"]
    assert [n["attrs"]["short_name"] for n in techniques] == [
        "PowerShell", "Disable or Modify Tools",
    ]
    process = next(n for n in graph["nodes"] if n["kind"] == "process")
    assert process["attrs"] == {}


def test_annotate_reports_which_attack_and_what_it_found() -> None:
    graph = annotate(_graph("T1059.001", "T1562.001", "T9999"))
    assert graph["attack"]["version"] == ATTACK_VERSION
    assert graph["attack"]["retired_drawn"] == 1
    assert graph["attack"]["unnameable_drawn"] == 1
    # The counts it already carried are untouched.
    assert graph["attack"]["corroborated"] == 0


def test_annotate_keeps_the_existing_node_attrs() -> None:
    graph = {
        "nodes": [{
            "kind": "technique", "label": "T1059",
            "attrs": {"id": "T1059", "named_by": "model_only"},
        }],
    }
    annotate(graph)
    assert graph["nodes"][0]["attrs"]["named_by"] == "model_only"
    assert graph["nodes"][0]["attrs"]["name"] == "Command and Scripting Interpreter"


def test_annotate_survives_a_graph_with_no_techniques() -> None:
    graph = annotate({"nodes": [{"kind": "host", "label": "exp-dc-01"}]})
    assert graph["attack"]["retired_drawn"] == 0
    assert graph["attack"]["version"] == ATTACK_VERSION


def test_tactic_rides_along_so_nothing_downstream_keeps_its_own_map() -> None:
    """The frontend held 38 hand-written prefixes because the catalogue was
    backend-only — three already stale in 19.2. Deleting that map is only safe
    if the tactic arrives with the node.
    """
    found = name_technique("T1562")
    assert found["tactic"] == "Stealth"
    assert found["tactics"] == ["Stealth"]
    # And the one the stale map got wrong: 19 split Defense Evasion.
    assert found["tactic"] != "Defense Evasion"
