"""The case graph: what it draws, and what it must never draw as fact.

A graph is far more persuasive than a table. 30,763 of the 30,803 ATT&CK
mappings in this estate are `not_corroborated` — the detection asserted a
technique and the investigation found nothing bearing on it either way — so
drawing those identically to the 40 that were confirmed would be the most
convincing wrong picture this platform could produce.
"""

from __future__ import annotations

from app.services.alert_case_graph_service import (
    MAX_NODES,
    build_case_graph,
)


def _case(**over):
    base = {
        "case_key": "k" * 64,
        "case_number": 1175,
        "label": "EXPDC402 - User account locked out",
        "entity_host": "EXPDC402",
        "entity_users": ["gmaciuc"],
        "score": 44,
        "alerts": [
            {
                "run_id": "run-1",
                "detection_name": "User account locked out",
                "detection_rule_name": "Windows audit failure event",
                "event_time": "2026-10-08T04:09:00Z",
                "entity_user": "gmaciuc",
                "overall_verdict": "inconclusive",
                "detection_rule_id": "60104",
            }
        ],
    }
    base.update(over)
    return base


# --- the ATT&CK layer, which is the risky one --------------------------------

def test_a_claimed_technique_is_never_drawn_as_a_finding():
    graph = build_case_graph(
        _case(),
        assessments={
            "run-1": [
                {"id": "T1110", "name": "Brute Force", "status": "not_corroborated",
                 "explanation": "The investigation found no evidence bearing on this technique."},
            ]
        },
    )
    technique = next(n for n in graph["nodes"] if n["kind"] == "technique")
    assert technique["status"] == "claimed"
    # And the edge that reaches it says so too, so a renderer cannot draw the
    # connection without knowing what kind of connection it is.
    edge = next(e for e in graph["edges"] if e["target"] == technique["id"])
    assert edge["kind"] == "claimed"
    assert graph["attack"] == {"corroborated": 0, "claimed": 1}


def test_a_corroborated_technique_is_marked_as_one():
    graph = build_case_graph(
        _case(),
        assessments={"run-1": [{"id": "T1059", "name": "Command Interpreter", "status": "confirmed",
                                "evidence": ["powershell -enc ..."]}]},
    )
    technique = next(n for n in graph["nodes"] if n["kind"] == "technique")
    assert technique["status"] == "corroborated"
    assert technique["evidence_count"] == 1
    assert graph["attack"] == {"corroborated": 1, "claimed": 0}


def test_an_unrecognised_status_is_treated_as_a_claim():
    """Never a third state a renderer has to guess at, and never the
    optimistic one: a status nobody anticipated is not evidence."""
    for status in (None, "", "unknown", "partial", "suggested", "ai_suggested"):
        graph = build_case_graph(
            _case(), assessments={"run-1": [{"id": "T1", "name": "x", "status": status}]},
        )
        assert graph["attack"]["claimed"] == 1, status
        assert graph["attack"]["corroborated"] == 0, status


def test_the_assessments_own_explanation_travels_with_the_node():
    """The difference between a mapping and a finding is exactly what that
    sentence says, and the panel shows it."""
    graph = build_case_graph(
        _case(),
        assessments={"run-1": [{"id": "T1110", "name": "Brute Force", "status": "not_corroborated",
                                "explanation": "This alert carried nothing that would show it either way."}]},
    )
    technique = next(n for n in graph["nodes"] if n["kind"] == "technique")
    assert "nothing that would show it" in technique["explanation"]


# --- what the graph is made of ----------------------------------------------

def test_an_alert_is_named_by_its_detection_not_its_carrier_rule():
    """Rule 60104 is "Windows audit failure event" and is the same string for
    every detection filed under it."""
    graph = build_case_graph(_case())
    alert = next(n for n in graph["nodes"] if n["kind"] == "alert")
    assert alert["label"] == "User account locked out"


def test_the_case_host_and_account_are_connected():
    graph = build_case_graph(_case())
    kinds = {n["kind"] for n in graph["nodes"]}
    assert {"case", "host", "account", "alert"} <= kinds
    pairs = {(e["source"].split(":")[0], e["target"].split(":")[0], e["kind"]) for e in graph["edges"]}
    assert ("case", "host", "on") in pairs
    assert ("case", "alert", "contains") in pairs
    assert ("alert", "account", "ran_as") in pairs


def test_process_ancestry_is_drawn_as_spawning_and_access_separately():
    """Sysmon gives a process its own GUID and names its parent, so the tree
    is observed. A process *reaching into* another is a different edge,
    because that is the shape injection makes."""
    graph = build_case_graph(
        _case(),
        processes=[
            {"guid": "{a}", "image": "C:\\Windows\\System32\\cmd.exe",
             "parent_guid": "{b}", "parent_image": "C:\\Program Files\\HealthService.exe",
             "command_line": "cmd.exe /C StartTracing.cmd"},
            {"guid": "{c}", "image": "C:\\Windows\\System32\\rundll32.exe",
             "accessed_guid": "{d}", "accessed_image": "C:\\Windows\\System32\\lsass.exe"},
        ],
    )
    kinds = {e["kind"] for e in graph["edges"]}
    assert "spawned" in kinds
    assert "accessed" in kinds
    # Named by the binary rather than by its whole path, which is unreadable
    # in a node that has to fit on screen.
    labels = {n["label"] for n in graph["nodes"] if n["kind"] == "process"}
    assert "cmd.exe" in labels and "lsass.exe" in labels


def test_a_graph_too_large_to_read_says_what_it_left_out():
    """A graph that quietly dropped a third of its nodes reads as a complete
    picture, which is worse than a smaller one that admits its bounds."""
    many = [
        {"run_id": f"run-{i}", "detection_name": f"detection {i}", "event_time": "2026-10-08T04:09:00Z"}
        for i in range(MAX_NODES + 80)
    ]
    graph = build_case_graph(_case(alerts=many))
    assert len(graph["nodes"]) <= MAX_NODES
    assert graph["dropped"], "the graph must say what it could not draw"
    # And no edge may point at a node that was dropped.
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])


def test_an_indicator_seen_on_two_alerts_is_one_node():
    """Which is the whole point of a graph: the same address reached by two
    alerts is a connection, not two unrelated leaves."""
    case = _case(alerts=[
        {"run_id": "run-1", "detection_name": "a", "event_time": "2026-10-08T04:09:00Z"},
        {"run_id": "run-2", "detection_name": "b", "event_time": "2026-10-08T04:19:00Z"},
    ])
    graph = build_case_graph(
        case, indicators={"run-1": ["10.10.126.119"], "run-2": ["10.10.126.119"]},
    )
    indicators = [n for n in graph["nodes"] if n["kind"] == "indicator"]
    assert len(indicators) == 1
    reaching = [e for e in graph["edges"] if e["target"] == indicators[0]["id"]]
    assert len(reaching) == 2


# --- the window a case is re-derived over -----------------------------------

def test_every_single_case_endpoint_resolves_over_the_same_window():
    """A case is derived from its alerts, so the window is part of its
    identity: one that forms over 720 hours does not form over 48.

    The detail call used 720 while graph, observables, narrative, close and
    analyse used the service default of 48, so on a case older than two days
    the page drew a full header and then four endpoints answering "No such
    case" — an empty graph on a real incident, no observables, and a manual
    close that could not find the case the analyst was reading. Case #834 was
    the one that showed it. These defaults must stay equal.
    """
    import inspect

    from app.api import detections

    def ceiling(param):
        """Pydantic v2 keeps the bound in `metadata`, not on the Query."""
        for item in param.default.metadata:
            if hasattr(item, "le"):
                return item.le
        return None

    endpoints = [
        detections.get_case,
        detections.get_case_narrative,
        detections.get_case_graph,
        detections.get_case_observables,
        detections.close_case_manually,
        detections.analyse_case_now,
    ]
    windows, ceilings = {}, {}
    for fn in endpoints:
        param = inspect.signature(fn).parameters.get("hours")
        assert param is not None, f"{fn.__name__} takes no window, so it uses the service default"
        windows[fn.__name__] = param.default.default
        ceilings[fn.__name__] = ceiling(param)

    assert set(windows.values()) == {detections.CASE_LOOKUP_HOURS}, windows
    assert set(ceilings.values()) == {detections.CASE_LOOKUP_MAX_HOURS}, ceilings


def test_a_single_case_accepts_every_window_the_cases_list_offers():
    """The list offers "All" — 17,520 hours — and a case found there links to
    a page that asks for the same window. At a ceiling of 8,760 every call
    from such a link came back 422, which the page showed as a load failure
    on a case that was right there in the list."""
    import inspect

    from app.api import detections

    listing = inspect.signature(detections.get_correlated_cases).parameters["hours"]
    widest = next(i.le for i in listing.default.metadata if hasattr(i, "le"))
    assert detections.CASE_LOOKUP_MAX_HOURS >= widest, (
        "a case can be listed over a window its own page cannot ask for"
    )


def test_the_single_case_endpoints_all_pass_that_window_through():
    """Taking the parameter is not enough — it has to reach `case_by_key`,
    which is where the window actually decides whether the case forms."""
    import inspect

    from app.api import detections

    source = inspect.getsource(detections)
    assert "case_by_key(db, case_key, scope=scope)" not in source, (
        "a single-case endpoint is still resolving on the 48-hour service default"
    )
