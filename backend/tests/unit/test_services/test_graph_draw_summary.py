"""Why a graph is as small as it is.

Node count tracks distinct behaviour, not alert volume, and the estate makes
that plain: 8 alerts over 8 rules draw 33 nodes, while 1,889 alerts over 1
rule draw 2. Both are correct and neither said so.
"""

from __future__ import annotations

from app.services.graph_draw_summary_service import summarise


def _graph(nodes: int, *, read=None, dropped=0, sources=None, collapsed=None):
    return {
        "nodes": [{"id": f"n{i}"} for i in range(nodes)],
        "coverage": {"alerts_read": read, "alerts_dropped": dropped},
        "sources": {"by_source": sources or []},
        "collapsed": collapsed or [],
    }


def test_a_case_whose_source_cannot_be_read_says_so_first():
    """#1849: 1,889 alerts, every one from `appsec-agent`, which has no field
    map. Two nodes is everything that could be read, and that is not a finding
    that little happened."""
    summary = summarise(
        graph=_graph(2, read=300, dropped=1589,
                     sources=[{"source": "appsec-agent", "alerts": 300, "mapped": False}]),
        members=1889, distinct_rules=1,
    )
    assert summary is not None
    assert summary["severity"] == "primary"
    assert "no field map" in summary["headline"]
    assert "not a finding that little happened" in summary["headline"]


def test_many_alerts_describing_few_things_is_explained_as_repetition():
    """#71: 1,217 alerts, 1,488 extracted observations, 22 distinct things.
    The analyst's cue is tuning, not hunting."""
    summary = summarise(
        graph=_graph(22, read=300, dropped=917,
                     sources=[{"source": "windows_eventchannel", "alerts": 300, "mapped": True}]),
        members=1217, distinct_rules=14,
    )
    assert summary is not None
    assert summary["severity"] == "note"
    assert "describe 22 distinct things" in summary["headline"]
    assert "not how often it was reported" in summary["headline"]
    assert any("not read" in note for note in summary["also"])


def test_a_proportionate_graph_says_nothing():
    """#1440: 8 alerts, 33 nodes. The common answer must stay quiet or the
    explanations that matter go unread."""
    assert summarise(
        graph=_graph(33, read=8, sources=[
            {"source": "windows_eventchannel", "alerts": 8, "mapped": True}]),
        members=8, distinct_rules=8,
    ) is None


def test_a_partly_unreadable_case_is_a_footnote_not_the_headline():
    """A case of mostly-Windows alerts with a few from an unmapped source draws
    most of itself; saying "almost nothing could be examined" would be false."""
    summary = summarise(
        graph=_graph(40, read=100, sources=[
            {"source": "windows_eventchannel", "alerts": 88, "mapped": True},
            {"source": "unstructured syslog", "alerts": 12, "mapped": False},
        ]),
        members=100, distinct_rules=9,
    )
    assert summary is not None
    assert summary["severity"] == "note"
    assert summary["headline"] is None
    assert any("no field map" in note for note in summary["also"])


def test_a_bounded_read_is_always_stated():
    """It is the one reason the drawing is incomplete rather than compact."""
    summary = summarise(
        graph=_graph(56, read=300, dropped=261, sources=[
            {"source": "windows_eventchannel", "alerts": 300, "mapped": True}]),
        members=561, distinct_rules=14,
    )
    assert summary is not None
    assert any("261 further alerts were not read" in n for n in summary["also"])


def test_folding_is_reported_as_its_own_reason():
    summary = summarise(
        graph=_graph(17, read=12, sources=[
            {"source": "windows_eventchannel", "alerts": 12, "mapped": True}],
            collapsed=[{"kind": "account", "members": 191}]),
        members=12, distinct_rules=4,
    )
    assert summary is not None
    assert any("191 near-identical nodes were folded" in n for n in summary["also"])
