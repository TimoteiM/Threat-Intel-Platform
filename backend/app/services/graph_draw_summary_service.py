"""Why a case's graph is as small as it is.

A graph tab showing two nodes for a 1,889-alert case reads as broken. It was
not: every one of #1849's alerts comes from `appsec-agent`, which has no field
map, so a host and a rule-asserted technique is everything that could be read.
And #71 draws 22 nodes from 1,217 alerts because its 1,488 extracted
observations are 1,488 sightings of the same 22 things — one rule firing over
and over on one host.

Both are correct. Neither says so, and a correct graph that reads as a broken
one is a defect in the graph.

So the size is explained wherever it needs explaining. Node count tracks
distinct behaviour, not alert volume, and the estate makes that plain:

    #1440      8 alerts,  8 distinct rules ->  33 nodes
    #61      561 alerts, 14 distinct rules ->  56 nodes
    #71    1,217 alerts, 14 distinct rules ->  22 nodes
    #1849  1,889 alerts,  1 distinct rule  ->   2 nodes

The three reasons a graph is small are different claims and must not be
conflated: nothing could be read from the source, the same few things happened
many times, or the read was bounded. An analyst can act on the second and
third; the first means the platform cannot see this source at all.
"""

from __future__ import annotations

from typing import Any, Sequence


def summarise(
    *,
    graph: dict[str, Any],
    members: int,
    distinct_rules: int | None = None,
) -> dict[str, Any] | None:
    """A sentence about why the drawing is this size, or None when obvious.

    Returns None when the graph is proportionate to its case — the common
    answer, which must stay quiet so the explanations that matter are read.
    """
    nodes = len(graph.get("nodes") or [])
    coverage = graph.get("coverage") or {}
    read = int(coverage.get("alerts_read") or members or 0)
    dropped = int(coverage.get("alerts_dropped") or 0)
    sources = (graph.get("sources") or {}).get("by_source") or []
    unmapped = [s for s in sources if not s.get("mapped")]
    unmapped_alerts = sum(int(s.get("alerts") or 0) for s in unmapped)
    collapsed = graph.get("collapsed") or []
    folded = sum(int(c.get("members") or 0) for c in collapsed)

    reasons: list[str] = []
    headline: str | None = None

    # 1. Nothing could be read. The strongest claim and the one that must lead,
    #    because it is the only one that is about the platform rather than the
    #    case.
    if read and unmapped_alerts >= read * 0.8:
        names = ", ".join(sorted({str(s.get("source")) for s in unmapped})[:3])
        headline = (
            f"{unmapped_alerts} of the {read} alerts read came from {names}, "
            "which this platform has no field map for — so almost nothing in "
            "this case could be examined. The few nodes below are not a "
            "finding that little happened."
        )
    elif unmapped_alerts:
        reasons.append(
            f"{unmapped_alerts} of the {read} alerts read came from a source "
            "with no field map and contributed nothing"
        )

    # 2. Repetition. Many alerts, few distinct things — the normal shape of a
    #    noisy rule, and the analyst's cue to go tuning rather than hunting.
    if headline is None and members >= 50 and nodes and members / max(nodes, 1) >= 8:
        rule_note = (
            f" across {distinct_rules} distinct rule"
            f"{'' if distinct_rules == 1 else 's'}"
            if distinct_rules
            else ""
        )
        headline = (
            f"{members} alerts{rule_note} describe {nodes} distinct things. "
            "The graph draws what happened, not how often it was reported, so "
            "a repeated detection appears once with its sightings counted on it."
        )

    # 3. The read was bounded. Stated whenever it was, because it is the one
    #    reason the drawing is incomplete rather than merely compact.
    if dropped:
        reasons.append(
            f"{dropped} further alerts were not read: the graph takes the most "
            "severe first and stops at its budget"
        )
    if folded:
        reasons.append(
            f"{folded} near-identical nodes were folded into "
            f"{len(collapsed)} group{'' if len(collapsed) == 1 else 's'}"
        )

    if headline is None and not reasons:
        return None
    return {
        "nodes": nodes,
        "alerts_in_case": members,
        "alerts_read": read,
        "headline": headline,
        "also": reasons,
        # So a renderer can decide where to put it: an unreadable source is the
        # primary message, the rest are footnotes.
        "severity": "primary" if headline and unmapped_alerts >= read * 0.8 else "note",
    }
