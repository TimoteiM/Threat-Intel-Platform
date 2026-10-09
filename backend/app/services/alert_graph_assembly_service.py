"""One case's graph, assembled from what each of its alerts witnessed.

The per-alert extractor cannot merge, because merging needs to see the other
alerts. `odsync.exe` is the example that forces this module to exist. Across
case #1440 it is named three ways:

    rule 100515   sourceImage, PID 7788          -> process:<host>:7788:odsync.exe
    rule 100710   parentImage, no PID            -> process:<host>:c:\\...\\odsync.exe
    rule 61017    parentImage, no PID            -> same
    rule 100311   the Run key's value data       -> file:<host>:c:\\...\\odsync.exe

Four observations, one binary. Drawn as four nodes, persistence sits on one
leaf and credential access on another and the graph hides the only thing worth
seeing: they are the same object. So this module runs a second merge pass over
the union, and rewrites the edges onto the surviving nodes.

What it adds beyond merging:

  * reused infrastructure — an address reached by two different relationships
    (a stager URL at 09:02, a C2 name resolving to it at 09:19) is flagged,
    because that convergence is the finding a table cannot show.
  * an inferred parent for an orphan — `reg.exe` wrote the Run key and the
    alert does not say what started `reg.exe`. The chain is broken there. A
    link to the nearest preceding process on the same host and account closes
    it, as a claim, never as an observation.

Status is never upgraded by assembly. A merged node is corroborated only if
one of the observations that formed it was a sensor field; everything else,
including anything whose basis is unrecognised, stays a claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from datetime import datetime
from typing import Any, Iterable

from app.services.alert_graph_extraction_service import (
    CLAIMED,
    CORROBORATED,
    INFERRED,
    OBSERVED,
    PARSED,
    Edge,
    Entity,
    Extracted,
    norm_path,
    path_label,
    status_for,
)

#: Hard cap before the renderer is forced to collapse. A graph that quietly
#: dropped a third of its nodes reads as a complete picture.
MAX_NODES = 150


@dataclass
class Witness:
    """One alert's claim on a node or an edge."""
    run_id: str
    rule_id: str | None
    detection: str | None
    event_time: datetime | None
    rule_level: int | None


@dataclass
class AssembledNode:
    kind: str
    merge_key: str
    label: str
    basis: str
    attrs: dict[str, Any]
    witnesses: list[Witness] = dc_field(default_factory=list)
    #: Other merge keys that collapsed into this one, so the side panel can
    #: say *why* two observations are one node.
    absorbed: list[str] = dc_field(default_factory=list)

    @property
    def status(self) -> str:
        return status_for(self.basis)


@dataclass
class AssembledEdge:
    kind: str
    source: str
    target: str
    basis: str
    attrs: dict[str, Any]
    witnesses: list[Witness] = dc_field(default_factory=list)

    @property
    def status(self) -> str:
        return status_for(self.basis)


@dataclass
class AlertEvidence:
    """One alert, and what it saw."""
    run_id: str
    rule_id: str | None
    detection: str | None
    event_time: datetime | None
    rule_level: int | None
    extracted: Extracted


def _better(basis_a: str, basis_b: str) -> str:
    """An observation outranks a parse, which outranks an inference."""
    order = {OBSERVED: 3, PARSED: 2, INFERRED: 1}
    return basis_a if order.get(basis_a, 0) >= order.get(basis_b, 0) else basis_b


def assemble(evidence: Iterable[AlertEvidence]) -> dict[str, Any]:
    nodes: dict[str, AssembledNode] = {}
    edges: dict[tuple[str, str, str], AssembledEdge] = {}

    for item in evidence:
        witness = Witness(
            run_id=item.run_id, rule_id=item.rule_id, detection=item.detection,
            event_time=item.event_time, rule_level=item.rule_level,
        )
        for entity in item.extracted.entities:
            node = nodes.get(entity.merge_key)
            if node is None:
                nodes[entity.merge_key] = AssembledNode(
                    kind=entity.kind, merge_key=entity.merge_key,
                    label=entity.label, basis=entity.basis,
                    attrs=dict(entity.attrs), witnesses=[witness],
                )
                continue
            node.basis = _better(node.basis, entity.basis)
            node.witnesses.append(witness)
            for key, value in entity.attrs.items():
                if value not in (None, "") and key not in node.attrs:
                    node.attrs[key] = value
        for edge in item.extracted.edges:
            key = (edge.kind, edge.source, edge.target)
            found = edges.get(key)
            if found is None:
                edges[key] = AssembledEdge(
                    kind=edge.kind, source=edge.source, target=edge.target,
                    basis=edge.basis, attrs=dict(edge.attrs), witnesses=[witness],
                )
                continue
            found.basis = _better(found.basis, edge.basis)
            found.witnesses.append(witness)
            for k, v in edge.attrs.items():
                if v not in (None, "") and k not in found.attrs:
                    found.attrs[k] = v

    _merge_same_binary(nodes, edges)
    _flag_reused_infrastructure(nodes, edges)
    _close_broken_chains(nodes, edges)

    return _render_payload(nodes, edges)


# --- second pass: the same binary named several ways -----------------------

def _canonical_for(nodes: dict[str, AssembledNode]) -> dict[str, str]:
    """Map every merge key onto the node that should survive.

    A process observed with a PID is the real observation; a process named
    only as somebody's parent, and a file that is only a path, are the same
    binary seen with less detail. The PID-bearing node wins so the surviving
    node is the corroborated one.
    """
    by_path: dict[tuple[str, str], list[AssembledNode]] = {}
    for node in nodes.values():
        if node.kind not in ("process", "file"):
            continue
        host = node.attrs.get("host")
        path = norm_path(node.attrs.get("image") or node.attrs.get("path"))
        if not host or not path:
            continue
        by_path.setdefault((str(host), path), []).append(node)

    redirect: dict[str, str] = {}
    for (_host, _path), group in by_path.items():
        if len(group) < 2:
            continue

        def rank(node: AssembledNode) -> tuple[int, int, int]:
            # A GUID is unambiguous; then a PID; then a process over a file.
            return (
                1 if node.attrs.get("guid") else 0,
                1 if node.attrs.get("pid") else 0,
                1 if node.kind == "process" else 0,
            )

        winner = max(group, key=rank)
        # Nothing to do when no member of the group was ever observed with an
        # identity of its own — two path-only mentions are already one node.
        if rank(winner) == (0, 0, 0) and all(n.kind == "file" for n in group):
            continue
        for node in group:
            if node.merge_key == winner.merge_key:
                continue
            redirect[node.merge_key] = winner.merge_key
            winner.absorbed.append(node.merge_key)
            winner.witnesses.extend(node.witnesses)
            for key, value in node.attrs.items():
                if value not in (None, "") and key not in winner.attrs:
                    winner.attrs[key] = value
            # Merging a path-only mention into a PID-bearing observation does
            # not make the merge observed: this binary *might* be the same run.
            # The node keeps the better basis it already had, and records that
            # the unification itself was inferred.
            winner.attrs["merged_without_pid"] = True
    return redirect


def _merge_same_binary(
    nodes: dict[str, AssembledNode],
    edges: dict[tuple[str, str, str], AssembledEdge],
) -> None:
    redirect = _canonical_for(nodes)
    if not redirect:
        return
    for key in redirect:
        nodes.pop(key, None)
    rebuilt: dict[tuple[str, str, str], AssembledEdge] = {}
    for (kind, source, target), edge in edges.items():
        new_source = redirect.get(source, source)
        new_target = redirect.get(target, target)
        if new_source == new_target:
            continue  # a self-edge is what "it spawned itself" would mean
        new_key = (kind, new_source, new_target)
        edge.source, edge.target = new_source, new_target
        found = rebuilt.get(new_key)
        if found is None:
            rebuilt[new_key] = edge
            continue
        found.basis = _better(found.basis, edge.basis)
        found.witnesses.extend(edge.witnesses)
        for k, v in edge.attrs.items():
            if v not in (None, "") and k not in found.attrs:
                found.attrs[k] = v
    edges.clear()
    edges.update(rebuilt)


# --- reused infrastructure -------------------------------------------------

def _flag_reused_infrastructure(
    nodes: dict[str, AssembledNode],
    edges: dict[tuple[str, str, str], AssembledEdge],
) -> None:
    """An address that served a stager and later answered a beacon.

    Two different relationships arriving at one address, or one address
    witnessed by two alerts minutes apart, is the convergence the board is
    being shown the graph for. Flagged here rather than left to the eye,
    because on a 60-node canvas nobody counts inbound edges.
    """
    inbound: dict[str, set[str]] = {}
    for (kind, _source, target) in edges:
        inbound.setdefault(target, set()).add(kind)
    for node in nodes.values():
        if node.kind not in ("ip", "domain"):
            continue
        kinds = inbound.get(node.merge_key, set())
        runs = {w.run_id for w in node.witnesses}
        if len(kinds) >= 2 or len(runs) >= 2:
            node.attrs["reused_infrastructure"] = True
            node.attrs["reached_by"] = sorted(kinds)


# --- closing a chain the telemetry leaves open -----------------------------

def _close_broken_chains(
    nodes: dict[str, AssembledNode],
    edges: dict[tuple[str, str, str], AssembledEdge],
    *,
    max_gap_seconds: int = 120,
) -> None:
    """Give a genuinely orphaned process the most likely parent, as a claim.

    `reg.exe` wrote the Run key at 09:02:47 and its alert names no parent, so
    the link from the command interpreter to persistence is simply absent.
    Leaving the gap draws two disconnected fragments and loses the story.

    The first version of this was far too eager and it is worth recording what
    it produced, because the failure is instructive: it drew `spawned
    odsync.exe -> lsass.exe`. LSASS was not spawned by anything here — it was
    *opened* — so the inference did not merely guess, it asserted the opposite
    of what the telemetry said, on an edge the board would have read as the
    credential-theft step. Three conditions now hold it back:

      * the process has no inbound edge of any kind, so a node already reached
        by `points_to`, `opened_handle` or `service_binary` is left alone;
      * no witnessing alert carried a parent field, so the sensor was silent
        rather than reporting a parent this disagreed with;
      * the gap to the candidate parent is under two minutes. `odsvc.exe`
        beacons 4m15s after `ps.exe` runs and is a service on another machine,
        so a link between them would be fiction; `reg.exe` follows PowerShell
        by 33 seconds.

    Even then the edge is a claim, carries the gap, and says in words that it
    is ours and not the sensor's.
    """
    inbound: set[str] = {target for (_kind, _source, target) in edges}
    processes = [
        n for n in nodes.values()
        if n.kind == "process"
        and n.attrs.get("host")
        # Only a process some alert was actually about. A node minted from
        # another process's `parentImage` is known to have started something
        # and nothing else, and giving it a parent is how this drew `reg.exe
        # spawned explorer.exe` — inverting the relationship the sensor had
        # just reported.
        and n.attrs.get("observed_as_subject")
    ]

    def earliest(node: AssembledNode) -> datetime | None:
        times = [w.event_time for w in node.witnesses if w.event_time]
        return min(times) if times else None

    ordered = sorted(
        (n for n in processes if earliest(n)),
        key=lambda n: (earliest(n), n.merge_key),
    )
    for index, node in enumerate(ordered):
        if index == 0 or node.merge_key in inbound:
            continue
        if node.attrs.get("parent_reported"):
            continue
        when = earliest(node)
        candidates = [
            other for other in ordered[:index]
            if other.attrs.get("host") == node.attrs.get("host")
            and other.merge_key != node.merge_key
            # Never invert a relationship already drawn the other way.
            and ("spawned", node.merge_key, other.merge_key) not in edges
        ]
        if not candidates:
            continue
        parent = candidates[-1]
        gap = (when - earliest(parent)).total_seconds() if when else None
        if gap is None or gap > max_gap_seconds:
            continue
        key = ("spawned", parent.merge_key, node.merge_key)
        if key in edges:
            continue
        edges[key] = AssembledEdge(
            kind="spawned", source=parent.merge_key, target=node.merge_key,
            basis=INFERRED,
            attrs={
                "inferred": True,
                "gap_seconds": int(gap),
                "why": (
                    "No alert names a parent for this process. Linked to the "
                    f"nearest preceding process on the same host, {int(gap)}s "
                    "earlier. This edge is ours, not the sensor's."
                ),
            },
            witnesses=list(node.witnesses[:1]),
        )


# --- payload ---------------------------------------------------------------

def _render_payload(
    nodes: dict[str, AssembledNode],
    edges: dict[tuple[str, str, str], AssembledEdge],
) -> dict[str, Any]:
    def node_json(node: AssembledNode) -> dict[str, Any]:
        runs = {w.run_id for w in node.witnesses}
        levels = [w.rule_level for w in node.witnesses if w.rule_level is not None]
        return {
            "id": node.merge_key,
            "kind": node.kind,
            "label": node.label,
            "status": node.status,
            "basis": node.basis,
            "attrs": node.attrs,
            "risk": max(levels) if levels else None,
            "witnesses": [
                {
                    "run_id": w.run_id, "rule_id": w.rule_id,
                    "detection": w.detection,
                    "at": w.event_time.isoformat() if w.event_time else None,
                }
                for w in sorted(
                    {w.run_id: w for w in node.witnesses}.values(),
                    key=lambda w: (w.event_time or datetime.min.replace(tzinfo=None),),
                )
            ],
            "witness_count": len(runs),
            "absorbed": node.absorbed,
        }

    def edge_json(edge: AssembledEdge) -> dict[str, Any]:
        runs = {w.run_id for w in edge.witnesses}
        return {
            "kind": edge.kind,
            "source": edge.source,
            "target": edge.target,
            "status": edge.status,
            "basis": edge.basis,
            "attrs": edge.attrs,
            # Stroke width is this count, so an edge two alerts agree on reads
            # as heavier than one a single alert asserted.
            "witness_count": len(runs),
        }

    node_list = [node_json(n) for n in nodes.values()]
    edge_list = [edge_json(e) for e in edges.values()]
    counts: dict[str, int] = {}
    for node in node_list:
        counts[node["kind"]] = counts.get(node["kind"], 0) + 1
    techniques = [n for n in node_list if n["kind"] == "technique"]
    return {
        "nodes": node_list,
        "edges": edge_list,
        "counts": counts,
        "attack": {
            "corroborated": sum(1 for t in techniques if t["status"] == CORROBORATED),
            "claimed": sum(1 for t in techniques if t["status"] == CLAIMED),
        },
        "integrity": {
            "nodes_corroborated": sum(1 for n in node_list if n["status"] == CORROBORATED),
            "nodes_claimed": sum(1 for n in node_list if n["status"] == CLAIMED),
            "edges_corroborated": sum(1 for e in edge_list if e["status"] == CORROBORATED),
            "edges_claimed": sum(1 for e in edge_list if e["status"] == CLAIMED),
        },
        "over_cap": len(node_list) > MAX_NODES,
    }
