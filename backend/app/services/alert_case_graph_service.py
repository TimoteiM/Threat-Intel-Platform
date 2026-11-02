"""One case, drawn as what happened rather than as a list of rows.

An analyst reading a case gets a verdict, a paragraph and a table of alerts.
None of those show the *shape* of an intrusion — which account, on which
device, spawning what, reaching which indicator, and in what order. That shape
is the thing a board asked to see and the thing a table is worst at.

**What this is not.** It is not a BloodHound graph. BloodHound draws Active
Directory entitlements — who can reach Domain Admin through group membership,
ACLs and GPO links — collected from the directory itself. This platform
ingests no directory objects, so none of those nodes or edges exist here. This
draws the incident: the records we actually hold about what was observed.

**Claimed and corroborated are drawn differently, always.** 30,763 of the
30,803 ATT&CK mappings in this estate are `not_corroborated` — the detection
asserted a technique and the investigation found nothing bearing on it either
way. A graph is more persuasive than a table, so rendering those identically
to the 40 that were confirmed would be the most convincing wrong picture this
platform could produce. Every technique node carries its status and the
explanation the assessment gave, and the edge that reaches it says which of
the two it is.

Everything here is derived from stored records on request. Nothing is
inferred, and a node exists only where a row does.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# A graph stops being readable long before it stops being drawable. Past this
# the page keeps the strongest material and says plainly what it left out,
# rather than rendering a hairball nobody can read.
MAX_NODES = 320
MAX_INDICATORS = 40
MAX_PROCESSES = 60

# Node kinds, in the order a legend should list them.
KINDS = ("case", "host", "account", "alert", "process", "technique", "indicator")


def _node(
    nodes: dict[str, dict[str, Any]], node_id: str, kind: str, label: str, **data: Any
) -> str:
    """Add a node once. Later mentions enrich it rather than replacing it."""
    existing = nodes.get(node_id)
    if existing is None:
        nodes[node_id] = {"id": node_id, "kind": kind, "label": label, **data}
        return node_id
    for key, value in data.items():
        if value not in (None, "", [], {}) and not existing.get(key):
            existing[key] = value
    return node_id


def _edge(edges: list[dict[str, Any]], source: str, target: str, kind: str, **data: Any) -> None:
    edges.append({"source": source, "target": target, "kind": kind, **data})


def _technique_status(raw: Any) -> str:
    """`corroborated` or `claimed` — never a third thing a renderer must guess at."""
    text = str(raw or "").strip().lower()
    return "corroborated" if text in {"confirmed", "corroborated", "evidenced"} else "claimed"


def build_case_graph(
    case: dict[str, Any],
    *,
    assessments: dict[str, Any] | None = None,
    indicators: dict[str, Iterable[str]] | None = None,
    processes: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Nodes and edges for one correlated case.

    `assessments`, `indicators` and `processes` are passed in rather than
    fetched here, so the shape of the graph is testable without a database and
    the endpoint decides what it can afford to load.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    dropped: dict[str, int] = {}

    alerts = list(case.get("alerts") or [])
    host = str(case.get("entity_host") or "").strip()
    case_id = f"case:{case.get('case_key')}"

    _node(
        nodes, case_id, "case",
        label=f"#{case.get('case_number')} · {case.get('label') or host or 'case'}",
        case_number=case.get("case_number"),
        score=case.get("score"),
        verdict=(case.get("lifecycle") or {}).get("resolution"),
        href=f"/detections/cases/{case.get('case_key')}",
        alert_count=len(alerts),
    )

    if host:
        host_id = f"host:{host.casefold()}"
        _node(nodes, host_id, "host", label=host, href=f"/detections/devices?host={host}")
        _edge(edges, case_id, host_id, "on")

    # The accounts the case touched, from the alerts themselves.
    for account in (case.get("entity_users") or []):
        name = str(account or "").strip()
        if not name:
            continue
        account_id = f"account:{name.casefold()}"
        _node(nodes, account_id, "account", label=name)
        if host:
            _edge(edges, f"host:{host.casefold()}", account_id, "account_on")

    assessments = assessments or {}
    indicators = indicators or {}
    indicator_budget = MAX_INDICATORS

    for alert in alerts:
        run_id = str(alert.get("run_id") or "")
        if not run_id:
            continue
        alert_id = f"alert:{run_id}"
        _node(
            nodes, alert_id, "alert",
            # What fired, not the rule that carried it — the carrier is the
            # same string for every detection filed under it.
            label=str(
                alert.get("detection_name") or alert.get("title") or alert.get("run_id")
            )[:90],
            at=alert.get("event_time"),
            verdict=alert.get("overall_verdict"),
            risk=alert.get("highest_risk_score"),
            rule_id=alert.get("detection_rule_id"),
            href=f"/alert-investigations/{run_id}",
        )
        _edge(edges, case_id, alert_id, "contains")

        account = str(alert.get("entity_user") or "").strip()
        if account:
            account_id = f"account:{account.casefold()}"
            _node(nodes, account_id, "account", label=account)
            _edge(edges, alert_id, account_id, "ran_as")

        # ATT&CK, with the two states kept apart.
        for technique in (assessments.get(run_id) or []):
            tid = str(technique.get("id") or "").strip()
            if not tid:
                continue
            status = _technique_status(technique.get("status"))
            technique_id = f"technique:{tid}"
            _node(
                nodes, technique_id, "technique", label=f"{tid} · {technique.get('name') or ''}".strip(" ·"),
                technique=tid,
                tactic=technique.get("tactic"),
                url=technique.get("url"),
                status=status,
                # The assessment's own words about why, which is the whole
                # difference between a mapping and a finding.
                explanation=str(technique.get("explanation") or "")[:400] or None,
                evidence_count=len(technique.get("evidence") or []),
            )
            _edge(edges, alert_id, technique_id, status)

        for value in list(indicators.get(run_id) or [])[:6]:
            text = str(value or "").strip()
            if not text:
                continue
            if indicator_budget <= 0:
                dropped["indicator"] = dropped.get("indicator", 0) + 1
                continue
            indicator_id = f"indicator:{text.casefold()}"
            if indicator_id not in nodes:
                indicator_budget -= 1
            _node(nodes, indicator_id, "indicator", label=text[:70])
            _edge(edges, alert_id, indicator_id, "names")

    # Process ancestry, from the logs retrieved around the alerts. This is the
    # part that shows what actually ran: Sysmon gives a process its own GUID
    # and names its parent, so the tree is observed rather than reconstructed.
    for index, process in enumerate(processes or []):
        if index >= MAX_PROCESSES:
            dropped["process"] = dropped.get("process", 0) + 1
            continue
        guid = str(process.get("guid") or "").strip()
        image = str(process.get("image") or "").strip()
        if not guid and not image:
            continue
        process_id = f"process:{guid or image.casefold()}"
        _node(
            nodes, process_id, "process", label=(image.rsplit("\\", 1)[-1] or image)[:70],
            image=image or None,
            command_line=str(process.get("command_line") or "")[:400] or None,
            at=process.get("at"),
            account=process.get("account"),
        )
        parent_guid = str(process.get("parent_guid") or "").strip()
        parent_image = str(process.get("parent_image") or "").strip()
        if parent_guid or parent_image:
            parent_id = f"process:{parent_guid or parent_image.casefold()}"
            _node(
                nodes, parent_id, "process",
                label=(parent_image.rsplit("\\", 1)[-1] or parent_image or "parent")[:70],
                image=parent_image or None,
            )
            _edge(edges, parent_id, process_id, "spawned")
        elif host:
            _edge(edges, f"host:{host.casefold()}", process_id, "ran")
        # EID 8/10: one process reaching into another. Drawn separately from
        # spawning because it is the shape injection makes.
        target_guid = str(process.get("accessed_guid") or "").strip()
        target_image = str(process.get("accessed_image") or "").strip()
        if target_guid or target_image:
            target_id = f"process:{target_guid or target_image.casefold()}"
            _node(
                nodes, target_id, "process",
                label=(target_image.rsplit("\\", 1)[-1] or target_image or "target")[:70],
                image=target_image or None,
            )
            _edge(edges, process_id, target_id, "accessed")

    # Bounded, and honest about it.
    if len(nodes) > MAX_NODES:
        keep_order = {kind: i for i, kind in enumerate(KINDS)}
        ordered = sorted(nodes.values(), key=lambda n: keep_order.get(n["kind"], 99))
        kept = {n["id"] for n in ordered[:MAX_NODES]}
        for node in ordered[MAX_NODES:]:
            dropped[node["kind"]] = dropped.get(node["kind"], 0) + 1
        nodes = {k: v for k, v in nodes.items() if k in kept}
        edges = [e for e in edges if e["source"] in kept and e["target"] in kept]

    counts: dict[str, int] = {}
    for node in nodes.values():
        counts[node["kind"]] = counts.get(node["kind"], 0) + 1

    corroborated = sum(
        1 for n in nodes.values() if n["kind"] == "technique" and n.get("status") == "corroborated"
    )
    claimed = counts.get("technique", 0) - corroborated

    return {
        "case_key": case.get("case_key"),
        "case_number": case.get("case_number"),
        "nodes": list(nodes.values()),
        "edges": edges,
        "counts": counts,
        "attack": {"corroborated": corroborated, "claimed": claimed},
        # Said rather than silently applied — a graph that quietly dropped a
        # third of its nodes reads as a complete picture.
        "dropped": dropped or None,
        "note": (
            "Drawn from the records held about this case. Techniques the "
            "detection asserted but the investigation could not corroborate "
            "are drawn as claims, not findings."
        ),
    }
