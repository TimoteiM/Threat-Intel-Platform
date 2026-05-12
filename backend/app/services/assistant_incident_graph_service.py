from __future__ import annotations

import re
from collections import Counter
from typing import Any

from app.models.database import AssistantSession
from app.services.soc_indicator_service import indicator_type_for_value


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def build_assistant_incident_graph(assistant_session: AssistantSession, report_markdown: str = "") -> dict[str, Any]:
    """Build a per-assistant-session incident graph from sanitized indicators and report text.

    This is intentionally separate from the global SOC indicator research graph. It models the
    single assistant investigation as an incident story: alert/case -> source indicators ->
    affected identities/assets -> post-authentication or related artifacts.
    """
    indicators = _extract_indicators(assistant_session)
    title = assistant_session.title or "Assistant investigation"
    mode = assistant_session.mode or "alert_analysis"
    summary_text = _first_report_paragraph(report_markdown) or title
    action_hints = _recommended_actions(report_markdown, indicators)
    score = _score_graph(indicators, report_markdown)
    risk = "High" if score >= 70 else "Medium" if score >= 40 else "Low"

    nodes: list[dict[str, Any]] = [
        {
            "id": "alert-001",
            "type": "alert",
            "label": title,
            "subtitle": "AI Assistant / " + mode.replace("_", " "),
            "severity": "high" if score >= 65 else "medium",
            "x": 520,
            "y": 80,
            "details": summary_text,
        }
    ]
    edges: list[dict[str, str]] = []

    buckets: dict[str, list[dict[str, Any]]] = {
        "ip": [],
        "user": [],
        "endpoint": [],
        "domain": [],
        "url": [],
        "hash": [],
        "sid": [],
        "other": [],
    }
    for row in indicators:
        bucket = _bucket_for_indicator(row["type"])
        buckets.setdefault(bucket, []).append(row)

    for idx, row in enumerate(buckets["ip"][:3]):
        node_id = f"ip-{idx + 1}"
        nodes.append(_node_from_indicator(row, node_id, x=220, y=210 + idx * 120, subtitle="Source / network indicator"))
        edges.append({"from": node_id, "to": "alert-001", "label": "generated"})

    if buckets["ip"]:
        nodes.append(
            {
                "id": "geo-1",
                "type": "geo",
                "label": "Geo / ASN Pivot",
                "subtitle": "Enrichment recommended",
                "severity": "medium",
                "x": 80,
                "y": 370,
                "details": "Resolve source network ownership, geolocation, ASN, VPN/proxy status, and prior reputation.",
            }
        )
        edges.append({"from": "ip-1", "to": "geo-1", "label": "resolved geo"})

    for idx, row in enumerate(buckets["user"][:8]):
        node_id = f"user-{idx + 1}"
        severity = "high" if _looks_privileged(row["value"]) else "medium"
        nodes.append(_node_from_indicator(row, node_id, x=470 + (idx % 4) * 190, y=260 + (idx // 4) * 120, subtitle="Targeted identity", severity=severity, node_type="user"))
        edges.append({"from": "alert-001", "to": node_id, "label": "targeted"})

    if _mentions_success(report_markdown) or len(buckets["user"]) > 1:
        nodes.append(
            {
                "id": "success-login",
                "type": "success",
                "label": "Successful Login / Follow-on Activity",
                "subtitle": "Potential account compromise",
                "severity": "critical" if _mentions_success(report_markdown) else "medium",
                "x": 670,
                "y": 430,
                "details": "Successful authentication or follow-on activity after suspicious events increases compromise likelihood.",
            }
        )
        if buckets["user"]:
            edges.append({"from": "user-1", "to": "success-login", "label": "auth success"})
        else:
            edges.append({"from": "alert-001", "to": "success-login", "label": "follow-up"})

    for idx, row in enumerate(buckets["endpoint"][:4]):
        node_id = f"endpoint-{idx + 1}"
        nodes.append(_node_from_indicator(row, node_id, x=450 + idx * 210, y=560, subtitle="Endpoint observed", node_type="endpoint"))
        edges.append({"from": "success-login" if any(n["id"] == "success-login" for n in nodes) else "alert-001", "to": node_id, "label": "session opened"})

    related = (buckets["domain"] + buckets["url"] + buckets["hash"])[:6]
    for idx, row in enumerate(related):
        node_id = f"related-{idx + 1}"
        nodes.append(_node_from_indicator(row, node_id, x=900 + (idx % 2) * 230, y=440 + (idx // 2) * 130, subtitle="Related IOC"))
        edges.append({"from": node_id, "to": "alert-001" if not buckets["user"] else f"user-{min(len(buckets['user']), 3)}", "label": "reported by"})

    _dedupe_edges(edges)
    return {
        "summary": {
            "incident": title,
            "risk": risk,
            "confidence": _confidence_from_report(report_markdown),
            "score": score,
            "lastSeen": assistant_session.completed_at.isoformat() if assistant_session.completed_at else None,
            "mode": mode,
        },
        "nodes": nodes[:42],
        "edges": edges[:80],
        "recommended_actions": action_hints,
        "data_checks": _graph_data_checks(nodes, edges),
    }


def _extract_indicators(assistant_session: AssistantSession) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for entry in sorted(assistant_session.entries, key=lambda item: item.entry_index):
        for token, value in (entry.token_map_json or {}).items():
            value_text = str(value or "").strip()
            if not value_text:
                continue
            indicator_type = indicator_type_for_value(value_text, token)
            key = (indicator_type, value_text.lower())
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "token": token,
                    "type": indicator_type,
                    "value": value_text,
                    "entry_label": entry.entry_label,
                    "entry_index": entry.entry_index,
                }
            )
    return rows


def _node_from_indicator(row: dict[str, Any], node_id: str, *, x: int, y: int, subtitle: str, severity: str | None = None, node_type: str | None = None) -> dict[str, Any]:
    kind = node_type or _node_type(row["type"])
    return {
        "id": node_id,
        "type": kind,
        "label": row["value"],
        "subtitle": subtitle,
        "severity": severity or _severity_for_type(row["type"], row["value"]),
        "x": x,
        "y": y,
        "details": f"{row['type']} indicator observed in assistant evidence as {row.get('token') or 'a resolved value'}.",
        "token": row.get("token"),
    }


def _bucket_for_indicator(indicator_type: str) -> str:
    if indicator_type == "ip":
        return "ip"
    if indicator_type in {"email", "account", "sid"}:
        return "user" if indicator_type != "sid" else "sid"
    if indicator_type == "host":
        return "endpoint"
    if indicator_type in {"domain", "url", "hash"}:
        return indicator_type
    return "other"


def _node_type(indicator_type: str) -> str:
    return {
        "email": "user",
        "account": "user",
        "host": "endpoint",
        "ip": "ip",
        "url": "domain",
        "domain": "domain",
        "hash": "malware",
        "sid": "user",
    }.get(indicator_type, "indicator")


def _severity_for_type(indicator_type: str, value: str) -> str:
    if indicator_type in {"ip", "url", "hash"}:
        return "high"
    if _looks_privileged(value):
        return "high"
    if indicator_type in {"email", "account", "domain", "host"}:
        return "medium"
    return "low"


def _looks_privileged(value: str) -> bool:
    lowered = value.lower()
    return any(term in lowered for term in ("admin", "support", "it.", "svc", "service", "root", "helpdesk"))


def _mentions_success(markdown: str) -> bool:
    lowered = markdown.lower()
    return any(term in lowered for term in ("successful login", "success login", "authenticated", "mailbox rule", "forwarding rule"))


def _score_graph(indicators: list[dict[str, Any]], markdown: str) -> int:
    counts = Counter(row["type"] for row in indicators)
    score = 20
    score += min(25, counts.get("ip", 0) * 12)
    score += min(24, (counts.get("email", 0) + counts.get("account", 0)) * 6)
    score += min(18, (counts.get("domain", 0) + counts.get("url", 0) + counts.get("hash", 0)) * 9)
    if _mentions_success(markdown):
        score += 18
    if any(_looks_privileged(row["value"]) for row in indicators):
        score += 8
    return max(0, min(100, score))


def _confidence_from_report(markdown: str) -> str:
    lowered = markdown.lower()
    if "high confidence" in lowered:
        return "High"
    if "low confidence" in lowered:
        return "Low"
    return "Medium"


def _first_report_paragraph(markdown: str) -> str:
    cleaned = re.sub(r"#+\s*", "", markdown or "").strip()
    for part in re.split(r"\n\s*\n|^- ", cleaned, flags=re.MULTILINE):
        text = part.strip(" -\n\t")
        if text and not text.lower().startswith("resolved identifiers"):
            return text[:420]
    return ""


def _recommended_actions(markdown: str, indicators: list[dict[str, Any]]) -> list[str]:
    actions = []
    if any(row["type"] == "ip" for row in indicators):
        actions.append("Review and block source IPs if corroborated by authentication or proxy telemetry.")
    if any(row["type"] in {"email", "account"} for row in indicators):
        actions.append("Reset passwords and validate MFA state for impacted accounts.")
    if _mentions_success(markdown):
        actions.append("Review mailbox rules, forwarding settings, and post-login activity.")
    if any(row["type"] in {"domain", "url", "hash"} for row in indicators):
        actions.append("Hunt related domains, URLs, and hashes across SIEM, EDR, DNS, and proxy logs.")
    if not actions:
        actions.append("Validate the alert against local telemetry and preserve the sanitized evidence.")
    return actions[:5]


def _dedupe_edges(edges: list[dict[str, str]]) -> None:
    seen = set()
    keep = []
    for edge in edges:
        key = (edge.get("from"), edge.get("to"), edge.get("label"))
        if key in seen:
            continue
        seen.add(key)
        keep.append(edge)
    edges[:] = keep


def _graph_data_checks(nodes: list[dict[str, Any]], edges: list[dict[str, str]]) -> list[dict[str, Any]]:
    node_ids = {node.get("id") for node in nodes}
    return [
        {"name": "unique node IDs", "passed": len(node_ids) == len(nodes)},
        {"name": "all edges reference valid nodes", "passed": all(edge.get("from") in node_ids and edge.get("to") in node_ids for edge in edges)},
        {"name": "all nodes include required fields", "passed": all(node.get("id") and node.get("type") and node.get("label") and node.get("severity") for node in nodes)},
        {"name": "graph contains multiple indicators", "passed": len(nodes) >= 2},
    ]
