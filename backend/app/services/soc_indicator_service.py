from __future__ import annotations

import ipaddress
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.database import AssistantEntry, AssistantSession, IOCRecord, Investigation, SOCIndicator


TOKEN_RE = re.compile(r"^\[(?P<prefix>[A-Z]+)_(?P<number>\d+)\]$")


def indicator_type_for_value(value: str, token: str | None = None) -> str:
    token_prefix = ""
    if token:
        match = TOKEN_RE.match(token)
        token_prefix = match.group("prefix") if match else ""
    if token_prefix == "EMAIL" or "@" in value:
        return "email"
    if token_prefix == "ACCOUNT":
        return "account"
    if token_prefix == "SID" or value.upper().startswith("S-1-"):
        return "sid"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return "hash"
    if "." in value:
        return "domain"
    return "host" if token_prefix == "HOST" else "indicator"


def normalize_indicator_value(value: Any, indicator_type: str | None = None) -> str:
    raw = str(value or "").strip().strip("\"'`")
    if not raw:
        return ""
    type_text = str(indicator_type or indicator_type_for_value(raw)).lower()
    if type_text == "url":
        parsed = urlparse(raw)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{host}{port}{path}{query}".rstrip("/")
    if type_text in {"domain", "host", "email"}:
        return raw.lower()
    return raw


class SOCIndicatorService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def sync_assistant_session_indicators(self, assistant_session: AssistantSession) -> None:
        """Persist sanitized token-map indicators for all entries in an assistant session."""
        if not hasattr(self.session, "execute") or not hasattr(self.session, "add"):
            return
        await self.session.execute(
            SOCIndicator.__table__.delete().where(SOCIndicator.assistant_session_id == assistant_session.id)
        )
        now = datetime.now(timezone.utc)
        for entry in sorted(assistant_session.entries, key=lambda row: row.entry_index):
            token_map = entry.token_map_json or {}
            summary = _summary_for_entry(entry)
            for token, value in token_map.items():
                value_text = str(value or "").strip()
                if not value_text:
                    continue
                indicator_type = indicator_type_for_value(value_text, token)
                normalized = normalize_indicator_value(value_text, indicator_type)
                if not normalized:
                    continue
                self.session.add(
                    SOCIndicator(
                        indicator_type=indicator_type,
                        value=value_text,
                        normalized_value=normalized,
                        token=token,
                        source="assistant",
                        context=entry.entry_label or assistant_session.title,
                        severity=_severity_for_indicator(indicator_type, value_text),
                        confidence="medium",
                        occurrence_count=max(1, summary.get(_summary_key(indicator_type), 1)),
                        metadata_json={
                            "assistant_mode": assistant_session.mode,
                            "source_type": assistant_session.source_type,
                            "entry_index": entry.entry_index,
                        },
                        investigation_id=assistant_session.linked_investigation_id,
                        assistant_session_id=assistant_session.id,
                        assistant_entry_id=entry.id,
                        first_seen_at=entry.created_at or now,
                        last_seen_at=now,
                    )
                )

    async def get_graph(
        self,
        *,
        search: str | None = None,
        severity: str | None = None,
        limit: int = 260,
    ) -> dict[str, Any]:
        stored_rows = await self._load_stored_indicators(search=search, severity=severity, limit=limit)
        investigation_iocs = await self._load_investigation_iocs(search=search, limit=limit)
        return build_soc_indicator_graph(stored_rows + investigation_iocs, limit=limit)

    async def _load_stored_indicators(
        self,
        *,
        search: str | None,
        severity: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        query = (
            select(SOCIndicator)
            .options(selectinload(SOCIndicator.assistant_session), selectinload(SOCIndicator.investigation))
            .order_by(desc(SOCIndicator.last_seen_at))
            .limit(max(limit, 50) * 3)
        )
        if search:
            pattern = f"%{search.strip()}%"
            query = query.where(or_(SOCIndicator.value.ilike(pattern), SOCIndicator.context.ilike(pattern)))
        if severity and severity.lower() != "all":
            query = query.where(SOCIndicator.severity == severity.lower())
        result = await self.session.execute(query)
        rows = []
        for item in result.scalars().all():
            rows.append(
                {
                    "id": str(item.id),
                    "type": item.indicator_type,
                    "value": item.value,
                    "normalized": item.normalized_value,
                    "source": item.source,
                    "context": item.context,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "occurrences": item.occurrence_count,
                    "first_seen": item.first_seen_at.isoformat() if item.first_seen_at else None,
                    "last_seen": item.last_seen_at.isoformat() if item.last_seen_at else None,
                    "assistant_session": _session_ref(item.assistant_session),
                    "investigation": _investigation_ref(item.investigation),
                }
            )
        return rows

    async def _load_investigation_iocs(self, *, search: str | None, limit: int) -> list[dict[str, Any]]:
        query = (
            select(IOCRecord, Investigation)
            .join(Investigation, Investigation.id == IOCRecord.investigation_id)
            .order_by(desc(IOCRecord.created_at))
            .limit(max(limit, 50) * 3)
        )
        if search:
            pattern = f"%{search.strip()}%"
            query = query.where(or_(IOCRecord.value.ilike(pattern), IOCRecord.context.ilike(pattern), Investigation.domain.ilike(pattern)))
        result = await self.session.execute(query)
        rows = []
        for ioc, inv in result.all():
            indicator_type = str(ioc.type or indicator_type_for_value(ioc.value)).lower()
            rows.append(
                {
                    "id": str(ioc.id),
                    "type": indicator_type,
                    "value": ioc.value,
                    "normalized": normalize_indicator_value(ioc.value, indicator_type),
                    "source": "investigation_ioc",
                    "context": ioc.context,
                    "severity": _severity_from_investigation(inv),
                    "confidence": ioc.confidence or inv.confidence or "medium",
                    "occurrences": 1,
                    "first_seen": ioc.created_at.isoformat() if ioc.created_at else None,
                    "last_seen": ioc.created_at.isoformat() if ioc.created_at else None,
                    "assistant_session": None,
                    "investigation": _investigation_ref(inv),
                }
            )
        return rows


def build_soc_indicator_graph(rows: list[dict[str, Any]], *, limit: int) -> dict[str, Any]:
    indicator_nodes: dict[str, dict[str, Any]] = {}
    context_nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    grouped_by_context: dict[str, list[str]] = defaultdict(list)

    for row in rows:
        key = f"indicator:{row['type']}:{row['normalized']}"
        existing = indicator_nodes.get(key)
        if existing:
            existing["occurrences"] += int(row.get("occurrences") or 1)
            existing["sources"] = sorted(set(existing["sources"]) | {row["source"]})
            existing["last_seen"] = max(existing.get("last_seen") or "", row.get("last_seen") or "") or existing.get("last_seen")
            existing["severity"] = _max_severity(existing["severity"], row.get("severity"))
        else:
            indicator_nodes[key] = {
                "id": key,
                "kind": "indicator",
                "type": row["type"],
                "label": _label_for_indicator(row["value"]),
                "value": row["value"],
                "severity": row.get("severity") or "medium",
                "confidence": row.get("confidence") or "medium",
                "sources": [row["source"]],
                "occurrences": int(row.get("occurrences") or 1),
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
                "summary": _indicator_summary(row),
            }

        for context_type, context in (("assistant", row.get("assistant_session")), ("investigation", row.get("investigation"))):
            if not context:
                continue
            context_key = f"{context_type}:{context['id']}"
            if context_key not in context_nodes:
                context_nodes[context_key] = {
                    "id": context_key,
                    "kind": context_type,
                    "type": context_type,
                    "label": context.get("title") or context.get("domain") or context_key,
                    "value": context.get("domain") or context.get("title") or context_key,
                    "severity": context.get("severity") or row.get("severity") or "medium",
                    "confidence": context.get("confidence") or row.get("confidence") or "medium",
                    "risk_score": context.get("risk_score"),
                    "url": context.get("url"),
                    "last_seen": row.get("last_seen"),
                    "summary": context.get("summary") or row.get("context") or "",
                }
            _add_edge(edges, context_key, key, "contains", row.get("severity") or "medium")
            grouped_by_context[context_key].append(key)

    for context_key, node_ids in grouped_by_context.items():
        counts = Counter(node_ids)
        unique_nodes = [node for node in counts if node in indicator_nodes]
        for idx, source in enumerate(unique_nodes[:18]):
            for target in unique_nodes[idx + 1 : idx + 7]:
                shared = context_nodes.get(context_key, {}).get("label", "shared case")
                _add_edge(edges, source, target, f"co-observed in {shared}", _max_severity(indicator_nodes[source]["severity"], indicator_nodes[target]["severity"]), dashed=True)

    nodes = list(context_nodes.values()) + list(indicator_nodes.values())
    nodes.sort(key=lambda node: (_severity_rank(node.get("severity")), -int(node.get("occurrences") or 1), node.get("label", "")))
    edges_list = list(edges.values())
    return {
        "nodes": nodes[:limit],
        "edges": [
            edge for edge in edges_list
            if edge["source"] in {node["id"] for node in nodes[:limit]}
            and edge["target"] in {node["id"] for node in nodes[:limit]}
        ][: limit * 2],
        "summary": {
            "total_nodes": len(nodes),
            "indicator_nodes": len(indicator_nodes),
            "assistant_cases": sum(1 for node in context_nodes.values() if node["kind"] == "assistant"),
            "investigation_cases": sum(1 for node in context_nodes.values() if node["kind"] == "investigation"),
            "edges": len(edges_list),
            "critical_or_high": sum(1 for node in indicator_nodes.values() if node.get("severity") in {"critical", "high"}),
        },
    }


def _add_edge(edges: dict[str, dict[str, Any]], source: str, target: str, label: str, severity: str, dashed: bool = False) -> None:
    if not source or not target or source == target:
        return
    edge_id = f"{source}->{target}:{label}"
    edges[edge_id] = {
        "id": edge_id,
        "source": source,
        "target": target,
        "label": label,
        "severity": severity,
        "dashed": dashed,
    }


def _session_ref(session: AssistantSession | None) -> dict[str, Any] | None:
    if not session:
        return None
    return {
        "id": str(session.id),
        "title": session.title,
        "mode": session.mode,
        "severity": "high" if session.mode == "incident_correlation" else "medium",
        "confidence": "medium",
        "summary": session.report_markdown[:240] if session.report_markdown else session.title,
        "url": f"/assistant?session={session.id}",
    }


def _investigation_ref(inv: Investigation | None) -> dict[str, Any] | None:
    if not inv:
        return None
    severity = _severity_from_investigation(inv)
    return {
        "id": str(inv.id),
        "domain": inv.domain,
        "title": inv.domain,
        "classification": inv.classification,
        "severity": severity,
        "confidence": inv.confidence or "medium",
        "risk_score": inv.risk_score,
        "summary": f"{inv.classification or 'Unknown'} investigation, risk {inv.risk_score if inv.risk_score is not None else 'N/A'}",
        "url": f"/investigations/{inv.id}",
    }


def _summary_for_entry(entry: AssistantEntry) -> dict[str, int]:
    counts: dict[str, int] = {}
    for token, value in (entry.token_map_json or {}).items():
        indicator_type = indicator_type_for_value(str(value), token)
        key = _summary_key(indicator_type)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _summary_key(indicator_type: str) -> str:
    return {
        "email": "emails",
        "account": "accounts",
        "domain": "hosts",
        "host": "hosts",
        "ip": "ips",
        "sid": "sids",
    }.get(indicator_type, "indicators")


def _severity_for_indicator(indicator_type: str, value: str) -> str:
    if indicator_type in {"ip", "url", "hash"}:
        return "high"
    if indicator_type in {"email", "account", "sid"}:
        return "medium"
    if indicator_type in {"domain", "host"} and "." in value:
        return "medium"
    return "low"


def _severity_from_investigation(inv: Investigation) -> str:
    classification = str(inv.classification or "").lower()
    if classification == "malicious":
        return "critical" if (inv.risk_score or 0) >= 85 else "high"
    if classification == "suspicious":
        return "medium"
    if classification == "benign":
        return "low"
    return "medium"


def _severity_rank(severity: Any) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(str(severity or "").lower(), 2)


def _max_severity(left: Any, right: Any) -> str:
    left_s = str(left or "medium").lower()
    right_s = str(right or "medium").lower()
    return left_s if _severity_rank(left_s) <= _severity_rank(right_s) else right_s


def _label_for_indicator(value: str) -> str:
    return value if len(value) <= 30 else f"{value[:27]}..."


def _indicator_summary(row: dict[str, Any]) -> str:
    context = row.get("context") or row.get("source") or "indicator"
    return f"{row.get('type', 'indicator')} observed from {context}"
