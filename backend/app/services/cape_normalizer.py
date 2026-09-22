"""Turn a CAPE report into the platform's own shape.

CAPE reports are large, deeply nested, and differ between versions and between
report formats. Every access here is defensive: a missing or oddly-typed branch
produces an empty list, never an exception, because a partially-parseable report
from a sample that really did execute is still evidence worth showing.

Two rules this file exists to enforce:

* **A missing malscore is not zero.** `tasks/view` frequently omits it, and a
  sample whose score is unknown must never be presented as clean. `malscore`
  stays None and `verdict` stays "unknown" unless the report actually said.
* **The verdict is an opinion, not a decision.** Nothing downstream may act on
  it automatically — see `SCORE_*` below. It is analyst evidence.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from app.models.schemas import (
    CapeBehaviourSummary,
    CapeDroppedFile,
    CapeNetworkIndicators,
    CapeNormalizedReport,
    CapeSignature,
)

logger = logging.getLogger(__name__)

# CAPE's malscore runs 0–10. These are a starting point for *display ordering*,
# deliberately not wired to any automatic action: a sandbox score is one input
# to an analyst's judgement, and this platform does not contain or remediate on
# the strength of one detonation.
SCORE_MALICIOUS = 7.0
SCORE_SUSPICIOUS = 4.0

# Ceilings per list. A busy sample can contact thousands of hosts; the point of
# the summary is that an analyst can read it.
_MAX_ITEMS = 200
_MAX_HTTP = 50
_MAX_PROCESS_TREE = 100
_MAX_SIGNATURES = 100
_MAX_DROPPED = 100


def normalize_report(
    payload: dict[str, Any],
    *,
    task_id: int | None = None,
    report_format: str | None = None,
    report_size_bytes: int | None = None,
) -> CapeNormalizedReport:
    """The authoritative mapping. `payload` is a CAPE JSON report."""
    if not isinstance(payload, dict):
        return CapeNormalizedReport(
            task_id=task_id,
            status="failed",
            errors=["CAPE report was not an object"],
            report_format=report_format,
        )

    info = _dict(payload.get("info"))
    target_file = _dict(_dict(payload.get("target")).get("file"))

    malscore = _as_float(payload.get("malscore"))
    if malscore is None:
        malscore = _as_float(info.get("malscore"))

    errors = _strings(_dict(payload.get("debug")).get("errors"))[:20]
    limitations: list[str] = []

    machine = _dict(info.get("machine"))
    signatures = _signatures(payload.get("signatures"))
    network = _network(payload.get("network"))
    behaviour = _behaviour(payload.get("behavior") or payload.get("behaviour"))
    dropped = _dropped(payload)
    configs = _configs(payload)

    if not behaviour.process_count and not network.domains and not network.hosts:
        # Nothing executed and nothing was contacted. Said out loud, because an
        # empty report reads exactly like a clean one otherwise.
        limitations.append(
            "No process activity and no network activity were recorded. "
            "The sample may not have executed in the guest."
        )
    if report_format and report_format != "json":
        limitations.append(
            f"Parsed from CAPE's '{report_format}' report, which carries less detail than the full JSON report."
        )

    return CapeNormalizedReport(
        task_id=task_id or _as_int(info.get("id")),
        status=str(payload.get("status") or info.get("status") or "reported").strip().lower(),
        malscore=malscore,
        verdict=verdict_for(malscore),
        detections=_detections(payload),
        signatures=signatures,
        sha256=_lower(target_file.get("sha256")),
        sha1=_lower(target_file.get("sha1")),
        md5=_lower(target_file.get("md5")),
        file_name=_text(target_file.get("name")),
        file_type=_text(target_file.get("type")),
        file_size=_as_int(target_file.get("size")),
        started_at=_text(info.get("started")),
        ended_at=_text(info.get("ended")),
        duration_seconds=_as_int(info.get("duration")),
        machine=_text(machine.get("name") or machine.get("label")) if machine else _text(info.get("machine")),
        route=_text(info.get("route")),
        network=network,
        behaviour=behaviour,
        dropped_files=dropped,
        extracted_configs=configs,
        has_screenshots=bool(payload.get("screenshots")),
        screenshot_count=len(payload.get("screenshots") or []) if isinstance(payload.get("screenshots"), list) else 0,
        report_format=report_format,
        report_size_bytes=report_size_bytes,
        errors=errors,
        limitations=limitations,
    )


def verdict_for(malscore: float | None) -> str:
    """Unknown when CAPE did not say. Never "benign" by absence of evidence."""
    if malscore is None:
        return "unknown"
    if malscore >= SCORE_MALICIOUS:
        return "malicious"
    if malscore >= SCORE_SUSPICIOUS:
        return "suspicious"
    return "likely_benign"


# ── sections ─────────────────────────────────────────────────────────────────


def _detections(payload: dict) -> list[str]:
    """Family names. CAPE has used strings and objects in this list."""
    found: list[str] = []
    raw = payload.get("detections")
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            name = item.get("family") or item.get("name") or item.get("detection")
            if name:
                found.append(str(name))
    if isinstance(raw, str) and raw.strip():
        found.append(raw.strip())
    # CAPE's own extraction often names the family only here.
    for config in _configs(payload):
        family = config.get("family") or config.get("cape_name")
        if family:
            found.append(str(family))
    return _dedupe(found)


def _signatures(raw: Any) -> list[CapeSignature]:
    out: list[CapeSignature] = []
    seen: set[str] = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name")) or _text(item.get("signature"))
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(
            CapeSignature(
                name=name,
                description=_text(item.get("description")) or "",
                severity=_as_int(item.get("severity")) or 0,
                confidence=_as_int(item.get("confidence")),
                ttps=_ttps(item),
            )
        )
        if len(out) >= _MAX_SIGNATURES:
            break
    out.sort(key=lambda s: s.severity, reverse=True)
    return out


def _ttps(item: dict) -> list[str]:
    """ATT&CK ids, from the several keys CAPE has used for them."""
    found: list[str] = []
    for key in ("ttp", "ttps", "attack", "attack_id", "mitre"):
        value = item.get(key)
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, str):
                    found.append(entry)
                elif isinstance(entry, dict):
                    tid = entry.get("id") or entry.get("technique_id") or entry.get("ttp")
                    if tid:
                        found.append(str(tid))
        elif isinstance(value, dict):
            found.extend(str(k) for k in value.keys())
    return _dedupe(found)[:20]


def _network(raw: Any) -> CapeNetworkIndicators:
    net = _dict(raw)
    domains: list[str] = []
    hosts: list[str] = []

    for entry in net.get("domains") if isinstance(net.get("domains"), list) else []:
        if isinstance(entry, dict):
            if entry.get("domain"):
                domains.append(str(entry["domain"]))
            if entry.get("ip"):
                hosts.append(str(entry["ip"]))
        elif isinstance(entry, str):
            domains.append(entry)

    dns_queries: list[str] = []
    for entry in net.get("dns") if isinstance(net.get("dns"), list) else []:
        if isinstance(entry, dict):
            request = entry.get("request") or entry.get("name")
            if request:
                dns_queries.append(str(request))
        elif isinstance(entry, str):
            dns_queries.append(entry)

    for entry in net.get("hosts") if isinstance(net.get("hosts"), list) else []:
        if isinstance(entry, str):
            hosts.append(entry)
        elif isinstance(entry, dict) and entry.get("ip"):
            hosts.append(str(entry["ip"]))

    destinations: list[str] = []
    for proto in ("tcp", "udp", "icmp"):
        for entry in net.get(proto) if isinstance(net.get(proto), list) else []:
            if not isinstance(entry, dict):
                continue
            dst = entry.get("dst") or entry.get("dport_ip") or entry.get("daddr")
            port = entry.get("dport") or entry.get("port")
            if dst:
                destinations.append(f"{dst}:{port}/{proto}" if port else f"{dst}/{proto}")
                hosts.append(str(dst))

    http_requests: list[dict] = []
    for key in ("http", "http_ex", "https_ex"):
        for entry in net.get(key) if isinstance(net.get(key), list) else []:
            if not isinstance(entry, dict):
                continue
            http_requests.append(
                {
                    "method": _text(entry.get("method")) or "GET",
                    "host": _text(entry.get("host")) or "",
                    "uri": _text(entry.get("uri") or entry.get("path")) or "",
                    "status": _as_int(entry.get("status")),
                }
            )
            if entry.get("host"):
                domains.append(str(entry["host"]))
            if len(http_requests) >= _MAX_HTTP:
                break

    tls_sni: list[str] = []
    for entry in net.get("tls") if isinstance(net.get("tls"), list) else []:
        if isinstance(entry, dict):
            sni = entry.get("sni") or entry.get("server_name")
            if sni:
                tls_sni.append(str(sni))
                domains.append(str(sni))

    return CapeNetworkIndicators(
        # Hostnames are case-insensitive, and these are looked up by JSONB
        # containment later — storing them lowercased makes that exact.
        domains=_dedupe(d.lower() for d in domains),
        dns_queries=_dedupe(d.lower() for d in dns_queries),
        hosts=_dedupe(hosts),
        destinations=_dedupe(destinations),
        http_requests=http_requests[:_MAX_HTTP],
        tls_sni=_dedupe(s.lower() for s in tls_sni),
    )


def _behaviour(raw: Any) -> CapeBehaviourSummary:
    behavior = _dict(raw)
    summary = _dict(behavior.get("summary"))

    tree_raw = behavior.get("processtree") or behavior.get("process_tree")
    tree = _process_tree(tree_raw)

    processes = behavior.get("processes")
    process_count = len(processes) if isinstance(processes, list) else len(tree)

    return CapeBehaviourSummary(
        mutexes=_dedupe(_strings(summary.get("mutex") or summary.get("mutexes"))),
        registry_keys=_dedupe(
            _strings(summary.get("keys"))
            + _strings(summary.get("write_keys"))
            + _strings(summary.get("read_keys"))
        ),
        files_written=_dedupe(_strings(summary.get("write_files") or summary.get("files_written"))),
        files_read=_dedupe(_strings(summary.get("read_files") or summary.get("files"))),
        commands=_dedupe(_strings(summary.get("executed_commands") or summary.get("commands"))),
        process_tree=tree,
        process_count=process_count,
    )


def _process_tree(raw: Any, depth: int = 0) -> list[dict]:
    """Flattened to name/pid/children-count: enough to read, not a memory dump."""
    if not isinstance(raw, list) or depth > 6:
        return []
    out: list[dict] = []
    for node in raw:
        if not isinstance(node, dict):
            continue
        children = node.get("children")
        out.append(
            {
                "name": _text(node.get("name") or node.get("process_name")) or "unknown",
                "pid": _as_int(node.get("pid")),
                "parent_pid": _as_int(node.get("parent_id") or node.get("ppid")),
                "command_line": (_text(node.get("command_line")) or "")[:500],
                "children": _process_tree(children, depth + 1),
            }
        )
        if len(out) >= _MAX_PROCESS_TREE:
            break
    return out


def _dropped(payload: dict) -> list[CapeDroppedFile]:
    out: list[CapeDroppedFile] = []
    seen: set[str] = set()

    def add(entry: Any, *, is_payload: bool) -> None:
        if not isinstance(entry, dict) or len(out) >= _MAX_DROPPED:
            return
        digest = _lower(entry.get("sha256")) or ""
        key = digest or _text(entry.get("name")) or ""
        if not key or key in seen:
            return
        seen.add(key)
        out.append(
            CapeDroppedFile(
                name=_text(entry.get("name")),
                sha256=digest or None,
                md5=_lower(entry.get("md5")),
                size=_as_int(entry.get("size")),
                file_type=_text(entry.get("type")),
                is_cape_payload=is_payload,
                cape_type=_text(entry.get("cape_type")),
            )
        )

    for entry in payload.get("dropped") if isinstance(payload.get("dropped"), list) else []:
        add(entry, is_payload=False)

    cape_section = _dict(payload.get("CAPE"))
    payloads = cape_section.get("payloads") if isinstance(cape_section.get("payloads"), list) else []
    for entry in payloads:
        add(entry, is_payload=True)
    # Older reports put the payload list directly under "CAPE".
    if isinstance(payload.get("CAPE"), list):
        for entry in payload["CAPE"]:
            add(entry, is_payload=True)

    return out


def _configs(payload: dict) -> list[dict]:
    """CAPE's config extraction — the C2 details, when it recognised a family."""
    found: list[dict] = []
    cape_section = _dict(payload.get("CAPE"))
    for source in (cape_section.get("configs"), payload.get("CAPE_configs"), payload.get("configs")):
        if isinstance(source, list):
            found.extend(c for c in source if isinstance(c, dict))
        elif isinstance(source, dict):
            found.append(source)
    return found[:20]


# ── primitives ───────────────────────────────────────────────────────────────


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for key in ("name", "value", "path", "key"):
                if item.get(key):
                    out.append(str(item[key]))
                    break
    return out


def _dedupe(values: Iterable[str]) -> list[str]:
    """Order-preserving, case-insensitive, trimmed, capped."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        cleaned = str(value).strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(cleaned)
        if len(out) >= _MAX_ITEMS:
            break
    return out


def _text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _lower(value: Any) -> str | None:
    text = _text(value)
    return text.lower() if text else None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
