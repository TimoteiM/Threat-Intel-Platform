"""
Normalized ANY.RUN sandbox intelligence.

This module turns provider-shaped behavior blobs into SOC-ready sections that
can be reused by the UI, exports, and IOC extraction without duplicating parser
logic in each caller.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

_SUSPICIOUS_COMMAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b.*(?:-enc|-encodedcommand|frombase64string)", re.I), "PowerShell encoded or base64 payload"),
    (re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b.*(?:downloadstring|invoke-webrequest|iwr\b|invoke-restmethod|irm\b)", re.I), "PowerShell web download/execution"),
    (re.compile(r"\b(?:cmd|powershell|pwsh)(?:\.exe)?\b.*(?:/c|\s-c\s).*https?://", re.I), "Shell command reaches an external URL"),
    (re.compile(r"\b(?:rundll32|regsvr32|mshta|wscript|cscript|wmic)(?:\.exe)?\b", re.I), "Living-off-the-land execution utility"),
    (re.compile(r"\b(?:certutil|bitsadmin|curl|wget)(?:\.exe)?\b.*https?://", re.I), "Command-line downloader"),
    (re.compile(r"\b(?:schtasks|at)(?:\.exe)?\b.*(?:/create|/sc|/tn)", re.I), "Scheduled task persistence"),
    (re.compile(r"\b(?:reg)(?:\.exe)?\b\s+add\b", re.I), "Registry modification"),
    (re.compile(r"\b(?:vssadmin|bcdedit|wbadmin)(?:\.exe)?\b", re.I), "Recovery or backup tampering utility"),
    (re.compile(r"\b(?:net|net1)(?:\.exe)?\b\s+user\b", re.I), "User account manipulation"),
    (re.compile(r"\bappdata\b|\btemp\b|\\startup\\", re.I), "Execution or file activity from a user-writable path"),
]


def build_anyrun_sandbox_intelligence(result: dict[str, Any] | None) -> dict[str, Any]:
    """Build normalized sandbox intelligence from a collector result item."""
    if not isinstance(result, dict):
        return {}

    raw = _as_dict(result.get("raw_summary"))
    dynamic = _as_dict(result.get("dynamic_io_summary"))
    behavior = _as_dict(raw.get("behavior_details"))
    graph = _as_dict(raw.get("behavior_graph"))

    contacted_hosts: list[dict[str, Any]] = []
    contacted_ips: list[dict[str, Any]] = []
    dropped_files: list[dict[str, Any]] = []
    suspicious_commands: list[dict[str, Any]] = []
    extracted_iocs: list[dict[str, Any]] = []

    seen_hosts: set[str] = set()
    seen_ips: set[tuple[str, str, str]] = set()
    seen_files: set[str] = set()
    seen_commands: set[str] = set()
    seen_iocs: set[tuple[str, str]] = set()

    def add_ioc(ioc_type: str, value: Any, context: str, confidence: str = "medium", source: str = "anyrun") -> None:
        text = _clean_text(value)
        if not text:
            return
        key = (ioc_type, text.lower())
        if key in seen_iocs:
            return
        seen_iocs.add(key)
        extracted_iocs.append(
            {
                "type": ioc_type,
                "value": text,
                "context": context,
                "confidence": confidence,
                "source": source,
            }
        )

    def add_host(value: Any, *, source: str, process: Any = None, threat_level: Any = None, threat_name: Any = None, url: Any = None) -> None:
        host = _normalize_host(value)
        if not host or _is_ip(host):
            if host and _is_ip(host):
                add_ip(host, source=source, process=process, threat_level=threat_level, threat_name=threat_name)
            return
        key = host.lower()
        if key in seen_hosts:
            return
        seen_hosts.add(key)
        level = _as_int(threat_level)
        contacted_hosts.append(
            {
                "host": host,
                "type": "domain",
                "source": source,
                "process": _clean_text(process),
                "threat_level": level,
                "threat_name": _join_names(threat_name),
                "url": _clean_text(url),
            }
        )
        add_ioc("domain", host, f"AnyRun {source}", "high" if level >= 2 else "medium")

    def add_ip(value: Any, *, source: str, process: Any = None, threat_level: Any = None, threat_name: Any = None, port: Any = None, protocol: Any = None) -> None:
        ip = _normalize_ip(value)
        if not ip:
            return
        port_text = _clean_text(port)
        proto_text = _clean_text(protocol)
        key = (ip.lower(), port_text.lower(), proto_text.lower())
        if key in seen_ips:
            return
        seen_ips.add(key)
        level = _as_int(threat_level)
        contacted_ips.append(
            {
                "ip": ip,
                "port": port_text,
                "protocol": proto_text,
                "source": source,
                "process": _clean_text(process),
                "threat_level": level,
                "threat_name": _join_names(threat_name),
            }
        )
        add_ioc("ip", ip, f"AnyRun {source}", "high" if level >= 2 else "medium")

    def add_file(entry: Any, *, process: Any, source: str) -> None:
        normalized = _normalize_file_artifact(entry, process=process, source=source)
        path = normalized.get("path") or normalized.get("name")
        if not path:
            return
        key = "::".join(
            str(normalized.get(k) or "").lower()
            for k in ("path", "name", "sha256", "sha1", "md5", "process", "source")
        )
        if key in seen_files:
            return
        seen_files.add(key)
        dropped_files.append(normalized)
        for hash_key in ("sha256", "sha1", "md5"):
            if normalized.get(hash_key):
                add_ioc("hash", normalized[hash_key], f"AnyRun process file artifact ({source})", "medium")

    def add_suspicious_command(proc: dict[str, Any], command: str, reasons: list[str]) -> None:
        command = _clean_text(command)
        if not command:
            return
        process = _process_name(proc)
        key = f"{process.lower()}::{command.lower()}"
        if key in seen_commands:
            return
        seen_commands.add(key)
        suspicious_commands.append(
            {
                "process": process,
                "pid": _clean_text(proc.get("pid")),
                "command_line": command,
                "reason": "; ".join(_dedupe_text(reasons))[:300],
                "threat_level": _as_int(proc.get("threat_level") or proc.get("threatLevel")),
                "threat_score": _as_float(proc.get("threat_score") or proc.get("threatScore") or proc.get("score")),
            }
        )

    dns_requests = _as_list(behavior.get("dns_requests")) + _as_list(dynamic.get("domains"))
    http_requests = _as_list(behavior.get("http_requests")) + _as_list(dynamic.get("urls"))
    connections = _as_list(behavior.get("connections")) + _as_list(dynamic.get("hosts"))
    process_details = _as_list(behavior.get("process_details"))
    processes = process_details or _as_list(behavior.get("processes"))

    for entry in dns_requests:
        if isinstance(entry, dict):
            domain = _first(entry, "domainName", "domain", "hostname", "host", "query", "name", "value", "ioc")
            add_host(domain, source="DNS request", process=_first(entry, "processName", "process"), threat_level=_first(entry, "threatLevel", "threat_level"), threat_name=_first(entry, "threatName", "threat_name"))
        else:
            add_host(entry, source="DNS request")

    for entry in http_requests:
        if isinstance(entry, dict):
            url = _first(entry, "url", "requestUrl", "requestURL", "uri", "request")
            if url:
                add_ioc("url", url, "AnyRun HTTP request", "medium")
                add_host(_host_from_url(url), source="HTTP request", process=_first(entry, "processName", "process"), threat_level=_first(entry, "threatLevel", "threat_level"), threat_name=_first(entry, "threatName", "threat_name"), url=url)
            add_host(_first(entry, "host", "hostname", "domain", "destinationHost"), source="HTTP request", process=_first(entry, "processName", "process"), threat_level=_first(entry, "threatLevel", "threat_level"), threat_name=_first(entry, "threatName", "threat_name"), url=url)
            add_ip(_first(entry, "destinationIP", "ip", "remoteIp", "remoteIP"), source="HTTP request", process=_first(entry, "processName", "process"), threat_level=_first(entry, "threatLevel", "threat_level"), threat_name=_first(entry, "threatName", "threat_name"), port=_first(entry, "destinationPort", "port"), protocol="tcp")
        else:
            add_ioc("url", entry, "AnyRun HTTP request", "medium")
            add_host(_host_from_url(entry), source="HTTP request", url=entry)

    for entry in connections:
        if isinstance(entry, dict):
            host = _first(entry, "destinationIP", "ip", "host", "hostname", "remoteIp", "remoteIP", "value")
            add_ip(host, source="network connection", process=_first(entry, "processName", "process"), threat_level=_first(entry, "threatLevel", "threat_level"), threat_name=_first(entry, "threatName", "threat_name"), port=_first(entry, "destinationPort", "port"), protocol=_first(entry, "protocol", "proto"))
            add_host(host, source="network connection", process=_first(entry, "processName", "process"), threat_level=_first(entry, "threatLevel", "threat_level"), threat_name=_first(entry, "threatName", "threat_name"))
        else:
            add_ip(entry, source="network connection")
            add_host(entry, source="network connection")

    for proc in processes:
        if not isinstance(proc, dict):
            continue
        process = _process_name(proc)
        command = _clean_text(proc.get("command_line") or proc.get("commandLine") or proc.get("cmd"))
        reasons = _suspicious_command_reasons(command)
        if _as_int(proc.get("threat_level") or proc.get("threatLevel")) >= 2 and command:
            reasons.append("AnyRun assigned a high process threat level")
        if reasons:
            add_suspicious_command(proc, command, reasons)

        events = _as_dict(proc.get("events"))
        for source_key in ("dropped_files", "created_files", "modified_files", "deleted_files", "files"):
            rows = _as_list(events.get(source_key)) + _as_list(proc.get(source_key)) + _as_list(proc.get(_camel_key(source_key)))
            for row in rows[:120]:
                add_file(row, process=process, source=source_key)

        for row in _as_list(events.get("dns_requests")):
            if isinstance(row, dict):
                add_host(_first(row, "domainName", "domain", "hostname", "host", "query", "name", "value"), source="process DNS request", process=process, threat_level=_first(row, "threatLevel", "threat_level"), threat_name=_first(row, "threatName", "threat_name"))
        for row in _as_list(events.get("http_requests")):
            if isinstance(row, dict):
                url = _first(row, "url", "requestUrl", "uri", "request")
                add_ioc("url", url, "AnyRun process HTTP request", "medium")
                add_host(_host_from_url(url) or _first(row, "host", "hostname", "domain"), source="process HTTP request", process=process, threat_level=_first(row, "threatLevel", "threat_level"), threat_name=_first(row, "threatName", "threat_name"), url=url)
        for row in _as_list(events.get("connections")):
            if isinstance(row, dict):
                endpoint = _first(row, "destinationIP", "ip", "host", "hostname", "remoteIp", "remoteIP")
                add_ip(endpoint, source="process connection", process=process, threat_level=_first(row, "threatLevel", "threat_level"), threat_name=_first(row, "threatName", "threat_name"), port=_first(row, "destinationPort", "port"), protocol=_first(row, "protocol", "proto"))
                add_host(endpoint, source="process connection", process=process, threat_level=_first(row, "threatLevel", "threat_level"), threat_name=_first(row, "threatName", "threat_name"))

    for entry in _as_list(raw.get("iocs")):
        if not isinstance(entry, dict):
            continue
        value = _clean_text(_first(entry, "ioc", "value", "indicator", "name"))
        if not value:
            continue
        ioc_type = _map_ioc_type(entry, value)
        if ioc_type:
            add_ioc(ioc_type, value, "AnyRun IOC report", "high" if _as_int(entry.get("threatLevel")) >= 2 else "medium")
            if ioc_type == "domain":
                add_host(value, source="IOC report", threat_level=entry.get("threatLevel"), threat_name=entry.get("threatName"))
            elif ioc_type == "ip":
                add_ip(value, source="IOC report", threat_level=entry.get("threatLevel"), threat_name=entry.get("threatName"))

    process_tree = _build_process_tree_summary(processes, graph)
    screenshots = _collect_screenshot_links(result, raw)

    contacted_hosts.sort(key=lambda row: (-_as_int(row.get("threat_level")), str(row.get("host") or "")))
    contacted_ips.sort(key=lambda row: (-_as_int(row.get("threat_level")), str(row.get("ip") or "")))
    dropped_files.sort(key=lambda row: (str(row.get("process") or ""), str(row.get("path") or row.get("name") or "")))
    suspicious_commands.sort(key=lambda row: (-_as_int(row.get("threat_level")), -_as_float(row.get("threat_score")), str(row.get("process") or "")))

    return {
        "summary": {
            "source": str(raw.get("source") or "anyrun"),
            "mode": str(raw.get("mode") or "lookup"),
            "analysis_id": result.get("analysis_id") or raw.get("analysis_id"),
            "analysis_link": result.get("analysis_link") or raw.get("permanentUrl"),
            "verdict": result.get("verdict") or raw.get("verdict"),
            "threat_score": result.get("threat_score") or raw.get("threat_score"),
            "process_count": process_tree.get("process_count", 0),
            "contacted_host_count": len(contacted_hosts),
            "contacted_ip_count": len(contacted_ips),
            "dropped_file_count": len(dropped_files),
            "suspicious_command_count": len(suspicious_commands),
            "screenshot_count": len(screenshots),
            "extracted_ioc_count": len(extracted_iocs),
        },
        "process_tree_summary": process_tree,
        "contacted_hosts": contacted_hosts[:200],
        "contacted_ips": contacted_ips[:200],
        "dropped_files": dropped_files[:200],
        "suspicious_commands": suspicious_commands[:100],
        "screenshot_thumbnails": screenshots[:12],
        "extracted_iocs": extracted_iocs[:500],
    }


def _build_process_tree_summary(processes: list[Any], graph: dict[str, Any]) -> dict[str, Any]:
    rows = [p for p in processes if isinstance(p, dict)]
    pid_set = {_clean_text(p.get("pid")) for p in rows if _clean_text(p.get("pid"))}
    root_rows: list[dict[str, Any]] = []
    high_risk: list[dict[str, Any]] = []

    for proc in rows:
        summary = _process_summary(proc)
        parent = _clean_text(proc.get("ppid") or proc.get("parentPid") or proc.get("parent_pid"))
        if not parent or parent not in pid_set or parent == summary.get("pid"):
            root_rows.append(summary)
        score = _process_risk_rank(proc)
        if score > 0:
            high_risk.append({**summary, "risk_rank": score})

    high_risk.sort(key=lambda row: (-_as_int(row.get("risk_rank")), str(row.get("name") or "")))
    edge_count = len(_as_list(graph.get("edges")))
    node_count = len(_as_list(graph.get("nodes")))
    process_count = len(rows) or max(0, node_count - 1)
    narrative = "No process execution details were returned by ANY.RUN."
    if process_count:
        roots = ", ".join([str(r.get("name") or "process") for r in root_rows[:3]]) or "unknown root"
        risky = ", ".join([str(r.get("name") or "process") for r in high_risk[:3]])
        narrative = f"ANY.RUN returned {process_count} process node(s); root process candidates: {roots}."
        if risky:
            narrative += f" Highest-signal process(es): {risky}."

    return {
        "process_count": process_count,
        "edge_count": edge_count,
        "root_processes": root_rows[:10],
        "high_risk_processes": high_risk[:15],
        "narrative": narrative,
    }


def _process_summary(proc: dict[str, Any]) -> dict[str, Any]:
    counts = _as_dict(proc.get("event_counts"))
    command = _clean_text(proc.get("command_line") or proc.get("commandLine") or proc.get("cmd"))
    return {
        "name": _process_name(proc),
        "pid": _clean_text(proc.get("pid")),
        "ppid": _clean_text(proc.get("ppid") or proc.get("parentPid") or proc.get("parent_pid")),
        "command_line": command,
        "threat_level": _as_int(proc.get("threat_level") or proc.get("threatLevel")),
        "threat_score": _as_float(proc.get("threat_score") or proc.get("threatScore") or proc.get("score")),
        "network_events": sum(_as_int(counts.get(k)) for k in ("dns_requests", "http_requests", "connections", "network_threats")),
        "file_events": sum(_as_int(counts.get(k)) for k in ("dropped_files", "created_files", "modified_files", "deleted_files")),
        "registry_events": _as_int(counts.get("registry_changes")),
    }


def _process_risk_rank(proc: dict[str, Any]) -> int:
    summary = _process_summary(proc)
    score = 0
    if _as_int(summary.get("threat_level")) >= 2:
        score += 8
    elif _as_int(summary.get("threat_level")) == 1:
        score += 4
    if _as_float(summary.get("threat_score")) >= 70:
        score += 6
    elif _as_float(summary.get("threat_score")) >= 35:
        score += 3
    if summary.get("network_events"):
        score += 2
    if summary.get("file_events"):
        score += 2
    if summary.get("registry_events"):
        score += 1
    if _suspicious_command_reasons(str(summary.get("command_line") or "")):
        score += 5
    return score


def _collect_screenshot_links(result: dict[str, Any], raw: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(value: Any, *, label: str = "Screenshot", kind: str = "screenshot") -> None:
        report_url = ""
        if isinstance(value, dict):
            url = _first(value, "thumbnail_url", "thumbnailUrl", "preview_url", "previewUrl", "url", "src", "href", "link")
            label_text = _clean_text(_first(value, "label", "title", "name", "type")) or label
            report_url = _clean_text(_first(value, "report_url", "reportUrl", "full_url", "fullUrl", "analysis_link", "analysisLink"))
        else:
            url = value
            label_text = label
        url_text = _clean_text(url)
        if not url_text or url_text.lower() in seen:
            return
        if not (url_text.startswith("http://") or url_text.startswith("https://") or url_text.startswith("data:image/")):
            return
        if url_text.startswith("data:image/") and len(url_text) > 250_000:
            return
        seen.add(url_text.lower())
        row = {"label": label_text[:80], "url": url_text, "kind": kind}
        if report_url.startswith("http://") or report_url.startswith("https://"):
            row["report_url"] = report_url
        out.append(row)

    for key in ("screenshots", "screenshot_thumbnails", "thumbnails", "images"):
        for value in _as_list(raw.get(key)) + _as_list(result.get(key)):
            add(value, label="ANY.RUN screenshot")

    report_excerpt = _as_dict(raw.get("report_excerpt"))
    reports = _as_dict(raw.get("report_links")) or _as_dict(report_excerpt.get("reports"))
    for key, value in reports.items():
        key_text = str(key or "").lower()
        if any(token in key_text for token in ("screen", "shot", "thumb", "image", "png", "jpg", "jpeg", "webp")):
            for row in _as_list(value) or [value]:
                add(row, label=str(key), kind="report_link")

    return out


def _normalize_file_artifact(entry: Any, *, process: Any, source: str) -> dict[str, Any]:
    if isinstance(entry, dict):
        path = _clean_text(_first(entry, "path", "filePath", "fullPath", "targetPath", "name", "filename", "fileName", "value"))
        name = _clean_text(_first(entry, "name", "filename", "fileName")) or _basename(path)
        sha256 = _clean_text(_first(entry, "sha256", "SHA256"))
        sha1 = _clean_text(_first(entry, "sha1", "SHA1"))
        md5 = _clean_text(_first(entry, "md5", "MD5", "hash"))
        action = _clean_text(_first(entry, "action", "operation", "event", "type")) or source
    else:
        path = _clean_text(entry)
        name = _basename(path)
        sha256 = sha1 = md5 = ""
        action = source
    return {
        "path": path,
        "name": name,
        "process": _clean_text(process),
        "action": action,
        "source": source,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
    }


def _suspicious_command_reasons(command: str) -> list[str]:
    text = _clean_text(command)
    if not text:
        return []
    return [reason for pattern, reason in _SUSPICIOUS_COMMAND_PATTERNS if pattern.search(text)]


def _map_ioc_type(entry: dict[str, Any], value: str) -> str:
    category = str(entry.get("category") or entry.get("type") or entry.get("iocType") or "").strip().lower()
    if category in {"domain", "domains", "hostname", "host"}:
        return "domain"
    if category in {"ip", "ipv4", "ipv6", "network"}:
        return "ip"
    if category in {"url", "uri", "http"}:
        return "url"
    if category in {"hash", "sha256", "sha1", "md5"}:
        return "hash"
    if value.startswith(("http://", "https://")):
        return "url"
    if _is_ip(value):
        return "ip"
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return "hash"
    if _looks_domain(value):
        return "domain"
    return ""


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text


def _join_names(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(_dedupe_text([_clean_text(v) for v in value if _clean_text(v)]))[:240]
    return _clean_text(value)[:240]


def _dedupe_text(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _clean_text(value)
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append(text)
    return out


def _as_int(value: Any) -> int:
    try:
        return int(float(str(value)))
    except Exception:
        return 0


def _as_float(value: Any) -> float:
    try:
        return float(str(value))
    except Exception:
        return 0.0


def _normalize_ip(value: Any) -> str:
    text = _clean_text(value).strip("[]")
    if not text:
        return ""
    if ":" in text and text.count(":") == 1 and "." in text:
        text = text.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        return ""


def _is_ip(value: Any) -> bool:
    return bool(_normalize_ip(value))


def _normalize_host(value: Any) -> str:
    text = _clean_text(value)
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return _host_from_url(text)
    text = text.strip().strip(".").lower()
    if "/" in text:
        text = text.split("/", 1)[0]
    if ":" in text and text.count(":") == 1:
        text = text.split(":", 1)[0]
    if _is_ip(text):
        return _normalize_ip(text)
    return text if _looks_domain(text) else ""


def _looks_domain(value: str) -> bool:
    text = _clean_text(value).strip(".")
    return bool(_DOMAIN_RE.match(text)) and not _is_ip(text)


def _host_from_url(value: Any) -> str:
    text = _clean_text(value)
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        return _normalize_host(parsed.hostname or "")
    except Exception:
        return ""


def _process_name(proc: dict[str, Any]) -> str:
    return _clean_text(proc.get("name") or proc.get("fileName") or proc.get("image") or proc.get("processName") or proc.get("file_path") or "process")


def _basename(path: str) -> str:
    text = _clean_text(path).replace("\\", "/")
    return text.rsplit("/", 1)[-1] if text else ""


def _camel_key(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])
