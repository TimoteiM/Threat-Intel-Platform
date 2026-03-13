"""
ANY.RUN integration (TI lookup + sandbox analysis).

Primary strategy:
1) Query TI lookup first (fast, no detonation) for URL/hash.
2) If not found and permitted, submit sandbox task (URL/file).
"""

from __future__ import annotations

import time
from contextlib import ExitStack
from typing import Any
from urllib.parse import urlparse

from app.config import get_settings


def lookup_anyrun(
    *,
    indicator: str,
    indicator_type: str,
    file_bytes: bytes | None = None,
    file_name: str | None = None,
    submit_on_not_found: bool = False,
) -> dict[str, Any]:
    settings = get_settings()
    api_key = (getattr(settings, "anyrun_api_key", "") or "").strip()
    sandbox_os = str(getattr(settings, "anyrun_sandbox_os", "windows") or "windows").strip().lower()
    privacy_type = str(getattr(settings, "anyrun_privacy_type", "owner") or "owner").strip().lower()
    timeout_url_domain = int(getattr(settings, "anyrun_timeout_url_domain_seconds", 45) or 45)
    timeout_file_hash = int(getattr(settings, "anyrun_timeout_file_hash_seconds", 90) or 90)
    if not api_key:
        return _error(indicator_type, "ANYRUN_API_KEY not configured")

    value = str(indicator or "").strip()
    if not value:
        return _error(indicator_type, "Empty indicator")

    try:
        from anyrun.connectors import LookupConnector, SandboxConnector
    except Exception as exc:
        return _error(indicator_type, f"anyrun-sdk unavailable: {exc}")

    # 1) TI lookup (url/hash)
    sandbox_timeout = timeout_file_hash if indicator_type == "hash" else timeout_url_domain
    if indicator_type in {"url", "hash"}:
        lookup_result = _lookup_intelligence(
            LookupConnector,
            SandboxConnector,
            api_key,
            indicator=value,
            indicator_type=indicator_type,
            sandbox_os=sandbox_os,
        )
        if lookup_result.get("checked"):
            lookup_analysis_id = str(lookup_result.get("analysis_id") or "").strip()
            force_hash_sandbox = bool(indicator_type == "hash" and submit_on_not_found and file_bytes)
            needs_enriched_sandbox = (
                _is_sparse_lookup_result(lookup_result)
                or (indicator_type == "url" and not lookup_analysis_id)
                or force_hash_sandbox
            )
            if (
                submit_on_not_found
                and indicator_type in {"url", "hash"}
                and needs_enriched_sandbox
            ):
                if indicator_type == "hash" and not file_bytes:
                    return lookup_result
                sandbox_result = _run_sandbox(
                    sandbox_connector_cls=SandboxConnector,
                    api_key=api_key,
                    sandbox_os=sandbox_os,
                    privacy_type=privacy_type,
                    indicator=value,
                    indicator_type=indicator_type,
                    file_bytes=file_bytes,
                    file_name=file_name,
                    timeout_seconds=sandbox_timeout,
                )
                if sandbox_result.get("checked"):
                    raw = sandbox_result.get("raw_summary") or {}
                    sandbox_result["raw_summary"] = {
                        **(raw if isinstance(raw, dict) else {}),
                        "lookup_fallback_used": True,
                        "lookup_summary": (lookup_result.get("raw_summary") or {}),
                    }
                    return sandbox_result
                # Do not silently degrade to lookup-only when sandbox enrichment is required.
                return sandbox_result
            return lookup_result
        not_found = "not found" in str(lookup_result.get("error") or "").lower() or "no info" in str(lookup_result.get("error") or "").lower()
        if not submit_on_not_found or (indicator_type == "hash" and not file_bytes):
            return lookup_result
        if not not_found:
            return lookup_result

    # 2) Sandbox submission fallback
    sandbox_result = _run_sandbox(
        sandbox_connector_cls=SandboxConnector,
        api_key=api_key,
        sandbox_os=sandbox_os,
        privacy_type=privacy_type,
        indicator=value,
        indicator_type=indicator_type,
        file_bytes=file_bytes,
        file_name=file_name,
        timeout_seconds=sandbox_timeout,
    )
    return sandbox_result


def _lookup_intelligence(
    lookup_connector_cls: Any,
    sandbox_connector_cls: Any,
    api_key: str,
    *,
    indicator: str,
    indicator_type: str,
    sandbox_os: str,
) -> dict[str, Any]:
    try:
        with ExitStack() as stack:
            conn = lookup_connector_cls(api_key)
            if hasattr(conn, "__enter__") and hasattr(conn, "__exit__"):
                conn = stack.enter_context(conn)
            kwargs: dict[str, Any] = {"lookup_depth": 180}
            if indicator_type == "url":
                kwargs["url"] = indicator
            else:
                kwargs["sha256"] = indicator
            data = conn.get_intelligence(**kwargs)
        if not isinstance(data, dict):
            return _error(indicator_type, "ANY.RUN lookup returned an unexpected response")

        summary = data.get("summary") or {}
        threat_level = summary.get("threatLevel")
        verdict = _normalize_lookup_verdict(threat_level)
        related_tasks = _ensure_list(data.get("sourceTasks") or data.get("relatedTasks"))
        related_incidents = _ensure_list(data.get("relatedIncidents"))
        threat_names = _ensure_list(data.get("threatName") or summary.get("threatName") or summary.get("threatNames"))
        destination_ip_geo = _ensure_list(data.get("destinationIPgeo") or data.get("destination_ip_geo"))
        destination_ports = _extract_ports(data)
        analysis_id = None
        analysis_link = None
        if isinstance(related_tasks, list) and related_tasks:
            first = related_tasks[0] if isinstance(related_tasks[0], dict) else {}
            analysis_link = str(first.get("related") or "").strip() or None
            analysis_id = _extract_task_id(analysis_link)

        if verdict == "unknown":
            return {
                "checked": False,
                "indicator_type": indicator_type,
                "verdict": "unknown",
                "error": "Not found in ANY.RUN intelligence lookup",
                "raw_summary": {"source": "anyrun", "mode": "lookup"},
            }

        threat_score: float | None = _lookup_level_to_score(threat_level)
        dyn_domains = data.get("relatedDNS") or []
        dyn_hosts = data.get("destinationIP") or []
        ioc_items: list[dict[str, Any]] = []
        report_excerpt: dict[str, Any] = {}
        behavior_details: dict[str, Any] = {}
        if analysis_id:
            try:
                with ExitStack() as stack:
                    sconn = _create_sandbox_connector(sandbox_connector_cls, api_key=api_key, sandbox_os=sandbox_os)
                    if sconn and hasattr(sconn, "__enter__") and hasattr(sconn, "__exit__"):
                        sconn = stack.enter_context(sconn)
                    if sconn:
                        report = sconn.get_analysis_report(analysis_id, report_format="summary")
                        ioc_report = sconn.get_analysis_report(analysis_id, report_format="ioc")
                        html_report = sconn.get_analysis_report(analysis_id, report_format="html")
                        report_data = (report or {}).get("data") or {}
                        ioc_items = _extract_iocs(ioc_report)
                        network = report_data.get("network") or {}
                        dyn_domains = network.get("domains") or dyn_domains
                        dyn_hosts = network.get("hosts") or dyn_hosts
                        destination_ip_geo = _ensure_list(
                            report_data.get("destinationIPgeo")
                            or network.get("destinationIPgeo")
                            or destination_ip_geo
                        )
                        destination_ports = _extract_ports(report_data) or _extract_ports(network) or destination_ports
                        related_incidents = _ensure_list(report_data.get("relatedIncidents")) or related_incidents
                        threat_names = _ensure_list(report_data.get("threatName")) or threat_names
                        related_tasks = _ensure_list(report_data.get("relatedTasks")) or related_tasks
                        processes = _ensure_list(report_data.get("processes"))
                        dns_requests = _ensure_list(network.get("dnsRequests"))
                        http_requests = _ensure_list(network.get("httpRequests"))
                        connections = _ensure_list(network.get("connections"))
                        network_threats = _ensure_list(network.get("threats"))
                        behavior_details = {
                            "dns_requests": dns_requests[:200],
                            "http_requests": http_requests[:200],
                            "connections": connections[:200],
                            "network_threats": network_threats[:200],
                            "processes": processes[:200],
                            "process_details": _extract_process_details(
                                report_data,
                                processes,
                                dns_requests=dns_requests,
                                http_requests=http_requests,
                                connections=connections,
                                network_threats=network_threats,
                            )[:400],
                        }
                        analysis_block = report_data.get("analysis") or {}
                        score_block = analysis_block.get("scores") or {}
                        report_verdict_raw = (
                            (score_block.get("verdict") or {}).get("threatLevelText")
                            or score_block.get("verdict_text")
                            or score_block.get("classification")
                        )
                        report_threat_score = _as_float(
                            score_block.get("threatScore")
                            or score_block.get("threat_score")
                            or score_block.get("threatLevel")
                            or score_block.get("threat_level")
                        )
                        if report_verdict_raw:
                            verdict = _normalize_anyrun_verdict(report_verdict_raw)
                        if report_threat_score is not None:
                            threat_score = _clamp_score_0_100(report_threat_score)

                        report_excerpt = {
                            "analysis": report_data.get("analysis") or {},
                            "reports": ((report_data.get("analysis") or {}).get("reports") or {}),
                            "network": {
                                "domains_count": len(dyn_domains),
                                "hosts_count": len(dyn_hosts),
                                "requests_count": (network.get("requests_count") or network.get("requestsCount")),
                            },
                            "ioc_count": len(ioc_items),
                            "html_report_bytes": len(html_report) if isinstance(html_report, str) else None,
                        }
            except Exception as exc:
                report_excerpt = {"report_error": str(exc)}

        return {
            "checked": True,
            "indicator_type": indicator_type,
            "verdict": verdict,
            "threat_score": threat_score,
            "analysis_id": analysis_id,
            "analysis_link": analysis_link,
            "dynamic_io_summary": {
                "domains": dyn_domains,
                "hosts": dyn_hosts,
                "mitre_attcks": [],
                "destinationIPgeo": destination_ip_geo,
                "destinationPort": destination_ports,
            },
            "raw_summary": {
                "source": "anyrun",
                "mode": "lookup",
                "summary": summary,
                "anyrun_ai_summary": _derive_anyrun_summary(report_excerpt.get("analysis") or {}, report_excerpt.get("network") or {}, {}),
                "threatName": threat_names,
                "destinationIPgeo": destination_ip_geo,
                "destinationPort": destination_ports,
                "relatedTasks": related_tasks,
                "relatedIncidents": related_incidents,
                "tags": summary.get("tags") or [],
                "related_tasks_count": len(related_tasks) if isinstance(related_tasks, list) else 0,
                "iocs": ioc_items[:500],
                "report_excerpt": report_excerpt,
                "behavior_details": behavior_details,
                "behavior_graph": _build_behavior_graph(
                    processes=_ensure_list((behavior_details or {}).get("processes")),
                    dns_requests=_ensure_list((behavior_details or {}).get("dns_requests")),
                    http_requests=_ensure_list((behavior_details or {}).get("http_requests")),
                    connections=_ensure_list((behavior_details or {}).get("connections")),
                    domains=dyn_domains,
                    hosts=dyn_hosts,
                ),
            },
        }
    except Exception as exc:
        return _error(indicator_type, f"ANY.RUN intelligence lookup failed: {exc}")


def _run_sandbox(
    *,
    sandbox_connector_cls: Any,
    api_key: str,
    sandbox_os: str,
    privacy_type: str,
    indicator: str,
    indicator_type: str,
    file_bytes: bytes | None,
    file_name: str | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    try:
        if indicator_type == "hash":
            max_upload_mb = int(getattr(get_settings(), "anyrun_max_upload_mb", 100) or 100)
            if file_bytes:
                file_size_mb = len(file_bytes) / (1024 * 1024)
                if file_size_mb > max_upload_mb:
                    return _error(
                        indicator_type,
                        f"ANY.RUN file sandbox skipped: sample size {file_size_mb:.1f} MB exceeds configured max {max_upload_mb} MB",
                    )
        with ExitStack() as stack:
            connector = _create_sandbox_connector(sandbox_connector_cls, api_key=api_key, sandbox_os=sandbox_os)
            if connector is None:
                return _error(indicator_type, "Failed to initialize ANY.RUN sandbox connector")
            if hasattr(connector, "__enter__") and hasattr(connector, "__exit__"):
                connector = stack.enter_context(connector)

            if indicator_type == "url":
                task_id = connector.run_url_analysis(indicator, opt_privacy_type=privacy_type)
            elif indicator_type == "hash":
                if not file_bytes:
                    return _error(indicator_type, "ANY.RUN hash sandbox submission requires uploaded file bytes")
                task_id = connector.run_file_analysis(
                    file_content=file_bytes,
                    filename=(file_name or "sample.bin"),
                    opt_privacy_type=privacy_type,
                )
            else:
                return _error(indicator_type, f"Unsupported Any.Run indicator type: {indicator_type}")

            analysis_id = str(task_id or "").strip()
            if not analysis_id:
                return _error(indicator_type, "ANY.RUN sandbox submission returned empty task id")

            _wait_status_stream(connector, analysis_id, timeout_seconds=max(10, int(timeout_seconds or 60)))
            verdict_raw = connector.get_analysis_verdict(analysis_id)
            verdict = _normalize_anyrun_verdict(verdict_raw)
            report = connector.get_analysis_report(analysis_id, report_format="summary")
            ioc_report = connector.get_analysis_report(analysis_id, report_format="ioc")
            html_report = connector.get_analysis_report(analysis_id, report_format="html")
        report_data = (report or {}).get("data") or {}
        analysis = (report_data.get("analysis") or {})
        network = (report_data.get("network") or {})
        counters = (report_data.get("counters") or {})
        processes = _ensure_list(report_data.get("processes"))
        scores = (analysis.get("scores") or {})
        summary = report_data.get("summary") or {}
        threat_names = _ensure_list(report_data.get("threatName") or summary.get("threatName"))
        destination_ip_geo = _ensure_list(report_data.get("destinationIPgeo") or network.get("destinationIPgeo"))
        destination_ports = _extract_ports(report_data) or _extract_ports(network)
        related_tasks = _ensure_list(report_data.get("relatedTasks"))
        related_incidents = _ensure_list(report_data.get("relatedIncidents"))
        dns_requests = _ensure_list(network.get("dnsRequests"))
        http_requests = _ensure_list(network.get("httpRequests"))
        connections = _ensure_list(network.get("connections"))
        network_threats = _ensure_list(network.get("threats"))
        ioc_items = _extract_iocs(ioc_report)

        dyn_domains = []
        for entry in dns_requests:
            if isinstance(entry, dict):
                dyn_domains.append(
                    {
                        "domainName": entry.get("domainName") or entry.get("domain") or entry.get("hostname"),
                        "threatLevel": entry.get("threatLevel") or 0,
                        "threatName": _ensure_list(entry.get("threatName")),
                        "date": entry.get("date") or entry.get("timestamp"),
                        "isMalconf": bool(entry.get("isMalconf")),
                    }
                )
        dyn_hosts = []
        for entry in connections:
            if isinstance(entry, dict):
                dyn_hosts.append(
                    {
                        "destinationIP": entry.get("destinationIP") or entry.get("ip") or entry.get("host"),
                        "threatLevel": entry.get("threatLevel") or 0,
                        "threatName": _ensure_list(entry.get("threatName")),
                        "date": entry.get("date") or entry.get("timestamp"),
                        "isMalconf": bool(entry.get("isMalconf")),
                        "destinationPort": entry.get("destinationPort") or entry.get("port"),
                    }
                )
        if not dyn_domains:
            dyn_domains = _ensure_list(network.get("domains"))
        if not dyn_hosts:
            dyn_hosts = _ensure_list(network.get("hosts"))

        threat_score = _as_float(
            scores.get("threatScore")
            or scores.get("threat_score")
            or scores.get("threatLevel")
            or scores.get("threat_level")
        )
        process_details = _extract_process_details(
            report_data,
            processes,
            dns_requests=dns_requests,
            http_requests=http_requests,
            connections=connections,
            network_threats=network_threats,
        )

        return {
            "checked": True,
            "indicator_type": indicator_type,
            "verdict": verdict,
            "threat_score": threat_score,
            "analysis_id": analysis_id,
            "analysis_link": analysis.get("permanentUrl"),
            "dynamic_io_summary": {
                "domains": dyn_domains,
                "hosts": dyn_hosts,
                "mitre_attcks": (report_data.get("mitre") or []),
                "destinationIPgeo": destination_ip_geo,
                "destinationPort": destination_ports,
            },
            "raw_summary": {
                "source": "anyrun",
                "mode": "sandbox",
                "summary": summary,
                "anyrun_ai_summary": _derive_anyrun_summary(analysis, network, report_data),
                "permanentUrl": analysis.get("permanentUrl"),
                "behavior_graph_url": ((analysis.get("reports") or {}).get("graph")),
                "ioc_report_url": ((analysis.get("reports") or {}).get("IOC")),
                "iocs": ioc_items[:500],
                "html_report_bytes": len(html_report) if isinstance(html_report, str) else None,
                "behavior_counts": {
                    "http_requests": len(http_requests) or _as_int(counters.get("httpRequests")),
                    "connections": len(connections) or _as_int(counters.get("connections")),
                    "dns_requests": len(dns_requests) or _as_int(counters.get("dnsRequests")),
                    "network_threats": len(network_threats) or _as_int(counters.get("threats")),
                    "processes": len(processes) or _as_int(counters.get("processes")),
                },
                "behavior_details": {
                    "dns_requests": dns_requests[:200],
                    "http_requests": http_requests[:200],
                    "connections": connections[:200],
                    "network_threats": network_threats[:200],
                    "processes": processes[:200],
                    "process_details": process_details[:400],
                },
                "behavior_graph": _build_behavior_graph(
                    processes=processes,
                    dns_requests=dns_requests,
                    http_requests=http_requests,
                    connections=connections,
                    domains=dyn_domains,
                    hosts=dyn_hosts,
                ),
                "threatName": threat_names,
                "destinationIPgeo": destination_ip_geo,
                "destinationPort": destination_ports,
                "relatedTasks": related_tasks,
                "relatedIncidents": related_incidents,
                "verdict_text": str(verdict_raw or ""),
            },
        }
    except Exception as exc:
        err = str(exc or "")
        lower_err = err.lower()
        if "contenttypeerror" in lower_err and "not supported between instances" in lower_err:
            return _error(
                indicator_type,
                "ANY.RUN sandbox submission failed: API returned non-JSON response (often HTTP 413 file too large or plan restriction).",
            )
        if "413" in lower_err:
            return _error(indicator_type, "ANY.RUN sandbox submission failed: file too large for this API tier (HTTP 413).")
        return _error(indicator_type, f"ANY.RUN sandbox submission failed: {exc}")


def _create_sandbox_connector(sandbox_connector_cls: Any, *, api_key: str, sandbox_os: str) -> Any | None:
    order = ("linux", "windows") if sandbox_os == "linux" else ("windows", "linux")
    for method in order:
        fn = getattr(sandbox_connector_cls, method, None)
        if callable(fn):
            try:
                return fn(api_key)
            except Exception:
                continue
    return None


def _wait_status_stream(connector: Any, task_id: str, timeout_seconds: int) -> None:
    deadline = time.time() + max(10, timeout_seconds)
    try:
        statuses = connector.get_task_status(task_id)
    except Exception:
        return
    for item in statuses:
        if time.time() > deadline:
            break
        status = str((item or {}).get("status") or "").upper()
        if status in {"COMPLETED", "FAILED"}:
            break


def _normalize_lookup_verdict(level: Any) -> str:
    try:
        n = int(level)
    except Exception:
        return "unknown"
    if n >= 2:
        return "malicious"
    if n == 1:
        return "suspicious"
    if n == 0:
        return "clean"
    return "unknown"


def _normalize_anyrun_verdict(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "malicious" in text:
        return "malicious"
    if "suspicious" in text:
        return "suspicious"
    if "no threats" in text or "clean" in text or "benign" in text:
        return "clean"
    return _normalize_lookup_verdict(value)


def _lookup_level_to_score(level: Any) -> float | None:
    try:
        n = int(level)
    except Exception:
        return None
    # Conservative normalization for lookup-only confidence (0..100 scale).
    if n <= 0:
        return 0.0
    if n == 1:
        return 40.0
    if n == 2:
        return 75.0
    if n == 3:
        return 90.0
    return 100.0


def _clamp_score_0_100(value: float | int | None) -> float | None:
    if value is None:
        return None
    try:
        v = float(value)
    except Exception:
        return None
    if v < 0:
        return 0.0
    if v > 100:
        return 100.0
    return v


def _extract_task_id(related: str | None) -> str | None:
    text = str(related or "").strip()
    if not text:
        return None
    if "/tasks/" in text:
        try:
            tail = text.split("/tasks/", 1)[1]
            return tail.split("/", 1)[0].strip() or None
        except Exception:
            return None
    return text


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except Exception:
        return None


def _ensure_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _extract_ports(payload: Any) -> list[int]:
    if not isinstance(payload, dict):
        return []
    ports: set[int] = set()
    keys = ("destinationPort", "destinationPorts", "port", "ports")
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (int, float, str)):
            maybe = _to_port(value)
            if maybe is not None:
                ports.add(maybe)
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    maybe = _to_port(item.get("port") or item.get("destinationPort"))
                else:
                    maybe = _to_port(item)
                if maybe is not None:
                    ports.add(maybe)
    network = payload.get("network")
    if isinstance(network, dict):
        for host in _ensure_list(network.get("hosts")):
            if isinstance(host, dict):
                maybe = _to_port(host.get("destinationPort") or host.get("port"))
                if maybe is not None:
                    ports.add(maybe)
        for conn in _ensure_list(network.get("connections")):
            if isinstance(conn, dict):
                maybe = _to_port(conn.get("destinationPort") or conn.get("port"))
                if maybe is not None:
                    ports.add(maybe)
    return sorted(ports)


def _to_port(value: Any) -> int | None:
    try:
        n = int(str(value).strip())
    except Exception:
        return None
    if 0 < n <= 65535:
        return n
    return None


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _extract_iocs(ioc_report: Any) -> list[dict[str, Any]]:
    if isinstance(ioc_report, list):
        return [x for x in ioc_report if isinstance(x, dict)]
    if isinstance(ioc_report, dict):
        data = ioc_report.get("data")
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            # some shapes may nest under known keys
            for key in ("items", "iocs", "indicators"):
                v = data.get(key)
                if isinstance(v, list):
                    return [x for x in v if isinstance(x, dict)]
    return []


def _derive_anyrun_summary(analysis: dict[str, Any], network: dict[str, Any], report_data: dict[str, Any]) -> str:
    try:
        verdict = ((analysis.get("scores") or {}).get("verdict") or {})
        tl_text = str(verdict.get("threatLevelText") or "").strip()
        tl = verdict.get("threatLevel")
        dns_n = len(_ensure_list(network.get("dnsRequests")))
        http_n = len(_ensure_list(network.get("httpRequests")))
        conn_n = len(_ensure_list(network.get("connections")))
        thr_n = len(_ensure_list(network.get("threats")))
        incidents = _ensure_list(report_data.get("incidents"))
        top_inc = []
        for inc in incidents[:3]:
            if isinstance(inc, dict):
                title = str(inc.get("title") or inc.get("desc") or "").strip()
                if title:
                    top_inc.append(title)
        parts = []
        if tl_text:
            parts.append(tl_text)
        elif tl is not None:
            parts.append(f"Threat level {tl}")
        parts.append(f"Observed {http_n} HTTP requests, {conn_n} connections, {dns_n} DNS requests, {thr_n} network threat events.")
        if top_inc:
            parts.append("Top incidents: " + "; ".join(top_inc) + ".")
        return " ".join(parts).strip()
    except Exception:
        return ""


def _build_behavior_graph(
    *,
    processes: list[Any],
    dns_requests: list[Any],
    http_requests: list[Any],
    connections: list[Any],
    domains: list[Any] | None = None,
    hosts: list[Any] | None = None,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(node_id: str, label: str, kind: str) -> None:
        if not node_id:
            return
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "label": label or node_id, "kind": kind}

    def add_edge(source: str, target: str, rel: str) -> None:
        if not source or not target or source == target:
            return
        edge_id = f"{source}->{target}:{rel}"
        if edge_id not in edges:
            edges[edge_id] = {"id": edge_id, "source": source, "target": target, "label": rel}

    add_node("analysis:root", "AnyRun Task", "analysis")

    process_index: dict[str, str] = {}
    for i, proc in enumerate(_ensure_list(processes)):
        if not isinstance(proc, dict):
            continue
        puid = str(proc.get("uuid") or proc.get("guid") or "").strip()
        pid = str(proc.get("pid") or "").strip()
        key = puid or (f"pid:{pid}" if pid else f"idx:{i}")
        node_id = f"process:{key}"
        label = str(proc.get("fileName") or proc.get("image") or proc.get("processName") or proc.get("name") or node_id)
        add_node(node_id, label, "process")
        add_edge("analysis:root", node_id, "spawns")
        if puid:
            process_index[puid] = node_id
        if pid:
            process_index[f"pid:{pid}"] = node_id

    def process_node_id(ref: Any) -> str:
        rid = str(ref or "").strip()
        if not rid:
            return ""
        if rid in process_index:
            return process_index[rid]
        if rid.isdigit() and f"pid:{rid}" in process_index:
            return process_index[f"pid:{rid}"]
        maybe = f"process:{rid}"
        if maybe in nodes:
            return maybe
        return ""

    for req in _ensure_list(dns_requests):
        if not isinstance(req, dict):
            continue
        domain = str(req.get("domainName") or req.get("domain") or req.get("hostname") or "").strip().lower()
        if not domain:
            continue
        dnode = f"domain:{domain}"
        add_node(dnode, domain, "domain")
        pnode = process_node_id(req.get("process") or req.get("pid"))
        if pnode:
            add_edge(pnode, dnode, "dns")
        else:
            add_edge("analysis:root", dnode, "resolves")
        ips = _ensure_list(req.get("ips")) + _ensure_list(req.get("answers"))
        for ip in ips:
            iptxt = str(ip or "").strip()
            if not iptxt:
                continue
            inode = f"ip:{iptxt}"
            add_node(inode, iptxt, "ip")
            add_edge(dnode, inode, "resolves_to")

    for req in _ensure_list(http_requests):
        if not isinstance(req, dict):
            continue
        url = str(req.get("url") or req.get("requestUrl") or "").strip()
        if not url:
            continue
        unode = f"url:{url}"
        add_node(unode, url, "url")
        pnode = process_node_id(req.get("process") or req.get("pid"))
        if pnode:
            add_edge(pnode, unode, "http")
        else:
            add_edge("analysis:root", unode, "requests")
        try:
            host = str(urlparse(url).hostname or "").strip().lower()
        except Exception:
            host = ""
        if host:
            dnode = f"domain:{host}"
            add_node(dnode, host, "domain")
            add_edge(unode, dnode, "targets")

    for conn in _ensure_list(connections):
        if not isinstance(conn, dict):
            continue
        ip = str(conn.get("destinationIP") or conn.get("ip") or conn.get("host") or "").strip()
        if not ip:
            continue
        inode = f"ip:{ip}"
        add_node(inode, ip, "ip")
        pnode = process_node_id(conn.get("process") or conn.get("pid"))
        rel = f"connects:{conn.get('destinationPort') or conn.get('port') or '-'}"
        if pnode:
            add_edge(pnode, inode, rel)
        else:
            add_edge("analysis:root", inode, rel)
        domain = str(conn.get("domain") or "").strip().lower()
        if domain:
            dnode = f"domain:{domain}"
            add_node(dnode, domain, "domain")
            add_edge(inode, dnode, "reverse_dns")

    for d in _ensure_list(domains):
        if not isinstance(d, dict):
            continue
        name = str(d.get("domainName") or d.get("domain") or "").strip().lower()
        if name:
            add_node(f"domain:{name}", name, "domain")
            add_edge("analysis:root", f"domain:{name}", "observed")
    for h in _ensure_list(hosts):
        if not isinstance(h, dict):
            continue
        ip = str(h.get("destinationIP") or h.get("ip") or h.get("host") or "").strip()
        if ip:
            add_node(f"ip:{ip}", ip, "ip")
            add_edge("analysis:root", f"ip:{ip}", "observed")

    node_list = list(nodes.values())[:800]
    node_ids = {n["id"] for n in node_list}
    edge_list = [e for e in edges.values() if e["source"] in node_ids and e["target"] in node_ids][:1500]
    return {"nodes": node_list, "edges": edge_list}


def _extract_process_details(
    report_data: dict[str, Any],
    processes: list[Any],
    *,
    dns_requests: list[Any] | None = None,
    http_requests: list[Any] | None = None,
    connections: list[Any] | None = None,
    network_threats: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Normalize per-process details (metadata + grouped events) for AnyRun-like deep process view.
    """
    out: list[dict[str, Any]] = []
    proc_rows = _ensure_list(processes)
    dns_requests = _ensure_list(dns_requests)
    http_requests = _ensure_list(http_requests)
    connections = _ensure_list(connections)
    network_threats = _ensure_list(network_threats)

    def _matches_process(ev: dict[str, Any], *, pid: Any, puid: Any, name: Any) -> bool:
        refs = {
            str(pid or "").strip(),
            str(puid or "").strip(),
            str(name or "").strip().lower(),
        }
        refs.discard("")
        if not refs:
            return False
        ev_refs = {
            str(ev.get("pid") or "").strip(),
            str(ev.get("process") or "").strip(),
            str(ev.get("processUuid") or ev.get("uuid") or ev.get("guid") or "").strip(),
            str(ev.get("processName") or ev.get("name") or "").strip().lower(),
        }
        ev_refs.discard("")
        return bool(refs & ev_refs)

    for idx, proc in enumerate(proc_rows):
        if not isinstance(proc, dict):
            continue
        pid = proc.get("pid")
        ppid = proc.get("ppid") or proc.get("parentPid")
        puid = proc.get("uuid") or proc.get("guid")
        pname = proc.get("fileName") or proc.get("image") or proc.get("processName") or proc.get("name")

        def _take_list(v: Any, limit: int = 120) -> list[Any]:
            return _ensure_list(v)[:limit]

        ev_http = _take_list(proc.get("httpRequests") or proc.get("http"))
        ev_conn = _take_list(proc.get("connections"))
        ev_threats = _take_list(proc.get("networkThreats") or proc.get("threats"))
        ev_dns = _take_list(proc.get("dnsRequests"))
        if not ev_dns:
            ev_dns = [x for x in dns_requests if isinstance(x, dict) and _matches_process(x, pid=pid, puid=puid, name=pname)][:120]
        if not ev_http:
            ev_http = [x for x in http_requests if isinstance(x, dict) and _matches_process(x, pid=pid, puid=puid, name=pname)][:120]
        if not ev_conn:
            ev_conn = [x for x in connections if isinstance(x, dict) and _matches_process(x, pid=pid, puid=puid, name=pname)][:120]
        if not ev_threats:
            ev_threats = [x for x in network_threats if isinstance(x, dict) and _matches_process(x, pid=pid, puid=puid, name=pname)][:120]

        events = {
            "modified_files": _take_list(proc.get("modifiedFiles") or proc.get("files_modified")),
            "registry_changes": _take_list(proc.get("registryChanges") or proc.get("registry")),
            "synchronization": _take_list(proc.get("synchronization")),
            "dns_requests": ev_dns,
            "http_requests": ev_http,
            "connections": ev_conn,
            "network_threats": ev_threats,
            "modules": _take_list(proc.get("modules")),
            "debug": _take_list(proc.get("debug")),
        }
        event_counts = {k: len(v) for k, v in events.items()}

        out.append(
            {
                "id": proc.get("id") or f"proc-{idx}",
                "uuid": puid,
                "pid": pid,
                "ppid": ppid,
                "name": pname,
                "image": proc.get("image"),
                "file_path": proc.get("filePath") or proc.get("path"),
                "command_line": proc.get("commandLine") or proc.get("cmd"),
                "username": (
                    proc.get("user")
                    or proc.get("username")
                    or proc.get("userName")
                    or ((proc.get("context") or {}).get("userName") if isinstance(proc.get("context"), dict) else None)
                ),
                "sid": proc.get("sid"),
                "integrity_level": (
                    proc.get("integrityLevel")
                    or proc.get("integrity_level")
                    or proc.get("il")
                    or ((proc.get("context") or {}).get("integrityLevel") if isinstance(proc.get("context"), dict) else None)
                ),
                "company": (
                    proc.get("company")
                    or proc.get("companyName")
                    or ((proc.get("versionInfo") or {}).get("company") if isinstance(proc.get("versionInfo"), dict) else None)
                ),
                "description": (
                    proc.get("description")
                    or proc.get("fileDescription")
                    or ((proc.get("versionInfo") or {}).get("description") if isinstance(proc.get("versionInfo"), dict) else None)
                ),
                "version": (
                    proc.get("version")
                    or proc.get("productVersion")
                    or ((proc.get("versionInfo") or {}).get("version") if isinstance(proc.get("versionInfo"), dict) else None)
                ),
                "start": (
                    proc.get("start")
                    or proc.get("startedAt")
                    or proc.get("time")
                    or ((proc.get("times") or {}).get("start") if isinstance(proc.get("times"), dict) else None)
                ),
                "threat_level": proc.get("threatLevel"),
                "threat_score": proc.get("threatScore") or proc.get("score"),
                "cert": proc.get("cert") if isinstance(proc.get("cert"), dict) else None,
                "events": events,
                "event_counts": event_counts,
            }
        )
    return out


def _is_sparse_lookup_result(result: dict[str, Any]) -> bool:
    raw = result.get("raw_summary") or {}
    summary = raw.get("summary") or {}
    details = _ensure_list(summary.get("details"))
    io = result.get("dynamic_io_summary") or {}
    domains = _ensure_list(io.get("domains"))
    hosts = _ensure_list(io.get("hosts"))
    ports = _ensure_list(raw.get("destinationPort")) or _ensure_list(io.get("destinationPort"))
    geo = _ensure_list(raw.get("destinationIPgeo")) or _ensure_list(io.get("destinationIPgeo"))
    related_tasks = _ensure_list(raw.get("relatedTasks"))
    behavior_details = raw.get("behavior_details") or {}
    process_details = _ensure_list((behavior_details or {}).get("process_details"))
    processes = _ensure_list((behavior_details or {}).get("processes"))
    analysis_id = str(result.get("analysis_id") or "").strip()
    if analysis_id:
        return False
    return (
        len(details) == 0
        and len(domains) == 0
        and len(hosts) == 0
        and len(ports) == 0
        and len(geo) == 0
        and len(related_tasks) == 0
        and len(processes) == 0
        and len(process_details) == 0
    )


def _error(indicator_type: str, message: str) -> dict[str, Any]:
    return {
        "checked": False,
        "indicator_type": indicator_type,
        "verdict": "unknown",
        "error": message,
        "raw_summary": {"source": "anyrun"},
    }


def _safe_close(conn: Any) -> None:
    if conn is None:
        return
    close = getattr(conn, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass
