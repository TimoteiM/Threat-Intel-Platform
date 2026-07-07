from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from app.models.database import AssistantSession


SUPPORTED_NODE_TYPES = {
    "alert", "ip", "geo", "user", "success", "endpoint", "mail", "domain", "file",
    "process", "app", "url", "mitre", "network", "registry", "command", "cloud", "volume",
}
SUPPORTED_SEVERITIES = {"low", "medium", "high", "critical"}
INVESTIGATION_TYPES = {
    "password_spray_account_takeover",
    "web_exploitation_campaign",
    "dns_phishing_activity",
    "endpoint_reconnaissance",
    "malware_execution_chain",
    "cloud_account_takeover",
    "suspicious_process_activity",
    "data_exfiltration",
    "lateral_movement",
    "privilege_escalation",
    "defense_evasion",
    "development_tool_false_positive",
    "identity_account_lifecycle",
    "log_volume_anomaly",
    "network_sniffing",
    "generic_multi_cluster_investigation",
}

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]{1,}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
PATH_RE = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?)+")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)

SENSITIVE_PATH_TERMS = ("/.env", ".env.bak", "config.php.bak", "/server-status", "wp-config", "backup", ".git")
EXPLOIT_TERMS = ("wget", "curl", "|sh", "command injection", "cgi-bin/luci", "luci", "bash -c")
RECON_COMMANDS = ("whoami", "net user", "nltest", "ipconfig", "tasklist", "net view", "quser")
LOLBINS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32")
PRIV_ESC_TERMS = ("privilege escalation", "uac bypass", "sudo", "setuid", "administrator", "seimpersonate")
LATERAL_TERMS = ("psexec", "wmic", "winrm", "remote service", "admin$", "smb", "rdp")
EXFIL_TERMS = ("exfiltration", "large upload", "mass download", "onedrive download", "sharepoint download")
SNIFFING_TERMS = ("promiscuous", "tcpdump", "tshark", "wireshark", "packet capture")
DEFENSE_EVASION_TERMS = ("defense evasion", "disable defender", "tamper", "clear logs", "t1036", "masquerad")
POST_LOGIN_ACTIONS = {"mailbox_rule_created", "file_accessed", "mfa_challenge_completed", "cloud_app_access"}
CLOUD_TERMS = ("azure ad", "oauth", "office 365", "onedrive", "sharepoint", "kerberos", "service ticket", "sso", "azureadssoacc")
DEV_TOOL_TERMS = ("visual studio code", "vs code", "vscode", "roslyn", "microsoft.codeanalysis", "ms-dotnettools.csharp", "language server", "analyzerassemblyloader")
FALSE_POSITIVE_TERMS = ("false positive", "likely benign", "legitimate", "normal build", "expected", "no evidence of malicious", "no evidence of", "rather than malicious")
ACCOUNT_LIFECYCLE_TERMS = (
    "account lifecycle",
    "account was created",
    "account created",
    "new account",
    "account deleted",
    "accounts were deleted",
    "user account deleted",
    "account expiration",
    "enabled for use",
    "windows security-auditing",
    "audit_success",
)
ACCOUNT_TOKEN_STOPWORDS = {
    "a",
    "an",
    "account",
    "accounts",
    "actor",
    "all",
    "and",
    "by",
    "configured",
    "created",
    "deleted",
    "enabled",
    "for",
    "initiated",
    "new",
    "same",
    "the",
    "then",
    "user",
    "users",
    "was",
    "were",
}


def build_assistant_incident_graph(assistant_session: AssistantSession, report_markdown: str = "") -> dict[str, Any]:
    raw_events = _assistant_session_events(assistant_session)
    interpretation = _interpretation_text(report_markdown)
    if interpretation:
        raw_events.append({"raw_text": interpretation, "rawRef": "ai-interpretation"})
    return buildGraphFromEvents(raw_events, interpretation, incident=assistant_session.title or "Assistant investigation")


def buildGraphFromEvents(
    rawEvents: list[Any],
    aiInterpretation: str | None = None,
    *,
    interpretation: str | None = None,
    incident: str = "SOC Investigation",
) -> dict[str, Any]:
    """Build deterministic graph data from evidence; AI text is only narrative."""
    normalized = normalizeEvents(rawEvents)
    entities = extractEntities(normalized)
    facts = extractFacts(normalized, entities)
    facts["incident"] = incident
    investigationType = classifyInvestigationType(facts)
    graph = buildGraphByType(facts, investigationType, interpretation if interpretation is not None else (aiInterpretation or ""))
    laidOutGraph = layoutGraphByType(graph, investigationType)
    validation = validateGraph(laidOutGraph, investigationType)
    laidOutGraph["data_checks"] = validation
    return laidOutGraph


def buildGraphFromEventsResult(rawEvents: list[Any], aiInterpretation: str | None = None) -> dict[str, Any]:
    graph = buildGraphFromEvents(rawEvents, aiInterpretation)
    return {"graph": graph, "validation": graph.get("data_checks") or []}


def buildGraphFromFacts(
    facts: dict[str, Any],
    *,
    incident: str = "SOC Investigation",
    interpretation: str = "",
    confidence: str = "Medium",
    recommended_actions: list[str] | None = None,
) -> dict[str, Any]:
    facts = {**facts, "incident": incident, "confidence": confidence}
    investigationType = classifyInvestigationType(facts)
    graph = buildGraphByType(facts, investigationType, interpretation)
    if recommended_actions is not None:
        graph["recommendedActions"] = recommended_actions
        graph["recommended_actions"] = recommended_actions
    graph = layoutGraphByType(graph, investigationType)
    graph["data_checks"] = validateGraph(graph, investigationType)
    return graph


def normalizeEvents(rawEvents: list[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(_expand_raw_events(rawEvents)):
        event = _normalize_one_event(raw, index)
        if _has_meaningful_event_fields(event):
            normalized.append(event)
    normalized.sort(key=lambda item: (item.get("timestamp") or "", item.get("rawRef") or ""))
    return normalized


def extractEntities(normalizedEvents: list[dict[str, Any]]) -> dict[str, list[str]]:
    entities: dict[str, set[str]] = defaultdict(set)
    for event in normalizedEvents:
        _collect(entities["ips"], event.get("sourceIp"), event.get("destinationIp"), event.get("clientIp"), event.get("endpointIp"))
        _collect(entities["users"], event.get("email"), event.get("user"), event.get("targetUser"), event.get("account"))
        _collect(entities["endpoints"], event.get("hostname"), event.get("deviceName"), event.get("endpointName"))
        _collect(entities["processes"], event.get("processName"))
        _collect(entities["parentProcesses"], event.get("parentProcessName"))
        _collect(entities["domains"], event.get("domain"))
        _collect(entities["urls"], event.get("urlPath"), event.get("requestUri"))
        _collect(entities["files"], event.get("fileName"), event.get("filePath"))
        _collect(entities["apps"], event.get("app"))
        _collect(entities["alerts"], event.get("alertName"), event.get("ruleName"), event.get("detectionName"))
        _collect(entities["mitre"], event.get("mitreTechnique"))
        _collect(entities["commands"], event.get("commandLine"))
        if event.get("firedCount"):
            entities["volumes"].add(str(event["firedCount"]))
        for email in event.get("targetedAccounts") or []:
            entities["users"].add(email)
    return {key: sorted(value) for key, value in entities.items()}


def extractFacts(normalizedEvents: list[dict[str, Any]], entities: dict[str, list[str]] | None = None) -> dict[str, Any]:
    entities = entities or extractEntities(normalizedEvents)
    events = list(normalizedEvents)
    timestamps = [event["timestamp"] for event in events if event.get("timestamp")]
    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    targets_by_ip: dict[str, set[str]] = defaultdict(set)
    alert_events: list[dict[str, Any]] = []
    web_events: list[dict[str, Any]] = []
    dns_events: list[dict[str, Any]] = []
    process_events: list[dict[str, Any]] = []
    volume_events: list[dict[str, Any]] = []
    sniffing_events: list[dict[str, Any]] = []
    cloud_events: list[dict[str, Any]] = []

    for event in events:
        text = _event_text(event)
        source_ip = event.get("sourceIp")
        if source_ip and event.get("action") == "login_failed":
            failures_by_ip[source_ip].append(event)
            for user in [event.get("email"), event.get("targetUser"), *(event.get("targetedAccounts") or [])]:
                if user:
                    targets_by_ip[source_ip].add(user)
        if event.get("alertName"):
            alert_events.append(event)
            if source_ip and _looks_like_password_spray(event.get("alertName") or ""):
                for user in event.get("targetedAccounts") or []:
                    targets_by_ip[source_ip].add(user)
        if _is_web_event(event):
            web_events.append(event)
        if event.get("eventType") == "dns" or event.get("domain") and "dns" in text:
            dns_events.append(event)
        if event.get("processName") or event.get("commandLine") or event.get("parentProcessName"):
            process_events.append(event)
        if event.get("firedCount") or "firedtimes" in text or "alert_count" in text:
            volume_events.append(event)
        if any(term in text for term in SNIFFING_TERMS):
            sniffing_events.append(event)
        if event.get("eventType") in {"cloud-app", "cloud"} or any(term in text for term in CLOUD_TERMS) or event.get("app") and any(term in text for term in ("sharepoint", "onedrive", "exchange", "mailbox", "mfa", "oauth")):
            cloud_events.append(event)

    spray_candidates: list[dict[str, Any]] = []
    for source_ip in sorted(set(failures_by_ip) | {event.get("sourceIp") for event in alert_events if event.get("sourceIp")}):
        ip_alerts = [event for event in alert_events if event.get("sourceIp") == source_ip]
        failed_count = max([len(failures_by_ip.get(source_ip, [])), *[_to_int(event.get("failedLoginCount")) for event in ip_alerts]])
        targeted = set(targets_by_ip.get(source_ip, set()))
        for event in ip_alerts:
            targeted.update(event.get("targetedAccounts") or [])
        distinct_count = max([len(targeted), *[_to_int(event.get("distinctEmailCount")) for event in ip_alerts]])
        if (failed_count >= 5 and distinct_count >= 3) or any(_looks_like_password_spray(event.get("alertName") or "") for event in ip_alerts):
            spray_candidates.append({
                "sourceIp": source_ip,
                "failedLoginCount": failed_count,
                "distinctEmailCount": distinct_count,
                "targetedEmails": sorted(targeted),
                "events": sorted(failures_by_ip.get(source_ip, []) + ip_alerts, key=lambda item: item.get("rawRef") or ""),
                "alertName": _first_value([event.get("alertName") for event in ip_alerts]) or "passwordSpray",
            })

    spray_by_ip = {candidate["sourceIp"]: candidate for candidate in spray_candidates}
    success_after_spray: list[dict[str, Any]] = []
    for event in events:
        candidate = spray_by_ip.get(event.get("sourceIp") or "")
        email = event.get("email")
        if candidate and email and event.get("action") == "login_success" and (not candidate["targetedEmails"] or email in candidate["targetedEmails"]):
            success_after_spray.append({"event": event, "sourceIp": event.get("sourceIp"), "email": email, "spray": candidate})

    success_users = {item["email"] for item in success_after_spray}
    post_login_actions: list[dict[str, Any]] = []
    for event in events:
        email = event.get("email")
        action = event.get("action")
        if email in success_users and (action in POST_LOGIN_ACTIONS or event.get("mfaResult")):
            normalized_action = action if action in POST_LOGIN_ACTIONS else "mfa_challenge_completed"
            post_login_actions.append({"event": {**event, "action": normalized_action}, "email": email, "sourceIp": event.get("sourceIp")})

    suspicious_paths: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exploit_payloads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    payload_domains: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in web_events:
        for path in event.get("paths") or []:
            if _is_suspicious_path(path):
                suspicious_paths[path].append(event)
        payload = event.get("exploitPayload")
        if payload:
            exploit_payloads[payload].append(event)
        for domain in event.get("payloadDomains") or []:
            payload_domains[domain].append(event)

    facts = {
        "events": events,
        "entities": entities,
        "firstSeen": min(timestamps) if timestamps else None,
        "lastSeen": max(timestamps) if timestamps else None,
        "sprayCandidates": spray_candidates,
        "successAfterSpray": success_after_spray,
        "postLoginActions": _dedupe_post_actions(post_login_actions),
        "compromisedAccounts": sorted({item["email"] for item in post_login_actions}),
        "webEvents": web_events,
        "sourceIps": sorted({ip for event in events for ip in (event.get("sourceIps") or ([event.get("sourceIp")] if event.get("sourceIp") else [])) if ip}),
        "suspiciousPaths": [{"path": path, "events": evs} for path, evs in sorted(suspicious_paths.items())],
        "exploitPayloads": [{"payload": payload, "events": evs} for payload, evs in sorted(exploit_payloads.items())],
        "payloadDomains": [{"domain": domain, "events": evs} for domain, evs in sorted(payload_domains.items())],
        "dnsEvents": dns_events,
        "processEvents": process_events,
        "volumeEvents": volume_events,
        "sniffingEvents": sniffing_events,
        "cloudEvents": cloud_events,
        "accountLifecycle": _extract_account_lifecycle_facts(events),
        "developmentToolFalsePositive": _extract_development_tool_false_positive_facts(events),
        "reconEvents": [event for event in process_events if any(cmd in _event_text(event) for cmd in RECON_COMMANDS)],
        "privilegeEscalationEvents": [event for event in events if any(term in _event_text(event) for term in PRIV_ESC_TERMS)],
        "lateralMovementEvents": [event for event in events if any(term in _event_text(event) for term in LATERAL_TERMS)],
        "dataExfiltrationEvents": [event for event in events if any(term in _event_text(event) for term in EXFIL_TERMS)],
        "defenseEvasionEvents": [event for event in events if any(term in _event_text(event) for term in DEFENSE_EVASION_TERMS)],
    }
    return facts


def classifyInvestigationType(facts: dict[str, Any]) -> str:
    has_account_lifecycle = _has_account_lifecycle(facts)
    has_dev_false_positive = _has_development_tool_false_positive(facts)
    has_web = bool(facts.get("suspiciousPaths") or facts.get("exploitPayloads"))
    has_sniffing = bool(facts.get("sniffingEvents")) or "T1040" in set(facts.get("entities", {}).get("mitre") or [])
    has_volume = any(_to_int(event.get("firedCount")) >= 1000 for event in facts.get("volumeEvents") or [])
    has_spray = bool(facts.get("sprayCandidates"))
    active_clusters = sum(1 for present in (has_web, has_sniffing, has_volume, bool(facts.get("dnsEvents")), has_spray, bool(facts.get("processEvents")), bool(facts.get("cloudEvents"))) if present)
    if has_account_lifecycle:
        return "identity_account_lifecycle"
    if has_dev_false_positive:
        return "development_tool_false_positive"
    if active_clusters >= 3:
        return "generic_multi_cluster_investigation"
    if has_spray:
        return "password_spray_account_takeover"
    if has_web:
        return "web_exploitation_campaign"
    if has_sniffing:
        return "network_sniffing"
    if has_volume:
        return "log_volume_anomaly"
    if _has_cloud_takeover(facts):
        return "cloud_account_takeover"
    if facts.get("cloudEvents"):
        return "generic_multi_cluster_investigation"
    if facts.get("dnsEvents") and any(_event_has_phishing_or_block(event) for event in facts["dnsEvents"]):
        return "dns_phishing_activity"
    if facts.get("dataExfiltrationEvents"):
        return "data_exfiltration"
    if facts.get("lateralMovementEvents"):
        return "lateral_movement"
    if facts.get("privilegeEscalationEvents"):
        return "privilege_escalation"
    if facts.get("defenseEvasionEvents"):
        return "defense_evasion"
    if facts.get("reconEvents"):
        return "endpoint_reconnaissance"
    if any(_is_malware_chain_event(event) for event in facts.get("processEvents") or []):
        return "malware_execution_chain"
    if facts.get("processEvents"):
        return "suspicious_process_activity"
    if facts.get("dnsEvents"):
        return "dns_phishing_activity"
    return "generic_multi_cluster_investigation"


def buildGraphByType(facts: dict[str, Any], investigationType: str, aiInterpretation: str | None = None) -> dict[str, Any]:
    builders = {
        "identity_account_lifecycle": _build_account_lifecycle_graph,
        "development_tool_false_positive": _build_development_tool_false_positive_graph,
        "password_spray_account_takeover": _build_password_spray_graph,
        "web_exploitation_campaign": _build_web_graph,
        "dns_phishing_activity": _build_dns_graph,
        "endpoint_reconnaissance": _build_process_graph,
        "malware_execution_chain": _build_process_graph,
        "suspicious_process_activity": _build_process_graph,
        "data_exfiltration": _build_process_graph,
        "lateral_movement": _build_process_graph,
        "privilege_escalation": _build_process_graph,
        "defense_evasion": _build_process_graph,
        "cloud_account_takeover": _build_cloud_graph,
        "network_sniffing": _build_sniffing_graph,
        "log_volume_anomaly": _build_volume_graph,
        "generic_multi_cluster_investigation": _build_generic_multi_cluster_graph,
    }
    graph = builders.get(investigationType, _build_generic_multi_cluster_graph)(facts, investigationType)
    graph["summary"] = {
        "incident": facts.get("incident") or _incident_title(investigationType),
        "risk": _risk_from_graph(graph),
        "confidence": facts.get("confidence") or _confidence_from_facts(facts, investigationType),
        "score": _score_from_graph(graph, facts),
        "lastSeen": facts.get("lastSeen") or "",
        "firstSeen": facts.get("firstSeen") or "",
        "investigationType": investigationType,
        "interpretation": aiInterpretation or _deterministic_interpretation(facts, investigationType),
        "analystTakeaway": aiInterpretation or _deterministic_interpretation(facts, investigationType),
        "timeWindow": _time_window(facts),
        "primaryIdentity": _first_value(facts.get("compromisedAccounts") or facts.get("entities", {}).get("users") or []) or "-",
    }
    actions = recommendedActionsForType(investigationType)
    graph["recommendedActions"] = actions
    graph["recommended_actions"] = actions
    graph["facts"] = _public_fact_summary(facts)
    return graph


def layoutGraphByType(graph: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes = graph.get("nodes") or []
    for node in nodes:
        node.setdefault("cluster", _cluster_for_node(node))
    if investigationType == "generic_multi_cluster_investigation":
        _layout_clusters(nodes)
    elif investigationType == "identity_account_lifecycle":
        _layout_by_roles(nodes, {"actor": (80, 260), "alert": (520, 80), "endpoint": (80, 520), "deletion_batch": (420, 300), "deleted_user": (360, 520), "created_event": (760, 300), "created_user": (760, 520), "config": (1000, 520), "context": (1000, 680)})
    elif investigationType == "development_tool_false_positive":
        _layout_by_roles(nodes, {"endpoint": (80, 300), "process": (380, 220), "file": (700, 260), "command": (700, 470), "alert": (980, 180), "mitre": (980, 420), "context": (1180, 560)})
    elif investigationType == "password_spray_account_takeover":
        _layout_by_roles(nodes, {"ip": (80, 240), "alert": (420, 80), "user": (360, 250), "success": (450, 500), "post": (700, 560), "context": (980, 660)})
    elif investigationType == "web_exploitation_campaign":
        _layout_by_roles(nodes, {"ip": (80, 220), "alert": (520, 80), "url": (360, 270), "command": (620, 330), "domain": (950, 300), "volume": (760, 650), "context": (960, 650)})
    elif investigationType == "dns_phishing_activity":
        _layout_by_roles(nodes, {"endpoint": (80, 220), "user": (80, 380), "domain": (420, 240), "alert": (760, 240), "network": (760, 380), "context": (900, 560)})
    elif investigationType == "cloud_account_takeover":
        _layout_by_roles(nodes, {"ip": (80, 220), "geo": (80, 380), "user": (420, 230), "success": (420, 430), "app": (760, 250), "mail": (760, 430), "file": (1000, 430), "alert": (900, 100), "context": (1000, 620)})
    elif investigationType == "network_sniffing":
        _layout_by_roles(nodes, {"endpoint": (80, 250), "network": (420, 250), "alert": (760, 250), "mitre": (900, 520), "process": (420, 440), "context": (900, 640)})
    elif investigationType == "log_volume_anomaly":
        _layout_by_roles(nodes, {"cloud": (80, 260), "endpoint": (80, 260), "volume": (420, 240), "alert": (420, 100), "process": (760, 260), "ip": (760, 520), "context": (940, 560)})
    else:
        _layout_by_roles(nodes, {"endpoint": (80, 260), "process": (420, 220), "command": (670, 300), "file": (900, 260), "registry": (900, 420), "domain": (900, 560), "ip": (900, 680), "alert": (420, 620), "mitre": (900, 620), "user": (160, 440), "context": (760, 720)})
    for node in nodes:
        node["x"] = int(node.get("x", 420))
        node["y"] = int(node.get("y", 760))
        node.pop("_role", None)
    return graph


def validateGraph(graph: dict[str, Any], investigationType: str | None = None) -> list[dict[str, Any]]:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    investigationType = investigationType or (graph.get("summary") or {}).get("investigationType") or ""
    node_ids = [node.get("id") for node in nodes]
    node_id_set = set(node_ids)
    edge_keys = [(edge.get("from"), edge.get("to"), edge.get("label")) for edge in edges]
    critical_isolated = [
        node for node in nodes
        if node.get("severity") == "critical"
        and node.get("type") != "alert"
        and not any(edge.get("from") == node.get("id") or edge.get("to") == node.get("id") for edge in edges)
    ]
    critical_without_evidence = [node for node in nodes if node.get("severity") == "critical" and not node.get("evidence")]
    checks = [
        {"name": "unique node IDs", "passed": len(node_id_set) == len(node_ids)},
        {"name": "all edges reference valid nodes", "passed": all(edge.get("from") in node_id_set and edge.get("to") in node_id_set for edge in edges)},
        {"name": "all nodes include required fields", "passed": all(_node_has_required_fields(node) for node in nodes)},
        {"name": "all severities are supported", "passed": all(node.get("severity") in SUPPORTED_SEVERITIES for node in nodes)},
        {"name": "no duplicate edges", "passed": len(edge_keys) == len(set(edge_keys))},
        {"name": "no isolated critical nodes unless they are the primary alert", "passed": not critical_isolated},
        {"name": "every critical node has evidence", "passed": not critical_without_evidence},
        {"name": "graph has at least one alert or campaign node", "passed": any(node.get("type") == "alert" for node in nodes)},
    ]
    if investigationType == "password_spray_account_takeover":
        checks.append({"name": "password spray has multiple targeted users", "passed": sum(1 for node in nodes if node.get("type") == "user") >= 3})
    if investigationType == "web_exploitation_campaign":
        checks.append({"name": "web exploitation has source IP and suspicious target", "passed": any(node.get("type") == "ip" for node in nodes) and any(node.get("type") in {"url", "command"} for node in nodes)})
    if investigationType == "dns_phishing_activity":
        checks.append({"name": "DNS graph has domain/query node", "passed": any(node.get("type") == "domain" for node in nodes)})
    if investigationType in {"endpoint_reconnaissance", "malware_execution_chain", "suspicious_process_activity", "data_exfiltration", "lateral_movement", "privilege_escalation", "defense_evasion"}:
        checks.append({"name": "process graph has process node", "passed": any(node.get("type") == "process" for node in nodes)})
    if investigationType == "network_sniffing":
        checks.append({"name": "network sniffing has endpoint/interface/MITRE or alert", "passed": any(node.get("type") == "endpoint" for node in nodes) and any(node.get("type") in {"network", "mitre", "alert"} for node in nodes)})
    if investigationType == "log_volume_anomaly":
        checks.append({"name": "log volume graph has volume/count/rule node", "passed": any(node.get("type") == "volume" for node in nodes)})
    if investigationType == "identity_account_lifecycle":
        checks.append({"name": "account lifecycle graph has actor and changed accounts", "passed": sum(1 for node in nodes if node.get("type") == "user") >= 2 and any("lifecycle" in (node.get("label") or "").lower() for node in nodes)})
    if investigationType == "development_tool_false_positive":
        checks.append({"name": "development tool false positive has endpoint and file/process context", "passed": any(node.get("type") == "endpoint" for node in nodes) and any(node.get("type") in {"file", "process"} for node in nodes)})
    return checks


def recommendedActionsForType(investigationType: str) -> list[str]:
    actions = {
        "web_exploitation_campaign": [
            "Review web server logs for response status and successful exploitation evidence.",
            "Check whether sensitive files such as .env or config backups are exposed.",
            "Validate whether the LuCI command-injection request reached a vulnerable asset.",
            "Block or rate-limit confirmed malicious source IPs.",
            "Search for payload domain access or script execution.",
        ],
        "network_sniffing": [
            "Verify whether promiscuous mode was expected for monitoring tools.",
            "Identify the process or user that enabled promiscuous mode.",
            "Check for packet capture tools such as tcpdump, tshark, or Wireshark.",
            "Review credential access indicators on the host.",
        ],
        "log_volume_anomaly": [
            "Identify top fired rules and top sources.",
            "Check whether the volume was caused by scanning, misconfiguration, looped ingestion, or alert storm.",
            "Validate pipeline health and duplicate ingestion.",
            "Suppress or tune noisy rules only after confirming benign activity.",
        ],
        "cloud_account_takeover": [
            "Reset password and revoke sessions.",
            "Validate MFA state and recent MFA changes.",
            "Review mailbox rules, forwarding, OAuth grants, and SharePoint access.",
            "Confirm activity with the user.",
        ],
        "password_spray_account_takeover": [
            "Block source IP if malicious.",
            "Reset impacted account credentials.",
            "Review successful logins after failures.",
            "Validate MFA approvals and impossible travel.",
        ],
        "identity_account_lifecycle": [
            "Validate whether the initiating account was authorized to delete and create these users.",
            "Review the change ticket, HR workflow, or automation run that should explain the account lifecycle changes.",
            "Confirm the new account owner, business purpose, expiration date, enablement status, and group memberships.",
            "Review domain controller security logs around the observed time window for related account-management events.",
            "Check whether the initiating service account was used from an unusual host or recently had credential changes.",
        ],
        "development_tool_false_positive": [
            "Confirm the file path belongs to the expected developer tooling workflow on the endpoint.",
            "Validate the file hash reputation and code-signing metadata before closing the alert.",
            "Check whether VS Code or the C# extension was active for the user at the detection time.",
            "Review endpoint telemetry for network connections, suspicious child processes, or persistence from the same process tree.",
            "Tune the rule for known Roslyn analyzer cache paths only after confirming this activity is benign.",
        ],
        "dns_phishing_activity": [
            "Review DNS, proxy, and endpoint telemetry for additional queries to the domain.",
            "Confirm the resolver block action and domain category.",
            "Inspect the endpoint for browser downloads or follow-on execution.",
            "Notify the user if the query came from an interactive session.",
        ],
    }
    return actions.get(investigationType, [
        "Validate the alert against raw telemetry before declaring compromise.",
        "Pivot on shared host, user, source IP, and time-window evidence.",
        "Preserve raw logs and compare with related alerts in the same interval.",
        "Escalate only relationships that are directly supported by evidence.",
    ])


def _build_account_lifecycle_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    lifecycle = facts.get("accountLifecycle") or {}
    evidence = lifecycle.get("evidence") or _event_refs(facts.get("events") or [])
    deleted_accounts = lifecycle.get("deletedAccounts") or []
    created_account = lifecycle.get("createdAccount") or ""
    actor = lifecycle.get("actor") or _first_value((facts.get("entities") or {}).get("users") or []) or "initiating-account"
    controller = lifecycle.get("domainController") or _first_value((facts.get("entities") or {}).get("endpoints") or []) or "domain-controller"
    alert_id = _node_id("alert", "account-lifecycle-manipulation")
    actor_id = _node_id("user", actor)
    controller_id = _node_id("endpoint", controller)
    deletion_id = _node_id("success", f"{actor}-deleted-{len(deleted_accounts)}-accounts")

    # This graph intentionally represents audited account-management operations.
    # It does not infer malware, compromise, or network causality from admin-change evidence alone.
    _add_node(nodes, _node(alert_id, "alert", "Account Lifecycle Manipulation", "Rapid account deletion and provisioning", "high" if len(deleted_accounts) >= 3 and created_account else "medium", "Multiple successful directory changes were clustered in time and performed by the same initiating account.", evidence, "alert", "Identity activity cluster"))
    _add_node(nodes, _node(actor_id, "user", actor, "Initiating account", "high" if len(deleted_accounts) >= 3 else "medium", "Account identified as the actor that initiated the directory modifications.", evidence, "actor", "Identity activity cluster"))
    _add_node(nodes, _node(controller_id, "endpoint", _short_host(controller), controller, "low", "Domain controller or directory host where the audit evidence was recorded.", evidence, "endpoint", "Identity activity cluster"))
    _add_node(nodes, _node(deletion_id, "success", f"{len(deleted_accounts)} account deletions" if deleted_accounts else "Account deletion activity", lifecycle.get("deletionWindow") or "Rapid successful deletions", "high" if len(deleted_accounts) >= 3 else "medium", "Successful account deletions observed close together. The graph records the operation without assuming it was unauthorized.", evidence, "deletion_batch", "Identity activity cluster"))
    _add_edge(edges, actor_id, alert_id, "initiated", evidence=evidence, confidence="high")
    _add_edge(edges, controller_id, alert_id, "recorded audit", evidence=evidence, confidence="high")
    _add_edge(edges, actor_id, deletion_id, "deleted accounts", evidence=evidence, confidence="high")

    for account in deleted_accounts:
        user_id = _node_id("user", account)
        _add_node(nodes, _node(user_id, "user", account, "Deleted account", "medium", "User account was deleted successfully according to audit evidence.", evidence, "deleted_user", "Identity activity cluster"))
        _add_edge(edges, deletion_id, user_id, "deleted", evidence=evidence, confidence="high")

    created_event_id = ""
    if created_account:
        created_event_id = _node_id("success", f"{actor}-created-{created_account}")
        created_user_id = _node_id("user", created_account)
        _add_node(nodes, _node(created_event_id, "success", "Account created", lifecycle.get("creationTiming") or "Created after deletions", "high", "A new account was created after the deletion batch by the same initiating account.", evidence, "created_event", "Identity activity cluster"))
        _add_node(nodes, _node(created_user_id, "user", created_account, "Newly created account", "high", "New account created and then configured/enabled according to audit evidence.", evidence, "created_user", "Identity activity cluster"))
        _add_edge(edges, actor_id, created_event_id, "created", evidence=evidence, confidence="high")
        _add_edge(edges, created_event_id, created_user_id, "created account", evidence=evidence, confidence="high")
        if deleted_accounts:
            _add_edge(edges, deletion_id, created_event_id, "13 minutes later" if lifecycle.get("creationTiming") else "followed by", evidence=evidence, confidence="medium")
        if lifecycle.get("expirationDate"):
            expiration_id = _node_id("success", f"{created_account}-expiration-{lifecycle['expirationDate']}")
            _add_node(nodes, _node(expiration_id, "success", "Expiration configured", str(lifecycle["expirationDate"]), "medium", "Account expiration date was configured after creation.", evidence, "config", "Identity activity cluster"))
            _add_edge(edges, created_user_id, expiration_id, "configured expiration", evidence=evidence, confidence="high")
        if lifecycle.get("enabled"):
            enabled_id = _node_id("success", f"{created_account}-enabled")
            _add_node(nodes, _node(enabled_id, "success", "Account enabled", "Enabled for use", "medium", "The created account was enabled for use.", evidence, "config", "Identity activity cluster"))
            _add_edge(edges, created_user_id, enabled_id, "enabled", evidence=evidence, confidence="high")

    if lifecycle.get("provider") or lifecycle.get("outcome"):
        audit_id = _node_id("alert", "windows-security-auditing-success")
        _add_node(nodes, _node(audit_id, "alert", "AUDIT_SUCCESS", lifecycle.get("provider") or "Windows Security-Auditing", "low", "Audit provider/outcome confirms the directory modifications succeeded.", evidence, "context", "Identity activity cluster"))
        _add_edge(edges, alert_id, audit_id, "confirmed by audit", evidence=evidence, confidence="high")

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_development_tool_false_positive_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    fp = facts.get("developmentToolFalsePositive") or {}
    evidence = fp.get("evidence") or _event_refs(facts.get("events") or [])
    alert_id = _node_id("alert", "development-tool-alert-review")
    endpoint = fp.get("endpoint") or "endpoint"
    endpoint_id = _node_id("endpoint", endpoint)
    process = fp.get("process") or "VS Code C# extension"
    process_id = _node_id("process", process)
    file_path = fp.get("filePath") or fp.get("fileName") or "Roslyn analyzer artifact"
    file_id = _node_id("file", file_path)

    # This template is deliberately a benign/false-positive review graph.
    # Mentions such as "no command injection" are treated as exculpatory context,
    # not exploit evidence, so no web attack or execution-success edge is created.
    _add_node(nodes, _node(alert_id, "alert", "Development Tool Alert Review", "Likely false positive / obfuscation technique", "medium", "Detection is explained by developer tooling and temporary Roslyn analyzer artifacts; malicious execution is not assumed.", evidence, "alert", "Endpoint activity cluster"))
    _add_node(nodes, _node(endpoint_id, "endpoint", endpoint, "Endpoint with detection", "low", "Endpoint where the uncommon file-path detection was observed.", evidence, "endpoint", "Endpoint activity cluster"))
    _add_node(nodes, _node(process_id, "process", process, "Legitimate developer tooling", "low", "VS Code C# extension or Roslyn tooling context explains the process lineage.", evidence, "process", "Endpoint activity cluster"))
    _add_node(nodes, _node(file_id, "file", _file_label(file_path), fp.get("sha1") or file_path, "medium", "Executable/DLL artifact observed at an uncommon temporary Roslyn analyzer path.", evidence, "file", "Endpoint activity cluster"))
    _add_edge(edges, endpoint_id, alert_id, "generated alert", evidence=evidence, confidence="high")
    _add_edge(edges, endpoint_id, process_id, "tool observed", evidence=evidence, confidence="high")
    _add_edge(edges, process_id, file_id, "loaded analyzer artifact", evidence=evidence, confidence="medium")
    _add_edge(edges, file_id, alert_id, "detected at uncommon path", evidence=evidence, confidence="high")

    if fp.get("commandLine"):
        command_id = _node_id("command", fp["commandLine"][:100])
        _add_node(nodes, _node(command_id, "command", "Language server command line", fp["commandLine"][:120], "low", "Command line contains extension paths and normal language-server configuration parameters.", evidence, "command", "Endpoint activity cluster"))
        _add_edge(edges, process_id, command_id, "started with config", evidence=evidence, confidence="medium")
    if fp.get("mitre"):
        mitre_id = _node_id("mitre", fp["mitre"])
        _add_node(nodes, _node(mitre_id, "mitre", fp["mitre"].upper(), "Masquerading / obfuscation detection", "low", "MITRE mapping was attached to the detection, but the interpretation indicates a likely benign development-tool cause.", evidence, "mitre", "Endpoint activity cluster"))
        _add_edge(edges, alert_id, mitre_id, "maps to", evidence=evidence, confidence="high")
    verdict_id = _node_id("alert", "likely-false-positive")
    _add_node(nodes, _node(verdict_id, "alert", "Likely False Positive", "No malicious network or injection evidence", "low", "Interpretation states no command injection, remote execution, or unauthorized network communication was present.", evidence, "context", "Endpoint activity cluster"))
    _add_edge(edges, alert_id, verdict_id, "explained by context", evidence=evidence, confidence="medium")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_password_spray_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    compromised = set(facts.get("compromisedAccounts") or [])
    for spray_idx, spray in enumerate(facts.get("sprayCandidates") or []):
        evidence = _event_refs(spray.get("events") or [])
        ip_id = _node_id("ip", spray["sourceIp"])
        alert_id = _node_id("alert", spray.get("alertName") or "passwordSpray")
        _add_node(nodes, _node(ip_id, "ip", spray["sourceIp"], "Password spray source", "high", f"{spray['sourceIp']} generated {spray.get('failedLoginCount', 0)} failed logins against {spray.get('distinctEmailCount', 0)} accounts.", evidence, "ip"))
        _add_node(nodes, _node(alert_id, "alert", "Password Spray Alert", f"{spray.get('failedLoginCount', 0)} failures / {spray.get('distinctEmailCount', 0)} accounts", "high", "Repeated failed authentications across multiple accounts from the same source IP.", evidence, "alert"))
        _add_edge(edges, ip_id, alert_id, "generated", evidence=evidence, confidence="high")
        for user_idx, email in enumerate(spray.get("targetedEmails") or []):
            is_compromised = email in compromised
            user_id = _node_id("user", email)
            _add_node(nodes, _node(user_id, "user", email, "Likely compromised account" if is_compromised else "Targeted account", "critical" if is_compromised else "medium", "Successful login and suspicious post-login action observed." if is_compromised else "Targeted by failed authentication attempts; no success evidence by itself.", evidence, "user"))
            _add_edge(edges, alert_id, user_id, "targeted", evidence=evidence, confidence="high")
    _add_success_and_post_login(nodes, edges, facts)
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_web_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    alert_id = _node_id("alert", "web-attack-campaign")
    campaign_evidence = _event_refs(facts.get("webEvents") or [])
    _add_node(nodes, _node(alert_id, "alert", "Web Attack Campaign", "Suspicious web request cluster", "high", "External requests targeted sensitive paths or included exploit-like payloads. This is an attempt cluster, not proof of compromise.", campaign_evidence, "alert", "Web activity cluster"))
    web_sources = sorted({ip for event in facts.get("webEvents") or [] for ip in (event.get("sourceIps") or ([event.get("sourceIp")] if event.get("sourceIp") else []))})
    for source_ip in web_sources:
        evs = [event for event in facts["webEvents"] if source_ip in (event.get("sourceIps") or [event.get("sourceIp")])]
        ip_id = _node_id("ip", source_ip)
        _add_node(nodes, _node(ip_id, "ip", source_ip, "External web source", "high", "Source IP observed sending suspicious HTTP requests.", _event_refs(evs), "ip", "Web activity cluster"))
        _add_edge(edges, ip_id, alert_id, "sent requests", evidence=_event_refs(evs), confidence="high")
    for item in facts.get("suspiciousPaths") or []:
        path_id = _node_id("url", item["path"])
        _add_node(nodes, _node(path_id, "url", item["path"], "Sensitive path / reconnaissance", "medium" if item["path"] == "/server-status" else "high", "Requested path is commonly probed during web exploitation or reconnaissance.", _event_refs(item["events"]), "url", "Web activity cluster"))
        _add_edge(edges, alert_id, path_id, "targeted", evidence=_event_refs(item["events"]), confidence="high")
    for item in facts.get("exploitPayloads") or []:
        payload_id = _node_id("command", item["payload"][:90])
        severity = "critical" if _payload_download_and_execute(item["payload"]) else "high"
        _add_node(nodes, _node(payload_id, "command", "LuCI / command injection payload" if "luci" in item["payload"].lower() else "Exploit payload", item["payload"][:90], severity, "Exploit syntax observed in request evidence. Execution is not assumed without endpoint evidence.", _event_refs(item["events"]), "command", "Web activity cluster"))
        _add_edge(edges, alert_id, payload_id, "attempted exploit", evidence=_event_refs(item["events"]), confidence="high")
        for domain in sorted({domain for event in item["events"] for domain in event.get("payloadDomains", [])}):
            domain_id = _node_id("domain", domain)
            domain_events = [event for event in item["events"] if domain in event.get("payloadDomains", [])]
            _add_node(nodes, _node(domain_id, "domain", domain, "Payload domain in request", "high", "Domain appeared inside an exploit/download payload.", _event_refs(domain_events), "domain", "Web activity cluster"))
            _add_edge(edges, payload_id, domain_id, "downloads payload", evidence=_event_refs(domain_events), confidence="medium")
    _add_volume_correlation(nodes, edges, facts, alert_id)
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_dns_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for idx, event in enumerate(facts.get("dnsEvents") or []):
        evidence = _event_refs([event])
        domain = event.get("domain") or "dns-query"
        domain_id = _node_id("domain", domain)
        alert_id = _node_id("alert", f"dns-{domain}")
        _add_node(nodes, _node(domain_id, "domain", domain, "DNS query domain", "high" if _event_has_phishing_or_block(event) else "medium", "DNS domain observed in resolver telemetry.", evidence, "domain", "DNS/network cluster"))
        _add_node(nodes, _node(alert_id, "alert", "DNS Phishing/Malware Alert", event.get("outcome") or "DNS security category", "high" if _event_has_phishing_or_block(event) else "medium", "Resolver or category evidence indicates suspicious DNS activity.", evidence, "alert", "DNS/network cluster"))
        _add_edge(edges, domain_id, alert_id, "categorized as phishing/malware" if _event_has_phishing_or_block(event) else "correlated with", evidence=evidence, confidence="high")
        endpoint_value = event.get("hostname") or event.get("endpointIp")
        if endpoint_value:
            endpoint_id = _node_id("endpoint", endpoint_value)
            _add_node(nodes, _node(endpoint_id, "endpoint", endpoint_value, event.get("endpointIp") or "Endpoint context", "medium", "Endpoint context observed for DNS query.", evidence, "endpoint", "DNS/network cluster"))
            _add_edge(edges, endpoint_id, domain_id, "queried", evidence=evidence, confidence="high")
        if event.get("email") or event.get("user"):
            user = event.get("email") or event.get("user")
            user_id = _node_id("user", user)
            _add_node(nodes, _node(user_id, "user", user, "User context", "low", "User context associated with DNS event.", evidence, "user", "DNS/network cluster"))
            if endpoint_value:
                _add_edge(edges, user_id, _node_id("endpoint", endpoint_value), "logged in user", evidence=evidence, confidence="medium")
        if event.get("outcome") == "blocked":
            resolver_id = _node_id("network", event.get("app") or "dns-resolver")
            _add_node(nodes, _node(resolver_id, "network", event.get("app") or "DNS Resolver", "Security action", "low", "Resolver/security control blocked the query.", evidence, "network", "DNS/network cluster"))
            _add_edge(edges, resolver_id, domain_id, "blocked", evidence=evidence, confidence="high")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_process_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    alert_id = _node_id("alert", investigationType)
    evs = facts.get("processEvents") or facts.get("events") or []
    _add_node(nodes, _node(alert_id, "alert", _incident_title(investigationType), "Endpoint/process evidence", "high" if evs else "medium", "Process relationships are created only from parent, child, command, file, registry, or network fields in the evidence.", _event_refs(evs), "alert", "Endpoint activity cluster"))
    for idx, event in enumerate(evs):
        evidence = _event_refs([event])
        endpoint = event.get("hostname") or event.get("endpointIp")
        endpoint_id = ""
        if endpoint:
            endpoint_id = _node_id("endpoint", endpoint)
            _add_node(nodes, _node(endpoint_id, "endpoint", endpoint, event.get("endpointIp") or "Endpoint", "medium", "Endpoint observed in process telemetry.", evidence, "endpoint", "Endpoint activity cluster"))
            _add_edge(edges, endpoint_id, alert_id, "generated", evidence=evidence, confidence="high")
        parent = event.get("parentProcessName")
        child = event.get("processName")
        if parent:
            parent_id = _node_id("process", parent)
            _add_node(nodes, _node(parent_id, "process", parent, "Parent process", _process_severity(parent, event), "Parent process from telemetry.", evidence, "process", "Endpoint activity cluster"))
            if endpoint_id:
                _add_edge(edges, endpoint_id, parent_id, "ran process", evidence=evidence, confidence="high")
        if child:
            child_id = _node_id("process", child)
            _add_node(nodes, _node(child_id, "process", child, "Child process", _process_severity(child, event), "Process observed in execution telemetry.", evidence, "process", "Endpoint activity cluster"))
            _add_edge(edges, child_id, alert_id, "flagged", evidence=evidence, confidence="high")
            if parent:
                _add_edge(edges, _node_id("process", parent), child_id, "spawned", evidence=evidence, confidence="high")
            elif endpoint_id:
                _add_edge(edges, endpoint_id, child_id, "ran process", evidence=evidence, confidence="high")
        if event.get("commandLine"):
            cmd_id = _node_id("command", event["commandLine"][:100])
            _add_node(nodes, _node(cmd_id, "command", _command_label(event["commandLine"]), event["commandLine"][:120], _command_severity(event["commandLine"]), "Command line recorded in telemetry.", evidence, "command", "Endpoint activity cluster"))
            if child:
                _add_edge(edges, _node_id("process", child), cmd_id, "executed", evidence=evidence, confidence="high")
        if event.get("filePath") or event.get("fileName"):
            file_value = event.get("filePath") or event.get("fileName")
            file_id = _node_id("file", file_value)
            _add_node(nodes, _node(file_id, "file", file_value, "File artifact", "medium", "File artifact observed in endpoint telemetry.", evidence, "file", "Endpoint activity cluster"))
            if child:
                _add_edge(edges, _node_id("process", child), file_id, "created/read/wrote", evidence=evidence, confidence="medium")
        for domain in event.get("payloadDomains") or ([] if not event.get("domain") else [event["domain"]]):
            domain_id = _node_id("domain", domain)
            _add_node(nodes, _node(domain_id, "domain", domain, "Network artifact", "medium", "Network destination observed with process evidence.", evidence, "domain", "Endpoint activity cluster"))
            if child:
                _add_edge(edges, _node_id("process", child), domain_id, "connected to", evidence=evidence, confidence="medium")
        mitre = event.get("mitreTechnique") or ("T1040" if "t1040" in _event_text(event) else "")
        if mitre:
            mitre_id = _node_id("mitre", mitre)
            _add_node(nodes, _node(mitre_id, "mitre", mitre.upper(), "MITRE technique", "low", "MITRE mapping present in event evidence.", evidence, "mitre", "Endpoint activity cluster"))
            _add_edge(edges, alert_id, mitre_id, "maps to", evidence=evidence, confidence="high")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_cloud_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    graph = _build_password_spray_graph(facts, investigationType) if facts.get("sprayCandidates") else {"nodes": [], "edges": []}
    nodes = {node["id"]: node for node in graph["nodes"]}
    edges = {(edge["from"], edge["to"], edge["label"]): edge for edge in graph["edges"]}
    suspicious = _cloud_is_suspicious(facts)
    alert_id = _node_id("alert", "cloud-account-takeover" if suspicious else "cloud-identity-activity")
    evidence = _event_refs(facts.get("cloudEvents") or facts.get("events") or [])
    _add_node(
        nodes,
        _node(
            alert_id,
            "alert",
            "Cloud Account Takeover" if suspicious else "Cloud Identity Activity",
            "Suspicious cloud identity activity" if suspicious else "OAuth/Kerberos/OneDrive activity",
            "high" if suspicious else "medium",
            "Cloud events indicate suspicious login or post-login activity." if suspicious else "Cloud authentication and service access were extracted from the interpretation without assuming compromise.",
            evidence,
            "alert",
            "Cloud activity cluster",
        ),
    )
    for event in facts.get("cloudEvents") or []:
        ev = _event_refs([event])
        user = event.get("email") or event.get("user")
        if user:
            user_id = _node_id("user", user)
            _add_node(nodes, _node(user_id, "user", user, "Cloud user account", "high" if suspicious else "medium", "User account observed in cloud activity.", ev, "user", "Cloud activity cluster"))
            _add_edge(edges, user_id, alert_id, "possible account takeover" if suspicious else "cloud activity", evidence=ev, confidence="medium")
        for source_ip in event.get("sourceIps") or ([event.get("sourceIp")] if event.get("sourceIp") else []):
            ip_id = _node_id("ip", source_ip)
            _add_node(nodes, _node(ip_id, "ip", source_ip, "Authentication source IP", "high" if suspicious else "medium", "Source IP observed authenticating to cloud account.", ev, "ip", "Cloud activity cluster"))
            if not user:
                _add_edge(edges, ip_id, alert_id, "cloud authentication", evidence=ev, confidence="medium")
                continue
            _add_edge(edges, ip_id, _node_id("user", user), "authenticated", evidence=ev, confidence="high")
        endpoint = event.get("hostname") or event.get("endpointName") or event.get("deviceName")
        if endpoint:
            endpoint_id = _node_id("endpoint", endpoint)
            _add_node(nodes, _node(endpoint_id, "endpoint", endpoint, event.get("endpointIp") or "Managed device", "low", "Device context observed in cloud identity activity.", ev, "endpoint", "Cloud activity cluster"))
            if user:
                _add_edge(edges, _node_id("user", user), endpoint_id, "used device", evidence=ev, confidence="medium")
        for app in _cloud_apps(event):
            app_id = _node_id("app", app)
            _add_node(nodes, _node(app_id, "app", app, "Cloud app/service", "low", "Cloud service or application observed in interpretation.", ev, "app", "Cloud activity cluster"))
            if user:
                _add_edge(edges, _node_id("user", user), app_id, "accessed", evidence=ev, confidence="medium")
        for service in _cloud_services(event):
            service_id = _node_id("cloud", service)
            _add_node(nodes, _node(service_id, "cloud", service, "Kerberos/service ticket target", "low", "Service ticket or cloud service target observed in interpretation.", ev, "app", "Cloud activity cluster"))
            if user:
                _add_edge(edges, _node_id("user", user), service_id, "requested ticket", evidence=ev, confidence="medium")
    _add_success_and_post_login(nodes, edges, facts)
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_sniffing_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for idx, event in enumerate(facts.get("sniffingEvents") or facts.get("events") or []):
        evidence = _event_refs([event])
        endpoint = event.get("hostname") or event.get("endpointIp") or "endpoint"
        interface = event.get("networkInterface") or _regex_value(event.get("raw") or "", r"\b(?:interface|ifname|device)\s*[=:]\s*([A-Za-z0-9_.:-]+)") or "network-interface"
        endpoint_id = _node_id("endpoint", endpoint)
        interface_id = _node_id("network", interface)
        alert_id = _node_id("alert", "promiscuous-mode")
        mitre_id = _node_id("mitre", event.get("mitreTechnique") or "T1040")
        _add_node(nodes, _node(endpoint_id, "endpoint", endpoint, event.get("endpointIp") or "Host observed", "medium", "Endpoint associated with network sniffing evidence.", evidence, "endpoint", "DNS/network cluster"))
        _add_node(nodes, _node(interface_id, "network", interface, "Network interface", "medium", "Interface observed in promiscuous mode evidence.", evidence, "network", "DNS/network cluster"))
        _add_node(nodes, _node(alert_id, "alert", "Promiscuous Mode Alert", "Potential network sniffing", "high", "Promiscuous mode or packet capture behavior observed.", evidence, "alert", "DNS/network cluster"))
        _add_node(nodes, _node(mitre_id, "mitre", "T1040", "Network Sniffing", "low", "MITRE T1040 mapping for network sniffing.", evidence, "mitre", "DNS/network cluster"))
        _add_edge(edges, endpoint_id, interface_id, "interface observed", evidence=evidence, confidence="high")
        _add_edge(edges, interface_id, alert_id, "entered promiscuous mode", evidence=evidence, confidence="high")
        _add_edge(edges, alert_id, mitre_id, "maps to", evidence=evidence, confidence="high")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_volume_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    alert_id = _node_id("alert", "log-volume-anomaly")
    evidence = _event_refs(facts.get("volumeEvents") or [])
    _add_node(nodes, _node(alert_id, "alert", "Log Volume Anomaly", "High fired rule volume", "medium", "High alert count or firedtimes observed; cause is not assumed.", evidence, "alert", "SIEM/volume cluster"))
    for event in facts.get("volumeEvents") or []:
        ev = _event_refs([event])
        source = event.get("hostname") or event.get("app") or event.get("sourceIp") or "log-source"
        source_id = _node_id("cloud", source)
        count = _to_int(event.get("firedCount"))
        volume_id = _node_id("volume", f"{event.get('ruleName') or 'firedtimes'}-{count}")
        _add_node(nodes, _node(source_id, "cloud", source, "Log source / SIEM component", "low", "Source associated with high-volume alert aggregation.", ev, "cloud", "SIEM/volume cluster"))
        _add_node(nodes, _node(volume_id, "volume", f"{count:,} firedtimes" if count else "High firedtimes", event.get("ruleName") or event.get("alertName") or "Fired rule count", "medium" if count < 50000 else "high", "High fired rule volume observed in evidence.", ev, "volume", "SIEM/volume cluster"))
        _add_edge(edges, source_id, alert_id, "generated", evidence=ev, confidence="high")
        _add_edge(edges, alert_id, volume_id, "high firedtimes", evidence=ev, confidence="high")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _build_generic_multi_cluster_graph(facts: dict[str, Any], investigationType: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    cluster_alerts: list[str] = []
    partials = []
    if facts.get("suspiciousPaths") or facts.get("exploitPayloads"):
        partials.append(_build_web_graph)
    if facts.get("sprayCandidates"):
        partials.append(_build_password_spray_graph)
    if facts.get("dnsEvents"):
        partials.append(_build_dns_graph)
    if facts.get("processEvents"):
        partials.append(_build_process_graph)
    if facts.get("sniffingEvents"):
        partials.append(_build_sniffing_graph)
    if facts.get("volumeEvents"):
        partials.append(_build_volume_graph)
    if facts.get("cloudEvents"):
        partials.append(_build_cloud_graph)
    for partial_builder in partials:
        partial = partial_builder(facts, investigationType)
        for node in partial.get("nodes") or []:
            _add_node(nodes, node)
            if node.get("type") == "alert":
                cluster_alerts.append(node["id"])
        for edge in partial.get("edges") or []:
            _add_edge(edges, edge.get("from"), edge.get("to"), edge.get("label") or "correlated with", evidence=edge.get("evidence") or [], confidence=edge.get("confidence") or "medium")
    unique_alerts = sorted(set(cluster_alerts))
    for left, right in zip(unique_alerts, unique_alerts[1:]):
        left_node = nodes.get(left, {})
        right_node = nodes.get(right, {})
        label = "possible volume driver" if "volume" in (right_node.get("label") or "").lower() or "volume" in (left_node.get("label") or "").lower() else "time-correlated"
        # Cross-cluster edges are intentionally cautious: same window is correlation, not causality.
        _add_edge(edges, left, right, label, evidence=sorted(set((left_node.get("evidence") or []) + (right_node.get("evidence") or []))), confidence="low")
    if not nodes:
        alert_id = _node_id("alert", "soc-investigation")
        evidence = _event_refs(facts.get("events") or [])
        _add_node(nodes, _node(alert_id, "alert", "SOC Investigation", "Evidence cluster", "medium", "Submitted logs did not match a specific deterministic template.", evidence, "alert", "Generic cluster"))
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _add_success_and_post_login(nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], facts: dict[str, Any]) -> None:
    success_by_email: dict[str, str] = {}
    for item in facts.get("successAfterSpray") or []:
        event = item["event"]
        evidence = _event_refs([event])
        email = item["email"]
        success_id = _node_id("success", f"{email}-login-success")
        success_by_email[email] = success_id
        _add_node(nodes, _node(success_id, "success", "Successful Login", email, "critical", f"{email} authenticated from the spray source after failed attempts.", evidence, "success", "Identity activity cluster"))
        _add_edge(edges, _node_id("user", email), success_id, "auth success", evidence=evidence, confidence="high")
    for idx, item in enumerate(facts.get("postLoginActions") or []):
        event = item["event"]
        email = item["email"]
        success_id = success_by_email.get(email)
        if not success_id:
            continue
        node = _post_action_node(event, email, idx)
        if node:
            _add_node(nodes, node)
            _add_edge(edges, success_id, node["id"], "post-login activity", evidence=node.get("evidence") or [], confidence="high")


def _post_action_node(event: dict[str, Any], email: str, idx: int) -> dict[str, Any] | None:
    evidence = _event_refs([event])
    if event.get("action") == "mfa_challenge_completed":
        return _node(_node_id("app", f"{email}-mfa"), "app", "MFA approved", event.get("mfaResult") or "MFA event", "high", f"MFA approval observed after suspicious authentication for {email}.", evidence, "post", "Identity activity cluster")
    if event.get("action") == "mailbox_rule_created":
        return _node(_node_id("mail", f"{email}-{event.get('ruleName') or 'mailbox-rule'}"), "mail", event.get("ruleName") or "Mailbox rule", event.get("app") or "Exchange Online", "high", f"Mailbox rule created after suspicious authentication for {email}.", evidence, "post", "Cloud activity cluster")
    if event.get("action") == "file_accessed":
        return _node(_node_id("file", f"{email}-{event.get('fileName') or event.get('app') or 'file'}"), "file", event.get("fileName") or "Cloud file access", event.get("app") or "Cloud app", "high", f"File access observed after suspicious authentication for {email}.", evidence, "post", "Cloud activity cluster")
    if event.get("action") == "cloud_app_access":
        return _node(_node_id("app", f"{email}-{event.get('app') or 'cloud'}"), "app", event.get("app") or "Cloud app", "Post-login cloud activity", "medium", f"Cloud app activity observed after suspicious authentication for {email}.", evidence, "post", "Cloud activity cluster")
    return None


def _add_volume_correlation(nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], facts: dict[str, Any], campaign_id: str) -> None:
    for event in facts.get("volumeEvents") or []:
        evidence = _event_refs([event])
        volume_id = _node_id("volume", f"{event.get('ruleName') or 'firedtimes'}-{event.get('firedCount') or ''}")
        _add_node(nodes, _node(volume_id, "volume", f"{_to_int(event.get('firedCount')):,} firedtimes" if event.get("firedCount") else "High firedtimes", event.get("ruleName") or "Alert volume", "medium", "High alert volume is time-correlated; it is not direct proof of successful exploitation.", evidence, "volume", "SIEM/volume cluster"))
        _add_edge(edges, campaign_id, volume_id, "possible volume driver", evidence=evidence, confidence="low")


def _node(node_id: str, node_type: str, label: str, subtitle: str, severity: str, details: str, evidence: list[str], role: str, cluster: str | None = None) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type,
        "label": str(label or node_type),
        "subtitle": str(subtitle or node_type),
        "severity": severity if severity in SUPPORTED_SEVERITIES else "low",
        "x": 0,
        "y": 0,
        "details": details,
        "evidence": sorted(set(evidence)),
        "rawRefs": sorted(set(evidence)),
        "_role": role,
        "cluster": cluster,
    }


def _add_node(nodes: dict[str, dict[str, Any]], node: dict[str, Any]) -> None:
    if not node.get("id"):
        return
    existing = nodes.get(node["id"])
    if not existing:
        node["evidence"] = sorted(set(node.get("evidence") or []))
        node["rawRefs"] = sorted(set(node.get("rawRefs") or node.get("evidence") or []))
        nodes[node["id"]] = node
        return
    existing["severity"] = _max_severity(existing.get("severity"), node.get("severity"))
    existing["evidence"] = sorted(set(existing.get("evidence") or []) | set(node.get("evidence") or []))
    existing["rawRefs"] = sorted(set(existing.get("rawRefs") or []) | set(node.get("rawRefs") or []))
    existing["details"] = existing.get("details") or node.get("details")
    existing["cluster"] = existing.get("cluster") or node.get("cluster")


def _add_edge(edges: dict[tuple[str, str, str], dict[str, Any]], source: str | None, target: str | None, label: str | None, *, evidence: list[str], confidence: str = "medium") -> None:
    if not source or not target or not label or not evidence:
        return
    key = (source, target, label)
    if key in edges:
        edges[key]["evidence"] = sorted(set(edges[key].get("evidence") or []) | set(evidence))
        edges[key]["rawRefs"] = edges[key]["evidence"]
        return
    edges[key] = {"from": source, "to": target, "label": label, "evidence": sorted(set(evidence)), "rawRefs": sorted(set(evidence)), "confidence": confidence}


def _layout_by_roles(nodes: list[dict[str, Any]], anchors: dict[str, tuple[int, int]]) -> None:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in sorted(nodes, key=lambda item: (item.get("_role") or item.get("type") or "", item.get("id") or "")):
        grouped[node.get("_role") or node.get("type") or "context"].append(node)
    for role, group in grouped.items():
        x, y = anchors.get(role) or anchors.get(group[0].get("type") or "") or anchors.get("context") or (420, 760)
        for idx, node in enumerate(group):
            node["x"] = x + (idx % 3) * 240
            node["y"] = y + (idx // 3) * 125


def _layout_clusters(nodes: list[dict[str, Any]]) -> None:
    cluster_positions = {
        "Web activity cluster": (70, 90),
        "Identity activity cluster": (70, 520),
        "Endpoint activity cluster": (680, 90),
        "DNS/network cluster": (680, 520),
        "Cloud activity cluster": (1160, 90),
        "SIEM/volume cluster": (1160, 520),
        "Generic cluster": (420, 360),
    }
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in sorted(nodes, key=lambda item: (item.get("cluster") or "", item.get("type") or "", item.get("id") or "")):
        grouped[node.get("cluster") or "Generic cluster"].append(node)
    for cluster, group in grouped.items():
        base_x, base_y = cluster_positions.get(cluster, (420, 360))
        for idx, node in enumerate(group):
            node["x"] = base_x + (idx % 2) * 230
            node["y"] = base_y + (idx // 2) * 118


def _extract_account_lifecycle_facts(events: list[dict[str, Any]]) -> dict[str, Any]:
    deleted_accounts: set[str] = set()
    created_account = ""
    actor = ""
    domain_controller = ""
    expiration_date = ""
    deletion_window = ""
    creation_timing = ""
    enabled = False
    provider = ""
    outcome = ""
    evidence_events: list[dict[str, Any]] = []

    for event in events:
        raw = str(event.get("raw") or "")
        lower = raw.lower()
        action = str(event.get("action") or "").lower()
        lifecycle_hit = action in {"account_deleted", "account_created", "account_expiration_set", "account_enabled"} or any(term in lower for term in ACCOUNT_LIFECYCLE_TERMS)
        if not lifecycle_hit:
            continue
        evidence_events.append(event)
        for account in _accounts_deleted_from_text(raw):
            deleted_accounts.add(account)
        if action == "account_deleted":
            account = event.get("targetUser") or event.get("account") or event.get("email") or event.get("user")
            if account:
                deleted_accounts.add(str(account))
        if not created_account:
            created_account = _clean_account_token(
                _regex_value(raw, r"\bnew\s+account\s+([A-Za-z0-9_.@$\\-]+)\s+was\s+created\b")
                or _regex_value(raw, r"\baccount\s+([A-Za-z0-9_.@$\\-]+)\s+(?:was\s+)?created\b")
                or (str(event.get("targetUser") or event.get("account") or "") if action == "account_created" else "")
            )
        if not actor:
            actor = (
                _regex_value(raw, r"\binitiated\s+by\s+([A-Za-z0-9_.@$\\-]+)\b")
                or _regex_value(raw, r"\bcreated\s+by\s+(?:the\s+same\s+)?([A-Za-z0-9_.@$\\-]+)\b")
                or _regex_value(raw, r"\bperformed\s+by\s+([A-Za-z0-9_.@$\\-]+)\b")
                or str(event.get("user") or "")
            )
        if not domain_controller:
            domain_controller = (
                _regex_value(raw, r"\bdomain\s+controller\s+([A-Za-z0-9_.-]+)\b")
                or _regex_value(raw, r"\bon\s+domain\s+controller\s+([A-Za-z0-9_.-]+)\b")
                or str(event.get("hostname") or "")
            )
        if not expiration_date:
            expiration_date = _regex_value(raw, r"\bexpiration\s+date\s+of\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})\b") or (raw if action == "account_expiration_set" else "")
        if not deletion_window:
            start_time = _regex_value(raw, r"\b(\d{2}:\d{2}:\d{2})\s*[–-]\s*\d{2}:\d{2}:\d{2}\s*UTC\b")
            end_time = _regex_value(raw, r"\b\d{2}:\d{2}:\d{2}\s*[–-]\s*(\d{2}:\d{2}:\d{2})\s*UTC\b")
            if start_time and end_time:
                deletion_window = f"{start_time}-{end_time} UTC"
        if not creation_timing and re.search(r"\b(?:approximately\s+)?13\s+minutes\s+later\b", raw, flags=re.IGNORECASE):
            creation_timing = "Approximately 13 minutes later"
        enabled = enabled or action == "account_enabled" or "enabled for use" in lower or "account enabled" in lower
        provider = provider or ("Windows Security-Auditing" if "windows security-auditing" in lower else "")
        outcome = outcome or ("AUDIT_SUCCESS" if "audit_success" in lower else "")

    if not (deleted_accounts or created_account):
        return {}
    return {
        "deletedAccounts": sorted(deleted_accounts),
        "createdAccount": created_account,
        "actor": actor,
        "domainController": domain_controller,
        "expirationDate": expiration_date,
        "enabled": enabled,
        "provider": provider,
        "outcome": outcome,
        "deletionWindow": deletion_window,
        "creationTiming": creation_timing,
        "evidence": _event_refs(evidence_events),
    }


def _accounts_deleted_from_text(text: str) -> list[str]:
    accounts: list[str] = []
    for match in re.finditer(r"\b(?:user\s+)?accounts?\s*\(([^)]+)\)\s+were\s+deleted\b", text or "", flags=re.IGNORECASE):
        accounts.extend(_split_account_list(match.group(1)))
    single = _clean_account_token(_regex_value(text, r"\baccount\s+([A-Za-z0-9_.@$\\-]+)\s+(?:was\s+)?deleted\b"))
    if single:
        accounts.append(single)
    return sorted(set(account for account in accounts if account))


def _split_account_list(value: str) -> list[str]:
    return [account for item in re.split(r"\s*,\s*|\s+and\s+", value or "") if (account := _clean_account_token(item))]


def _clean_account_token(value: Any) -> str:
    token = str(value or "").strip().strip("`'\".,:;()[]{}")
    lower = token.lower()
    if not token or lower in ACCOUNT_TOKEN_STOPWORDS:
        return ""
    if len(token) < 3:
        return ""
    # Account names in these interpretations should contain an identifier-like
    # signal: a digit, separator, domain marker, machine suffix, or email form.
    # This prevents grammar words such as "was" from becoming user nodes.
    if not re.search(r"[\d@._$\\-]", token):
        return ""
    return token


def _has_account_lifecycle(facts: dict[str, Any]) -> bool:
    lifecycle = facts.get("accountLifecycle") or {}
    return bool(lifecycle.get("deletedAccounts") or lifecycle.get("createdAccount"))


def _extract_development_tool_false_positive_facts(events: list[dict[str, Any]]) -> dict[str, Any]:
    evidence_events: list[dict[str, Any]] = []
    endpoint = ""
    process = ""
    file_path = ""
    file_name = ""
    command_line = ""
    sha1 = ""
    mitre = ""
    for event in events:
        raw = str(event.get("raw") or "")
        lower = raw.lower()
        has_dev_context = any(term in lower for term in DEV_TOOL_TERMS)
        has_benign_context = any(term in lower for term in FALSE_POSITIVE_TERMS)
        has_file_context = bool(event.get("filePath") or event.get("fileName") or ".dll" in lower or SHA1_RE.search(raw))
        if not (has_dev_context and (has_benign_context or has_file_context)):
            continue
        evidence_events.append(event)
        endpoint = endpoint or event.get("hostname") or _regex_value(raw, r"\bendpoint\s+([A-Za-z0-9_.-]+)\b")
        process = process or event.get("processName") or _regex_value(raw, r"\b(?:process|extension process)\s*\(?`?([A-Za-z0-9_.@\\/$ -]*ms-dotnettools\.csharp[A-Za-z0-9_.@\\/$ -]*)`?\)?")
        file_path = file_path or event.get("filePath") or _extract_windows_path(raw)
        file_name = file_name or event.get("fileName") or _file_label(file_path)
        command_line = command_line or event.get("commandLine") or _sentence_with(raw, ("extension paths", "language server", "configuration parameters", "command line"))
        sha1 = sha1 or _first_regex(SHA1_RE, raw)
        mitre = mitre or event.get("mitreTechnique") or _regex_value(raw, r"\bMITRE\s+(T\d{4}(?:\.\d{3})?)\b")
    if not evidence_events:
        return {}
    return {
        "endpoint": endpoint,
        "process": process or "VS Code C# extension",
        "filePath": file_path,
        "fileName": file_name,
        "commandLine": command_line,
        "sha1": sha1,
        "mitre": mitre,
        "evidence": _event_refs(evidence_events),
    }


def _has_development_tool_false_positive(facts: dict[str, Any]) -> bool:
    fp = facts.get("developmentToolFalsePositive") or {}
    return bool(fp.get("evidence"))


def _normalize_one_event(raw: Any, index: int) -> dict[str, Any]:
    raw_ref = f"event-{index + 1}"
    data: dict[str, Any] = {}
    text = ""
    if isinstance(raw, dict) and ("raw_text" in raw or "sanitized_text" in raw):
        raw_ref = str(raw.get("rawRef") or raw_ref)
        token_map = raw.get("token_map") if isinstance(raw.get("token_map"), dict) else {}
        text = _restore_tokens_in_text(str(raw.get("raw_text") or raw.get("sanitized_text") or ""), token_map)
        data = _flatten_dict(_extract_json_payload(text) or {})
    elif isinstance(raw, dict):
        raw_ref = str(raw.get("id") or raw.get("rawRef") or raw_ref)
        data = _flatten_dict(raw)
        text = json.dumps(raw, default=str)
    else:
        text = str(raw or "")
        data = _flatten_dict(_extract_json_payload(text) or {})
    lower_text = text.lower()

    timestamp = _first_value_by_keys(data, ("@timestamp", "timestamp", "event_time", "createddatetime", "creationtime", "time"))
    action = _normalize_action(_first_value_by_keys(data, ("event_action", "action", "operation", "alert_name", "rule.description")), lower_text, data)
    event_type = _normalize_event_type(_first_value_by_keys(data, ("event_type", "eventtype", "type", "recordtype")), action, lower_text)
    outcome = _normalize_outcome(_first_value_by_keys(data, ("event_outcome", "outcome", "status", "resultstatus")), lower_text, data)
    source_ip = _first_value_by_keys(data, ("source_ip", "src_ip", "client_ip", "sourceip", "clientip", "ipaddress", "actoripaddress", "src"))
    destination_ip = _first_value_by_keys(data, ("destination_ip", "dest_ip", "destinationip", "dst"))
    endpoint_ip = _first_value_by_keys(data, ("endpoint_ip", "endpointip", "host_ip"))
    email = _first_value_by_keys(data, ("email_address", "email", "userprincipalname", "userid", "username", "target_user", "targetuser", "account"))
    user = _first_value_by_keys(data, ("user", "data.win.eventdata.user"))
    hostname = _first_value_by_keys(data, ("hostname", "host.name", "endpoint.name", "device_name", "devicename", "agent.name", "host"))
    request_uri = _first_value_by_keys(data, ("request_uri", "requesturi", "url_path", "url.path", "uri", "path"))
    domain = _first_value_by_keys(data, ("domain", "query", "dns.question.name", "dns_question_name"))
    command_line = _first_value_by_keys(data, ("process.command_line", "command_line", "commandline", "data.win.eventdata.commandline"))
    process_name = _process_name(_first_value_by_keys(data, ("process_name", "process.name", "processname", "data.win.eventdata.originalfilename", "originalfilename", "image", "process_image", "data.win.eventdata.image")))
    parent_process = _process_name(_first_value_by_keys(data, ("parent_process_name", "parent.process.name", "parentprocessname", "parentimage", "data.win.eventdata.parentimage")))
    fired_count = _max_int(
        _first_value_by_keys(data, ("firedtimes", "fired_count", "alert_count", "firedtimes")),
        _regex_value(text, r"\bfiredtimes\s*(?:=|:|ranging from\s+\d+\s+to)?\s*([0-9,]+)"),
        _regex_value(text, r"\balert_count\s*(?:=|:)?\s*([0-9,]+)"),
        _regex_value(text, r"\bfired\s+([0-9,]+)\+?\s+times\b"),
    )

    if not email:
        email = _first_regex(EMAIL_RE, text)
    source_ips = sorted({ip for ip in IP_RE.findall(text or "") if _valid_source_ip(ip)})
    if not source_ip:
        source_ip = source_ips[0] if source_ips else (_first_regex(IPV6_RE, text))
    if not hostname:
        hostname = (
            _regex_value(text, r"agent=\{[^}]*\bname=([^,}]+)")
            or _regex_value(text, r"\bhost(?:name)?[=:]\s*([A-Za-z0-9_.-]+)")
            or _regex_value(text, r"\bdevice\s*\(([A-Za-z0-9_.-]+)\)")
            or _regex_value(text, r"\bWindows\s+\d+\s+device\s*\(([A-Za-z0-9_.-]+)\)")
            or _regex_value(text, r"\bon\s+([A-Za-z0-9_.-]+)\s+with\b")
            or _regex_value(text, r"\b([A-Za-z0-9_.-]+)\s+kernel log\b")
            or _regex_value(text, r"\bfrom\s+([A-Za-z0-9_.-]+)\s+with\s+firedtimes\b")
            or _regex_value(text, r"\bfired\s+[0-9,]+\+?\s+times\s+on\s+([A-Za-z0-9_.-]+)\b")
        )
    if not domain and event_type == "dns":
        domain = _first_domain(text)
    paths = _extract_paths(str(request_uri or "") + " " + text)
    payload_domains = _payload_domains(text)
    exploit_payload = _extract_exploit_payload(text)
    network_interface = _first_value_by_keys(data, ("interface", "network_interface", "ifname", "device")) or _regex_value(text, r"\b(ens\d+|eth\d+|enp\d+s\d+|wlan\d+)\b")
    windows_path = _extract_windows_path(text)

    return {
        "timestamp": str(timestamp or ""),
        "eventType": event_type,
        "action": action,
        "outcome": outcome,
        "sourceIp": str(source_ip or ""),
        "sourceIps": source_ips or ([str(source_ip)] if source_ip else []),
        "destinationIp": str(destination_ip or ""),
        "clientIp": str(_first_value_by_keys(data, ("client_ip", "clientip")) or ""),
        "sourceCountry": str(_first_value_by_keys(data, ("source_country", "sourcecountry", "location.countryorregion")) or ""),
        "sourceAsn": str(_first_value_by_keys(data, ("source_asn", "sourceasn", "asn")) or ""),
        "sourceProvider": str(_first_value_by_keys(data, ("source_provider", "sourceprovider", "provider", "asn_org")) or ""),
        "email": str(email or ""),
        "user": str(user or ""),
        "targetUser": str(_first_value_by_keys(data, ("target_user", "targetuser")) or ""),
        "account": str(_first_value_by_keys(data, ("account",)) or ""),
        "hostname": str(hostname or ""),
        "deviceName": str(_first_value_by_keys(data, ("device_name", "devicename")) or ""),
        "endpointName": str(_first_value_by_keys(data, ("endpoint.name", "endpoint_name")) or ""),
        "endpointIp": str(endpoint_ip or ""),
        "networkInterface": str(network_interface or ""),
        "app": str(_first_value_by_keys(data, ("app", "appdisplayname", "destination_app", "destinationapp", "cloud_app", "cloudapp", "destinationservicename", "client_name")) or _cloud_app_from_text(text) or ""),
        "alertName": str(_first_value_by_keys(data, ("alert_name", "alertname", "rule_name", "rule.description", "detection_name")) or ("passwordSpray" if "passwordspray" in lower_text or "password spray" in lower_text else "")),
        "ruleName": str(_first_value_by_keys(data, ("rule_name", "rulename", "rule.description")) or ""),
        "detectionName": str(_first_value_by_keys(data, ("detection_name", "detectionname")) or ""),
        "fileName": str(_first_value_by_keys(data, ("file_name", "filename", "objectid")) or _file_label(windows_path) or ""),
        "filePath": str(_first_value_by_keys(data, ("file_path", "filepath", "file.path")) or windows_path or ""),
        "urlPath": str(_first_value_by_keys(data, ("url_path", "url.path")) or ""),
        "requestUri": str(request_uri or ""),
        "domain": str(domain or _first_domain(" ".join(payload_domains)) or ""),
        "paths": paths,
        "payloadDomains": payload_domains,
        "exploitPayload": exploit_payload,
        "mfaResult": str(_first_value_by_keys(data, ("mfa_result", "mfaresult", "status.additionaldetails")) or ""),
        "processName": process_name,
        "processImage": str(_first_value_by_keys(data, ("process_image", "processimage", "data.win.eventdata.image", "image")) or ""),
        "parentProcessName": parent_process,
        "parentProcessImage": str(_first_value_by_keys(data, ("parent_process_image", "parentprocessimage", "data.win.eventdata.parentimage", "parentimage")) or ""),
        "commandLine": str(command_line or _regex_value(text, r"CommandLine:\s*(.+?)(?:\s+CurrentDirectory:|\s+User:|$)") or ""),
        "parentCommandLine": str(_first_value_by_keys(data, ("parent_command_line", "parentcommandline", "data.win.eventdata.parentcommandline")) or ""),
        "mitreTechnique": str(_first_value_by_keys(data, ("mitre_technique", "mitre.technique", "technique")) or ("T1040" if "t1040" in lower_text else "")),
        "failedLoginCount": _to_int(_first_value_by_keys(data, ("failed_login_count", "failedlogincount"))),
        "distinctEmailCount": _to_int(_first_value_by_keys(data, ("distinct_email_count", "distinctemailcount"))),
        "firedCount": fired_count,
        "targetedAccounts": _targeted_accounts(data, text),
        "rawRef": raw_ref,
        "raw": text[:1600],
    }


def _normalize_action(value: Any, lowered_text: str, data: dict[str, Any]) -> str:
    value_text = str(value or "").lower()
    outcome_text = str(_first_value_by_keys(data, ("event_outcome", "outcome", "status", "resultstatus")) or "").lower()
    error_code = str(_first_value_by_keys(data, ("status.errorcode", "errornumber", "errorcode")) or "")
    if "account" in lowered_text and any(term in lowered_text for term in ("were deleted", "was deleted", "account deleted", "user deleted")):
        return "account_deleted"
    if any(term in lowered_text for term in ("new account", "account was created", "account created")):
        return "account_created"
    if "account expiration" in lowered_text or "expiration date" in lowered_text:
        return "account_expiration_set"
    if "enabled for use" in lowered_text or "account enabled" in lowered_text:
        return "account_enabled"
    if "mailbox_rule" in value_text or "mailbox rule" in lowered_text or "forwarding" in lowered_text:
        return "mailbox_rule_created"
    if "file_access" in value_text or "file accessed" in lowered_text or "sharepoint" in lowered_text and "file" in lowered_text:
        return "file_accessed"
    if "dns_query" in value_text or "dns query" in lowered_text:
        return "dns_query"
    if "passwordspray" in value_text or "password spray" in lowered_text:
        return "password_spray_alert"
    if any(term in lowered_text for term in ("successful oauth", "oauth2 login", "authenticated to office 365", "result status \"success\"", "status success")):
        return "login_success"
    if ("login_success" in value_text or value_text in {"log in", "login", "signin"} and outcome_text == "success" or outcome_text in {"success", "succeeded"} or error_code == "0") and "failed" not in lowered_text:
        return "login_success"
    if "userloginfailed" in value_text or "login_failed" in value_text or "failed" in lowered_text and "login" in lowered_text or error_code not in {"", "0"}:
        return "login_failed"
    if "mfa" in lowered_text and any(term in lowered_text for term in ("approved", "success", "completed")):
        return "mfa_challenge_completed"
    if any(term in lowered_text for term in CLOUD_TERMS) or "cloud" in lowered_text and any(term in lowered_text for term in ("sharepoint", "onedrive", "exchange", "app")):
        return "cloud_app_access"
    return value_text.replace(" ", "_") if value_text else ""


def _normalize_event_type(value: Any, action: str, lowered_text: str) -> str:
    value_text = str(value or "").lower()
    if action in {"account_deleted", "account_created", "account_expiration_set", "account_enabled"} or any(term in lowered_text for term in ACCOUNT_LIFECYCLE_TERMS):
        return "identity"
    if action == "password_spray_alert" or "security-alert" in value_text or "alert" in value_text:
        return "security-alert"
    if action in {"login_failed", "login_success"} or "authentication" in value_text or "sign-in" in lowered_text:
        return "authentication"
    if action in {"mailbox_rule_created", "file_accessed", "mfa_challenge_completed", "cloud_app_access"} or any(term in lowered_text for term in CLOUD_TERMS + ("exchange online",)):
        return "cloud-app"
    if action == "dns_query" or "dns" in value_text or "dns" in lowered_text:
        return "dns"
    if any(term in lowered_text for term in ("http", "request_uri", "/.env", "/server-status", "cgi-bin/luci")):
        return "web"
    if "process" in value_text or "sysmon" in lowered_text or "commandline" in lowered_text:
        return "process"
    return value_text or "event"


def _normalize_outcome(value: Any, lowered_text: str, data: dict[str, Any]) -> str:
    value_text = str(value or "").lower()
    error_code = str(_first_value_by_keys(data, ("status.errorcode", "errornumber", "errorcode")) or "")
    if "blocked" in value_text or "blocked" in lowered_text:
        return "blocked"
    if value_text in {"success", "succeeded"} or error_code == "0":
        return "success"
    if "fail" in value_text or error_code not in {"", "0"}:
        return "failure"
    return value_text


def _assistant_session_events(assistant_session: AssistantSession) -> list[Any]:
    return [{
        "raw_text": entry.raw_text or "",
        "sanitized_text": entry.sanitized_text or "",
        "token_map": entry.token_map_json or {},
        "rawRef": entry.entry_label or f"entry-{entry.entry_index + 1}",
    } for entry in sorted(assistant_session.entries, key=lambda item: item.entry_index)]


def _expand_raw_events(raw_events: list[Any]) -> list[Any]:
    expanded: list[Any] = []
    for item in raw_events or []:
        if isinstance(item, dict) and ("raw_text" in item or "sanitized_text" in item):
            raw_ref = str(item.get("rawRef") or f"entry-{len(expanded) + 1}")
            token_map = item.get("token_map") if isinstance(item.get("token_map"), dict) else {}
            text = _restore_tokens_in_text(str(item.get("raw_text") or item.get("sanitized_text") or ""), token_map)
            parsed = _try_json(text)
            if isinstance(parsed, list):
                for idx, event in enumerate(parsed):
                    expanded.append({**event, "rawRef": f"{raw_ref}:{idx + 1}"} if isinstance(event, dict) else {"raw_text": str(event), "rawRef": f"{raw_ref}:{idx + 1}"})
            elif isinstance(parsed, dict) and isinstance(parsed.get("rawLogs"), list):
                for idx, raw_log in enumerate(parsed["rawLogs"]):
                    expanded.append({"raw_text": raw_log, "token_map": token_map, "rawRef": f"{raw_ref}:{idx + 1}"})
            else:
                expanded.extend(_split_text_events(text, raw_ref, token_map))
        elif isinstance(item, dict) and isinstance(item.get("rawLogs"), list):
            expanded.extend(item["rawLogs"])
        elif isinstance(item, str):
            parsed = _try_json(item)
            if isinstance(parsed, list):
                expanded.extend(parsed)
            elif isinstance(parsed, dict) and isinstance(parsed.get("rawLogs"), list):
                expanded.extend(parsed["rawLogs"])
            else:
                expanded.extend(_split_text_events(item, f"entry-{len(expanded) + 1}", {}))
        else:
            expanded.append(item)
    return expanded


def _split_text_events(text: str, raw_ref: str, token_map: dict[str, Any]) -> list[dict[str, Any]]:
    lines = [line.strip(" -\t") for line in str(text or "").splitlines() if line.strip(" -\t")]
    if len(lines) <= 1:
        return [{"raw_text": text, "token_map": token_map, "rawRef": raw_ref}]
    return [{"raw_text": line, "token_map": token_map, "rawRef": f"{raw_ref}:{idx + 1}"} for idx, line in enumerate(lines)]


def _extract_paths(text: str) -> list[str]:
    paths = set()
    for url in URL_RE.findall(text or ""):
        match = re.search(r"https?://[^/]+([^?\s\"']*)", url, flags=re.IGNORECASE)
        if match and match.group(1):
            paths.add(match.group(1))
    for path in PATH_RE.findall(text or ""):
        cleaned = path.rstrip(".,)")
        if len(cleaned) > 1 and not re.match(r"/\d+$", cleaned):
            paths.add(cleaned)
    return sorted(paths)


def _extract_windows_path(text: str) -> str:
    match = re.search(r"[A-Za-z]:\\[^\n`\"']+", text or "")
    if not match:
        return ""
    return match.group(0).strip().rstrip(").,")


def _file_label(path: Any) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    return re.split(r"[\\/]", text)[-1] or text


def _sentence_with(text: str, terms: tuple[str, ...]) -> str:
    for sentence in re.split(r"(?<=[.!?])\s+", str(text or "").replace("\n", " ")):
        lower = sentence.lower()
        if any(term in lower for term in terms):
            return sentence.strip()
    return ""


def _payload_domains(text: str) -> list[str]:
    ignored = {"env.bak", "config.php.bak", "a.sh"}
    domains = {domain.lower() for domain in DOMAIN_RE.findall(text or "")}
    return sorted(domain for domain in domains if domain not in ignored and not domain.endswith(("company.com", "microsoft.com")))


def _valid_source_ip(value: str) -> bool:
    if not value or value in {"0.0.0.0", "255.255.255.255"}:
        return False
    if value.startswith("127."):
        return False
    return True


def _extract_exploit_payload(text: str) -> str:
    lower = (text or "").lower()
    if _negates_exploit_context(lower):
        return ""
    if not any(term in lower for term in EXPLOIT_TERMS):
        return ""
    snippet = text.strip().replace("\n", " ")
    if "cgi-bin/luci" in lower:
        idx = lower.find("cgi-bin/luci")
        return snippet[max(0, idx - 30): idx + 180]
    for term in ("wget", "curl", "|sh", ";"):
        idx = lower.find(term)
        if idx >= 0:
            return snippet[max(0, idx - 50): idx + 160]
    return snippet[:180]


def _flatten_dict(value: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out[path.lower()] = item
            out[str(key).lower()] = item
            out.update(_flatten_dict(item, path))
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            out.update(_flatten_dict(item, f"{prefix}.{idx}" if prefix else str(idx)))
    return out


def _first_value_by_keys(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    lowered = {key.lower(): value for key, value in data.items()}
    for key in keys:
        key_lower = key.lower()
        if lowered.get(key_lower) not in (None, "", []):
            return lowered[key_lower]
        for data_key, value in lowered.items():
            if data_key.endswith("." + key_lower) and value not in (None, "", []):
                return value
    return None


def _targeted_accounts(data: dict[str, Any], text: str) -> list[str]:
    accounts: set[str] = set()
    value = _first_value_by_keys(data, ("targeted_accounts", "targetedaccounts"))
    if isinstance(value, list):
        accounts.update(str(item).strip().lower() for item in value if str(item).strip())
    accounts.update(match.group(0).lower() for match in EMAIL_RE.finditer(text or ""))
    return sorted(accounts)


def _extract_json_payload(text: str) -> Any:
    parsed = _try_json(text)
    if parsed is not None:
        return parsed
    for match in re.finditer(r"[\[{]", text or ""):
        parsed = _try_json(text[match.start():])
        if parsed is not None:
            return parsed
    return None


def _try_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _restore_tokens_in_text(text: str, token_map: dict[str, Any]) -> str:
    restored = text
    for token, value in sorted(token_map.items(), key=lambda item: len(str(item[0])), reverse=True):
        restored = restored.replace(str(token), str(value))
    return restored


def _has_meaningful_event_fields(event: dict[str, Any]) -> bool:
    return any(event.get(key) for key in ("eventType", "action", "sourceIp", "email", "alertName", "domain", "hostname", "processName", "paths", "firedCount", "mitreTechnique", "filePath", "fileName"))


def _node_id(prefix: str, value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(value or prefix).lower()).strip("-")
    return f"{prefix}-{cleaned or prefix}"


def _node_has_required_fields(node: dict[str, Any]) -> bool:
    return bool(node.get("id") and node.get("type") in SUPPORTED_NODE_TYPES and node.get("label") and node.get("severity") in SUPPORTED_SEVERITIES and isinstance(node.get("x"), int) and isinstance(node.get("y"), int) and node.get("details") is not None)


def _event_refs(events: list[dict[str, Any]]) -> list[str]:
    return sorted({str(event.get("rawRef") or "") for event in events if event.get("rawRef")})


def _dedupe_post_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    keep: list[dict[str, Any]] = []
    for item in actions:
        event = item["event"]
        key = (item.get("email") or "", event.get("action") or "", event.get("rawRef") or "")
        if key not in seen:
            seen.add(key)
            keep.append(item)
    return keep


def _event_text(event: dict[str, Any]) -> str:
    return " ".join(str(event.get(key) or "") for key in ("raw", "action", "alertName", "ruleName", "commandLine", "requestUri", "urlPath", "domain", "processName")).lower()


def _is_web_event(event: dict[str, Any]) -> bool:
    text = _event_text(event)
    if _negates_exploit_context(text):
        return event.get("eventType") == "web" or bool(event.get("paths")) and any(_is_suspicious_path(path) for path in event.get("paths") or [])
    return event.get("eventType") == "web" or bool(event.get("paths")) and any(_is_suspicious_path(path) for path in event.get("paths") or []) or any(term in text for term in EXPLOIT_TERMS)


def _negates_exploit_context(text: str) -> bool:
    lower = str(text or "").lower()
    return any(phrase in lower for phrase in (
        "no evidence of malicious command injection",
        "no evidence of command injection",
        "no malicious command injection",
        "rather than malicious",
        "false positive",
    ))


def _is_suspicious_path(path: str) -> bool:
    lower = (path or "").lower()
    return any(term in lower for term in SENSITIVE_PATH_TERMS)


def _event_has_phishing_or_block(event: dict[str, Any]) -> bool:
    text = _event_text(event)
    return event.get("outcome") == "blocked" or any(term in text for term in ("phishing", "malware", "blocked"))


def _payload_download_and_execute(payload: str) -> bool:
    lower = (payload or "").lower()
    return ("wget" in lower or "curl" in lower) and any(term in lower for term in ("|sh", " sh", "bash", "chmod", ";"))


def _has_cloud_takeover(facts: dict[str, Any]) -> bool:
    text = " ".join(_event_text(event) for event in facts.get("cloudEvents") or [])
    return _cloud_is_suspicious(facts)


def _cloud_is_suspicious(facts: dict[str, Any]) -> bool:
    text = " ".join(_event_text(event) for event in facts.get("cloudEvents") or [])
    if any(term in text for term in ("no malicious", "normal oauth", "normal business", "routine cloud", "all events show successful authentication")):
        return False
    return any(term in text for term in ("impossible travel", "mfa anomaly", "mailbox rule", "forwarding", "oauth grant", "suspicious login", "account takeover")) and bool(facts.get("cloudEvents"))


def _cloud_app_from_text(text: str) -> str:
    lowered = (text or "").lower()
    if "office 365" in lowered:
        return "Office 365"
    if "onedrive" in lowered:
        return "OneDrive"
    if "sharepoint" in lowered:
        return "SharePoint"
    if "azure ad" in lowered:
        return "Azure AD"
    return ""


def _cloud_apps(event: dict[str, Any]) -> list[str]:
    text = _event_text(event)
    apps = set()
    if event.get("app"):
        apps.add(event["app"])
    for label, term in (("Office 365", "office 365"), ("Azure AD", "azure ad"), ("OneDrive", "onedrive"), ("SharePoint", "sharepoint"), ("Edge", "edge browser")):
        if term in text:
            apps.add(label)
    return sorted(apps)


def _cloud_services(event: dict[str, Any]) -> list[str]:
    raw = event.get("raw") or ""
    services = set(re.findall(r"\b[A-Z0-9_.$-]+\$@?[A-Z0-9_.-]*\b", raw, flags=re.IGNORECASE))
    if "kerberos" in raw.lower():
        services.add("Kerberos service tickets")
    return sorted(service.strip("@") for service in services if service)


def _is_malware_chain_event(event: dict[str, Any]) -> bool:
    text = _event_text(event)
    return any(bin_name in text for bin_name in LOLBINS) and any(term in text for term in ("download", "http", "encodedcommand", "invoke-webrequest", "start-process"))


def _process_severity(name: str, event: dict[str, Any]) -> str:
    text = f"{name} {_event_text(event)}"
    if any(term in text for term in LOLBINS) or _is_malware_chain_event(event):
        return "high"
    if any(term in text for term in RECON_COMMANDS):
        return "medium"
    return "medium"


def _command_severity(command: str) -> str:
    lower = (command or "").lower()
    if any(term in lower for term in LOLBINS) or any(term in lower for term in ("encodedcommand", "downloadstring", "invoke-webrequest")):
        return "high"
    if any(term in lower for term in RECON_COMMANDS):
        return "medium"
    return "low"


def _command_label(command: str) -> str:
    for token in ("powershell", "cmd.exe", "wscript", "mshta", "rundll32", "regsvr32", "whoami", "ipconfig", "nltest"):
        if token in (command or "").lower():
            return token
    return "Command line"


def _risk_from_graph(graph: dict[str, Any]) -> str:
    severities = [node.get("severity") for node in graph.get("nodes") or []]
    if "critical" in severities:
        return "Critical"
    if "high" in severities:
        return "High"
    if "medium" in severities:
        return "Medium"
    return "Low"


def _score_from_graph(graph: dict[str, Any], facts: dict[str, Any]) -> int:
    score = 20
    for node in graph.get("nodes") or []:
        score += {"critical": 18, "high": 10, "medium": 4, "low": 1}.get(node.get("severity"), 0)
    if facts.get("compromisedAccounts"):
        score += 10
    return min(100, score)


def _confidence_from_facts(facts: dict[str, Any], investigationType: str) -> str:
    if facts.get("events") and any((event.get("rawRef") or "").startswith("event-") is False for event in facts.get("events") or []):
        return "High"
    return "Medium"


def _deterministic_interpretation(facts: dict[str, Any], investigationType: str) -> str:
    return f"Deterministic graph generated from normalized evidence as {investigationType.replace('_', ' ')}. Relationships are evidence-backed; correlated clusters use cautious labels and do not imply compromise."


def _public_fact_summary(facts: dict[str, Any]) -> dict[str, Any]:
    return {
        "passwordSpraySources": [item["sourceIp"] for item in facts.get("sprayCandidates") or []],
        "compromisedAccounts": facts.get("compromisedAccounts") or [],
        "sourceIps": facts.get("sourceIps") or [],
        "suspiciousPaths": [item["path"] for item in facts.get("suspiciousPaths") or []],
        "volumeEvents": len(facts.get("volumeEvents") or []),
        "developmentToolFalsePositive": {
            "endpoint": (facts.get("developmentToolFalsePositive") or {}).get("endpoint") or "",
            "fileName": (facts.get("developmentToolFalsePositive") or {}).get("fileName") or "",
            "sha1": (facts.get("developmentToolFalsePositive") or {}).get("sha1") or "",
        },
        "accountLifecycle": {
            "actor": (facts.get("accountLifecycle") or {}).get("actor") or "",
            "deletedAccounts": (facts.get("accountLifecycle") or {}).get("deletedAccounts") or [],
            "createdAccount": (facts.get("accountLifecycle") or {}).get("createdAccount") or "",
        },
    }


def _incident_title(investigationType: str) -> str:
    return investigationType.replace("_", " ").title()


def _time_window(facts: dict[str, Any]) -> str:
    first = facts.get("firstSeen")
    last = facts.get("lastSeen")
    if first and last and first != last:
        return f"{first} - {last}"
    return first or last or "-"


def _cluster_for_node(node: dict[str, Any]) -> str:
    return node.get("cluster") or {
        "ip": "Web activity cluster",
        "user": "Identity activity cluster",
        "success": "Identity activity cluster",
        "endpoint": "Endpoint activity cluster",
        "process": "Endpoint activity cluster",
        "command": "Endpoint activity cluster",
        "domain": "DNS/network cluster",
        "network": "DNS/network cluster",
        "cloud": "Cloud activity cluster",
        "app": "Cloud activity cluster",
        "mail": "Cloud activity cluster",
        "volume": "SIEM/volume cluster",
    }.get(node.get("type"), "Generic cluster")


def _max_severity(left: str | None, right: str | None) -> str:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return left if rank.get(left or "", 0) >= rank.get(right or "", 0) else right or left or "low"


def _collect(target: set[str], *values: Any) -> None:
    for value in values:
        if isinstance(value, list):
            for item in value:
                if str(item or "").strip():
                    target.add(str(item).strip())
        elif str(value or "").strip():
            target.add(str(value).strip())


def _first_regex(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text or "")
    return match.group(0) if match else ""


def _first_domain(text: str) -> str:
    for match in DOMAIN_RE.finditer(text or ""):
        value = match.group(0).lower()
        if "@" not in value:
            return value
    return ""


def _regex_value(text: str, pattern: str) -> str:
    match = re.search(pattern, text or "", flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _process_name(value: Any) -> str:
    text = str(value or "").strip().strip('"').replace("\\\\", "\\")
    return re.split(r"[\\/]", text)[-1] if text else ""


def _short_host(value: Any) -> str:
    text = str(value or "").strip()
    return text.split(".")[0] if text else ""


def _first_value(values: list[Any]) -> Any:
    for value in values:
        if value:
            return value
    return None


def _max_int(*values: Any) -> int:
    ints = [_to_int(value) for value in values]
    return max(ints) if ints else 0


def _to_int(value: Any) -> int:
    try:
        return int(str(value or "0").replace(",", ""))
    except Exception:
        return 0


def _looks_like_password_spray(value: str) -> bool:
    return "passwordspray" in value.lower().replace(" ", "") or "password spray" in value.lower()


def _interpretation_text(markdown: str) -> str:
    text = markdown or ""
    text = re.split(r"\n\s*---\s*\n", text, maxsplit=1)[0]
    text = re.split(r"\n\s*##\s+Resolved Identifiers\b", text, maxsplit=1, flags=re.IGNORECASE)[0]
    return text.strip()
