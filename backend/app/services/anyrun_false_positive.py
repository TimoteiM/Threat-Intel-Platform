"""Narrow, evidence-combination false-positive handling for ANY.RUN detections."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


MSDW_SIGNATURE = "ET USER_AGENTS Microsoft Dr Watson User-Agent (MSDW)"
MSDW_USER_AGENT = "MSDW"
SVCHOST_PATH = r"C:\Windows\System32\svchost.exe"
MSDW_DISPOSITION = "Likely benign Windows diagnostic traffic"
MSDW_REASON = (
    "The MSDW User-Agent is associated with Microsoft Dr Watson / Windows diagnostic "
    "traffic and, by itself, is not sufficient evidence of malicious svchost.exe behavior."
)

_CORROBORATING_TERMS = (
    "process injection", "injected thread", "remote thread", "credential access",
    "credential dumping", "lsass dump", "mimikatz", "persistence", "runonce",
    "scheduled task", "startup folder", "encodedcommand", "frombase64string",
    "obfuscated command", "payload download", "downloaded payload", "command and control",
    "command-and-control", " c2 ", "beaconing", "malicious destination",
)
_COMMAND_TERMS = (
    " -enc", "-encodedcommand", "frombase64string", "downloadstring",
    "invoke-webrequest", " iwr ", "certutil", "bitsadmin", "mshta", "regsvr32",
    "rundll32", "powershell.exe -e", "base64",
)
_PAYLOAD_EXTENSIONS = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".msi", ".scr")


def apply_anyrun_msdw_false_positive_exclusion(result: dict[str, Any] | None) -> dict[str, Any]:
    """Return an annotated result with only qualified MSDW detections made non-actionable."""
    if not isinstance(result, dict):
        return result or {}
    out = deepcopy(result)
    raw = _dict(out.get("raw_summary"))
    if _list(raw.get("false_positive_exclusions")):
        return out
    details = _dict(raw.get("behavior_details"))
    process_details = [row for row in _list(details.get("process_details")) if isinstance(row, dict)]
    raw_processes = [row for row in _list(details.get("processes")) if isinstance(row, dict)]
    global_threats = [row for row in _list(details.get("network_threats")) if isinstance(row, dict)]
    global_http = [row for row in _list(details.get("http_requests")) if isinstance(row, dict)]
    exclusions: list[dict[str, Any]] = []

    for proc in process_details:
        if not _is_exact_svchost_path(proc) or not _has_valid_microsoft_signature(proc):
            continue
        proc_events = _dict(proc.get("events"))
        proc_threats = [row for row in _list(proc_events.get("network_threats")) if isinstance(row, dict)]
        related_http = [row for row in _list(proc_events.get("http_requests")) if isinstance(row, dict)]
        related_http.extend(row for row in global_http if _event_matches_process(row, proc))
        candidates = [row for row in proc_threats if _is_exact_msdw_signature(row) and _event_has_msdw_context(row, related_http)]
        if not candidates:
            candidates = [
                row for row in global_threats
                if _event_matches_process(row, proc)
                and _is_exact_msdw_signature(row)
                and _event_has_msdw_context(row, related_http)
            ]
        if not candidates:
            continue
        if _process_has_corroborating_behavior(proc, candidates, process_details):
            continue

        for event in candidates:
            _mark_event_informational(event)
        for event in global_threats:
            if _event_matches_process(event, proc) and _is_exact_msdw_signature(event) and _event_has_msdw_context(event, related_http):
                _mark_event_informational(event)
        for request in related_http:
            if _exact_user_agent(request) == MSDW_USER_AGENT and _event_only_has_msdw_detection(request):
                _mark_related_request_informational(request)

        original_level = proc.get("threat_level") or proc.get("threatLevel")
        original_score = proc.get("threat_score") or proc.get("threatScore")
        proc["original_threat_level"] = original_level
        proc["original_threat_score"] = original_score
        proc["threat_level"] = 0
        proc["threat_score"] = 0
        proc["classification"] = "informational"
        proc["verdict"] = "benign"
        proc["threat_name"] = _without_msdw_signature(proc.get("threat_name") or proc.get("threatName"))
        proc["false_positive_exclusion"] = _exclusion_metadata(proc)
        counts = _dict(proc.get("event_counts"))
        total_threats = int(counts.get("network_threats") or len(proc_threats))
        counts["network_threats_total"] = total_threats
        counts["network_threats_excluded"] = len(candidates)
        counts["network_threats"] = max(0, total_threats - len(candidates))
        proc["event_counts"] = counts

        for raw_proc in raw_processes:
            if _same_process(raw_proc, proc):
                _mark_raw_process_informational(raw_proc)

        for event in candidates:
            exclusions.append({
                **_exclusion_metadata(proc),
                "event_id": _first(event, "id", "uuid", "eventId"),
                "timestamp": _first(event, "date", "timestamp", "time"),
                "signature": MSDW_SIGNATURE,
                "user_agent": MSDW_USER_AGENT,
            })

    if not exclusions:
        return out

    details["process_details"] = process_details
    details["processes"] = raw_processes
    details["network_threats"] = global_threats
    details["http_requests"] = global_http
    raw["behavior_details"] = details
    counts = _dict(raw.get("behavior_counts"))
    original_count = int(counts.get("network_threats") or len(global_threats))
    excluded_count = len(exclusions)
    counts["network_threats_total"] = original_count
    counts["network_threats_excluded"] = excluded_count
    counts["network_threats"] = max(0, original_count - excluded_count)
    raw["behavior_counts"] = counts
    raw["false_positive_exclusions"] = exclusions
    raw["threatName"] = _without_msdw_signature(raw.get("threatName"))
    raw["tags"] = _without_msdw_signature(raw.get("tags"))
    raw["html_threat_labels"] = _without_msdw_signature(raw.get("html_threat_labels"))
    out["threat_names"] = _without_msdw_signature(out.get("threat_names"))
    out["false_positive_exclusions"] = exclusions

    if not _task_has_remaining_actionable_evidence(out):
        original_verdict = out.get("verdict")
        original_score = out.get("threat_score")
        out["provider_verdict"] = out.get("provider_verdict") or original_verdict
        out["verdict"] = "clean"
        out["threat_score"] = 0
        out["verdict_context"] = {
            **_dict(out.get("verdict_context")),
            "original_verdict": original_verdict,
            "original_threat_score": original_score,
            "effective_verdict": "clean",
            "msdw_false_positive_exclusion_applied": True,
            "excluded_from_final_risk": True,
            "reason": MSDW_REASON,
        }
        raw["original_verdict"] = original_verdict
        raw["original_threat_score"] = original_score
        raw["verdict"] = "clean"
        raw["threat_score"] = 0
        raw["anyrun_ai_summary"] = f"{MSDW_DISPOSITION}. {MSDW_REASON}"
    out["raw_summary"] = raw
    return out


def _is_exact_svchost_path(proc: dict[str, Any]) -> bool:
    path = str(_first(proc, "file_path", "filePath", "path", "imagePath", "fullPath") or "").strip()
    return path.casefold() == SVCHOST_PATH.casefold()


def _has_valid_microsoft_signature(proc: dict[str, Any]) -> bool:
    cert = _dict(proc.get("cert") or proc.get("certificate") or proc.get("digitalSignature") or proc.get("authenticode"))
    if not cert:
        return False
    valid_values = [cert.get(key) for key in ("valid", "verified", "trusted", "isValid", "isVerified", "signatureValid")]
    status = str(_first(cert, "status", "verificationStatus", "signatureStatus") or "").strip().lower()
    valid = any(value is True for value in valid_values) or status in {"valid", "verified", "trusted", "signed and verified"}
    identity = " ".join(str(value or "") for value in cert.values()).lower()
    return valid and "microsoft" in identity


def _process_has_corroborating_behavior(proc: dict[str, Any], candidates: list[dict[str, Any]], processes: list[dict[str, Any]]) -> bool:
    if proc.get("is_malconf") or proc.get("isMalconf"):
        return True
    other_names = _without_msdw_signature(proc.get("threat_name") or proc.get("threatName"))
    if other_names:
        return True
    command = str(proc.get("command_line") or proc.get("commandLine") or proc.get("cmd") or "").lower()
    if any(term in f" {command} " for term in _COMMAND_TERMS):
        return True
    events = _dict(proc.get("events"))
    for event in _list(events.get("network_threats")):
        if isinstance(event, dict) and event not in candidates and not event.get("excluded_from_final_risk"):
            return True
    for key in ("created_files", "dropped_files", "modified_files", "files"):
        for event in _list(events.get(key)):
            if isinstance(event, dict) and _row_has_malicious_verdict(event):
                return True
    for key in ("registry_changes", "modules", "debug", "synchronization"):
        for event in _list(events.get(key)):
            text = _flatten_text(event).lower()
            if any(term in f" {text} " for term in _CORROBORATING_TERMS):
                return True
    for event in _list(events.get("http_requests")) + _list(events.get("connections")):
        if not isinstance(event, dict):
            continue
        if _exact_user_agent(event) == MSDW_USER_AGENT and _event_only_has_msdw_detection(event):
            continue
        if _row_has_malicious_verdict(event):
            return True
        text = _flatten_text(event).lower()
        url = str(_first(event, "url", "requestUrl", "uri") or "").lower().split("?", 1)[0]
        if any(term in f" {text} " for term in ("payload download", "command and control", "command-and-control", "confirmed malicious")):
            return True
        if url.endswith(_PAYLOAD_EXTENSIONS) and any(word in text for word in ("download", "attachment", "payload")):
            return True
    pid = str(proc.get("pid") or "").strip()
    puid = str(proc.get("uuid") or "").strip()
    for child in processes:
        if child is proc:
            continue
        parent = str(child.get("ppid") or child.get("parentPid") or child.get("parent_ref") or "").strip()
        if parent and parent in {pid, puid} and _child_is_suspicious(child):
            return True
    return False


def _child_is_suspicious(child: dict[str, Any]) -> bool:
    if int(child.get("threat_level") or child.get("threatLevel") or 0) >= 1:
        return True
    if _list(child.get("threat_name") or child.get("threatName")):
        return True
    command = str(child.get("command_line") or child.get("commandLine") or child.get("cmd") or "").lower()
    return any(term in f" {command} " for term in _COMMAND_TERMS)


def _task_has_remaining_actionable_evidence(result: dict[str, Any]) -> bool:
    raw = _dict(result.get("raw_summary"))
    details = _dict(raw.get("behavior_details"))
    if _without_msdw_signature(raw.get("threatName") or result.get("threat_names")):
        return True
    suspicious_tag_terms = ("phish", "credential", "malware", "trojan", "steal", "c2", "exploit", "clickfix", "obfuscat")
    if any(any(term in str(tag).lower() for term in suspicious_tag_terms) for tag in _list(raw.get("tags"))):
        return True
    for event in _list(details.get("network_threats")):
        if isinstance(event, dict) and not event.get("excluded_from_final_risk"):
            return True
    for proc in _list(details.get("process_details")):
        if not isinstance(proc, dict) or proc.get("false_positive_exclusion"):
            continue
        if int(proc.get("threat_level") or 0) >= 1 or _without_msdw_signature(proc.get("threat_name")):
            return True
        if _child_is_suspicious(proc):
            return True
    for ioc in _list(raw.get("iocs")):
        if isinstance(ioc, dict) and _row_has_malicious_verdict(ioc):
            return True
    return False


def _event_has_msdw_context(event: dict[str, Any], related_http: list[dict[str, Any]]) -> bool:
    if _exact_user_agent(event) == MSDW_USER_AGENT:
        return True
    return any(_exact_user_agent(row) == MSDW_USER_AGENT for row in related_http)


def _exact_user_agent(row: dict[str, Any]) -> str:
    for key in ("userAgent", "user_agent", "httpUserAgent", "http_user_agent", "ua"):
        value = row.get(key)
        if isinstance(value, str):
            return value.strip()
    for container in ("http", "request", "headers"):
        nested = row.get(container)
        if isinstance(nested, dict):
            for key, value in nested.items():
                if str(key).lower().replace("-", "_") in {"user_agent", "useragent"} and isinstance(value, str):
                    return value.strip()
    return ""


def _is_exact_msdw_signature(row: dict[str, Any]) -> bool:
    values = [_first(row, "signature", "signatureName", "rule", "msg", "message", "name", "threatName", "title")]
    values.extend(_list(row.get("threatName") or row.get("threat_name")))
    return any(str(value or "").strip() == MSDW_SIGNATURE for value in values)


def _event_matches_process(event: dict[str, Any], proc: dict[str, Any]) -> bool:
    event_refs = {str(_first(event, "pid", "processId", "process_id") or "").strip(), str(_first(event, "process", "processUuid", "uuid", "guid") or "").strip()}
    proc_refs = {str(proc.get("pid") or "").strip(), str(proc.get("uuid") or "").strip(), str(proc.get("id") or "").strip()}
    event_refs.discard(""); proc_refs.discard("")
    if event_refs & proc_refs:
        return True
    event_name = str(_first(event, "processName", "process_name") or "").strip().casefold()
    proc_name = str(_first(proc, "name", "image", "processName") or "").strip().casefold()
    return bool(event_name and proc_name and event_name == proc_name)


def _same_process(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return _event_matches_process(left, right) or (
        str(_first(left, "filePath", "path", "imagePath") or "").strip().casefold()
        == str(_first(right, "file_path", "filePath", "path") or "").strip().casefold()
        and str(left.get("pid") or "").strip() == str(right.get("pid") or "").strip()
    )


def _event_only_has_msdw_detection(row: dict[str, Any]) -> bool:
    names = _list(row.get("threatName") or row.get("threat_name"))
    direct = _first(row, "signature", "signatureName", "rule", "msg", "message")
    if direct:
        names.append(direct)
    return not names or all(str(name or "").strip() == MSDW_SIGNATURE for name in names)


def _row_has_malicious_verdict(row: dict[str, Any]) -> bool:
    verdict = str(_first(row, "verdict", "classification", "status") or "").lower()
    level = int(_first(row, "threatLevel", "threat_level", "severityLevel") or 0)
    malicious = row.get("malicious") is True or row.get("isMalicious") is True
    names = _without_msdw_signature(row.get("threatName") or row.get("threat_name"))
    return malicious or verdict in {"malicious", "high", "critical"} or level >= 2 or bool(names)


def _mark_event_informational(event: dict[str, Any]) -> None:
    event["original_threat_level"] = event.get("threatLevel") or event.get("threat_level")
    event["original_severity"] = event.get("severity")
    event["threatLevel"] = 0
    event["threat_level"] = 0
    event["severity"] = "informational"
    event["classification"] = MSDW_DISPOSITION
    event["disposition"] = MSDW_DISPOSITION
    event["reason"] = MSDW_REASON
    event["excluded_from_malicious_indicator_count"] = True
    event["excluded_from_final_risk"] = True
    event["suppressed"] = False


def _mark_related_request_informational(request: dict[str, Any]) -> None:
    request["threatLevel"] = 0
    request["threat_level"] = 0
    request["msdw_false_positive_context"] = True
    request["excluded_from_malicious_indicator_count"] = True


def _mark_raw_process_informational(proc: dict[str, Any]) -> None:
    proc["originalThreatLevel"] = proc.get("threatLevel")
    proc["originalThreatScore"] = proc.get("threatScore") or proc.get("score")
    proc["threatLevel"] = 0
    proc["threatScore"] = 0
    proc["threatName"] = _without_msdw_signature(proc.get("threatName"))
    proc["classification"] = "informational"
    proc["falsePositiveExclusion"] = {"type": "msdw_windows_diagnostic", "reason": MSDW_REASON}


def _exclusion_metadata(proc: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "anyrun_msdw_windows_diagnostic",
        "process": str(proc.get("name") or "svchost.exe"),
        "process_path": SVCHOST_PATH,
        "classification": MSDW_DISPOSITION,
        "severity": "informational",
        "reason": MSDW_REASON,
        "preserved_for_timeline": True,
        "excluded_from_malicious_indicator_count": True,
        "excluded_from_final_risk": True,
    }


def _without_msdw_signature(value: Any) -> list[str]:
    return [str(item) for item in _list(value) if str(item or "").strip() != MSDW_SIGNATURE]


def _flatten_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key} {_flatten_text(item)}" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(_flatten_text(item) for item in value)
    return str(value or "")


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, "", []):
            return row.get(key)
    return None


def _dict(value: Any) -> dict[str, Any]: return value if isinstance(value, dict) else {}
def _list(value: Any) -> list[Any]: return value if isinstance(value, list) else ([] if value in (None, "") else [value])
