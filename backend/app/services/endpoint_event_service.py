"""
Endpoint telemetry (Sysmon / EDR process events) inside an alert body.

A network alert is a bag of indicators; an endpoint event is a story — this
process, started by that one, with this command line, as this user, from this
directory. The indicator extractor sees almost none of that: a Sysmon Process
Create carries one file hash and nothing else it can look up.

So the alert pipeline parses these events into structured fields and derives
deterministic behaviour signals from them (encoded PowerShell, download cradles,
shadow-copy deletion, recon bursts, execution from user-writable paths,
Office-spawning-a-shell). The signals become findings with a risk score, exactly
like collector reputation does for an indicator, and travel in the same exported
document list under `report_type: "endpoint_event"`.

Parsing is field-name driven rather than delimiter driven: Sysmon values contain
colons, spaces and quotes (`Image: C:\\Program Files\\…`), so the only reliable
boundary is the next known field name.
"""

from __future__ import annotations

import re
from typing import Any

# ── Event headers Sysmon writes above the field list ──────────────────────────

EVENT_HEADERS: dict[str, str] = {
    "process create": "process_create",
    "process terminated": "process_terminated",
    "network connection detected": "network_connection",
    "dns query": "dns_query",
    "file created": "file_create",
    "file create": "file_create",
    "registry value set": "registry_set",
    "registry object added or deleted": "registry_add_delete",
    "image loaded": "image_load",
    "pipe created": "pipe_create",
    "createremotethread detected": "remote_thread",
    "process accessed": "process_access",
    "raw access read detected": "raw_access_read",
    "driver loaded": "driver_load",
    "wmievent": "wmi_event",
}

# ── Fields we understand (order irrelevant; used to build the split pattern) ──

EVENT_FIELDS: tuple[str, ...] = (
    "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion",
    "Description", "Product", "Company", "OriginalFileName", "CommandLine",
    "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId",
    "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId",
    "ParentImage", "ParentCommandLine", "ParentUser",
    # network / dns / file / registry / image-load variants
    "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname",
    "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp",
    "DestinationHostname", "DestinationPort", "DestinationPortName",
    "QueryName", "QueryStatus", "QueryResults", "TargetFilename",
    "CreationUtcTime", "TargetObject", "Details", "EventType", "ImageLoaded",
    "Signed", "Signature", "SignatureStatus", "PipeName", "SourceImage",
    "TargetImage", "GrantedAccess", "CallTrace", "Device",
)

_HEADER_RE = re.compile(
    r"(?:^|[\r\n]|\s)(" + "|".join(re.escape(h) for h in sorted(EVENT_HEADERS, key=len, reverse=True)) + r")\s*:",
    re.IGNORECASE,
)
_FIELD_RE = re.compile(
    r"(?<![\w-])(" + "|".join(EVENT_FIELDS) + r")\s*:\s",
    re.IGNORECASE,
)

# Fields whose absence is written as a bare dash by Sysmon.
_EMPTY_VALUES = {"-", "", "n/a", "null"}

MAX_EVENTS = 20
MAX_VALUE_CHARS = 4000

# ── Behaviour rules ───────────────────────────────────────────────────────────

SEVERITY_RISK = {"high": 80, "medium": 50, "low": 25, "info": 5}

# Interpreters and signed-binary proxies worth noticing in a command line.
LOLBINS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe",
    "cmstp.exe", "msiexec.exe", "odbcconf.exe", "forfiles.exe", "pcalua.exe",
    "curl.exe", "wget.exe", "bash.exe", "sh.exe", "python.exe", "python3.exe",
})

# Parents that have no business spawning a shell or interpreter.
SUSPICIOUS_PARENTS = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
    "acrobat.exe", "acrord32.exe", "wscript.exe", "mshta.exe", "eqnedt32.exe",
})

# Paths a user (or anything that phishes one) can write to.
USER_WRITABLE_MARKERS = (
    r"\appdata\\", r"\temp\\", r"\downloads\\", r"\public\\", r"\programdata\\",
    r"\users\public", r"\onedrive", r"\dropbox", r"\google drive",
)

# (id, severity, title, pattern, explanation)
COMMAND_RULES: tuple[tuple[str, str, str, re.Pattern[str], str], ...] = (
    (
        "encoded_powershell", "high", "Base64-encoded PowerShell command",
        re.compile(r"(?:-enc(?:odedcommand)?|-e\s+[A-Za-z0-9+/=]{40,})\b", re.IGNORECASE),
        "Encoded command lines hide their payload from log review and are rare in legitimate automation.",
    ),
    (
        "powershell_stealth_flags", "medium", "PowerShell run hidden and unrestricted",
        re.compile(r"-(?:w|windowstyle)\s+hidden|-(?:nop|noprofile)\b|-ep\s+bypass|-executionpolicy\s+bypass", re.IGNORECASE),
        "Hidden windows and bypassed execution policy are the standard flags of a dropper.",
    ),
    (
        "download_cradle", "high", "Remote payload download in the command line",
        re.compile(
            r"(?:downloadstring|downloadfile|invoke-webrequest|iwr\s|\bwget\b|\bcurl\b\s+-o|"
            r"certutil(?:\.exe)?\s+[^|]*-urlcache|bitsadmin[^|]*\/transfer|start-bitstransfer)",
            re.IGNORECASE,
        ),
        "The process fetches content from the network and writes or executes it locally.",
    ),
    (
        "in_memory_execution", "high", "In-memory execution primitive",
        re.compile(r"\b(?:iex|invoke-expression|frombase64string|reflection\.assembly|::load\()", re.IGNORECASE),
        "Code is decoded and executed without ever touching disk, which defeats file-based detection.",
    ),
    (
        "shadow_copy_tampering", "high", "Backup or recovery tampering",
        re.compile(r"vssadmin[^|]*delete\s+shadows|wbadmin[^|]*delete|bcdedit[^|]*recoveryenabled\s+no", re.IGNORECASE),
        "Deleting shadow copies or disabling recovery immediately precedes ransomware encryption.",
    ),
    (
        "log_tampering", "high", "Event log clearing",
        re.compile(r"wevtutil[^|]*\bcl\b|clear-eventlog|remove-eventlog", re.IGNORECASE),
        "Clearing event logs destroys the evidence of what the intruder did.",
    ),
    (
        "defence_tampering", "high", "Security tooling disabled",
        re.compile(r"set-mppreference[^|]*-disable|add-mppreference[^|]*-exclusionpath|sc\s+stop\s+\w*(?:defend|sense)", re.IGNORECASE),
        "Defender exclusions or stopped security services are a hallmark of hands-on-keyboard intrusion.",
    ),
    (
        "credential_access", "high", "Credential store access",
        re.compile(r"\b(?:mimikatz|sekurlsa|lsass|comsvcs\.dll[^|]*minidump|vaultcmd|reg\s+save\s+hklm\\sam)", re.IGNORECASE),
        "The command touches LSASS or the credential vaults, i.e. credential theft.",
    ),
    (
        "persistence", "medium", "Persistence mechanism",
        re.compile(r"schtasks[^|]*\/create|new-scheduledtask|reg\s+add[^|]*\\run|sc\s+create\b|new-service", re.IGNORECASE),
        "The command installs something that survives reboot.",
    ),
    (
        "process_termination", "medium", "Forced process termination",
        re.compile(r"taskkill[^|]*\/f|stop-process[^|]*-force|pkill\b|killall\b", re.IGNORECASE),
        "Forcibly killing processes is used both by cleanup scripts and by malware disabling defences.",
    ),
    (
        "host_recon", "low", "Host or network reconnaissance",
        re.compile(r"\b(?:whoami|systeminfo|net\s+(?:user|group|localgroup|view)|nltest|tasklist|netstat|ipconfig\s*\/all|arp\s+-a)\b", re.IGNORECASE),
        "Enumeration commands are normal for administrators and routine for an intruder getting oriented.",
    ),
    (
        "remote_access", "medium", "Remote execution or lateral movement tooling",
        re.compile(r"\b(?:psexec|wmic[^|]*\/node:|enter-pssession|invoke-command[^|]*-computername|winrs)\b", re.IGNORECASE),
        "The command reaches another host.",
    ),
    (
        "obfuscation", "medium", "Obfuscated command line",
        re.compile(r"(?:\^\w){4,}|(?:`\w){4,}|\$\{[^}]*\}\s*\+\s*\$\{", re.IGNORECASE),
        "Caret/backtick escaping and string concatenation are used to break up detectable keywords.",
    ),
)

LONG_COMMAND_LINE = 1200


# ── Parsing ───────────────────────────────────────────────────────────────────


def parse_endpoint_events(text: str, *, max_events: int = MAX_EVENTS) -> list[dict[str, Any]]:
    """
    Structured events found in an alert body.

    Returns one dict per event: `{event_type, header, fields, hashes, truncated}`.
    Text that carries no recognisable header and no field cluster yields nothing —
    a plain phishing alert must not be mistaken for endpoint telemetry.
    """
    body = str(text or "")
    if not body.strip():
        return []

    events: list[dict[str, Any]] = []
    for header, block in _split_events(body):
        fields = _parse_fields(block)
        if len(fields) < 3:
            continue  # a stray "Image:" in prose is not an event
        events.append(
            {
                "event_type": EVENT_HEADERS.get((header or "").lower(), "endpoint_event"),
                "header": header or "Endpoint event",
                "fields": fields,
                "hashes": _hashes_from(fields.get("Hashes", "")),
            }
        )
        if len(events) >= max_events:
            break
    return events


def _split_events(body: str) -> list[tuple[str | None, str]]:
    """Split on Sysmon headers; fall back to one headerless block."""
    matches = list(_HEADER_RE.finditer(body))
    if not matches:
        return [(None, body)]

    blocks: list[tuple[str | None, str]] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        blocks.append((match.group(1).strip(), body[start:end]))
    return blocks


def _parse_fields(block: str) -> dict[str, str]:
    """`Key: value` pairs, where a value runs until the next known key."""
    fields: dict[str, str] = {}
    matches = list(_FIELD_RE.finditer(block))
    for index, match in enumerate(matches):
        name = match.group(1)
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(block)
        value = block[start:end].strip().strip(",").strip()
        if value.lower() in _EMPTY_VALUES:
            continue
        canonical = _canonical_field(name)
        fields.setdefault(canonical, value[:MAX_VALUE_CHARS])
    return fields


def _canonical_field(name: str) -> str:
    lowered = name.lower()
    for field in EVENT_FIELDS:
        if field.lower() == lowered:
            return field
    return name


def _hashes_from(value: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    for algo, digest in re.findall(r"([A-Z0-9]+)\s*=\s*([A-F0-9]+)", value or "", re.IGNORECASE):
        digests.setdefault(algo.lower(), digest.lower())
    return digests


# ── Behaviour signals ─────────────────────────────────────────────────────────


def assess_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Deterministic signals for one parsed event, most severe first."""
    fields = event.get("fields") or {}
    command = " ".join(
        str(fields.get(key) or "") for key in ("CommandLine", "ParentCommandLine", "Details")
    )
    image = _basename(fields.get("Image"))
    parent_image = _basename(fields.get("ParentImage"))
    signals: list[dict[str, Any]] = []

    for rule_id, severity, title, pattern, explanation in COMMAND_RULES:
        match = pattern.search(command)
        if not match:
            continue
        signals.append(
            _signal(
                rule_id, severity, title, explanation,
                evidence={"matched": match.group(0)[:120], "field": "CommandLine"},
            )
        )

    if image in LOLBINS and fields.get("CommandLine"):
        signals.append(
            _signal(
                "interpreter_execution", "info", f"Command interpreter executed ({image})",
                "Interpreters and signed proxy binaries are how most malicious command lines run — "
                "on its own this is normal on a developer or admin workstation.",
                evidence={"image": fields.get("Image")},
            )
        )

    if parent_image in SUSPICIOUS_PARENTS and image in LOLBINS:
        signals.append(
            _signal(
                "office_spawns_shell", "high", f"{parent_image} spawned {image}",
                "A document or script host starting a shell is the classic macro/exploit execution chain.",
                evidence={"parent_image": fields.get("ParentImage"), "image": fields.get("Image")},
            )
        )

    writable = _user_writable_path(fields.get("Image") or "")
    if writable:
        signals.append(
            _signal(
                "user_writable_execution", "medium", "Executed from a user-writable location",
                "Binaries under AppData, Temp, Downloads or a cloud-sync folder are not managed software; "
                "anything that phishes a user can drop one there.",
                evidence={"image": fields.get("Image"), "location": writable},
            )
        )

    command_line = str(fields.get("CommandLine") or "")
    if len(command_line) > LONG_COMMAND_LINE:
        signals.append(
            _signal(
                "long_command_line", "low", f"Unusually long command line ({len(command_line)} chars)",
                "Very long command lines usually mean generated or packed script content.",
                evidence={"length": len(command_line)},
            )
        )

    if str(fields.get("IntegrityLevel") or "").lower() in ("high", "system"):
        signals.append(
            _signal(
                "elevated_integrity", "low", f"Process runs at {fields['IntegrityLevel']} integrity",
                "Elevated execution widens what a compromise of this process can reach.",
                evidence={"integrity_level": fields.get("IntegrityLevel")},
            )
        )

    signals.sort(key=lambda item: (-SEVERITY_RISK.get(item["severity"], 0), item["id"]))
    return signals


def _signal(signal_id: str, severity: str, title: str, explanation: str, *, evidence: dict) -> dict[str, Any]:
    return {
        "id": signal_id,
        "severity": severity,
        "title": title,
        "explanation": explanation,
        "evidence": {key: value for key, value in evidence.items() if value not in (None, "")},
    }


def _basename(path: str | None) -> str:
    text = str(path or "").strip().strip('"')
    if not text:
        return ""
    return re.split(r"[\\/]", text)[-1].lower()


def _user_writable_path(path: str) -> str:
    lowered = str(path or "").lower().replace("/", "\\")
    for marker in USER_WRITABLE_MARKERS:
        cleaned = marker.replace("\\\\", "\\")
        if cleaned in lowered:
            return cleaned.strip("\\")
    return ""


# ── Report ────────────────────────────────────────────────────────────────────


def build_event_report(
    event: dict[str, Any],
    *,
    schema_version: str,
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    """One endpoint event as an exportable document, verdict included."""
    signals = assess_event(event)
    fields = event.get("fields") or {}
    risk = max((SEVERITY_RISK.get(s["severity"], 0) for s in signals), default=0)
    high_or_medium = [s for s in signals if s["severity"] in ("high", "medium")]

    if risk >= 70:
        classification = "malicious"
    elif risk >= 35:
        classification = "suspicious"
    elif signals:
        classification = "benign"
    else:
        classification = "inconclusive"

    return {
        "schema_version": schema_version,
        "report_type": "endpoint_event",
        "event": {
            "type": event.get("event_type"),
            "header": event.get("header"),
            "utc_time": fields.get("UtcTime"),
            "host_user": fields.get("User"),
            "image": fields.get("Image"),
            "command_line": fields.get("CommandLine"),
            "parent_image": fields.get("ParentImage"),
            "parent_command_line": fields.get("ParentCommandLine"),
            "current_directory": fields.get("CurrentDirectory"),
            "integrity_level": fields.get("IntegrityLevel"),
            "process_id": fields.get("ProcessId"),
            "parent_process_id": fields.get("ParentProcessId"),
            "process_guid": fields.get("ProcessGuid"),
            "logon_id": fields.get("LogonId"),
            "hashes": event.get("hashes") or {},
            "fields": fields,
        },
        "verdict": {
            "classification": classification,
            "risk_score": risk,
            "confidence": 0.8 if high_or_medium else 0.5,
            "reasons": [s["title"] for s in signals[:8]] or ["No behaviour signal matched this event."],
            "sources": ["endpoint_behaviour"],
        },
        "findings": [
            {
                "source": "Endpoint behaviour",
                "collector": "endpoint_behaviour",
                "type": "sandbox_behaviour",
                "severity": signal["severity"],
                "summary": signal["title"],
                "data": {"explanation": signal["explanation"], **signal["evidence"]},
            }
            for signal in signals
        ],
        "sources_checked": ["endpoint_behaviour"],
        "errors": [],
        "started_at": started_at,
        "completed_at": completed_at,
    }
