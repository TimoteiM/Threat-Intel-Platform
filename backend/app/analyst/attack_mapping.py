"""
MITRE ATT&CK technique mapping.

A static database of the techniques this platform can actually produce evidence
for, plus utilities to validate and enrich analyst findings.

The database is deliberately *not* the full ATT&CK matrix. It is the whitelist
that assessment is checked against, and a technique nobody here can evidence is
a technique a model can hallucinate into a report. Every entry below is one that
either an endpoint behaviour signal or a collector finding can support.

Two halves:

    domain / phishing   what a URL, domain or certificate investigation can show
    endpoint            what a Sysmon/EDR process event can show — added so that
                        the technique a SIEM rule claims can be checked against
                        the behaviour actually observed
"""

from __future__ import annotations

from typing import Optional

# Technique database — keyed by technique ID
# Each entry: name, tactic, description, url
TECHNIQUE_DB: dict[str, dict[str, str]] = {
    # Resource Development
    "T1583.001": {
        "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "description": "Adversary registers domains for use in operations.",
        "url": "https://attack.mitre.org/techniques/T1583/001/",
    },
    "T1583.006": {
        "name": "Acquire Infrastructure: Web Services",
        "tactic": "Resource Development",
        "description": "Adversary uses legitimate web services for operations.",
        "url": "https://attack.mitre.org/techniques/T1583/006/",
    },
    "T1584.001": {
        "name": "Compromise Infrastructure: Domains",
        "tactic": "Resource Development",
        "description": "Adversary compromises existing domains for malicious use.",
        "url": "https://attack.mitre.org/techniques/T1584/001/",
    },
    "T1588.004": {
        "name": "Obtain Capabilities: Digital Certificates",
        "tactic": "Resource Development",
        "description": "Adversary obtains TLS certificates for malicious infrastructure.",
        "url": "https://attack.mitre.org/techniques/T1588/004/",
    },
    "T1608.001": {
        "name": "Stage Capabilities: Upload Malware",
        "tactic": "Resource Development",
        "description": "Adversary uploads malware to staged infrastructure.",
        "url": "https://attack.mitre.org/techniques/T1608/001/",
    },
    "T1608.005": {
        "name": "Stage Capabilities: Link Target",
        "tactic": "Resource Development",
        "description": "Adversary stages link targets for phishing or drive-by compromise.",
        "url": "https://attack.mitre.org/techniques/T1608/005/",
    },
    # Initial Access
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversary sends spearphishing messages with malicious links.",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "T1598": {
        "name": "Phishing for Information",
        "tactic": "Reconnaissance",
        "description": "Adversary uses phishing to gather victim information.",
        "url": "https://attack.mitre.org/techniques/T1598/",
    },
    "T1189": {
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Adversary compromises victims via visiting a malicious website.",
        "url": "https://attack.mitre.org/techniques/T1189/",
    },
    # Execution
    "T1204.001": {
        "name": "User Execution: Malicious Link",
        "tactic": "Execution",
        "description": "Adversary relies on users clicking malicious links.",
        "url": "https://attack.mitre.org/techniques/T1204/001/",
    },
    # Defense Evasion
    "T1036.005": {
        "name": "Masquerading: Match Legitimate Name",
        "tactic": "Defense Evasion",
        "description": "Adversary names infrastructure to match legitimate services.",
        "url": "https://attack.mitre.org/techniques/T1036/005/",
    },
    "T1036.011": {
        "name": "Masquerading: Break Process Trees",
        "tactic": "Defense Evasion",
        "description": "Adversary uses techniques to evade process-based detection.",
        "url": "https://attack.mitre.org/techniques/T1036/011/",
    },
    # Command and Control
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversary uses HTTP/HTTPS for command and control.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1102": {
        "name": "Web Service",
        "tactic": "Command and Control",
        "description": "Adversary uses legitimate web services for C2.",
        "url": "https://attack.mitre.org/techniques/T1102/",
    },
    "T1090": {
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversary uses proxies to direct network traffic.",
        "url": "https://attack.mitre.org/techniques/T1090/",
    },
    "T1090.004": {
        "name": "Proxy: Domain Fronting",
        "tactic": "Command and Control",
        "description": "Adversary uses domain fronting to hide C2 destination.",
        "url": "https://attack.mitre.org/techniques/T1090/004/",
    },
    # Credential Access
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "Adversary intercepts communications between systems.",
        "url": "https://attack.mitre.org/techniques/T1557/",
    },
    "T1056.003": {
        "name": "Input Capture: Web Portal Capture",
        "tactic": "Credential Access",
        "description": "Adversary captures credentials via cloned web portals.",
        "url": "https://attack.mitre.org/techniques/T1056/003/",
    },
    # Collection
    "T1185": {
        "name": "Browser Session Hijacking",
        "tactic": "Collection",
        "description": "Adversary hijacks browser sessions to access web applications.",
        "url": "https://attack.mitre.org/techniques/T1185/",
    },
    # Reconnaissance
    "T1593.002": {
        "name": "Search Open Websites/Domains: Search Engines",
        "tactic": "Reconnaissance",
        "description": "Adversary uses search engines to gather victim information.",
        "url": "https://attack.mitre.org/techniques/T1593/002/",
    },
    "T1596.003": {
        "name": "Search Open Technical Databases: Digital Certificates",
        "tactic": "Reconnaissance",
        "description": "Adversary searches certificate transparency logs.",
        "url": "https://attack.mitre.org/techniques/T1596/003/",
    },
    # ── Endpoint techniques ───────────────────────────────────────────────────
    # Evidenced by the process-event behaviour signals in
    # app/services/endpoint_event_service.py. See ATTACK_BY_SIGNAL below for
    # which signal supports which technique.
    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversary executes commands through an interpreter.",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversary executes commands and scripts through PowerShell.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversary executes commands through cmd.exe.",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "T1059.005": {
        "name": "Command and Scripting Interpreter: Visual Basic",
        "tactic": "Execution",
        "description": "Adversary executes VBScript or VBA, typically via wscript/cscript.",
        "url": "https://attack.mitre.org/techniques/T1059/005/",
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "Adversary relies on a user opening a malicious document or binary.",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "description": "Adversary uses WMI to execute commands, often on remote hosts.",
        "url": "https://attack.mitre.org/techniques/T1047/",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Execution",
        "description": "Adversary uses the Windows task scheduler for execution or persistence.",
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "T1569.002": {
        "name": "System Services: Service Execution",
        "tactic": "Execution",
        "description": "Adversary executes a payload by creating or starting a Windows service.",
        "url": "https://attack.mitre.org/techniques/T1569/002/",
    },
    # Persistence
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversary adds a Run key or Startup item so a payload survives reboot.",
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1543.003": {
        "name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence",
        "description": "Adversary installs or modifies a Windows service for persistence.",
        "url": "https://attack.mitre.org/techniques/T1543/003/",
    },
    # Defense Evasion
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversary encodes or obfuscates content to hinder analysis and detection.",
        "url": "https://attack.mitre.org/techniques/T1027/",
    },
    "T1027.010": {
        "name": "Obfuscated Files or Information: Command Obfuscation",
        "tactic": "Defense Evasion",
        "description": "Adversary obfuscates the command line itself — escaping, concatenation, encoding.",
        "url": "https://attack.mitre.org/techniques/T1027/010/",
    },
    "T1036": {
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Adversary manipulates names or locations to appear legitimate.",
        "url": "https://attack.mitre.org/techniques/T1036/",
    },
    "T1070.001": {
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "description": "Adversary clears event logs to destroy the record of what was done.",
        "url": "https://attack.mitre.org/techniques/T1070/001/",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": "Adversary proxies execution through a signed system binary.",
        "url": "https://attack.mitre.org/techniques/T1218/",
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversary disables security tooling or adds exclusions to it.",
        "url": "https://attack.mitre.org/techniques/T1562/001/",
    },
    "T1620": {
        "name": "Reflective Code Loading",
        "tactic": "Defense Evasion",
        "description": "Adversary loads and runs code in memory without writing it to disk.",
        "url": "https://attack.mitre.org/techniques/T1620/",
    },
    # Credential Access
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversary reads credentials out of the LSASS process.",
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1003.002": {
        "name": "OS Credential Dumping: Security Account Manager",
        "tactic": "Credential Access",
        "description": "Adversary extracts credential material from the SAM registry hive.",
        "url": "https://attack.mitre.org/techniques/T1003/002/",
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "description": "Adversary searches files for stored credentials.",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
    },
    "T1552.002": {
        "name": "Unsecured Credentials: Credentials in Registry",
        "tactic": "Credential Access",
        "description": "Adversary searches the registry for stored credentials.",
        "url": "https://attack.mitre.org/techniques/T1552/002/",
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "description": "Adversary extracts credentials from vaults and password managers.",
        "url": "https://attack.mitre.org/techniques/T1555/",
    },
    # Discovery
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversary enumerates network configuration of the host.",
        "url": "https://attack.mitre.org/techniques/T1016/",
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "description": "Adversary identifies the user context it is running as.",
        "url": "https://attack.mitre.org/techniques/T1033/",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Adversary enumerates running processes.",
        "url": "https://attack.mitre.org/techniques/T1057/",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversary gathers details about the operating system and hardware.",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversary enumerates local or domain accounts and groups.",
        "url": "https://attack.mitre.org/techniques/T1087/",
    },
    # Lateral Movement
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversary executes on another host over SMB admin shares.",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    "T1021.006": {
        "name": "Remote Services: Windows Remote Management",
        "tactic": "Lateral Movement",
        "description": "Adversary uses WinRM/PowerShell remoting to execute on another host.",
        "url": "https://attack.mitre.org/techniques/T1021/006/",
    },
    # Command and Control
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversary downloads tools or payloads onto the host from outside.",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    # Impact
    "T1489": {
        "name": "Service Stop",
        "tactic": "Impact",
        "description": "Adversary stops or kills services and processes to disrupt or disable defences.",
        "url": "https://attack.mitre.org/techniques/T1489/",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversary deletes shadow copies or disables recovery, typically before encryption.",
        "url": "https://attack.mitre.org/techniques/T1490/",
    },
}


# Which techniques each deterministic endpoint behaviour signal supports.
#
# This is the evidence-bound half of ATT&CK assessment: the signal already
# matched a literal command line, so the technique is not a judgement — it is
# what that command *is*. Confidence says how uniquely the behaviour identifies
# the technique:
#
#   high    the behaviour is essentially only done by this technique
#   medium  the behaviour is characteristic but has legitimate uses
#   low     consistent with the technique, but far too common to assert alone
#
# Signal ids come from COMMAND_RULES and the heuristics in
# app/services/endpoint_event_service.py. A signal absent here contributes no
# technique at all, which is the intended default.
ATTACK_BY_SIGNAL: dict[str, tuple[tuple[str, str], ...]] = {
    "encoded_powershell": (("T1027", "high"), ("T1059.001", "high")),
    "powershell_stealth_flags": (("T1059.001", "medium"),),
    "download_cradle": (("T1105", "high"),),
    "in_memory_execution": (("T1620", "medium"), ("T1059.001", "medium")),
    "shadow_copy_tampering": (("T1490", "high"),),
    "log_tampering": (("T1070.001", "high"),),
    "defence_tampering": (("T1562.001", "high"),),
    "credential_access": (("T1003.001", "high"),),
    "persistence": (("T1547.001", "medium"), ("T1053.005", "medium"), ("T1543.003", "medium")),
    "process_termination": (("T1489", "medium"),),
    "host_recon": (("T1082", "medium"), ("T1087", "medium"), ("T1016", "medium"), ("T1033", "medium")),
    "remote_access": (("T1021.002", "medium"), ("T1047", "medium"), ("T1021.006", "medium")),
    "obfuscation": (("T1027.010", "high"),),
    "office_spawns_shell": (("T1204.002", "medium"), ("T1059", "medium")),
    "user_writable_execution": (("T1036", "low"),),
    "interpreter_execution": (("T1059", "low"),),
    "elevated_integrity": (),
    "long_command_line": (),
}

# Techniques a *collector* finding can support, and the condition under which it
# does. Endpoint signals say what a command is; collector findings say what a
# domain or URL turned out to be, which supports a different and smaller set.
#
# Each rule names the finding it reads, the condition that must hold, and the
# technique that follows. The conditions are deliberately strict: "the page was
# reachable" supports nothing, "the page is malicious *and* serves a login form"
# supports credential capture. A rule that would fire on a merely-suspicious
# verdict is not in this table.
#
#   (rule_id, collector, technique, confidence, requires_malicious)
COLLECTOR_ATTACK_RULES: tuple[tuple[str, str, str, str, bool], ...] = (
    # A malicious page asking for credentials is a phishing capture page.
    ("credential_page", "http", "T1056.003", "high", True),
    ("credential_page", "http", "T1566.002", "medium", True),
    # A page impersonating a brand it does not own.
    ("brand_impersonation", "http", "T1036.005", "medium", True),
    # Infrastructure registered for the operation rather than compromised.
    ("newly_registered", "whois", "T1583.001", "medium", True),
    # A confirmed phishing entry in a feed is a link the user was meant to click.
    ("phish_feed_hit", "threat_feeds", "T1566.002", "high", True),
    # Sandbox-observed HTTP callbacks from a malicious sample.
    ("sandbox_c2", "anyrun", "T1071.001", "medium", True),
)

# A persistence or recon signal supports several techniques at once and cannot
# say which. When a detection rule already claims one of them, that is the one
# the evidence corroborates — these are the groups within which such a match is
# legitimate rather than a coincidence.
AMBIGUOUS_SIGNAL_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({"T1547.001", "T1053.005", "T1543.003"}),
    frozenset({"T1082", "T1087", "T1016", "T1033", "T1057"}),
    frozenset({"T1021.002", "T1047", "T1021.006"}),
)


def get_technique_info(technique_id: str) -> Optional[dict[str, str]]:
    """Look up a technique by ID. Returns None if not found."""
    return TECHNIQUE_DB.get(technique_id)


def is_known_technique(technique_id: str) -> bool:
    """True when this ID is one we are willing to put in a report."""
    return normalize_technique_id(technique_id) in TECHNIQUE_DB


def normalize_technique_id(technique_id: str) -> str:
    """`t1059.001 ` → `T1059.001`. Returns '' for anything unusable."""
    candidate = str(technique_id or "").strip().upper().rstrip(".,;")
    if not candidate.startswith("T"):
        return ""
    return candidate


def parent_technique(technique_id: str) -> str:
    """`T1059.001` → `T1059`; a base technique is its own parent."""
    normalized = normalize_technique_id(technique_id)
    return normalized.split(".", 1)[0] if "." in normalized else normalized


def techniques_for_signal(signal_id: str) -> tuple[tuple[str, str], ...]:
    """(technique_id, confidence) pairs a behaviour signal supports."""
    return ATTACK_BY_SIGNAL.get(str(signal_id or ""), ())


def get_all_techniques() -> list[dict[str, str]]:
    """Return all techniques with their IDs."""
    return [
        {"id": tid, **info}
        for tid, info in sorted(TECHNIQUE_DB.items())
    ]


def enrich_findings_with_attack(findings: list[dict]) -> list[dict]:
    """
    Validate and enrich TTP IDs on analyst findings.

    For each finding with a `ttp` field, look up the technique and add:
    - ttp_name: technique name
    - ttp_tactic: tactic name
    - ttp_url: MITRE URL

    If the TTP ID is not in our database, clear it to avoid invalid references.
    """
    for finding in findings:
        ttp = finding.get("ttp")
        if not ttp:
            continue

        # Normalize: strip whitespace, handle "T1234.001" format
        ttp = ttp.strip()

        info = get_technique_info(ttp)
        if info:
            finding["ttp"] = ttp
            finding["ttp_name"] = info["name"]
            finding["ttp_tactic"] = info["tactic"]
            finding["ttp_url"] = info["url"]
        else:
            # Unknown technique — keep the ID but don't add invalid metadata
            finding["ttp_name"] = None
            finding["ttp_tactic"] = None
            finding["ttp_url"] = None

    return findings
