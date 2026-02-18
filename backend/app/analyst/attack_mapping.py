"""
MITRE ATT&CK technique mapping for domain investigation findings.

Provides a static database of techniques relevant to domain/phishing
investigations, and utilities to validate and enrich analyst findings.
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
}


def get_technique_info(technique_id: str) -> Optional[dict[str, str]]:
    """Look up a technique by ID. Returns None if not found."""
    return TECHNIQUE_DB.get(technique_id)


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
