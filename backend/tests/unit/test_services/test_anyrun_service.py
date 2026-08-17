from __future__ import annotations

import sys
import time
import types

from app.services import anyrun_service as svc


class _LookupConnector:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get_intelligence(self, **kwargs):
        return {
            "summary": {"threatLevel": 2, "detectedType": "phishing", "lastSeen": "2026-03-11T12:00:00Z"},
            "threatName": ["phishing-kit"],
            "destinationIPgeo": [{"destinationIP": "1.2.3.4", "country": "US"}],
            "destinationPort": [443, "8080"],
            "relatedTasks": [{"id": "task-1", "related": "https://app.any.run/tasks/task-1"}],
            "relatedIncidents": [{"id": "incident-1"}],
            "relatedDNS": [{"domainName": "evil.example", "threatLevel": 2}],
            "destinationIP": [{"destinationIP": "1.2.3.4", "threatLevel": 2}],
        }


class _SandboxConnector:
    @staticmethod
    def windows(api_key: str):
        return _SandboxConnector()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get_analysis_report(self, analysis_id: str, report_format: str = "summary"):
        return {"data": {"network": {"domains": [], "hosts": []}}}


def _install_fake_anyrun_sdk(monkeypatch):
    connectors_module = types.SimpleNamespace(
        LookupConnector=_LookupConnector,
        SandboxConnector=_SandboxConnector,
    )
    monkeypatch.setitem(sys.modules, "anyrun", types.SimpleNamespace(connectors=connectors_module))
    monkeypatch.setitem(sys.modules, "anyrun.connectors", connectors_module)


def test_lookup_intelligence_maps_expected_fields():
    out = svc._lookup_intelligence(
        _LookupConnector,
        _SandboxConnector,
        "k",
        indicator="https://bad.example",
        indicator_type="url",
        sandbox_os="windows",
    )
    assert out["checked"] is True
    assert out["verdict"] == "malicious"
    assert out["raw_summary"]["threatName"] == ["phishing-kit"]
    assert out["raw_summary"]["destinationPort"] == [443, 8080]
    assert out["raw_summary"]["relatedTasks"]
    assert out["raw_summary"]["relatedIncidents"]
    assert out["dynamic_io_summary"]["destinationIPgeo"]
    assert out["dynamic_io_summary"]["destinationPort"] == [443, 8080]


def test_lookup_intelligence_normalizes_object_shaped_labels(monkeypatch):
    class _ObjectLabelLookupConnector(_LookupConnector):
        def get_intelligence(self, **kwargs):
            return {
                "summary": {
                    "threatLevel": 2,
                    "detectedType": "phishing",
                    "lastSeen": "2026-03-11T12:00:00Z",
                    "tags": [{"count": 2, "threatName": "phishing"}, {"name": "credential theft"}],
                },
                "threatName": [{"count": 3, "threatName": "phishing-kit"}, {"label": "brand abuse"}],
                "relatedTasks": [{"id": "task-1", "related": "https://app.any.run/tasks/task-1"}],
                "relatedIncidents": [],
            }

    out = svc._lookup_intelligence(
        _ObjectLabelLookupConnector,
        _SandboxConnector,
        "k",
        indicator="https://bad.example",
        indicator_type="url",
        sandbox_os="windows",
    )

    assert out["checked"] is True
    assert out["raw_summary"]["threatName"] == ["phishing-kit", "brand abuse"]
    assert out["raw_summary"]["tags"] == ["phishing", "credential theft"]
    assert "phishing-kit" in out["raw_summary"]["anyrun_ai_summary"]
    assert "credential theft" in out["raw_summary"]["anyrun_ai_summary"]


def test_extract_ports_from_nested_payload():
    payload = {
        "destinationPort": ["443", "bad", 8080],
        "network": {
            "hosts": [{"destinationPort": "8443"}],
            "connections": [{"port": "53"}],
        },
    }
    assert svc._extract_ports(payload) == [53, 443, 8080, 8443]


def test_build_behavior_graph_from_network_details():
    processes = [
        {"uuid": "p1", "pid": 1234, "fileName": "msedge.exe"},
        {"uuid": "p2", "pid": 4, "fileName": "System"},
    ]
    dns_requests = [
        {"process": "p1", "domainName": "evil.example", "ips": ["1.2.3.4"]},
        {"process": "p2", "domainName": "cdn.example", "ips": ["5.6.7.8"]},
    ]
    http_requests = [
        {"process": "p1", "url": "https://evil.example/login"},
        {"process": "p1", "url": "https://cdn.example/app.js"},
    ]
    connections = [
        {"process": "p1", "destinationIP": "1.2.3.4", "destinationPort": 443},
        {"process": "p2", "destinationIP": "8.8.8.8", "destinationPort": 53},
    ]

    graph = svc._build_behavior_graph(
        processes=processes,
        dns_requests=dns_requests,
        http_requests=http_requests,
        connections=connections,
    )

    assert isinstance(graph, dict)
    assert graph["nodes"]
    assert graph["edges"]

    ids = {n["id"] for n in graph["nodes"]}
    assert "process:p1" in ids
    assert "analysis:root" in ids
    assert all(not node_id.startswith("domain:") for node_id in ids)
    assert all(not node_id.startswith("ip:") for node_id in ids)
    assert all(not node_id.startswith("url:") for node_id in ids)

    edge_pairs = {(e["source"], e["target"]) for e in graph["edges"]}
    assert ("analysis:root", "process:p1") in edge_pairs


def test_process_relevance_score_prefers_high_signal_processes():
    suspicious = {
        "pid": 200,
        "name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
        "event_counts": {"connections": 2, "modified_files": 1, "registry_changes": 1},
        "children": ["400"],
    }
    common = {
        "pid": 100,
        "name": "svchost.exe",
        "command_line": "svchost.exe -k netsvcs",
        "event_counts": {"connections": 0, "modified_files": 0, "registry_changes": 0},
        "children": [],
    }

    assert svc._process_relevance_score(suspicious, parent_is_suspicious=False) >= 3
    assert svc._process_relevance_score(common, parent_is_suspicious=False) < 3


def test_build_behavior_graph_keeps_suspicious_execution_chain_only():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "explorer.exe"},
        {"uuid": "mid", "pid": 20, "ppid": 10, "fileName": "cmd.exe", "commandLine": "cmd.exe /c start"},
        {"uuid": "bad", "pid": 30, "ppid": 20, "fileName": "powershell.exe", "commandLine": "powershell.exe -enc AAAA"},
        {"uuid": "noise", "pid": 40, "ppid": 10, "fileName": "runtimebroker.exe"},
    ]
    connections = [{"process": "bad", "destinationIP": "1.2.3.4", "destinationPort": 443}]
    process_details = svc._extract_process_details({}, processes, connections=connections)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = {n["label"] for n in graph["nodes"]}
    assert "AnyRun Task" in labels
    assert "explorer.exe" in labels
    assert "cmd.exe" in labels
    assert "powershell.exe" in labels
    assert "runtimebroker.exe" not in labels
    assert all(edge["source"].startswith("process:") or edge["source"] == "analysis:root" for edge in graph["edges"])
    assert all(edge["target"].startswith("process:") for edge in graph["edges"])


def test_build_behavior_graph_collapses_repeated_low_signal_system_processes():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "explorer.exe"},
        {"uuid": "svc1", "pid": 11, "ppid": 10, "fileName": "svchost.exe"},
        {"uuid": "svc2", "pid": 12, "ppid": 10, "fileName": "svchost.exe"},
        {"uuid": "svc3", "pid": 13, "ppid": 10, "fileName": "svchost.exe"},
        {"uuid": "bad", "pid": 30, "ppid": 10, "fileName": "powershell.exe", "commandLine": "powershell.exe -enc AAAA"},
    ]
    connections = [{"process": "bad", "destinationIP": "1.2.3.4", "destinationPort": 443}]
    process_details = svc._extract_process_details({}, processes, connections=connections)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = [n["label"] for n in graph["nodes"]]
    assert "svchost.exe" not in labels
    assert all("instances" not in label for label in labels)


def test_build_behavior_graph_keeps_only_immediate_child_context_for_suspicious_process():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "explorer.exe"},
        {"uuid": "cmd", "pid": 20, "ppid": 10, "fileName": "cmd.exe", "commandLine": "cmd.exe /c start"},
        {"uuid": "bad", "pid": 30, "ppid": 20, "fileName": "powershell.exe", "commandLine": "powershell.exe -enc AAAA"},
        {"uuid": "shell", "pid": 40, "ppid": 30, "fileName": "ShellExperienceHost.exe"},
        {"uuid": "search", "pid": 50, "ppid": 40, "fileName": "SearchApp.exe"},
        {"uuid": "broker", "pid": 60, "ppid": 50, "fileName": "RuntimeBroker.exe"},
    ]
    connections = [{"process": "bad", "destinationIP": "1.2.3.4", "destinationPort": 443}]
    process_details = svc._extract_process_details({}, processes, connections=connections)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = {n["label"] for n in graph["nodes"]}
    assert "powershell.exe" in labels
    assert "cmd.exe" in labels
    assert "explorer.exe" in labels
    assert "ShellExperienceHost.exe" in labels
    assert "SearchApp.exe" not in labels
    assert "RuntimeBroker.exe" not in labels


def test_build_behavior_graph_collapses_low_signal_windows_ancestry_chain():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "wininit.exe"},
        {"uuid": "svc", "pid": 20, "ppid": 10, "fileName": "services.exe"},
        {"uuid": "sv1", "pid": 30, "ppid": 20, "fileName": "svchost.exe"},
        {"uuid": "sv2", "pid": 31, "ppid": 30, "fileName": "svchost.exe"},
        {"uuid": "con1", "pid": 32, "ppid": 31, "fileName": "conhost.exe"},
        {"uuid": "bad", "pid": 40, "ppid": 32, "fileName": "powershell.exe", "commandLine": "powershell.exe -enc AAAA"},
    ]
    connections = [{"process": "bad", "destinationIP": "1.2.3.4", "destinationPort": 443}]
    process_details = svc._extract_process_details({}, processes, connections=connections)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = {n["label"] for n in graph["nodes"]}
    assert "powershell.exe" in labels
    assert "wininit.exe" in labels
    assert "conhost.exe" in labels
    assert "svchost.exe" not in labels
    assert "services.exe" not in labels


def test_build_behavior_graph_drops_benign_sibling_branches_from_kept_path():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "wininit.exe"},
        {"uuid": "svc", "pid": 20, "ppid": 10, "fileName": "services.exe"},
        {"uuid": "goodsvchost", "pid": 30, "ppid": 20, "fileName": "svchost.exe"},
        {"uuid": "noiseedge", "pid": 31, "ppid": 20, "fileName": "msedge.exe"},
        {"uuid": "noisehost", "pid": 32, "ppid": 20, "fileName": "conhost.exe"},
        {"uuid": "bad", "pid": 40, "ppid": 30, "fileName": "powershell.exe", "commandLine": "powershell.exe -enc AAAA"},
    ]
    connections = [{"process": "bad", "destinationIP": "1.2.3.4", "destinationPort": 443}]
    process_details = svc._extract_process_details({}, processes, connections=connections)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = {n["label"] for n in graph["nodes"]}
    assert "powershell.exe" in labels
    assert "wininit.exe" in labels
    assert "svchost.exe" in labels
    assert "services.exe" not in labels
    assert "msedge.exe" not in labels
    assert "conhost.exe" not in labels


def test_build_behavior_graph_keeps_meaningful_sibling_branches():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "explorer.exe"},
        {"uuid": "cmd-low", "pid": 20, "ppid": 10, "fileName": "cmd.exe", "commandLine": "cmd.exe /c start"},
        {"uuid": "low", "pid": 30, "ppid": 20, "fileName": "mshta.exe", "commandLine": "mshta.exe https://example.test/a"},
        {"uuid": "cmd-high", "pid": 40, "ppid": 10, "fileName": "cmd.exe", "commandLine": "cmd.exe /c start"},
        {"uuid": "high", "pid": 50, "ppid": 40, "fileName": "powershell.exe", "commandLine": "powershell.exe -enc AAAA"},
    ]
    connections = [
        {"processUuid": "low", "destinationIP": "2.2.2.2", "destinationPort": 443},
        {"processUuid": "high", "destinationIP": "1.2.3.4", "destinationPort": 443},
    ]
    http_requests = [
        {"processUuid": "high", "url": "https://evil.example/payload"},
    ]
    process_details = svc._extract_process_details({}, processes, connections=connections, http_requests=http_requests)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = [n["label"] for n in graph["nodes"]]
    edge_pairs = {(e["source"], e["target"]) for e in graph["edges"]}

    assert labels.count("cmd.exe") == 2
    assert "mshta.exe" in labels
    assert labels.count("powershell.exe") == 1
    assert ("process:cmd-high", "process:high") in edge_pairs
    assert ("process:cmd-low", "process:low") in edge_pairs


def test_build_behavior_graph_keeps_file_writing_process_without_threat_score():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "explorer.exe"},
        {"uuid": "writer", "pid": 20, "ppid": 10, "fileName": "dropper.exe", "modifiedFiles": [{"path": "C:/Temp/payload.dll"}]},
        {"uuid": "noise", "pid": 30, "ppid": 10, "fileName": "runtimebroker.exe"},
    ]
    process_details = svc._extract_process_details({}, processes)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = {n["label"] for n in graph["nodes"]}
    edge_pairs = {(e["source"], e["target"]) for e in graph["edges"]}

    assert "explorer.exe" in labels
    assert "dropper.exe" in labels
    assert "runtimebroker.exe" not in labels
    assert ("process:root", "process:writer") in edge_pairs


def test_build_behavior_graph_keeps_flagged_browser_process_branch():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "[System Process]"},
        {"uuid": "svc", "pid": 20, "ppid": 10, "fileName": "svchost.exe"},
        {
            "uuid": "edge-good",
            "pid": 30,
            "ppid": 10,
            "fileName": "msedge.exe",
            "threatLevel": 2,
            "threatName": ["#PHISHING"],
            "isMalconf": True,
        },
        {"uuid": "edge-noise1", "pid": 31, "ppid": 10, "fileName": "msedge.exe"},
        {"uuid": "edge-noise2", "pid": 32, "ppid": 10, "fileName": "msedge.exe"},
    ]
    http_requests = [
        {"processUuid": "edge-good", "url": "https://evil.example/login"},
    ]
    process_details = svc._extract_process_details({}, processes, http_requests=http_requests)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = [n["label"] for n in graph["nodes"]]
    edge_pairs = {(e["source"], e["target"]) for e in graph["edges"]}

    assert labels.count("msedge.exe") == 1
    assert ("process:root", "process:edge-good") in edge_pairs
    assert ("process:root", "process:edge-noise1") not in edge_pairs
    assert ("process:root", "process:edge-noise2") not in edge_pairs


def test_build_behavior_graph_keeps_browser_branch_when_anyrun_verdict_is_nested():
    processes = [
        {"uuid": "root", "pid": 10, "fileName": "[System Process]"},
        {
            "uuid": "edge-good",
            "pid": 30,
            "ppid": 10,
            "fileName": "msedge.exe",
            "scores": {"verdict": {"threatLevel": 2, "threatLevelText": "Phishing"}},
            "threatName": ["#PHISHING"],
        },
        {"uuid": "edge-noise", "pid": 31, "ppid": 10, "fileName": "msedge.exe"},
    ]
    process_details = svc._extract_process_details({}, processes)

    graph = svc._build_behavior_graph(
        processes=process_details,
        dns_requests=[],
        http_requests=[],
        connections=[],
    )

    labels = [n["label"] for n in graph["nodes"]]
    edge_pairs = {(e["source"], e["target"]) for e in graph["edges"]}

    assert labels.count("msedge.exe") == 1
    assert ("process:root", "process:edge-good") in edge_pairs
    assert ("process:root", "process:edge-noise") not in edge_pairs


def test_extract_process_details_does_not_assign_events_to_all_duplicate_process_names():
    processes = [
        {"uuid": "sv1", "pid": 101, "fileName": "svchost.exe"},
        {"uuid": "sv2", "pid": 102, "fileName": "svchost.exe"},
    ]
    connections = [
        {"pid": 101, "processName": "svchost.exe", "destinationIP": "1.2.3.4", "destinationPort": 443},
    ]

    process_details = svc._extract_process_details({}, processes, connections=connections)
    details_by_pid = {str(item["pid"]): item for item in process_details}

    assert details_by_pid["101"]["event_counts"]["connections"] == 1
    assert details_by_pid["102"]["event_counts"]["connections"] == 0


def test_extract_process_details_matches_uuid_stored_in_event_process_field():
    processes = [
        {"uuid": "edge-uuid", "pid": 8164, "fileName": "msedge.exe"},
    ]
    http_requests = [
        {"process": "edge-uuid", "url": "https://evil.example/login"},
    ]
    network_threats = [
        {"process": "edge-uuid", "processName": "msedge.exe", "priority": 2, "msg": "PHISHING [ANY.RUN] Suspected Phishing Domain"},
    ]

    process_details = svc._extract_process_details(
        {},
        processes,
        http_requests=http_requests,
        network_threats=network_threats,
    )

    assert process_details[0]["event_counts"]["http_requests"] == 1
    assert process_details[0]["event_counts"]["network_threats"] == 1


def test_lookup_anyrun_preserves_lookup_when_sandbox_parallel_limit(monkeypatch):
    _install_fake_anyrun_sdk(monkeypatch)

    class _Settings:
        anyrun_api_key = "ak"
        anyrun_api_key_fallback = ""
        anyrun_sandbox_os = "windows"
        anyrun_privacy_type = "owner"
        anyrun_timeout_url_domain_seconds = 45
        anyrun_timeout_file_hash_seconds = 90

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    monkeypatch.setattr(
        svc,
        "_lookup_intelligence",
        lambda *args, **kwargs: {
            "checked": True,
            "indicator_type": "url",
            "verdict": "clean",
            "analysis_id": "",
            "raw_summary": {"source": "anyrun", "mode": "lookup"},
        },
    )
    monkeypatch.setattr(
        svc,
        "_run_sandbox",
        lambda **kwargs: {
            "checked": False,
            "indicator_type": "url",
            "verdict": "unknown",
            "error": "ANY.RUN sandbox submission deferred: parallel task limit reached",
            "raw_summary": {"source": "anyrun"},
        },
    )

    out = svc.lookup_anyrun(
        indicator="https://example.test",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert out["checked"] is True
    assert out["verdict"] == "clean"
    assert out["raw_summary"]["mode"] == "lookup_deferred"
    assert out["raw_summary"]["sandbox_deferred"] is True
    assert "parallel task limit" in out["raw_summary"]["sandbox_error"]


def test_lookup_anyrun_preserves_lookup_when_sandbox_returns_null_payload(monkeypatch):
    _install_fake_anyrun_sdk(monkeypatch)

    class _Settings:
        anyrun_api_key = "ak"
        anyrun_api_key_fallback = ""
        anyrun_sandbox_os = "windows"
        anyrun_privacy_type = "owner"
        anyrun_timeout_url_domain_seconds = 45
        anyrun_timeout_file_hash_seconds = 90

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    monkeypatch.setattr(
        svc,
        "_lookup_intelligence",
        lambda *args, **kwargs: {
            "checked": True,
            "indicator_type": "url",
            "verdict": "clean",
            "analysis_id": "",
            "raw_summary": {"source": "anyrun", "mode": "lookup"},
        },
    )
    monkeypatch.setattr(
        svc,
        "_run_sandbox",
        lambda **kwargs: {
            "checked": False,
            "indicator_type": "url",
            "verdict": "unknown",
            "error": "ANY.RUN sandbox submission failed: provider returned an empty/invalid response (SDK null payload).",
            "raw_summary": {"source": "anyrun"},
        },
    )

    out = svc.lookup_anyrun(
        indicator="https://example.test",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert out["checked"] is True
    assert out["verdict"] == "clean"
    assert out["raw_summary"]["mode"] == "lookup_deferred"
    assert out["raw_summary"]["sandbox_deferred"] is True
    assert "empty/invalid response" in out["raw_summary"]["sandbox_error"]


def test_lookup_anyrun_uses_fallback_key_when_primary_is_parallel_limited(monkeypatch):
    _install_fake_anyrun_sdk(monkeypatch)

    class _Settings:
        anyrun_api_key = "ak-primary"
        anyrun_api_key_fallback = "ak-fallback"
        anyrun_sandbox_os = "windows"
        anyrun_privacy_type = "owner"
        anyrun_timeout_url_domain_seconds = 45
        anyrun_timeout_file_hash_seconds = 90

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(
        svc,
        "_lookup_intelligence",
        lambda *args, **kwargs: {
            "checked": True,
            "indicator_type": "url",
            "verdict": "clean",
            "analysis_id": "",
            "raw_summary": {"source": "anyrun", "mode": "lookup"},
        },
    )

    calls: list[str] = []

    def fake_run_sandbox(**kwargs):
        calls.append(kwargs["api_key"])
        if kwargs["api_key"] == "ak-primary":
            return {
                "checked": False,
                "indicator_type": "url",
                "verdict": "unknown",
                "error": "ANY.RUN sandbox submission deferred: parallel task limit reached",
                "raw_summary": {"source": "anyrun"},
            }
        return {
            "checked": True,
            "indicator_type": "url",
            "verdict": "malicious",
            "analysis_id": "task-fallback",
            "raw_summary": {"source": "anyrun", "mode": "sandbox"},
        }

    monkeypatch.setattr(svc, "_run_sandbox", fake_run_sandbox)

    out = svc.lookup_anyrun(
        indicator="https://example.test",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert calls == ["ak-primary", "ak-fallback"]
    assert out["checked"] is True
    assert out["verdict"] == "malicious"
    assert out["raw_summary"]["api_key_slot"] == "fallback"


def test_lookup_anyrun_does_not_use_fallback_key_for_non_deferred_primary_error(monkeypatch):
    _install_fake_anyrun_sdk(monkeypatch)

    class _Settings:
        anyrun_api_key = "ak-primary"
        anyrun_api_key_fallback = "ak-fallback"
        anyrun_sandbox_os = "windows"
        anyrun_privacy_type = "owner"
        anyrun_timeout_url_domain_seconds = 45
        anyrun_timeout_file_hash_seconds = 90

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(
        svc,
        "_lookup_intelligence",
        lambda *args, **kwargs: {
            "checked": True,
            "indicator_type": "url",
            "verdict": "clean",
            "analysis_id": "",
            "raw_summary": {"source": "anyrun", "mode": "lookup"},
        },
    )

    calls: list[str] = []

    def fake_run_sandbox(**kwargs):
        calls.append(kwargs["api_key"])
        return {
            "checked": False,
            "indicator_type": "url",
            "verdict": "unknown",
            "error": "ANY.RUN sandbox submission failed: provider returned 500",
            "raw_summary": {"source": "anyrun"},
        }

    monkeypatch.setattr(svc, "_run_sandbox", fake_run_sandbox)

    out = svc.lookup_anyrun(
        indicator="https://example.test",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert calls == ["ak-primary"]
    assert out["checked"] is False
    assert "provider returned 500" in out["error"]


def test_lookup_anyrun_attaches_domain_intelligence_to_first_domain_result(monkeypatch):
    _install_fake_anyrun_sdk(monkeypatch)

    class _Settings:
        anyrun_api_key = "ak"
        anyrun_api_key_fallback = ""
        anyrun_sandbox_os = "windows"
        anyrun_privacy_type = "owner"
        anyrun_timeout_url_domain_seconds = 45
        anyrun_timeout_file_hash_seconds = 90

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    def fake_lookup_intelligence(*args, **kwargs):
        if kwargs["indicator_type"] == "domain":
            return {
                "checked": True,
                "indicator_type": "domain",
                "verdict": "malicious",
                "analysis_id": "domain-task-1",
                "raw_summary": {"source": "anyrun", "mode": "lookup"},
            }
        return {
            "checked": True,
            "indicator_type": "url",
            "verdict": "malicious",
            "analysis_id": "url-task-1",
            "raw_summary": {"source": "anyrun", "mode": "lookup"},
        }

    monkeypatch.setattr(svc, "_lookup_intelligence", fake_lookup_intelligence)

    out = svc.lookup_anyrun(
        indicator="https://onvmbp01.onenet.be",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert out["checked"] is True
    assert out["analysis_id"] == "url-task-1"
    assert out["domain_intelligence"]["checked"] is True
    assert out["domain_intelligence"]["analysis_id"] == "domain-task-1"


def test_lookup_anyrun_marks_domain_intelligence_failure_explicitly(monkeypatch):
    _install_fake_anyrun_sdk(monkeypatch)

    class _Settings:
        anyrun_api_key = "ak"
        anyrun_api_key_fallback = ""
        anyrun_sandbox_os = "windows"
        anyrun_privacy_type = "owner"
        anyrun_timeout_url_domain_seconds = 45
        anyrun_timeout_file_hash_seconds = 90

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    def fake_lookup_intelligence(*args, **kwargs):
        if kwargs["indicator_type"] == "domain":
            return {
                "checked": False,
                "indicator_type": "domain",
                "verdict": "unknown",
                "error": "domain lookup timed out",
                "raw_summary": {"source": "anyrun", "mode": "lookup"},
            }
        return {
            "checked": True,
            "indicator_type": "url",
            "verdict": "malicious",
            "analysis_id": "url-task-1",
            "raw_summary": {"source": "anyrun", "mode": "lookup"},
        }

    monkeypatch.setattr(svc, "_lookup_intelligence", fake_lookup_intelligence)

    out = svc.lookup_anyrun(
        indicator="https://onvmbp01.onenet.be",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert out["checked"] is True
    assert out["domain_intelligence"]["checked"] is False
    assert "timed out" in out["domain_intelligence"]["error"]


def test_lookup_anyrun_keeps_lookup_and_sandbox_when_both_complete(monkeypatch):
    _install_fake_anyrun_sdk(monkeypatch)

    class _Settings:
        anyrun_api_key = "ak"
        anyrun_api_key_fallback = ""
        anyrun_sandbox_os = "windows"
        anyrun_privacy_type = "owner"
        anyrun_timeout_url_domain_seconds = 45
        anyrun_timeout_file_hash_seconds = 90

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    def fake_lookup_intelligence(*args, **kwargs):
        if kwargs["indicator_type"] == "domain":
            return {
                "checked": True,
                "indicator_type": "domain",
                "verdict": "malicious",
                "analysis_id": "domain-task-1",
                "raw_summary": {"source": "anyrun", "mode": "lookup"},
            }
        return {
            "checked": True,
            "indicator_type": "url",
            "verdict": "malicious",
            "analysis_id": "lookup-task-1",
            "raw_summary": {"source": "anyrun", "mode": "lookup"},
        }

    monkeypatch.setattr(svc, "_lookup_intelligence", fake_lookup_intelligence)
    monkeypatch.setattr(
        svc,
        "_run_anyrun_sandbox_with_fallback",
        lambda *args, **kwargs: {
            "checked": True,
            "indicator_type": "url",
            "verdict": "clean",
            "analysis_id": "sandbox-task-1",
            "raw_summary": {"source": "anyrun", "mode": "sandbox"},
        },
    )

    out = svc.lookup_anyrun(
        indicator="https://onvmbp01.onenet.be",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert out["checked"] is True
    assert out["analysis_id"] == "lookup-task-1"
    assert len(out["additional_items"]) == 1
    assert out["additional_items"][0]["analysis_id"] == "sandbox-task-1"
    assert out["additional_items"][0]["raw_summary"]["mode"] == "sandbox"


def test_anyrun_conflicting_clean_lookup_downgrades_opaque_malicious_sandbox():
    sandbox = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "malicious",
        "analysis_id": "sandbox-task-1",
        "raw_summary": {
            "source": "anyrun",
            "mode": "sandbox",
            "behavior_counts": {"network_threats": 0},
        },
    }
    lookup = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "clean",
        "threat_score": 0,
        "raw_summary": {"source": "anyrun", "mode": "lookup"},
    }

    out = svc._reconcile_anyrun_sandbox_lookup_verdict(sandbox, lookup)

    assert out["provider_verdict"] == "malicious"
    assert out["verdict"] == "suspicious"
    assert out["verdict_context"]["conflict"] is True
    assert out["verdict_context"]["final_verdict"] == "suspicious"
    assert out["verdict_context"]["evidence_reasons"] == []


def test_anyrun_conflicting_clean_lookup_retains_malicious_with_concrete_evidence():
    sandbox = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "malicious",
        "threat_score": 75,
        "analysis_id": "sandbox-task-1",
        "raw_summary": {
            "source": "anyrun",
            "mode": "sandbox",
            "threatName": ["phishing-kit"],
            "behavior_counts": {"network_threats": 1},
        },
    }
    lookup = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "clean",
        "threat_score": 0,
        "raw_summary": {"source": "anyrun", "mode": "lookup"},
    }

    out = svc._reconcile_anyrun_sandbox_lookup_verdict(sandbox, lookup)

    assert out["verdict"] == "malicious"
    assert out["verdict_context"]["conflict"] is True
    assert out["verdict_context"]["final_verdict"] == "malicious"
    assert out["verdict_context"]["evidence_reasons"]


def test_anyrun_conflicting_clean_lookup_retains_malicious_with_clickfix_tags():
    sandbox = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "malicious",
        "analysis_id": "sandbox-task-1",
        "raw_summary": {
            "source": "anyrun",
            "mode": "sandbox",
            "summary": {
                "tags": ["clickfix", "phishing", "obfuscated-js", "tds", "clearfake"],
                "tracker": "ClickFix",
            },
            "behavior_counts": {"network_threats": 0},
        },
    }
    lookup = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "clean",
        "threat_score": 0,
        "raw_summary": {"source": "anyrun", "mode": "lookup"},
    }

    out = svc._reconcile_anyrun_sandbox_lookup_verdict(sandbox, lookup)

    assert out["verdict"] == "malicious"
    assert out["verdict_context"]["final_verdict"] == "malicious"
    assert any("clickfix" in reason.lower() for reason in out["verdict_context"]["evidence_reasons"])


def test_extract_anyrun_html_threat_labels_from_report_chips():
    """
    Specific families are still scraped from the report; "phishing" no longer is.

    This test used to expect "phishing" here too. It cannot be honoured: the
    scraper matches substrings across the entire report page, so it has no way
    to tell this chip from the word in a nav menu or a filter dropdown. In the
    stored corpus it scraped "phishing" from 99 reports, 91 of them tasks
    ANY.RUN had marked "No threats detected".

    Nothing real is lost. Of 103 records carrying a phishing label, only 3 came
    from ANY.RUN's API rather than this scraper — and all 3 were on non-clean
    verdicts. The API field is precise and still feeds threatName; this scraper
    only ever needed to cover the specific families the JSON omits.
    """
    html = """
    <span class="tag">clickfix</span>
    <span class="tag">phishing</span>
    <span class="tag">exploit-kit</span>
    <span class="tag">obfuscated-js</span>
    <span class="tag">clearfake</span>
    """

    labels = svc._extract_anyrun_html_threat_labels(html)

    assert labels == ["clickfix", "clearfake", "exploit-kit", "obfuscated-js"]
    assert "phishing" not in labels


def test_extract_anyrun_screenshots_uses_thumbnail_only_as_preview():
    report_data = {
        "analysis": {"permanentUrl": "https://app.any.run/tasks/task-1"},
        "screenshots": [
            {
                "time": 8011,
                "permanentUrl": "https://content.any.run/tasks/task-1/download/screens/shot-1/image.jpeg",
                "thumbnailUrl": "https://content.any.run/tasks/task-1/download/thumbnails/shot-1/image.jpeg",
            }
        ],
    }

    screenshots = svc._extract_screenshot_thumbnails(report_data, "")

    assert screenshots == [
        {
            "label": "ANY.RUN sandbox screenshot",
            "url": "https://content.any.run/tasks/task-1/download/screens/shot-1/image.jpeg",
            "thumbnail_url": "https://content.any.run/tasks/task-1/download/thumbnails/shot-1/image.jpeg",
            "captured_at": 8011,
            "report_url": "https://app.any.run/tasks/task-1#Screenshots",
        }
    ]


def test_extract_anyrun_screenshots_reads_analysis_content_path():
    report_data = {
        "analysis": {
            "permanentUrl": "https://app.any.run/tasks/task-1",
            "content": {
                "screenshots": [
                    {
                        "uuid": "shot-1",
                        "time": 3193,
                        "permanentUrl": "https://content.any.run/tasks/task-1/download/screens/shot-1/image.jpeg",
                        "thumbnailUrl": "https://content.any.run/tasks/task-1/download/thumbnails/shot-1/image.jpeg",
                    }
                ]
            },
        }
    }

    screenshots = svc._extract_screenshot_thumbnails(report_data, "")

    assert len(screenshots) == 1
    assert screenshots[0]["url"].endswith("/download/screens/shot-1/image.jpeg")
    assert screenshots[0]["thumbnail_url"].endswith("/download/thumbnails/shot-1/image.jpeg")


def test_extract_anyrun_screenshots_supports_serialized_report_objects():
    report_data = {
        "screenshots": [
            "@{time=2980; uuid=shot-1; permanentUrl=https://content.any.run/tasks/task-1/download/screens/shot-1/image.jpeg; "
            "thumbnailUrl=https://content.any.run/tasks/task-1/download/thumbnails/shot-1/image.jpeg}"
        ]
    }

    screenshots = svc._extract_screenshot_thumbnails(report_data, "")

    assert screenshots[0]["url"].endswith("/download/screens/shot-1/image.jpeg")
    assert screenshots[0]["thumbnail_url"].endswith("/download/thumbnails/shot-1/image.jpeg")
    assert screenshots[0]["captured_at"] == "2980"


def test_extract_anyrun_html_threat_labels_ignores_generic_ui_words():
    html = """
    <script>const credentialField = true; const tds = window.trackingData;</script>
    <div>Enter your credential to continue. Internal TDS component.</div>
    <span class="tag">credential harvesting</span>
    <span class="tag">tdsshop</span>
    """

    labels = svc._extract_anyrun_html_threat_labels(html)

    assert "credential" not in labels
    assert "tds" not in labels
    assert labels == ["credential-harvesting", "tdsshop"]


def test_parallel_limit_error_helper_matches_provider_error_text():
    exc = Exception("[AnyRun Exception] Status code: 403. Description: Parallel task limit")
    assert svc._is_parallel_limit_error(exc) is True


def test_submission_fallback_candidate_matches_sdk_null_payload():
    exc = Exception("'NoneType' object has no attribute 'get'")
    assert svc._is_submission_fallback_candidate(exc) is True


def test_submission_fallback_candidate_matches_provider_plan_restriction():
    exc = Exception("[AnyRun Exception] Status code: 403. Description: API is not available on the free plan")
    assert svc._is_submission_fallback_candidate(exc) is True


def test_submit_anyrun_task_walks_named_privacy_levels_on_plan_restriction(monkeypatch):
    """
    The fallback names each privacy level instead of omitting the argument.

    Omitting it lets the SDK apply its own default, which is `bylink` — a level
    this plan forbids — so the retry was guaranteed to fail with the same 403
    it was retrying, and the reported error was that guaranteed failure rather
    than the original one.
    """
    class _Settings:
        anyrun_parallel_limit_retries = 0
        anyrun_parallel_backoff_seconds = 0
        anyrun_transient_retries = 0
        anyrun_transient_backoff_seconds = 0

    class _Connector:
        def __init__(self):
            self.calls = []

        def run_url_analysis(self, target, opt_privacy_type=None, opt_automated_interactivity=None):
            self.calls.append((target, opt_privacy_type, opt_automated_interactivity))
            if opt_privacy_type == "owner":
                raise RuntimeError("[AnyRun Exception] Status code: 403. Description: API is not available on the free plan")
            return "task-ok"

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    connector = _Connector()

    out = svc._submit_anyrun_task_with_fallback(
        connector=connector,
        indicator="example.test",
        indicator_type="url",
        privacy_type="owner",
        file_bytes=None,
        file_name=None,
    )

    assert out == "task-ok"
    assert connector.calls == [
        ("https://example.test", "owner", True),
        ("https://example.test", "byteam", True),
    ]
    # `public` is never reached automatically: publishing a customer's sample to
    # a public feed is a disclosure decision, not a fallback.
    assert "public" not in [call[1] for call in connector.calls]


def test_submit_anyrun_task_reports_the_providers_own_error_text(monkeypatch):
    """
    A failure names what ANY.RUN said, not what our SDK wrapper felt like.

    This previously returned "provider returned an empty/invalid response
    (SDK null payload)" — a description of a bug in a component that was
    working, while the provider's actual answer said which setting to change.
    """
    class _Settings:
        anyrun_parallel_limit_retries = 0
        anyrun_parallel_backoff_seconds = 0
        anyrun_transient_retries = 0
        anyrun_transient_backoff_seconds = 0

    class _ProviderError(RuntimeError):
        status_code = 403
        description = "Chosen privacy type is unavailable due to plan limits or team privacy settings"

    class _Connector:
        def run_url_analysis(self, target, **kwargs):
            raise _ProviderError("[AnyRun Exception] Status code: 403.")

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    out = svc._submit_anyrun_task_with_fallback(
        connector=_Connector(),
        indicator="example.test",
        indicator_type="url",
        privacy_type="owner",
        file_bytes=None,
        file_name=None,
    )

    assert "Chosen privacy type is unavailable" in out["__error__"]
    assert "403" in out["__error__"]
    assert "SDK null payload" not in out["__error__"]
    # The levels that were tried, so the next step is obvious from the message.
    assert "owner" in out["__error__"] and "byteam" in out["__error__"]


def test_sandbox_slot_admits_one_task_at_a_time(monkeypatch):
    """
    The plan allows one task at a time, so tasks queue rather than race.

    The email pipeline sends the .eml and its URLs together; without this they
    collided on the single slot and lost to "403 Parallel task limit".
    """
    import threading as _threading

    class _Settings:
        anyrun_max_parallel_submissions = 1

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    svc._SUBMISSION_GATE_STATE.clear()

    overlap_seen = []
    in_flight = 0
    guard = _threading.Lock()

    def run_one():
        nonlocal in_flight
        with svc._serialised_submission(30) as acquired:
            assert acquired is True
            with guard:
                in_flight += 1
                overlap_seen.append(in_flight)
            time.sleep(0.05)
            with guard:
                in_flight -= 1

    threads = [_threading.Thread(target=run_one) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert overlap_seen == [1, 1, 1, 1], f"tasks overlapped: {overlap_seen}"


def test_sandbox_slot_is_released_when_the_task_raises(monkeypatch):
    """A failed task must not strand the slot — the next one would never run."""
    class _Settings:
        anyrun_max_parallel_submissions = 1

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    svc._SUBMISSION_GATE_STATE.clear()

    try:
        with svc._serialised_submission(5) as acquired:
            assert acquired is True
            raise RuntimeError("submission blew up")
    except RuntimeError:
        pass

    with svc._serialised_submission(2) as acquired:
        assert acquired is True, "the slot was never released"


def test_submit_anyrun_task_adds_residential_proxy_geo_when_country_selected(monkeypatch):
    class _Settings:
        anyrun_parallel_limit_retries = 0
        anyrun_parallel_backoff_seconds = 0
        anyrun_transient_retries = 0
        anyrun_transient_backoff_seconds = 0
        anyrun_url_sandbox_analysis_timeout = 120
        anyrun_url_sandbox_mitm = True

    class _Connector:
        def __init__(self):
            self.calls = []

        def run_url_analysis(self, target, **kwargs):
            self.calls.append((target, kwargs))
            return "task-ok"

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    connector = _Connector()

    out = svc._submit_anyrun_task_with_fallback(
        connector=connector,
        indicator="example.test",
        indicator_type="url",
        privacy_type="owner",
        file_bytes=None,
        file_name=None,
        use_residential_proxy=True,
        proxy_country="US",
    )

    assert out == "task-ok"
    assert connector.calls[0][0] == "https://example.test"
    assert connector.calls[0][1]["opt_automated_interactivity"] is True
    assert connector.calls[0][1]["opt_network_residential_proxy"] is True
    assert connector.calls[0][1]["opt_network_residential_proxy_geo"] == "US"


def test_submit_anyrun_task_omits_residential_proxy_when_disabled(monkeypatch):
    class _Settings:
        anyrun_parallel_limit_retries = 0
        anyrun_parallel_backoff_seconds = 0
        anyrun_transient_retries = 0
        anyrun_transient_backoff_seconds = 0
        anyrun_url_sandbox_analysis_timeout = 120
        anyrun_url_sandbox_mitm = True

    class _Connector:
        def __init__(self):
            self.calls = []

        def run_url_analysis(self, target, **kwargs):
            self.calls.append((target, kwargs))
            return "task-ok"

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    connector = _Connector()

    out = svc._submit_anyrun_task_with_fallback(
        connector=connector,
        indicator="example.test",
        indicator_type="url",
        privacy_type="owner",
        file_bytes=None,
        file_name=None,
        use_residential_proxy=False,
        proxy_country=None,
    )

    assert out == "task-ok"
    assert "opt_network_residential_proxy" not in connector.calls[0][1]
    assert "opt_network_residential_proxy_geo" not in connector.calls[0][1]
    assert connector.calls[0][1]["opt_automated_interactivity"] is True


def test_submit_anyrun_task_uses_fastest_geo_when_residential_enabled_without_country(monkeypatch):
    class _Settings:
        anyrun_parallel_limit_retries = 0
        anyrun_parallel_backoff_seconds = 0
        anyrun_transient_retries = 0
        anyrun_transient_backoff_seconds = 0
        anyrun_url_sandbox_analysis_timeout = 120
        anyrun_url_sandbox_mitm = True

    class _Connector:
        def __init__(self):
            self.calls = []

        def run_url_analysis(self, target, **kwargs):
            self.calls.append((target, kwargs))
            return "task-ok"

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    connector = _Connector()

    out = svc._submit_anyrun_task_with_fallback(
        connector=connector,
        indicator="example.test",
        indicator_type="url",
        privacy_type="owner",
        file_bytes=None,
        file_name=None,
        use_residential_proxy=True,
        proxy_country=None,
    )

    assert out == "task-ok"
    assert connector.calls[0][1]["opt_network_residential_proxy"] is True
    assert connector.calls[0][1]["opt_network_residential_proxy_geo"] == "fastest"


def test_submit_anyrun_file_task_adds_residential_proxy(monkeypatch):
    class _Settings:
        anyrun_parallel_limit_retries = 0
        anyrun_parallel_backoff_seconds = 0
        anyrun_transient_retries = 0
        anyrun_transient_backoff_seconds = 0

    class _Connector:
        def __init__(self):
            self.calls = []

        def run_file_analysis(self, **kwargs):
            self.calls.append(kwargs)
            return "task-ok"

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    connector = _Connector()

    out = svc._submit_anyrun_task_with_fallback(
        connector=connector,
        indicator="sha256",
        indicator_type="hash",
        privacy_type="owner",
        file_bytes=b"sample",
        file_name="sample.bin",
        use_residential_proxy=True,
        proxy_country="gb",
    )

    assert out == "task-ok"
    assert connector.calls[0]["opt_network_residential_proxy"] is True
    assert connector.calls[0]["opt_network_residential_proxy_geo"] == "GB"
    assert connector.calls[0]["opt_automated_interactivity"] is True


def test_submit_anyrun_task_fails_closed_when_sdk_cannot_enable_interactivity(monkeypatch):
    class _Settings:
        anyrun_parallel_limit_retries = 0
        anyrun_parallel_backoff_seconds = 0
        anyrun_transient_retries = 0
        anyrun_transient_backoff_seconds = 0
        anyrun_url_sandbox_analysis_timeout = 120
        anyrun_url_sandbox_mitm = True

    class _OutdatedConnector:
        def run_url_analysis(self, target, opt_timeout=120):
            return "task-should-not-run"

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    out = svc._submit_anyrun_task_with_fallback(
        connector=_OutdatedConnector(),
        indicator="example.test",
        indicator_type="url",
        privacy_type="owner",
        file_bytes=None,
        file_name=None,
    )

    assert "required Enterprise sandbox option" in out["__error__"]
    assert "opt_automated_interactivity" in out["__error__"]


def test_transient_provider_error_matches_unknown_error():
    exc = Exception("[AnyRun Exception] Status code: 500. Description: Unknown error")
    assert svc._is_transient_provider_error(exc) is True


def test_normalize_submission_url_adds_https_for_bare_domain():
    assert svc._normalize_submission_url("example.test") == "https://example.test"
    assert svc._normalize_submission_url("http://example.test") == "http://example.test"
    assert svc._normalize_submission_url("https:example.test") == "https://example.test"


def test_wait_status_stream_returns_completed_status():
    class _Connector:
        def get_task_status(self, task_id):
            yield {"status": "RUNNING"}
            yield {"status": "COMPLETED"}

    assert svc._wait_status_stream(_Connector(), "task-1", timeout_seconds=30) == "COMPLETED"


def test_run_sandbox_returns_report_not_ready_when_task_still_running(monkeypatch):
    class _Connector:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def run_url_analysis(self, target, opt_privacy_type=None, opt_automated_interactivity=None):
            assert opt_automated_interactivity is True
            return "task-1"

        def get_task_status(self, task_id):
            yield {"status": "RUNNING"}

        def get_analysis_report(self, analysis_id, report_format="summary"):
            return {"data": {"status": "running"}}

        def get_analysis_verdict(self, analysis_id):
            raise AttributeError("'NoneType' object has no attribute 'get'")

    monkeypatch.setattr(svc, "_create_sandbox_connector", lambda *args, **kwargs: _Connector())

    out = svc._run_sandbox(
        sandbox_connector_cls=object(),
        api_key="ak",
        sandbox_os="windows",
        privacy_type="owner",
        indicator="example.test",
        indicator_type="url",
        file_bytes=None,
        file_name=None,
        timeout_seconds=45,
    )

    assert out["checked"] is False
    assert out["error"] == "ANY.RUN sandbox task is still running and the report is not ready yet."


def test_run_sandbox_uses_completed_report_after_wait(monkeypatch):
    class _Connector:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def run_url_analysis(self, target, opt_privacy_type=None, opt_automated_interactivity=None):
            assert opt_automated_interactivity is True
            return "task-1"

        def get_task_status(self, task_id):
            yield {"status": "RUNNING"}
            yield {"status": "COMPLETED"}

        def get_analysis_verdict(self, analysis_id):
            return "No threats detected"

        def get_analysis_report(self, analysis_id, report_format="summary"):
            if report_format == "summary":
                return {
                    "data": {
                        "status": "completed",
                        "analysis": {"permanentUrl": "https://app.any.run/tasks/task-1", "scores": {}},
                        "network": {"dnsRequests": [], "httpRequests": [], "connections": [], "threats": []},
                        "counters": {},
                        "processes": [],
                        "summary": {},
                    }
                }
            if report_format == "ioc":
                return {"data": []}
            return ""

    monkeypatch.setattr(svc, "_create_sandbox_connector", lambda *args, **kwargs: _Connector())

    out = svc._run_sandbox(
        sandbox_connector_cls=object(),
        api_key="ak",
        sandbox_os="windows",
        privacy_type="owner",
        indicator="example.test",
        indicator_type="url",
        file_bytes=None,
        file_name=None,
        timeout_seconds=45,
    )

    assert out["checked"] is True
    assert out["verdict"] == "clean"
    assert out["analysis_id"] == "task-1"


def test_run_sandbox_retries_summary_report_without_explicit_format(monkeypatch):
    class _Connector:
        def __init__(self):
            self.report_calls = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def run_url_analysis(self, target, opt_privacy_type=None, opt_automated_interactivity=None):
            assert opt_automated_interactivity is True
            return "task-1"

        def get_task_status(self, task_id):
            yield {"status": "COMPLETED"}

        def get_analysis_verdict(self, analysis_id):
            return "No threats detected"

        def get_analysis_report(self, analysis_id, report_format=None):
            self.report_calls.append(report_format)
            if report_format == "summary":
                raise RuntimeError("[AnyRun Exception] Status code: 400. Description: Invalid summary type.")
            if report_format == "ioc":
                return {"data": []}
            if report_format == "html":
                return ""
            return {
                "data": {
                    "status": "completed",
                    "analysis": {"permanentUrl": "https://app.any.run/tasks/task-1", "scores": {}},
                    "network": {"dnsRequests": [], "httpRequests": [], "connections": [], "threats": []},
                    "counters": {},
                    "processes": [],
                    "summary": {},
                }
            }

    connector = _Connector()
    monkeypatch.setattr(svc, "_create_sandbox_connector", lambda *args, **kwargs: connector)

    out = svc._run_sandbox(
        sandbox_connector_cls=object(),
        api_key="ak",
        sandbox_os="windows",
        privacy_type="owner",
        indicator="example.test",
        indicator_type="url",
        file_bytes=None,
        file_name=None,
        timeout_seconds=45,
    )

    assert out["checked"] is True
    assert out["verdict"] == "clean"
    assert out["analysis_id"] == "task-1"
    assert connector.report_calls[:2] == ["summary", None]


def test_run_sandbox_defers_rather_than_queueing_forever(monkeypatch):
    """
    A task that cannot get the slot in time defers instead of parking.

    Serialising must not create a new way to hang: the slot is held for a whole
    analysis, so threads behind it need a bounded wait and an exit the rest of
    the pipeline already understands.
    """
    class _Settings:
        anyrun_max_parallel_submissions = 1
        anyrun_submission_queue_wait_seconds = 1
        anyrun_max_upload_mb = 100

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    svc._SUBMISSION_GATE_STATE.clear()

    class _NeverReached:
        @staticmethod
        def windows(api_key):
            raise AssertionError("no connector should be created without the slot")

    # Occupy the only slot, then try to run a second task behind it.
    with svc._serialised_submission(5) as acquired:
        assert acquired is True
        out = svc._run_sandbox(
            sandbox_connector_cls=_NeverReached,
            api_key="k",
            sandbox_os="windows",
            privacy_type="owner",
            indicator="https://bad.example",
            indicator_type="url",
            file_bytes=None,
            file_name=None,
            timeout_seconds=45,
        )

    assert out["checked"] is False
    assert "deferred" in str(out["error"])
    # The deferred wording is what preserves the lookup half of the result.
    assert svc._is_deferred_anyrun_sandbox_error(out["error"]) is True


def test_privacy_plan_restriction_is_treated_as_deferred():
    """
    A forbidden privacy level is permanent for this key but not for the fallback
    key, which may sit on a different plan — so the result stays retryable and
    the lookup half is kept.
    """
    message = (
        "ANY.RUN sandbox submission failed: HTTP 403: Chosen privacy type is unavailable "
        "due to plan limits or team privacy settings (tried privacy levels: owner, byteam, bylink)"
    )
    assert svc._is_deferred_anyrun_sandbox_error(message) is True


# ── Fabricated threat labels ──────────────────────────────────────────────────

def test_no_html_marker_is_a_generic_word():
    """
    The marker test is a substring search over ANY.RUN's whole report page, so a
    generic word matches on essentially every report regardless of verdict.

    This has regressed twice already — "credential" and "tds" were removed, then
    "phishing" was left in and scraped from 99 reports, 91 of which ANY.RUN had
    called "No threats detected". Enforcing it here is what stops a third time.
    """
    for marker, label in svc._ANYRUN_HTML_THREAT_MARKERS:
        assert marker.strip().lower() not in svc._GENERIC_LABEL_WORDS, (
            f"marker {marker!r} is too generic for a document-wide substring match"
        )
        assert label.strip().lower() not in svc._GENERIC_LABEL_WORDS, (
            f"label {label!r} is too generic for a document-wide substring match"
        )


def test_html_threat_labels_ignores_the_word_phishing_in_page_furniture():
    """A word in the UI chrome is not a verdict about the sample."""
    html = """
      <html><head><title>ANY.RUN sandbox report</title></head>
      <body>
        <nav><ul><li>All</li><li>Phishing</li><li>Trojan</li><li>Ransomware</li></ul></nav>
        <select id="tag-filter"><option value="phishing">phishing</option></select>
        <script>const CATEGORIES = ["phishing","stealer","malware"];</script>
        <div class="verdict">No threats detected</div>
      </body></html>
    """
    assert svc._extract_anyrun_html_threat_labels(html) == []


def test_html_threat_labels_still_finds_specific_families():
    """The specific markers are the reason the scraper exists — keep them working."""
    html = "<div class='chip'>ClickFix</div><div class='chip'>Fake CAPTCHA</div>"
    labels = svc._extract_anyrun_html_threat_labels(html)
    assert "clickfix" in labels
    assert "fake-captcha" in labels


# ── Informational Suricata events are not threats ─────────────────────────────

def test_informational_suricata_events_are_not_threats():
    """
    "INFO [ANY.RUN] Google Tag Manager analytics", classed "Not Suspicious
    Traffic", is a note that ordinary traffic happened — not a finding.
    """
    benign = {
        "msg": "INFO [ANY.RUN] Google Tag Manager analytics (googletagmanager .com)",
        "class": "Not Suspicious Traffic",
        "priority": 3,
        "pro": 0,
    }
    assert svc._is_significant_network_threat(benign) is False


def test_real_suricata_findings_are_kept():
    for threat in (
        {"msg": "ET MALWARE Observed DNS Query", "class": "A Network Trojan was detected", "priority": 1},
        {"msg": "ET EXPLOIT Kit Landing", "class": "Exploit Kit Activity Detected", "priority": 1},
        {"msg": "ET PHISHING Landing Page", "class": "Possible Social Engineering Attempted", "priority": 2},
    ):
        assert svc._is_significant_network_threat(threat) is True, threat


def test_unknown_high_priority_class_is_kept():
    """An unfamiliar class we have never seen must not be dropped silently."""
    assert svc._is_significant_network_threat(
        {"msg": "Something new", "class": "Brand New Category", "priority": 1}
    ) is True


def test_split_network_threats_keeps_informational_events_rather_than_discarding_them():
    threats = [
        {"msg": "INFO [ANY.RUN] analytics", "class": "Not Suspicious Traffic", "priority": 3},
        {"msg": "ET MALWARE beacon", "class": "A Network Trojan was detected", "priority": 1},
    ]
    significant, informational = svc._split_network_threats(threats)
    assert len(significant) == 1 and significant[0]["class"] == "A Network Trojan was detected"
    assert len(informational) == 1


def test_all_informational_task_reports_zero_threats_not_the_raw_counter(monkeypatch):
    """
    The count must not fall back to ANY.RUN's unfiltered total.

    behavior_counts sits next to fields that use `len(x) or counters[...]`. With
    filtering, an all-informational task makes that len() zero, and the `or`
    would hand back the raw count — reporting exactly the number the filter
    exists to suppress.
    """
    class _Connector:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def run_url_analysis(self, target, **kwargs):
            return "task-1"

        def get_task_status(self, task_id):
            yield {"status": "COMPLETED"}

        def get_analysis_verdict(self, analysis_id):
            return "No threats detected"

        def get_analysis_report(self, analysis_id, report_format="summary"):
            if report_format == "ioc":
                return {"data": []}
            if report_format == "html":
                return "<html><body>filter: phishing</body></html>"
            return {
                "data": {
                    "status": "completed",
                    "analysis": {"permanentUrl": "https://app.any.run/tasks/task-1", "scores": {}},
                    "network": {
                        "dnsRequests": [], "httpRequests": [], "connections": [],
                        "threats": [
                            {"msg": "INFO [ANY.RUN] Google Tag Manager analytics",
                             "class": "Not Suspicious Traffic", "priority": 3, "pro": 0},
                            {"msg": "INFO [ANY.RUN] Google Tag Manager analytics",
                             "class": "Not Suspicious Traffic", "priority": 3, "pro": 0},
                            {"msg": "INFO [ANY.RUN] Google Tag Manager analytics",
                             "class": "Not Suspicious Traffic", "priority": 3, "pro": 0},
                        ],
                    },
                    "counters": {"threats": 3},
                    "processes": [],
                    "summary": {},
                }
            }

    monkeypatch.setattr(svc, "_create_sandbox_connector", lambda *a, **k: _Connector())

    out = svc._run_sandbox(
        sandbox_connector_cls=object(), api_key="ak", sandbox_os="windows",
        privacy_type="owner", indicator="patromil.test", indicator_type="url",
        file_bytes=None, file_name=None, timeout_seconds=45,
    )

    raw = out["raw_summary"]
    assert out["verdict"] == "clean"
    assert raw["behavior_counts"]["network_threats"] == 0, "raw counter leaked through"
    assert raw["behavior_counts"]["network_informational_events"] == 3
    assert raw["behavior_details"]["network_threats"] == []
    # And the clean run must not pick up a fabricated label from page furniture.
    assert raw["html_threat_labels"] == []
    assert "phishing" not in [str(t).lower() for t in raw.get("threatName") or []]


def test_clean_run_with_only_informational_events_offers_no_malicious_reasons():
    """
    The end of the chain: with the label gone and the events reclassified, there
    is nothing left to argue the sample was malicious.
    """
    result = {
        "verdict": "clean",
        "raw_summary": {
            "verdict_text": "No threats detected",
            "tags": [],
            "threatName": [],
            "behavior_counts": {"network_threats": 0, "network_informational_events": 3},
            "behavior_details": {"network_threats": []},
        },
    }
    assert svc._anyrun_concrete_sandbox_reasons(result) == []
