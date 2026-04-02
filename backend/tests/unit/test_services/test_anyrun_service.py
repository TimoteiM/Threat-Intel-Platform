from __future__ import annotations

import sys
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


def test_build_behavior_graph_does_not_keep_descendant_noise_from_inherited_suspicion():
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
    assert "ShellExperienceHost.exe" not in labels
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
    assert "Windows system chain (5 processes)" in labels
    assert "svchost.exe" not in labels
    assert "conhost.exe" not in labels


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
    assert "Windows system chain (3 processes)" in labels
    assert "msedge.exe" not in labels
    assert "conhost.exe" not in labels


def test_build_behavior_graph_prefers_single_strongest_suspicious_branch():
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

    assert labels.count("cmd.exe") == 1
    assert "mshta.exe" not in labels
    assert labels.count("powershell.exe") == 1
    assert ("process:cmd-high", "process:high") in edge_pairs
    assert ("process:cmd-low", "process:low") not in edge_pairs


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


def test_parallel_limit_error_helper_matches_provider_error_text():
    exc = Exception("[AnyRun Exception] Status code: 403. Description: Parallel task limit")
    assert svc._is_parallel_limit_error(exc) is True


def test_submission_fallback_candidate_matches_sdk_null_payload():
    exc = Exception("'NoneType' object has no attribute 'get'")
    assert svc._is_submission_fallback_candidate(exc) is True


def test_submission_fallback_candidate_matches_provider_plan_restriction():
    exc = Exception("[AnyRun Exception] Status code: 403. Description: API is not available on the free plan")
    assert svc._is_submission_fallback_candidate(exc) is True


def test_submit_anyrun_task_retries_without_privacy_on_provider_plan_restriction(monkeypatch):
    class _Settings:
        anyrun_parallel_limit_retries = 0
        anyrun_parallel_backoff_seconds = 0
        anyrun_transient_retries = 0
        anyrun_transient_backoff_seconds = 0

    class _Connector:
        def __init__(self):
            self.calls = []

        def run_url_analysis(self, target, opt_privacy_type=None):
            self.calls.append((target, opt_privacy_type))
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
        ("https://example.test", "owner"),
        ("https://example.test", None),
    ]


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

        def run_url_analysis(self, target, opt_privacy_type=None):
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

        def run_url_analysis(self, target, opt_privacy_type=None):
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
