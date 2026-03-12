from __future__ import annotations

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
    assert "domain:evil.example" in ids
    assert "ip:1.2.3.4" in ids
    assert "url:https://evil.example/login" in ids

    edge_pairs = {(e["source"], e["target"]) for e in graph["edges"]}
    assert ("process:p1", "domain:evil.example") in edge_pairs
    assert ("process:p1", "url:https://evil.example/login") in edge_pairs
    assert ("process:p1", "ip:1.2.3.4") in edge_pairs
