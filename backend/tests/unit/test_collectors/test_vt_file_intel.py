from __future__ import annotations

from types import SimpleNamespace

from app.collectors.vt_collector import VTCollector
from app.tasks.analysis_task import _build_iocs_from_evidence, _generate_automated_report


class _MockResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload
        self.text = ""

    def json(self) -> dict:
        return self._payload


def test_vt_hash_parses_malware_family_and_yara(monkeypatch):
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 1,
                    "harmless": 20,
                    "undetected": 51,
                },
                "last_analysis_results": {},
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan",
                    "popular_threat_name": [
                        {"value": "AgentTesla", "count": 2},
                        {"value": "agenttesla", "count": 1},
                    ],
                },
                "crowdsourced_yara_results": [
                    {"ruleset_name": "community", "rule_name": "AgentTesla_Generic"},
                    {"ruleset_name": "community", "rule_name": "AgentTesla_Generic"},
                ],
            }
        }
    }

    monkeypatch.setattr(
        "app.collectors.vt_collector.get_settings",
        lambda: SimpleNamespace(virustotal_api_key="test-key"),
    )
    monkeypatch.setattr(
        "app.collectors.vt_collector.requests.get",
        lambda *args, **kwargs: _MockResponse(200, payload),
    )

    collector = VTCollector(
        domain="46a18bce8e2ff662b700c91d340a519376e712fe0af0d335536e4f9fd253f10a",
        investigation_id="test-001",
        observable_type="hash",
    )
    evidence, meta, _ = collector.run()

    assert meta.status.value == "completed"
    assert evidence.malware_family_names == ["AgentTesla", "trojan"]
    assert evidence.yara_rule_matches == ["community:AgentTesla_Generic"]


def test_fast_path_uses_family_and_yara_as_technical_evidence():
    evidence = {
        "domain": "46a18bce8e2ff662b700c91d340a519376e712fe0af0d335536e4f9fd253f10a",
        "vt": {
            "found": True,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_vendors": 72,
            "malware_family_names": ["Lumma"],
            "yara_rule_matches": ["community:Infostealer_Lumma"],
        },
    }

    report = _generate_automated_report(evidence, "hash")
    iocs = _build_iocs_from_evidence(evidence, "hash")

    assert report.get("schema_version")
    assert report["classification"] == "suspicious"
    assert any("Malware family tags:" in line for line in report["key_evidence"])
    assert any("YARA matches:" in line for line in report["key_evidence"])
    assert any(ioc["type"] == "malware_family" and ioc["value"] == "Lumma" for ioc in iocs)
    assert any(
        ioc["type"] == "yara_rule" and ioc["value"] == "community:Infostealer_Lumma"
        for ioc in iocs
    )
