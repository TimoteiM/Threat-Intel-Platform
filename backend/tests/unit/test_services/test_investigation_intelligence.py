from __future__ import annotations

from app.services.investigation_intelligence import build_investigation_intelligence


def test_build_investigation_intelligence_derives_soc_sections() -> None:
    evidence = {
        "domain": "agence-immobiliere-lyon.com",
        "observable_type": "domain",
        "dns": {
            "meta": {"collector": "dns", "status": "completed", "completed_at": "2026-05-05T08:00:00+00:00"},
            "a": ["203.0.113.10"],
            "ns": ["ns1.example.net"],
        },
        "vt": {
            "meta": {"collector": "vt", "status": "completed"},
            "found": True,
            "malicious_count": 4,
            "suspicious_count": 1,
            "total_vendors": 80,
            "last_analysis_date": "2026-05-05T08:10:00+00:00",
        },
        "hybrid_analysis": {
            "items": [
                {
                    "verdict": "malicious",
                    "analysis_id": "task-1",
                    "threat_score": 90,
                    "sandbox_intelligence": {
                        "summary": {
                            "analysis_id": "task-1",
                            "verdict": "malicious",
                            "threat_score": 90,
                            "process_count": 2,
                            "contacted_host_count": 1,
                            "suspicious_command_count": 1,
                        },
                        "process_tree_summary": {
                            "root_processes": [{"name": "explorer.exe", "pid": "1"}],
                            "high_risk_processes": [{"name": "msedge.exe", "pid": "736", "risk_rank": 12}],
                        },
                        "contacted_hosts": [{"host": "bad.example", "source": "HTTP request", "threat_level": 2}],
                        "contacted_ips": [{"ip": "198.51.100.22", "port": "443", "threat_level": 2}],
                        "dropped_files": [{"path": "C:\\Temp\\dropper.exe", "sha256": "a" * 64}],
                        "suspicious_commands": [{"process": "msedge.exe", "command_line": "powershell -enc AAA", "reason": "encoded command"}],
                        "extracted_iocs": [{"type": "url", "value": "https://bad.example/payload", "source": "anyrun", "confidence": "high"}],
                    },
                }
            ]
        },
        "opencti": {
            "found": True,
            "score": 80,
            "observable_id": "obs-1",
            "standard_id": "url--1",
            "observable_entity_type": "Url",
            "observable_value": "https://agence-immobiliere-lyon.com",
            "labels": ["clickfix"],
            "notes": ["Matched via search term: 'https://agence-immobiliere-lyon.com'"],
            "indicators": [{"id": "ind-1", "pattern": "[url:value = 'https://agence-immobiliere-lyon.com']"}],
            "reports": [{"id": "rep-1", "name": "Abuse.ch URLhaus", "published": "2026-05-05T07:55:00+00:00"}],
            "threat_actors": [],
            "malware_families": [{"id": "mw-1", "name": "ClickFix"}],
            "attack_patterns": [{"id": "ap-1", "name": "Command and Scripting Interpreter", "mitre_id": "T1059"}],
            "campaigns": [],
            "intrusion_sets": [],
        },
    }
    report = {
        "classification": "malicious",
        "confidence": "high",
        "risk_score": 90,
        "primary_reasoning": "AnyRun and OpenCTI both identify malicious activity.",
        "iocs": [{"type": "domain", "value": "agence-immobiliere-lyon.com", "context": "Primary", "confidence": "high"}],
    }
    detail = {
        "id": "case-1",
        "domain": "agence-immobiliere-lyon.com",
        "observable_type": "domain",
        "created_at": "2026-05-05T07:50:00+00:00",
        "concluded_at": "2026-05-05T08:20:00+00:00",
        "classification": "malicious",
        "risk_score": 90,
    }

    out = build_investigation_intelligence(evidence=evidence, report=report, detail=detail)

    assert out["confidence_engine"]["verdict"] == "malicious"
    assert out["confidence_engine"]["confidence"] == "high"
    assert out["opencti_resolver"]["status"] == "matched"
    assert out["opencti_resolver"]["matched_term"] == "https://agence-immobiliere-lyon.com"
    assert out["ioc_quality"]["summary"]["actionable_count"] >= 3
    assert any(event["source"] == "anyrun" for event in out["evidence_timeline"])
    assert any(node["type"] == "malware" for node in out["investigation_graph"]["nodes"])
    assert out["soc_report_builder"]["readiness_score"] >= 70
