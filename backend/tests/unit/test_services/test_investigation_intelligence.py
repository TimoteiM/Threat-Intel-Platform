from __future__ import annotations

from app.services.investigation_intelligence import (
    build_evidence_matrix_rows,
    build_investigation_intelligence,
)


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
        "signals": [
            {
                "id": "vt-detection",
                "category": "reputation",
                "description": "VirusTotal vendors flagged the observable.",
                "severity": "warning",
                "evidence_refs": ["vt.malicious_count"],
            }
        ],
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
    assert "OpenCTI Resolution" not in [section["title"] for section in out["soc_report_builder"]["sections"]]
    assert "Unified Evidence Timeline" not in [section["title"] for section in out["soc_report_builder"]["sections"]]
    assert out["soc_report_builder"]["evidence_matrix"]
    assert out["soc_report_builder"]["preview"]["evidence_matrix"]


def test_ioc_quality_does_not_escalate_low_risk_verdict() -> None:
    evidence = {
        "domain": "securdoccle-itffjyqdi.k9p4mt-7q2v.com",
        "observable_type": "domain",
        "final_risk": {
            "risk_score": 12,
            "risk_level": "low",
            "rationale": ["No strong malicious signal; monitor and corroborate with external context"],
        },
        "vt": {
            "found": True,
            "malicious_count": 3,
            "suspicious_count": 0,
            "total_vendors": 91,
            "reputation_score": 0,
        },
        "urlscan": {
            "verdict": "unknown",
            "score": 0,
        },
        "hybrid_analysis": {
            "items": [
                {
                    "verdict": "unknown",
                    "threat_score": 8,
                    "sandbox_intelligence": {
                        "summary": {
                            "verdict": "unknown",
                            "threat_score": 8,
                            "process_count": 169,
                            "contacted_host_count": 26,
                            "suspicious_command_count": 1,
                        },
                        "extracted_iocs": [
                            {
                                "type": "domain",
                                "value": f"ioc-{idx}.example",
                                "source": "anyrun",
                                "context": "contacted host",
                                "confidence": "high",
                            }
                            for idx in range(12)
                        ],
                    },
                }
            ],
        },
    }
    report = {
        "classification": "suspicious",
        "confidence": "medium",
        "risk_score": 15,
        "primary_reasoning": "Low-confidence suspicious activity with limited corroboration.",
    }
    detail = {
        "domain": "securdoccle-itffjyqdi.k9p4mt-7q2v.com",
        "observable_type": "domain",
        "classification": "suspicious",
        "risk_score": 15,
    }

    out = build_investigation_intelligence(evidence=evidence, report=report, detail=detail)
    confidence = out["confidence_engine"]
    ioc_component = next(row for row in confidence["components"] if row["source"] == "ioc_quality")

    assert ioc_component["risk_signal"] is False
    assert ioc_component["verdict"] == "informational"
    assert confidence["score"] < 35
    assert confidence["score"] == 15
    assert confidence["verdict"] == "suspicious"


def test_build_evidence_matrix_rows_falls_back_to_collector_values() -> None:
    rows = build_evidence_matrix_rows(
        evidence={
            "vt": {"malicious_count": 2, "suspicious_count": 1},
            "dns": {"a": ["203.0.113.10"]},
            "signals": [
                {
                    "category": "reputation",
                    "severity": "warning",
                    "description": "Reputation signal.",
                    "evidence_refs": ["vt.malicious_count", "missing.path"],
                }
            ],
        },
        report={"key_evidence": ["missing.path"], "findings": []},
    )

    assert any(row["ref"] == "vt.malicious_count" for row in rows)
    assert all("No value was available" not in row["value"] for row in rows)
