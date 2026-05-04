from __future__ import annotations

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[3]
sys.path = [path for path in sys.path if path != str(BACKEND_ROOT)]
sys.path.insert(0, str(BACKEND_ROOT))
if "app" in sys.modules and str(getattr(sys.modules["app"], "__file__", "")).endswith("/app/__init__.py"):
    sys.modules.pop("app", None)

from app.services.anyrun_intelligence import build_anyrun_sandbox_intelligence


def test_build_anyrun_sandbox_intelligence_extracts_network_process_and_iocs():
    result = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "malicious",
        "analysis_id": "task-1",
        "analysis_link": "https://app.any.run/tasks/task-1",
        "threat_score": 91,
        "dynamic_io_summary": {
            "domains": [{"domainName": "evil.example", "threatLevel": 2}],
            "hosts": [{"destinationIP": "203.0.113.10", "destinationPort": 443}],
            "urls": [{"url": "https://evil.example/payload.bin"}],
        },
        "raw_summary": {
            "source": "anyrun",
            "mode": "sandbox",
            "screenshots": [{"url": "https://app.any.run/screenshot/task-1.png", "label": "Desktop"}],
            "iocs": [{"type": "sha256", "value": "a" * 64}],
            "behavior_graph": {"nodes": [{"id": "analysis:root"}, {"id": "pid:100"}], "edges": [{"id": "a"}]},
            "behavior_details": {
                "dns_requests": [{"domainName": "cdn.evil.example", "processName": "powershell.exe"}],
                "http_requests": [{"url": "https://evil.example/payload.bin", "processName": "powershell.exe"}],
                "connections": [{"destinationIP": "203.0.113.10", "destinationPort": 443, "processName": "powershell.exe"}],
                "process_details": [
                    {
                        "pid": 100,
                        "ppid": 0,
                        "name": "powershell.exe",
                        "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
                        "threat_level": 2,
                        "event_counts": {"created_files": 1, "http_requests": 1, "connections": 1},
                        "events": {
                            "created_files": [{"path": "C:\\Users\\Public\\payload.exe", "sha256": "b" * 64}],
                            "http_requests": [{"url": "https://evil.example/payload.bin"}],
                            "connections": [{"destinationIP": "203.0.113.10", "destinationPort": 443}],
                        },
                    }
                ],
            },
        },
    }

    out = build_anyrun_sandbox_intelligence(result)

    assert out["summary"]["process_count"] == 1
    assert out["summary"]["contacted_host_count"] >= 2
    assert out["summary"]["contacted_ip_count"] >= 1
    assert out["summary"]["dropped_file_count"] == 1
    assert out["summary"]["suspicious_command_count"] == 1
    assert out["summary"]["screenshot_count"] == 1
    assert any(row["host"] == "evil.example" for row in out["contacted_hosts"])
    assert any(row["ip"] == "203.0.113.10" and str(row["port"]) == "443" for row in out["contacted_ips"])
    assert out["dropped_files"][0]["path"].endswith("payload.exe")
    assert "encoded" in out["suspicious_commands"][0]["reason"].lower()
    assert any(row["type"] == "url" and row["value"] == "https://evil.example/payload.bin" for row in out["extracted_iocs"])
    assert any(row["type"] == "hash" and row["value"] == "b" * 64 for row in out["extracted_iocs"])
