from __future__ import annotations

from copy import deepcopy
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[3]
sys.path = [path for path in sys.path if path != str(BACKEND_ROOT)]
sys.path.insert(0, str(BACKEND_ROOT))
if "app" in sys.modules and str(getattr(sys.modules["app"], "__file__", "")).endswith("/app/__init__.py"):
    sys.modules.pop("app", None)

from app.services.anyrun_false_positive import (
    MSDW_DISPOSITION,
    MSDW_REASON,
    MSDW_SIGNATURE,
    apply_anyrun_msdw_false_positive_exclusion,
)
from app.services.anyrun_intelligence import build_anyrun_sandbox_intelligence
from app.services.risk_aggregator import aggregate_risk
from app.services.investigation_intelligence import build_evidence_timeline


def _base_result() -> dict:
    threat = {
        "id": "ids-1",
        "pid": 812,
        "signature": MSDW_SIGNATURE,
        "userAgent": "MSDW",
        "threatLevel": 2,
        "severity": "high",
        "timestamp": "2026-07-20T12:00:00Z",
    }
    http = {
        "pid": 812,
        "url": "http://diagnostics.example/report",
        "userAgent": "MSDW",
        "threatName": [MSDW_SIGNATURE],
        "threatLevel": 2,
    }
    proc = {
        "id": "proc-1",
        "uuid": "proc-uuid-1",
        "pid": 812,
        "ppid": 700,
        "name": "svchost.exe",
        "file_path": r"C:\Windows\System32\svchost.exe",
        "command_line": r"C:\Windows\System32\svchost.exe -k WerSvcGroup",
        "threat_level": 2,
        "threat_score": 80,
        "threat_name": [MSDW_SIGNATURE],
        "cert": {
            "verified": True,
            "status": "valid",
            "subject": "Microsoft Windows",
            "issuer": "Microsoft Windows Production PCA 2011",
        },
        "events": {
            "network_threats": [deepcopy(threat)],
            "http_requests": [deepcopy(http)],
            "connections": [],
            "created_files": [],
            "dropped_files": [],
            "modified_files": [],
            "registry_changes": [],
            "modules": [],
            "debug": [],
            "synchronization": [],
        },
        "event_counts": {"network_threats": 1, "http_requests": 1},
    }
    raw_proc = {
        "uuid": "proc-uuid-1",
        "pid": 812,
        "ppid": 700,
        "fileName": "svchost.exe",
        "filePath": r"C:\Windows\System32\svchost.exe",
        "threatLevel": 2,
        "threatScore": 80,
        "threatName": [MSDW_SIGNATURE],
        "cert": deepcopy(proc["cert"]),
    }
    return {
        "checked": True,
        "verdict": "malicious",
        "threat_score": 80,
        "threat_names": [MSDW_SIGNATURE],
        "raw_summary": {
            "source": "anyrun",
            "mode": "sandbox",
            "threatName": [MSDW_SIGNATURE],
            "tags": [],
            "iocs": [],
            "behavior_counts": {"network_threats": 1, "http_requests": 1, "processes": 1},
            "behavior_details": {
                "network_threats": [deepcopy(threat)],
                "http_requests": [deepcopy(http)],
                "connections": [],
                "processes": [raw_proc],
                "process_details": [proc],
            },
        },
    }


def _process(result: dict) -> dict:
    return result["raw_summary"]["behavior_details"]["process_details"][0]


def test_qualified_msdw_event_is_preserved_but_excluded_from_risk():
    out = apply_anyrun_msdw_false_positive_exclusion(_base_result())

    assert out["verdict"] == "clean"
    assert out["provider_verdict"] == "malicious"
    assert out["threat_score"] == 0
    assert out["raw_summary"]["behavior_counts"]["network_threats"] == 0
    assert out["raw_summary"]["behavior_counts"]["network_threats_excluded"] == 1
    proc = _process(out)
    assert proc["classification"] == "informational"
    assert proc["threat_level"] == 0
    event = proc["events"]["network_threats"][0]
    assert event["classification"] == MSDW_DISPOSITION
    assert event["reason"] == MSDW_REASON
    assert event["excluded_from_malicious_indicator_count"] is True
    assert event["excluded_from_final_risk"] is True
    assert event["suppressed"] is False
    assert event["signature"] == MSDW_SIGNATURE
    assert apply_anyrun_msdw_false_positive_exclusion(out) == out

    intel = build_anyrun_sandbox_intelligence(out)
    assert intel["summary"]["informational_event_count"] == 1
    assert intel["informational_events"][0]["title"] == MSDW_DISPOSITION
    assert intel["informational_events"][0]["preserved_for_timeline"] is True

    aggregate = aggregate_risk({"hybrid_analysis": {"items": [out]}})
    assert aggregate["components"]["sandbox_score"] == 0.0
    assert aggregate["risk_score"] == 0

    timeline = build_evidence_timeline(
        evidence={"hybrid_analysis": {"items": [{**out, "sandbox_intelligence": intel}]}},
        report={},
        detail={"domain": "diagnostics.example"},
    )
    assert any(event["title"] == MSDW_DISPOSITION and event["severity"] == "info" for event in timeline)


@pytest.mark.parametrize(
    ("mutation",),
    [
        (lambda p: p.update(file_path=r"C:\Windows\SysWOW64\svchost.exe"),),
        (lambda p: p["cert"].update(verified=False, status="invalid"),),
        (lambda p: p["cert"].update(subject="Contoso Ltd", issuer="Contoso CA"),),
        (lambda p: p["events"]["network_threats"][0].update(userAgent="Mozilla/5.0"),),
        (lambda p: p["events"]["network_threats"][0].update(signature="ET OTHER Detection"),),
    ],
)
def test_exclusion_requires_every_identity_and_signature_condition(mutation):
    result = _base_result()
    proc = _process(result)
    mutation(proc)
    if proc["events"]["network_threats"][0].get("userAgent") != "MSDW":
        proc["events"]["http_requests"][0]["userAgent"] = "Mozilla/5.0"
        result["raw_summary"]["behavior_details"]["network_threats"][0]["userAgent"] = "Mozilla/5.0"
        result["raw_summary"]["behavior_details"]["http_requests"][0]["userAgent"] = "Mozilla/5.0"
    if proc["events"]["network_threats"][0].get("signature") != MSDW_SIGNATURE:
        result["raw_summary"]["behavior_details"]["network_threats"][0]["signature"] = "ET OTHER Detection"
    out = apply_anyrun_msdw_false_positive_exclusion(result)
    assert out["verdict"] == "malicious"
    assert not out.get("false_positive_exclusions")


@pytest.mark.parametrize(
    "corroboration",
    [
        "malicious_file",
        "process_injection",
        "credential_access",
        "persistence",
        "suspicious_child",
        "encoded_command",
        "payload_download",
        "c2_destination",
    ],
)
def test_corroborating_malicious_behavior_blocks_exclusion(corroboration):
    result = _base_result()
    proc = _process(result)
    events = proc["events"]
    if corroboration == "malicious_file":
        events["created_files"] = [{"path": r"C:\Temp\payload.dll", "verdict": "malicious"}]
    elif corroboration == "process_injection":
        events["debug"] = [{"message": "Process injection into explorer.exe"}]
    elif corroboration == "credential_access":
        events["debug"] = [{"message": "Credential access from LSASS"}]
    elif corroboration == "persistence":
        events["registry_changes"] = [{"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "action": "persistence"}]
    elif corroboration == "suspicious_child":
        result["raw_summary"]["behavior_details"]["process_details"].append({"pid": 900, "ppid": 812, "name": "powershell.exe", "threat_level": 2})
    elif corroboration == "encoded_command":
        proc["command_line"] = "powershell.exe -EncodedCommand SQBFAFgA"
    elif corroboration == "payload_download":
        events["http_requests"].append({"pid": 812, "url": "https://evil.example/payload.exe", "verdict": "malicious"})
    elif corroboration == "c2_destination":
        events["connections"] = [{"destinationIP": "203.0.113.8", "threatLevel": 2, "threatName": ["Confirmed C2"]}]

    out = apply_anyrun_msdw_false_positive_exclusion(result)
    assert out["verdict"] == "malicious"
    assert not out.get("false_positive_exclusions")


def test_unrelated_detection_is_retained_while_qualified_msdw_event_is_excluded():
    result = _base_result()
    result["raw_summary"]["behavior_details"]["process_details"].append({
        "pid": 901,
        "ppid": 700,
        "name": "powershell.exe",
        "file_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "threat_level": 2,
        "threat_name": ["Malicious PowerShell payload"],
        "command_line": "powershell.exe -EncodedCommand AAAA",
        "events": {},
    })

    out = apply_anyrun_msdw_false_positive_exclusion(result)

    assert out["verdict"] == "malicious"
    assert out["threat_score"] == 80
    assert len(out["false_positive_exclusions"]) == 1
    assert _process(out)["classification"] == "informational"
    assert out["raw_summary"]["behavior_details"]["process_details"][1]["threat_level"] == 2
