"""
The factual roll-up that sits beside the AI narrative.

The AI reads the alert text alone and runs in parallel with the collectors, so a
hash could only ever be *named*. These lines say what the sources found.
"""

import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services.alert_indicator_summary_service import build_indicator_summary

HASH = "acf4ecb52e601f7b4a37db51b07650b5d0315eafd010590e98079fa026da4b7b"


def _hash_report(**overrides):
    report = {
        "report_type": "indicator",
        "status": "completed",
        "indicator": {"value": HASH, "type": "hash", "observable_type": "hash"},
        "verdict": {"classification": "malicious", "risk_score": 90},
        "findings": [
            {
                "source": "VirusTotal", "collector": "vt", "type": "reputation", "severity": "high",
                "summary": "21 of 91 engines flag this as malicious",
                "data": {
                    "malicious": 21, "total_engines": 91,
                    "flagged_by": ["BitDefender", "ESET", "Fortinet", "GData", "Sophos"],
                    "detections": ["Trojan.Win32.Emotet"],
                },
            },
            {
                "source": "VirusTotal", "collector": "vt", "type": "file_profile", "severity": "medium",
                "summary": "invoice.exe — PE32 executable, 412.0 KB, unsigned",
                "data": {
                    "file_name": "invoice.exe",
                    "other_names": ["setup.exe", "rechnung.exe"],
                    "file_type": "PE32 executable",
                    "size_bytes": 421888,
                    "signature": {"signed": False, "verified": "invalid"},
                    "threat_label": "trojan.emotet/heurist",
                    "imphash": "8e6df21baebf68cc126345d8edca4189",
                },
            },
            {
                "source": "AnyRun", "collector": "hybrid_analysis", "type": "sandbox_behaviour",
                "severity": "high", "summary": "Sandbox verdict: malicious", "data": {},
            },
        ],
    }
    report.update(overrides)
    return report


def test_a_hash_line_says_what_virustotal_found():
    summary = build_indicator_summary([_hash_report()])
    line = summary["indicators"][0]["line"]

    assert "21 of 91 engines malicious" in line
    assert "Trojan.Win32.Emotet" in line
    assert "submitted as invoice.exe" in line
    assert "PE32 executable" in line
    assert "412.0 KB" in line
    assert "also seen as setup.exe, rechnung.exe" in line
    assert "signature invalid" in line
    assert "VT threat label trojan.emotet/heurist" in line
    assert "sandbox: Sandbox verdict: malicious" in line


def test_the_facts_are_structured_not_only_prose():
    entry = build_indicator_summary([_hash_report()])["indicators"][0]
    assert entry["vt_malicious"] == 21
    assert entry["vt_total"] == 91
    assert entry["file_name"] == "invoice.exe"
    assert entry["file_type"] == "PE32 executable"
    assert entry["signed"] is False
    assert entry["threat_label"] == "trojan.emotet/heurist"
    assert entry["imphash"] == "8e6df21baebf68cc126345d8edca4189"


def test_a_signed_file_says_who_signed_it():
    report = _hash_report()
    report["findings"][1]["data"]["signature"] = {"signed": True, "signer": "Microsoft Corporation"}
    line = build_indicator_summary([report])["indicators"][0]["line"]
    assert "signed by Microsoft Corporation" in line


def test_a_clean_hash_reports_the_engine_count_and_the_file():
    report = _hash_report(verdict={"classification": "benign", "risk_score": 5})
    report["findings"][0]["data"] = {"malicious": 0, "total_engines": 75}
    line = build_indicator_summary([report])["indicators"][0]["line"]
    assert "no detections across 75 engines" in line
    assert "submitted as invoice.exe" in line


def test_the_headline_leads_with_the_worst_indicator():
    quiet = {
        "indicator": {"value": "8.8.8.8", "type": "ip"},
        "verdict": {"classification": "benign", "risk_score": 0},
        "findings": [],
        "status": "completed",
    }
    summary = build_indicator_summary([quiet, _hash_report()])
    assert summary["headline"].startswith("SHA256 acf4ecb52e601f7b…")
    assert "21 of 91 engines malicious" in summary["headline"]
    # …and the flagged indicator is ordered first.
    assert summary["indicators"][0]["type"] == "hash"


def test_a_run_where_nothing_was_flagged_says_so():
    quiet = {
        "indicator": {"value": "expertware.net", "type": "domain"},
        "verdict": {"classification": "benign", "risk_score": 5},
        "findings": [],
        "status": "completed",
    }
    summary = build_indicator_summary([quiet])
    assert summary["headline"] == "1 indicator(s) checked — none was flagged by any source."


def test_skipped_and_running_indicators_state_their_position():
    skipped = {
        "indicator": {"value": "10.0.0.5", "type": "ip"},
        "verdict": {"classification": "not_investigated", "risk_score": 0},
        "status": "skipped", "skip_reason": "private_or_reserved_address", "findings": [],
    }
    running = {
        "indicator": {"value": "evil.com", "type": "domain"},
        "verdict": {"classification": "not_investigated", "risk_score": 0},
        "status": "investigating", "findings": [],
        "investigation": {"investigation_id": "abc"},
    }
    lines = [e["line"] for e in build_indicator_summary([skipped, running])["indicators"]]
    assert any("not investigated (private or reserved address)" in line for line in lines)
    assert any("investigation still running" in line for line in lines)


def test_an_empty_run_is_handled():
    summary = build_indicator_summary([])
    assert summary["headline"] == "No indicators were extracted from this alert."
    assert summary["indicators"] == []
