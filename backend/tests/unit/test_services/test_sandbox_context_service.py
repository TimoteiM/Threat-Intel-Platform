"""The sandbox digest, and the truncation it exists to prevent.

The bug these cover: `compact_case_context` bounds the evidence tree to four
levels, and the ANY.RUN payload needs five, so every field of the analysis
reached the model as the literal string "[truncated]". Asked what the sandbox
found, the assistant said it had no access to the process tree, which was true.
"""

from __future__ import annotations

from app.services.investigation_case_story_service import compact_case_context
from app.services.sandbox_context_service import summarize_sandbox_evidence


def _evidence() -> dict:
    """Shaped like a real ANY.RUN run: signal buried in OS/browser telemetry."""
    return {
        "hybrid_analysis": {
            "meta": {"status": "completed", "collector": "hybrid_analysis"},
            "items": [
                {
                    "verdict": "malicious",
                    "analysis_id": "cfc0f9ab",
                    "analysis_link": "https://app.any.run/tasks/cfc0f9ab",
                    "tags": ["exploit-kit"],
                    "threat_names": [],
                    "raw_summary": {
                        "anyrun_ai_summary": "Malicious activity. TA569 detected (SURICATA).",
                        "verdict_text": "Malicious activity",
                        "threatName": ["exploit-kit"],
                        "behavior_counts": {"processes": 183, "network_threats": 13},
                        "behavior_details": {
                            # Nine of one rule, four of another — the shape the
                            # real payload takes, and the reason these are
                            # grouped rather than listed.
                            "network_threats": (
                                [
                                    {"sid": 2071928, "msg": "ET EXPLOIT_KIT TA569 Gholoader CnC TDS Domain in TLS SNI",
                                     "class": "Exploit Kit Activity Detected", "priority": 1,
                                     "dstip": "95.133.228.51", "dstport": 443,
                                     "processName": "msedge.exe", "pid": 5040,
                                     "time": "2026-09-11T06:20:00.974Z"}
                                ] * 9
                                + [
                                    {"sid": 2071927, "msg": "ET EXPLOIT_KIT TA569 Gholoader CnC Domain in DNS Lookup",
                                     "class": "Exploit Kit Activity Detected", "priority": 1,
                                     "dstip": "192.168.100.2", "dstport": 53,
                                     "processName": "msedge.exe", "pid": 5040,
                                     "time": "2026-09-11T06:20:06.086Z"}
                                ] * 4
                            ),
                        },
                        "iocs": [
                            {"ioc": "cdn14.example.org", "type": "domain",
                             "category": "DNS requests", "reputation": 2},
                            {"ioc": "benign.example.com", "type": "domain",
                             "category": "DNS requests", "reputation": 0},
                        ],
                    },
                    "sandbox_intelligence": {
                        "process_tree_summary": {
                            "process_count": 183,
                            "edge_count": 28,
                            "narrative": "183 process nodes; highest-signal: msedge.exe",
                            "root_processes": [{"pid": "0", "name": "[System Process]"}],
                            "high_risk_processes": [
                                {"pid": "5040", "ppid": "7848", "name": "msedge.exe",
                                 "risk_rank": 10, "threat_level": 2, "network_events": 94,
                                 "command_line": "msedge.exe --type=utility"},
                            ],
                        },
                        "suspicious_commands": [
                            {"pid": "5040", "process": "msedge.exe", "threat_level": 2,
                             "reason": "AnyRun assigned a high process threat level",
                             "command_line": "msedge.exe --type=utility"},
                        ],
                        "contacted_hosts": [
                            {"host": "bad.example.org", "threat_level": 2, "threat_name": "exploit-kit"},
                            {"host": "settings-win.data.microsoft.com", "threat_level": 0, "threat_name": ""},
                        ],
                        "contacted_ips": [{"ip": "10.0.0.1", "threat_level": 0, "threat_name": ""}],
                        "extracted_iocs": [{"type": "domain", "value": "a.example.com"}] * 101,
                        "dropped_files": [],
                    },
                }
            ],
        }
    }


def test_digest_surfaces_the_verdict_and_what_anyrun_named():
    run = summarize_sandbox_evidence(_evidence())["runs"][0]
    assert run["verdict"] == "malicious"
    assert run["verdict_text"] == "Malicious activity"
    assert run["tags"] == ["exploit-kit"]
    assert "TA569" in run["anyrun_summary"]


def test_digest_carries_the_process_tree():
    tree = summarize_sandbox_evidence(_evidence())["runs"][0]["process_tree"]
    assert tree["process_count"] == 183
    assert tree["edge_count"] == 28
    high = tree["high_risk_processes"][0]
    assert high["name"] == "msedge.exe"
    assert high["threat_level"] == 2
    assert high["network_events"] == 94


def test_only_threat_bearing_rows_survive_but_totals_are_kept():
    run = summarize_sandbox_evidence(_evidence())["runs"][0]
    # The Microsoft telemetry host is dropped; the flagged one is not.
    assert [h["host"] for h in run["threat_bearing_hosts"]] == ["bad.example.org"]
    # Reputation 0 indicators are noise; reputation 2 is the finding.
    assert [i["indicator"] for i in run["flagged_indicators"]] == ["cdn14.example.org"]
    # Dropping them must not read as "nothing was contacted".
    assert run["omitted"]["contacted_hosts_total"] == 2
    assert run["omitted"]["extracted_iocs_total"] == 101


def test_no_sandbox_evidence_yields_nothing():
    assert summarize_sandbox_evidence({}) is None
    assert summarize_sandbox_evidence({"hybrid_analysis": {"items": []}}) is None


def test_case_context_does_not_truncate_the_sandbox():
    """The regression. Before the digest, every field here was "[truncated]"."""
    context = compact_case_context(
        detail={"id": "x", "domain": "example.com"},
        evidence=_evidence(),
        report={},
        intelligence={},
    )
    run = context["sandbox"]["runs"][0]
    assert run["verdict"] == "malicious"
    assert run["process_tree"]["process_count"] == 183
    assert run["suspicious_commands"][0]["process"] == "msedge.exe"

    flattened = str(context["sandbox"])
    assert "[truncated]" not in flattened


def test_network_threats_group_by_rule_not_by_event():
    """"13 network threats" is not an answer; the two rules behind it are."""
    threats = summarize_sandbox_evidence(_evidence())["runs"][0]["network_threats"]
    assert threats["event_count"] == 13
    assert threats["distinct_rules"] == 2

    top = threats["rules"][0]
    assert top["events"] == 9
    assert top["signature_id"] == 2071928
    assert "Gholoader" in top["rule"]
    assert top["destinations"] == ["95.133.228.51:443"]
    assert top["processes"] == ["msedge.exe (pid 5040)"]

    # Ordered by how often each fired, so the strongest signal leads.
    assert [r["events"] for r in threats["rules"]] == [9, 4]


def test_no_ids_events_is_none_not_an_empty_shell():
    evidence = _evidence()
    evidence["hybrid_analysis"]["items"][0]["raw_summary"]["behavior_details"] = {}
    assert summarize_sandbox_evidence(evidence)["runs"][0]["network_threats"] is None
