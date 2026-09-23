"""Mapping a CAPE report onto the platform's own shape.

The fixtures are fabricated, reduced CAPE reports. The point of most of these
is not that the happy path maps — it is that a *partial* report maps without
inventing a verdict, because that is the failure that would quietly mark
malware as clean.
"""

from __future__ import annotations

import pytest

from app.services.cape_normalizer import SCORE_MALICIOUS, normalize_report, verdict_for


def report(**overrides) -> dict:
    base = {
        "info": {"id": 100, "started": "2026-09-22 10:00:00", "ended": "2026-09-22 10:03:00",
                 "duration": 180, "machine": {"name": "cuckoo4"}, "route": "internet"},
        "target": {"file": {"name": "invoice.exe", "sha256": "a" * 64, "sha1": "b" * 40,
                            "md5": "c" * 32, "size": 51200, "type": "PE32 executable"}},
        "malscore": 8.4,
        "detections": ["Emotet"],
        "signatures": [
            {"name": "injection_runpe", "description": "Injects into a process",
             "severity": 3, "ttp": ["T1055"]},
            {"name": "antivm", "description": "Checks for a VM", "severity": 1},
        ],
        "network": {
            "domains": [{"domain": "C2.Example.Test", "ip": "203.0.113.5"}],
            "dns": [{"request": "c2.example.test", "type": "A"}],
            "tcp": [{"dst": "203.0.113.5", "dport": 443}],
            "http": [{"method": "POST", "host": "c2.example.test", "uri": "/gate.php", "status": 200}],
            "tls": [{"sni": "C2.example.test"}],
        },
        "behavior": {
            "processtree": [{"name": "invoice.exe", "pid": 1200,
                             "children": [{"name": "powershell.exe", "pid": 1300}]}],
            "processes": [{"pid": 1200}, {"pid": 1300}],
            "summary": {"mutex": ["Global\\\\abc", "Global\\\\abc"],
                        "write_files": ["C:\\\\Users\\\\x\\\\a.tmp"],
                        "executed_commands": ["powershell -enc ..."]},
        },
        "dropped": [{"name": "a.tmp", "sha256": "d" * 64, "size": 900, "type": "data"}],
        "CAPE": {"payloads": [{"name": "payload.bin", "sha256": "e" * 64, "cape_type": "Emotet Payload"}],
                 "configs": [{"family": "Emotet", "c2": ["http://c2.example.test/gate.php"]}]},
        "screenshots": [{"path": "1.png"}, {"path": "2.png"}],
        "debug": {"errors": []},
    }
    base.update(overrides)
    return base


# ── The rule that matters most ───────────────────────────────────────────────


def test_a_missing_malscore_is_unknown_not_benign():
    """tasks/view routinely omits malscore. Defaulting it to zero would mark
    every unfinished analysis clean."""
    payload = report()
    payload.pop("malscore")
    result = normalize_report(payload, task_id=100)
    assert result.malscore is None
    assert result.verdict == "unknown"


@pytest.mark.parametrize(
    "score,expected",
    [(None, "unknown"), (0.0, "likely_benign"), (3.9, "likely_benign"),
     (4.0, "suspicious"), (6.9, "suspicious"), (7.0, "malicious"), (10.0, "malicious")],
)
def test_the_verdict_follows_the_score(score, expected):
    assert verdict_for(score) == expected


def test_a_zero_score_is_not_the_same_as_no_score():
    assert verdict_for(0.0) != verdict_for(None)


# ── Mapping ──────────────────────────────────────────────────────────────────


def test_the_headline_fields_map():
    r = normalize_report(report(), task_id=100, report_format="json", report_size_bytes=4096)
    assert r.task_id == 100
    assert r.malscore == 8.4 and r.verdict == "malicious"
    assert r.detections and "Emotet" in r.detections
    assert r.sha256 == "a" * 64 and r.sha1 == "b" * 40 and r.md5 == "c" * 32
    assert r.file_name == "invoice.exe" and r.file_size == 51200
    assert r.machine == "cuckoo4" and r.route == "internet"
    assert r.report_format == "json" and r.report_size_bytes == 4096


def test_signatures_are_ordered_by_severity_and_carry_ttps():
    r = normalize_report(report())
    assert [s.name for s in r.signatures] == ["injection_runpe", "antivm"]
    assert r.signatures[0].ttps == ["T1055"]


def test_network_indicators_are_deduplicated_and_lowercased():
    """Hostnames are case-insensitive, and the same host appears in several
    sections of a CAPE report."""
    r = normalize_report(report())
    assert r.network.domains == ["c2.example.test"]
    assert r.network.tls_sni == ["c2.example.test"]
    assert r.network.destinations == ["203.0.113.5:443/tcp"]
    assert r.network.hosts == ["203.0.113.5"]
    assert r.network.http_requests[0]["uri"] == "/gate.php"


def test_behaviour_is_summarised_and_deduplicated():
    r = normalize_report(report())
    assert r.behaviour.mutexes == ["Global\\\\abc"]
    assert r.behaviour.process_count == 2
    assert r.behaviour.process_tree[0]["name"] == "invoice.exe"
    assert r.behaviour.process_tree[0]["children"][0]["name"] == "powershell.exe"


def test_dropped_files_and_cape_payloads_are_both_captured():
    r = normalize_report(report())
    by_hash = {d.sha256: d for d in r.dropped_files}
    assert by_hash["d" * 64].is_cape_payload is False
    assert by_hash["e" * 64].is_cape_payload is True
    assert by_hash["e" * 64].cape_type == "Emotet Payload"


def test_extracted_configuration_is_preserved():
    r = normalize_report(report())
    assert r.extracted_configs and r.extracted_configs[0]["family"] == "Emotet"


def test_screenshot_availability_is_reported():
    r = normalize_report(report())
    assert r.has_screenshots is True and r.screenshot_count == 2


# ── Partial and hostile input ────────────────────────────────────────────────


def test_an_empty_report_does_not_raise_and_says_what_is_missing():
    r = normalize_report({"info": {"id": 5}}, task_id=5)
    assert r.malscore is None and r.verdict == "unknown"
    assert any("may not have executed" in note for note in r.limitations)


def test_a_report_that_is_not_an_object_is_handled():
    r = normalize_report(["not", "a", "report"], task_id=9)
    assert r.status == "failed" and r.errors


def test_odd_types_in_every_section_do_not_raise():
    """A real CAPE report has surprised this parser before; none of it may throw."""
    r = normalize_report({
        "info": "not-a-dict", "target": 12, "signatures": "nope",
        "network": {"domains": ["plain.test", 7, {"no_domain": 1}], "tcp": "nope", "tls": [None]},
        "behavior": {"summary": {"mutex": [{"name": "m"}, 5]}, "processtree": "nope"},
        "dropped": [None, {"name": "x"}], "CAPE": "nope", "malscore": "not-a-number",
    })
    assert r.malscore is None
    assert r.network.domains == ["plain.test"]
    assert r.behaviour.mutexes == ["m"]


def test_a_lite_report_is_flagged_as_less_detailed():
    r = normalize_report(report(), report_format="lite")
    assert any("lite" in note for note in r.limitations)


def test_cape_errors_are_surfaced_not_swallowed():
    r = normalize_report(report(debug={"errors": ["Analysis failed: no route to guest"]}))
    assert r.errors == ["Analysis failed: no route to guest"]


def test_indicator_lists_are_capped():
    payload = report(network={"domains": [{"domain": f"h{i}.test"} for i in range(1000)]})
    assert len(normalize_report(payload).network.domains) <= 200


def test_the_score_threshold_is_a_display_boundary_not_an_action():
    """Documented explicitly: nothing in this platform acts on it by itself."""
    assert SCORE_MALICIOUS == 7.0


# ── CAPE's IOC summary ───────────────────────────────────────────────────────
#
# The fallback when a report will not fit — one PDF produced 139MB of JSON
# against a 64MB ceiling, while the IOC summary for the same task was 116KB.
# It uses different shapes for the same facts, and every one of them returned
# empty on the first attempt.


def ioc_payload() -> dict:
    """Reduced from the real task-8 response."""
    return {
        "info": {"id": 8, "machine": "cuckoo1", "route": "internet", "duration": 287},
        "target": {"file": {"name": "report.pdf", "type": "PDF document, version 1.7"}},
        "malscore": 10.0,
        "network": {"domains": [{"domain": "a.test"}], "hosts": ["1.2.3.4"]},
        # A single root dict, children under spawned_processes — not a list.
        "process_tree": {"pid": 792, "name": "svchost.exe",
                         "spawned_processes": [{"pid": 3816, "name": "WmiPrvSE.exe",
                                                "spawned_processes": [{"pid": 99, "name": "acro.exe"}]}]},
        # Dicts of lists, not flat lists.
        "registry": {"modified": ["HKCU\\A", "HKCU\\B"], "deleted": ["HKCU\\C"]},
        "files": {"modified": ["C:\\a.json", "C:\\b.json"], "deleted": ["C:\\c.tmp"]},
        "mutexes": ["Global\\One", "Global\\Two"],
        "executed_commands": ["acrocef.exe --x"],
        "dropped": [{"sha256": "d" * 64, "name": "x.bin"}],
        "signatures": [],
    }


def test_the_ioc_summary_normalizes_like_a_report():
    r = normalize_report(ioc_payload(), task_id=8, report_format="iocs")
    assert r.malscore == 10.0 and r.verdict == "malicious"
    assert r.file_name == "report.pdf"
    assert r.machine == "cuckoo1" and r.route == "internet"
    assert r.network.domains == ["a.test"]
    assert len(r.dropped_files) == 1


def test_a_single_root_process_tree_is_understood():
    """A dict root with spawned_processes, counted through the whole tree —
    the first pass reported 1 process for an analysis that ran four."""
    r = normalize_report(ioc_payload(), report_format="iocs")
    assert r.behaviour.process_count == 3
    assert r.behaviour.process_tree[0]["name"] == "svchost.exe"
    assert r.behaviour.process_tree[0]["children"][0]["name"] == "WmiPrvSE.exe"


def test_registry_and_file_activity_grouped_as_dicts_are_read():
    """{modified, deleted} rather than a flat list. Both are writes; mapping
    the whole dict onto files_read reported 497 modified paths as zero."""
    r = normalize_report(ioc_payload(), report_format="iocs")
    assert sorted(r.behaviour.registry_keys) == ["HKCU\\A", "HKCU\\B", "HKCU\\C"]
    assert sorted(r.behaviour.files_written) == ["C:\\a.json", "C:\\b.json", "C:\\c.tmp"]
    assert r.behaviour.mutexes == ["Global\\One", "Global\\Two"]
    assert r.behaviour.commands == ["acrocef.exe --x"]


def test_the_reduced_source_is_declared():
    """An analyst must not read "no signatures" as "nothing suspicious" when
    signatures simply are not in this payload."""
    r = normalize_report(ioc_payload(), report_format="iocs")
    note = " ".join(r.limitations)
    assert "IOC summary" in note
    assert "signatures" in note.lower()
