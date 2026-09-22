"""What the models are told about CAPE.

Three consumers read sandbox evidence — the classification analyst, the case
story writer and the alert digest — and all three previously had no idea CAPE
existed. These cover the projection they share and the alert finding that
carries it, concentrating on the two ways a sandbox summary misleads a reader:
a missing score read as zero, and an empty network section read as "quiet"
when the analysis simply had no network.
"""

from __future__ import annotations

import pytest

from app.services.alert_finding_builder import build_indicator_findings
from app.services.alert_indicator_summary_service import build_indicator_summary
from app.services.sandbox_context_service import summarize_cape_evidence


def report(**overrides) -> dict:
    base = {
        "task_id": 12,
        "verdict": "malicious",
        "malscore": 8.5,
        "detections": ["Emotet"],
        "signatures": [
            {"name": "injection_runpe", "severity": 3, "description": "Injects", "ttps": ["T1055"]},
            {"name": "antivm", "severity": 1, "description": "VM checks", "ttps": []},
        ],
        "file_type": "PE32+ executable",
        "machine": "cuckoo3",
        "route": "internet",
        "network": {
            "domains": ["c2.example.test"],
            "destinations": ["203.0.113.5:443/tcp"],
            "dns_queries": ["c2.example.test"],
            "tls_sni": ["c2.example.test"],
        },
        "behaviour": {"commands": ["powershell -enc"], "mutexes": ["m1"],
                      "files_written": ["a.tmp"], "registry_keys": ["HKCU\\\\Run"],
                      "process_count": 6},
        "dropped_files": [
            {"sha256": "d" * 64, "is_cape_payload": False},
            {"sha256": "e" * 64, "is_cape_payload": True, "cape_type": "Emotet Payload"},
            {"sha256": "f" * 64, "is_cape_payload": True, "cape_type": "Emotet Payload"},
        ],
        "extracted_configs": [{"family": "Emotet"}],
        "errors": [],
        "limitations": [],
    }
    base.update(overrides)
    return base


def evidence(**overrides) -> dict:
    return {"cape": {"available": True, "report": report(**overrides)}}


# ── The projection given to the models ───────────────────────────────────────


def test_a_collector_that_did_not_run_produces_no_section():
    """Silence, so the prompt omits CAPE entirely rather than asserting on it."""
    assert summarize_cape_evidence({}) is None
    assert summarize_cape_evidence({"cape": None}) is None


def test_an_unavailable_sandbox_says_so_rather_than_saying_nothing():
    """"CAPE was not consulted" and "CAPE found nothing" are different facts."""
    out = summarize_cape_evidence({"cape": {"available": False, "reason": "No analysis for this hash."}})
    assert out["analysed"] is False
    assert "No analysis for this hash." in out["why_not"]
    assert "not evidence that the sample is safe" in out["caution"]


def test_the_headline_findings_reach_the_model():
    out = summarize_cape_evidence(evidence())
    assert out["analysed"] is True
    assert out["verdict"] == "malicious"
    assert out["malware_score"] == "8.5/10"
    assert out["named_families"] == ["Emotet"]
    assert out["task_id"] == 12
    assert [s["name"] for s in out["top_signatures"]] == ["injection_runpe", "antivm"]
    assert out["top_signatures"][0]["attack"] == ["T1055"]


def test_a_missing_score_is_spelled_out_as_unknown():
    """The single most dangerous field to hand a model as a bare number."""
    out = summarize_cape_evidence(evidence(malscore=None))
    assert "not scored" in out["malware_score"]
    assert "not as clean" in out["malware_score"]
    assert "0" not in out["malware_score"].split("—")[0]


def test_no_network_without_internet_is_flagged_as_meaningless():
    """A report run with route=none has no C2 traffic by construction."""
    out = summarize_cape_evidence(
        evidence(route="none", network={"domains": [], "destinations": [], "dns_queries": [], "tls_sni": []})
    )
    note = out["network"]["note"]
    assert "without internet access" in note
    assert "means nothing" in note


def test_no_network_with_internet_is_reported_plainly():
    out = summarize_cape_evidence(
        evidence(route="internet", network={"domains": [], "destinations": [], "dns_queries": [], "tls_sni": []})
    )
    assert "internet access enabled" in out["network"]["note"]


def test_long_lists_are_sampled_but_their_real_size_is_stated():
    """So the model can say "80 domains, 15 shown" instead of implying 15."""
    many = [f"h{i}.test" for i in range(80)]
    out = summarize_cape_evidence(evidence(network={"domains": many, "destinations": [],
                                                    "dns_queries": [], "tls_sni": []}))
    assert len(out["network"]["contacted_domains"]) == 15
    assert out["network"]["contacted_domains_total"] == 80


def test_payload_families_are_deduplicated():
    out = summarize_cape_evidence(evidence())
    assert out["dropped_files"] == {
        "total": 3, "cape_extracted_payloads": 2, "payload_types": ["Emotet Payload"]
    }


def test_analysis_errors_and_limitations_are_carried_through():
    out = summarize_cape_evidence(evidence(
        errors=["no route to guest"],
        limitations=["PDF dynamic execution is unavailable"],
    ))
    assert out["errors"] == ["no route to guest"]
    assert "PDF" in out["limitations"][0]


# ── The alert finding ────────────────────────────────────────────────────────


def test_a_cape_detonation_becomes_a_finding_the_alert_ai_reads():
    findings = build_indicator_findings(evidence())
    cape = next(f for f in findings if f["collector"] == "cape")
    assert cape["severity"] == "high"
    assert "malicious (8.5/10)" in cape["summary"]
    assert "Emotet" in cape["summary"]
    assert cape["data"]["task_id"] == 12
    assert cape["data"]["contacted_domains"] == ["c2.example.test"]
    assert cape["data"]["scored"] is True


@pytest.mark.parametrize(
    "verdict,expected",
    [("malicious", "high"), ("suspicious", "medium"), ("likely_benign", "info"), ("unknown", "info")],
)
def test_the_verdict_sets_the_severity(verdict, expected):
    findings = build_indicator_findings(evidence(verdict=verdict))
    assert next(f for f in findings if f["collector"] == "cape")["severity"] == expected


def test_an_unscored_analysis_does_not_become_a_benign_finding():
    findings = build_indicator_findings(evidence(malscore=None, verdict="unknown"))
    cape = next(f for f in findings if f["collector"] == "cape")
    assert "not scored" in cape["summary"]
    # The key is absent once None is stripped, which is precisely how a missing
    # score becomes a zero downstream — so an explicit flag carries the fact.
    assert "malscore" not in cape["data"]
    assert cape["data"]["scored"] is False


def test_no_finding_when_cape_has_nothing():
    assert build_indicator_findings({"cape": {"available": False, "reason": "x"}}) == []
    assert build_indicator_findings({}) == []


# ── The indicator line ───────────────────────────────────────────────────────


def _summary_for(ev: dict) -> dict:
    return build_indicator_summary([{
        "indicator": {"value": "a" * 64, "type": "hash"},
        "status": "completed",
        "verdict": {"classification": "malicious", "risk_score": 90},
        "findings": build_indicator_findings(ev),
    }])["indicators"][0]


def test_the_indicator_line_carries_the_cape_verdict():
    entry = _summary_for(evidence())
    assert "CAPE sandbox verdict: malicious" in entry["line"]
    assert entry["cape"]["task_id"] == 12
    assert entry["cape"]["verdict"] == "malicious"


def test_cape_is_preferred_over_the_other_sandboxes():
    """An on-premises detonation of this estate's own sample is more direct
    evidence than a third-party lookup, and only one sandbox line is emitted."""
    ev = evidence()
    ev["hybrid_analysis"] = {"items": [{"checked": True, "verdict": "suspicious", "threat_score": 50}]}
    entry = _summary_for(ev)
    assert "CAPE" in entry["line"]
    assert entry["line"].count("sandbox:") == 1


def test_the_other_sandboxes_still_work_when_cape_did_not_run():
    ev = {"hybrid_analysis": {"items": [{"checked": True, "verdict": "malicious"}]}}
    entry = _summary_for(ev)
    assert "Sandbox verdict: malicious" in entry["line"]


# ── The analyst sees it at all ───────────────────────────────────────────────


def test_collected_evidence_carries_a_cape_field():
    """Without this the collector's output never reaches the analyst prompt."""
    from app.models.schemas import CapeEvidence, CollectedEvidence

    assert "cape" in CollectedEvidence.model_fields
    built = CollectedEvidence(domain="x", investigation_id="y", cape=CapeEvidence(available=True))
    assert built.cape.available is True
    assert CollectedEvidence(domain="x", investigation_id="y").cape is None
