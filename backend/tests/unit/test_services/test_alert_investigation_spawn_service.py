from types import SimpleNamespace
from uuid import UUID

from app.services import alert_investigation_spawn_service as svc

INVESTIGATION_ID = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

CONCLUDED = {
    "investigation_id": INVESTIGATION_ID,
    "value": "myspotifypremium.info",
    "observable_type": "domain",
    "state": "concluded",
    "classification": "malicious",
    "confidence": "high",
    "risk_score": 88,
    "recommended_action": "block",
    "created_at": "2026-08-05T11:50:00+00:00",
    "concluded_at": "2026-08-05T11:56:00+00:00",
    "report": {
        "executive_summary": "Credential phishing page impersonating Spotify.",
        "key_evidence": ["VirusTotal: 9 of 94 engines flag this as malicious", "Domain registered 3 days ago"],
        "findings": [
            {"id": "vt", "title": "9 of 94 engines flag the domain", "severity": "high",
             "description": "Nine vendors classify it as phishing.", "evidence_refs": ["vt.malicious_count"]},
        ],
    },
    "evidence": {"vt": {"malicious_count": 9, "suspicious_count": 0, "total_vendors": 94}},
    "collector_runs": [
        {"collector": "vt", "status": "completed", "duration_ms": 900, "error": None},
        {"collector": "whois", "status": "failed", "duration_ms": 10, "error": "no output"},
    ],
}

INDICATOR = {"value": "myspotifypremium.info", "type": "domain", "observable_type": "domain"}


def _report(outcome, **kwargs):
    return svc.build_investigation_report(
        schema_version="1.0",
        indicator=INDICATOR,
        observable_type="domain",
        investigation_id=INVESTIGATION_ID,
        outcome=outcome,
        started_at="2026-08-05T11:50:00+00:00",
        **kwargs,
    )


def test_only_domains_and_urls_spawn_by_default():
    assert sorted(svc.spawn_types()) == ["domain", "url"]
    assert svc.should_spawn("domain") is True
    assert svc.should_spawn("url") is True
    assert svc.should_spawn("ip") is False
    assert svc.should_spawn("hash") is False
    assert svc.should_spawn("domain", enabled=False) is False


def test_concluded_investigation_becomes_a_full_indicator_report():
    report = _report(CONCLUDED)

    assert report["status"] == "completed"
    assert report["verdict"]["classification"] == "malicious"
    assert report["verdict"]["risk_score"] == 88
    assert report["verdict"]["confidence"] == 0.9
    assert report["verdict"]["reasons"][0].startswith("VirusTotal: 9 of 94")
    assert report["investigation"]["url"] == f"/investigations/{INVESTIGATION_ID}"
    assert report["investigation"]["recommended_action"] == "block"
    assert report["sources_checked"] == ["investigation", "vt", "whois"]
    # A failed collector inside the investigation is surfaced, not swallowed.
    assert report["errors"] == ["whois: no output"]
    assert any(f["collector"] == "vt" for f in report["findings"])
    analyst = next(f for f in report["findings"] if f["collector"] == "investigation")
    assert analyst["severity"] == "high"
    assert analyst["data"]["evidence_refs"] == ["vt.malicious_count"]


def test_running_investigation_is_reported_as_investigating():
    report = _report({**CONCLUDED, "state": "gathering", "classification": None, "risk_score": None})

    assert report["status"] == "investigating"
    assert report["verdict"]["classification"] == "not_investigated"
    assert report["verdict"]["risk_score"] == 0
    assert report["findings"] == []
    assert INVESTIGATION_ID in report["verdict"]["reasons"][0]


def test_failed_investigation_is_reported_as_failed():
    report = _report({**CONCLUDED, "state": "failed"})

    assert report["status"] == "failed"
    assert report["verdict"]["classification"] == "inconclusive"
    assert any("ended as failed" in error for error in report["errors"])


def test_raw_evidence_is_attached_only_on_request():
    assert "evidence" not in _report(CONCLUDED)
    assert _report(CONCLUDED, include_raw_evidence=True)["evidence"]["vt"]["malicious_count"] == 9


def test_pending_ids_are_collected_from_investigating_reports_only():
    reports = [
        _report({**CONCLUDED, "state": "gathering"}),
        _report(CONCLUDED),
        {"status": "skipped"},
    ]
    assert svc.pending_investigation_ids(reports) == [INVESTIGATION_ID]


def test_hydration_replaces_a_pending_report_once_the_investigation_concludes():
    reports = [_report({**CONCLUDED, "state": "gathering"})]

    changed = svc.hydrate_pending_reports(reports, {INVESTIGATION_ID: CONCLUDED}, schema_version="1.0")

    assert changed is True
    assert reports[0]["status"] == "completed"
    assert reports[0]["verdict"]["risk_score"] == 88
    assert reports[0]["indicator"] == INDICATOR
    # Started-at is preserved so the report keeps its original timeline.
    assert reports[0]["started_at"] == "2026-08-05T11:50:00+00:00"


def test_hydration_leaves_still_running_investigations_alone():
    reports = [_report({**CONCLUDED, "state": "gathering"})]

    changed = svc.hydrate_pending_reports(
        reports, {INVESTIGATION_ID: {**CONCLUDED, "state": "evaluating"}}, schema_version="1.0"
    )

    assert changed is False
    assert reports[0]["status"] == "investigating"


def test_outcomes_are_assembled_from_the_investigation_rows():
    investigation = SimpleNamespace(
        id=UUID(INVESTIGATION_ID),
        domain="myspotifypremium.info",
        observable_type="domain",
        client_domain=None,
        state="concluded",
        classification="malicious",
        confidence="high",
        risk_score=88,
        recommended_action="block",
        created_at=None,
        concluded_at=None,
    )
    report = SimpleNamespace(investigation_id=UUID(INVESTIGATION_ID), report_json={"key_evidence": ["a"]})
    stale_report = SimpleNamespace(investigation_id=UUID(INVESTIGATION_ID), report_json={"key_evidence": ["older"]})
    evidence = SimpleNamespace(investigation_id=UUID(INVESTIGATION_ID), evidence_json={"vt": {"malicious_count": 9}})
    collector = SimpleNamespace(
        investigation_id=UUID(INVESTIGATION_ID),
        collector_name="vt",
        status="completed",
        duration_ms=900,
        error=None,
    )

    outcomes = svc._assemble_outcomes([investigation], [report, stale_report], [evidence], [collector])

    outcome = outcomes[INVESTIGATION_ID]
    assert outcome["classification"] == "malicious"
    assert outcome["report"]["key_evidence"] == ["a"]     # newest iteration wins
    assert outcome["evidence"]["vt"]["malicious_count"] == 9
    assert outcome["collector_runs"] == [
        {"collector": "vt", "status": "completed", "duration_ms": 900, "error": None}
    ]


def test_unknown_ids_never_reach_the_database():
    assert svc.load_outcomes_sync([]) == {}
    assert svc.load_outcomes_sync(["not-a-uuid", None]) == {}
