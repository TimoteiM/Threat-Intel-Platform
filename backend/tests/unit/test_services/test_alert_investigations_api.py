import asyncio
import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.api import alert_investigations as api
from app.services import alert_report_export_service as export_service


AI_REPORT = {"report_type": "ai_assistant", "status": "completed", "report_markdown": "## Triage"}
INDICATOR_REPORT = {
    "report_type": "indicator",
    "status": "completed",
    "indicator": {"value": "expertware.net", "type": "domain"},
    "verdict": {"classification": "benign", "risk_score": 5},
}


def _run(**overrides) -> SimpleNamespace:
    base = {
        "id": UUID("11111111-2222-3333-4444-555555555555"),
        "title": "Windows audit failure event",
        "alert_body": "computer=exprdsh002.int.expertware.net",
        "context": "ticket INC-1",
        "status": "completed",
        "indicator_count": 2,
        "overall_verdict": "benign",
        "highest_risk_score": 5,
        "created_at": datetime(2026, 8, 5, 10, 0, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 8, 5, 10, 4, tzinfo=timezone.utc),
        "result_json": {
            "schema_version": "1.0",
            "summary": {"overall_verdict": "benign", "indicators_total": 1},
            "ai_report": AI_REPORT,
            "indicator_reports": [INDICATOR_REPORT],
            "reports": [AI_REPORT, INDICATOR_REPORT],
        },
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture
def stub_run(monkeypatch):
    def _install(run):
        async def fake_get_run(db, run_id):
            return run

        monkeypatch.setattr(api, "_get_run", fake_get_run)
        return run

    return _install


def _export(run_id="11111111-2222-3333-4444-555555555555", **kwargs):
    return asyncio.run(api.export_alert_investigation(None, run_id=run_id, **kwargs))


class _IngestDB(_FakeDBBase := object):
    """Enough AsyncSession for the create path: add / commit / refresh."""

    def __init__(self):
        self.added = []
        self.commits = 0

    def add(self, row):
        row.id = UUID("99999999-9999-9999-9999-999999999999")
        row.result_json = dict(row.result_json or {})
        self.added.append(row)

    async def commit(self):
        self.commits += 1

    async def refresh(self, _row):
        return None

    async def rollback(self):
        return None


def _ingest(db, **fields):
    """POST our own schema — a JSON object with alert_body, not waiting for it."""
    return asyncio.run(api.create_alert_investigation(db, fields, wait=False))


@pytest.fixture
def ingest_env(monkeypatch):
    """Ingest with the queue, history lookup and duplicate lookup stubbed out."""
    queued: list[tuple] = []

    monkeypatch.setattr(api, "_attach_prior_investigations", _noop_async)
    monkeypatch.setattr(api, "find_duplicate_run", _no_duplicate)
    monkeypatch.setattr(
        api.run_alert_body_investigation_task,
        "delay",
        lambda *args, **kwargs: queued.append((args, kwargs)) or SimpleNamespace(id="task-1"),
    )
    return queued


async def _noop_async(*args, **kwargs):
    return None


async def _no_duplicate(*args, **kwargs):
    return None


def test_ingest_returns_the_links_a_sender_needs(ingest_env):
    db = _IngestDB()
    body = "User clicked hxxps://evil-corp[.]net/login from 10.0.0.5"

    response = _ingest(db, alert_body=body, external_ref="INC-4471", run_ai=False)

    assert response["status"] == "queued"
    assert response["deduplicated"] is False
    assert response["external_ref"] == "INC-4471"
    run_id = response["run_id"]
    assert response["links"] == {
        "run": f"/api/alert-investigations/{run_id}",
        "report": f"/api/alert-investigations/{run_id}/export?format=report",
        "reports": f"/api/alert-investigations/{run_id}/export?format=reports",
        "full": f"/api/alert-investigations/{run_id}/export?format=full",
        "cancel": f"/api/alert-investigations/{run_id}/cancel",
        "ui": f"/alert-investigations/{run_id}",
    }
    assert response["callback"] is None
    # The body hash is stored so a repeat delivery can find this run.
    assert db.added[0].alert_body_hash == api.alert_body_hash(body)
    assert len(ingest_env) == 1                      # queued exactly once


def test_ingest_accepts_and_stores_a_callback_url(ingest_env):
    db = _IngestDB()

    response = _ingest(
        db,
        alert_body="Beacon to evil-corp.net",
        callback_url="http://10.10.30.50:8080/hooks/alert",
        run_ai=False,
    )

    assert response["callback"] == {"url": "http://10.10.30.50:8080/hooks/alert", "status": "pending"}
    assert db.added[0].callback_url == "http://10.10.30.50:8080/hooks/alert"


def test_ingest_rejects_a_callback_url_we_will_not_post_to(ingest_env):
    db = _IngestDB()

    with pytest.raises(api.HTTPException) as excinfo:
        _ingest(db, alert_body="Beacon to evil-corp.net", callback_url="http://127.0.0.1:9000/hook")

    assert excinfo.value.status_code == 400
    assert "blocked address" in str(excinfo.value.detail)
    assert db.added == []                            # nothing was queued


def test_repeated_delivery_of_the_same_alert_returns_the_first_run(monkeypatch, ingest_env):
    existing = _run(
        status="processing",
        callback_url=None,
        result_json={"extraction": {"investigable_total": 2}, "external_ref": "INC-1"},
    )

    async def duplicate(_db, body_hash, **kwargs):
        assert body_hash == api.alert_body_hash("Beacon to evil-corp.net")
        return existing

    monkeypatch.setattr(api, "find_duplicate_run", duplicate)
    db = _IngestDB()

    response = _ingest(db, alert_body="Beacon to evil-corp.net")

    assert response["deduplicated"] is True
    assert response["run_id"] == str(existing.id)
    assert response["external_ref"] == "INC-1"
    assert "already investigated" in response["message"]
    assert db.added == []                            # no second run
    assert ingest_env == []                          # no second pipeline


def test_dedupe_can_be_switched_off_per_delivery(monkeypatch, ingest_env):
    async def duplicate(*args, **kwargs):
        raise AssertionError("dedupe=False must not look for a duplicate")

    monkeypatch.setattr(api, "find_duplicate_run", duplicate)
    db = _IngestDB()

    response = _ingest(db, alert_body="Beacon to evil-corp.net", dedupe=False, run_ai=False)
    assert response["deduplicated"] is False


class _DeleteDB:
    """AsyncSession stand-in that records what the delete path removed."""

    def __init__(self, other_runs=(), investigations=()):
        self.deleted = []
        self.commits = 0
        self._other_runs = list(other_runs)
        self._investigations = set(investigations)

    async def execute(self, _statement):
        rows = self._other_runs

        class _Result:
            def all(self_inner):
                return rows

        return _Result()

    async def get(self, _model, key):
        return SimpleNamespace(id=key) if str(key) in self._investigations else None

    async def delete(self, row):
        self.deleted.append(row)

    async def commit(self):
        self.commits += 1


SPAWNED_A = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
SPAWNED_B = "cccccccc-1111-2222-3333-dddddddddddd"


def _run_with_investigations():
    spawned = {
        "report_type": "indicator",
        "status": "completed",
        "indicator": {"value": "evil-corp.net", "type": "domain"},
        "verdict": {},
        "investigation": {"investigation_id": SPAWNED_A, "state": "concluded"},
    }
    also_spawned = {
        "report_type": "indicator",
        "status": "completed",
        "indicator": {"value": "phish.test", "type": "domain"},
        "verdict": {},
        "investigation": {"investigation_id": SPAWNED_B, "state": "concluded"},
    }
    reused = {
        "report_type": "indicator",
        "status": "reused",
        "indicator": {"value": "siembiot.int", "type": "domain"},
        "verdict": {},
        "prior_investigation": {"investigation_id": "eeeeeeee-1111-2222-3333-ffffffffffff"},
    }
    return _run(
        result_json={
            "schema_version": "1.0",
            "indicator_reports": [spawned, also_spawned, reused],
            "reports": [spawned, also_spawned, reused],
        }
    )


def _delete(db, run_id="11111111-2222-3333-4444-555555555555"):
    return asyncio.run(api.delete_alert_investigation(db, run_id=run_id))


@pytest.fixture(autouse=True)
def _no_task_revocation(monkeypatch):
    monkeypatch.setattr(api, "find_task_ids", lambda **kwargs: [])
    monkeypatch.setattr(api, "revoke_task_ids", lambda ids: None)


def test_deleting_a_run_deletes_the_investigations_it_spawned(stub_run):
    run = stub_run(_run_with_investigations())
    db = _DeleteDB(investigations={SPAWNED_A, SPAWNED_B})

    response = _delete(db)

    assert sorted(response["deleted_investigations"]) == sorted([SPAWNED_A, SPAWNED_B])
    assert response["kept_investigations"] == []
    # Two investigations plus the run itself.
    assert len(db.deleted) == 3
    assert db.deleted[-1] is run


def test_a_reused_investigation_is_never_deleted(stub_run):
    stub_run(_run_with_investigations())
    db = _DeleteDB(investigations={SPAWNED_A, SPAWNED_B, "eeeeeeee-1111-2222-3333-ffffffffffff"})

    response = _delete(db)

    assert "eeeeeeee-1111-2222-3333-ffffffffffff" not in response["deleted_investigations"]


def test_an_investigation_another_run_references_is_kept(stub_run):
    stub_run(_run_with_investigations())
    # A second alert run reused SPAWNED_B — deleting it would gut that run's report.
    other = (UUID("77777777-7777-7777-7777-777777777777"),
             {"indicator_reports": [{"prior_investigation": {"investigation_id": SPAWNED_B}}]})
    db = _DeleteDB(other_runs=[other], investigations={SPAWNED_A, SPAWNED_B})

    response = _delete(db)

    assert response["deleted_investigations"] == [SPAWNED_A]
    assert response["kept_investigations"] == [SPAWNED_B]


def test_a_run_without_investigations_just_deletes_itself(stub_run):
    run = stub_run(_run())
    db = _DeleteDB()

    response = _delete(db)

    assert response["deleted_investigations"] == []
    assert db.deleted == [run]


def test_list_rows_say_how_many_investigations_a_delete_would_take():
    row = _run_with_investigations()
    assert api._list_item(row)["spawned_investigation_count"] == 2


def test_router_exposes_the_export_route():
    routes = {(route.path, tuple(sorted(route.methods or []))) for route in api.router.routes}
    assert ("/api/alert-investigations/{run_id}/export", ("GET",)) in routes


def test_export_defaults_to_the_report_list(stub_run):
    stub_run(_run())
    response = _export()

    payload = json.loads(response.body)
    assert isinstance(payload, list)
    assert [item["report_type"] for item in payload] == ["ai_assistant", "indicator"]
    assert response.media_type == "application/json"
    assert response.headers["x-alert-report-count"] == "2"
    assert response.headers["x-alert-run-status"] == "completed"
    assert "attachment" in response.headers["content-disposition"]
    assert "windows-audit-failure-event" in response.headers["content-disposition"]


def test_envelope_export_wraps_the_list_in_the_run_object(stub_run):
    stub_run(_run())
    payload = json.loads(_export(format="envelope").body)

    assert payload["run_id"] == "11111111-2222-3333-4444-555555555555"
    assert payload["status"] == "completed"
    assert payload["alert_body"].startswith("computer=")
    assert payload["summary"]["overall_verdict"] == "benign"
    assert [item["report_type"] for item in payload["reports"]] == ["ai_assistant", "indicator"]


def test_full_export_is_a_list_led_by_the_executive_summary(stub_run, monkeypatch):
    stub_run(_run())

    async def no_outcomes(_db, ids):
        return {}

    monkeypatch.setattr(api, "load_outcomes", no_outcomes)

    documents = json.loads(_export(format="full").body)

    assert isinstance(documents, list)
    assert [item["report_type"] for item in documents] == ["executive_summary", "indicator"]

    summary = documents[0]
    assert summary["run_id"] == "11111111-2222-3333-4444-555555555555"
    assert summary["overall_verdict"] == "benign"
    assert summary["alert_body"].startswith("computer=")
    # The AI reading of the alert is folded into the summary, not a separate doc.
    assert summary["ai_analysis"]["report_markdown"] == "## Triage"
    assert summary["ai_analysis"]["status"] == "completed"


def test_full_export_carries_each_investigation_in_full(stub_run, monkeypatch):
    report = {
        **INDICATOR_REPORT,
        "investigation": {"investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb", "state": "concluded"},
    }
    stub_run(
        _run(
            result_json={
                "schema_version": "1.0",
                "ai_report": AI_REPORT,
                "indicator_reports": [report],
                "reports": [AI_REPORT, report],
            }
        )
    )

    async def fake_load(_db, ids):
        assert ids == ["aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"]
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": CONCLUDED_OUTCOME}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    documents = json.loads(_export(format="full").body)
    investigation = documents[1]["investigation"]

    assert investigation["report"]["key_evidence"][0].startswith("VirusTotal")
    assert investigation["evidence"]["vt"]["malicious_count"] == 9
    assert investigation["collector_runs"][0]["collector"] == "vt"
    # The executive summary indexes it, so the first document alone is navigable.
    assert documents[0]["investigations"] == [
        {
            "investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "url": "/investigations/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "indicator": "expertware.net",
            "observable_type": None,
            "state": "concluded",
            "classification": None,
            "risk_score": None,
            "reused": False,
        }
    ]

    lean = json.loads(_export(format="full", evidence=False).body)
    assert "evidence" not in lean[1]["investigation"]
    assert lean[1]["investigation"]["report"]["key_evidence"]


REPORT_OUTCOME = {
    "investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
    "state": "concluded",
    "classification": "malicious",
    "confidence": "high",
    "risk_score": 80,
    "collector_runs": [{"collector": "vt", "status": "completed", "duration_ms": 900, "error": None}],
    "value": "myspotifypremium.info",
    "observable_type": "domain",
    "recommended_action": "block",
    "created_at": "2026-08-05T11:39:34+00:00",
    "concluded_at": "2026-08-05T11:42:26+00:00",
    "report": {
        "classification": "malicious",
        "confidence": "high",
        "risk_score": 80,
        "recommended_action": "block",
        "executive_summary": "Credential phishing page impersonating Spotify.",
        "primary_reasoning": "OpenPhish lists it. VirusTotal flags it. The page is parked.",
        "risk_rationale": "External intelligence floor enforced at 80/100.",
        "key_evidence": ["VirusTotal: 21 of 91 engines flag this as malicious"],
        "findings": [
            {"id": "vt", "title": "VirusTotal detection signal", "severity": "high",
             "description": "VT reports 21 malicious detections.", "evidence_refs": ["vt.malicious_count"]},
        ],
        "iocs": [{"type": "domain", "value": "myspotifypremium.info", "context": "Investigated domain",
                  "confidence": "low"}],
        "recommended_steps": ["Block at the perimeter", "Hunt for related indicators"],
    },
    "evidence": {
        "dns": {"a": ["102.135.105.190"], "ns": ["ns3.my-ndns.com"]},
        "http": {"final_url": "http://myspotifypremium.info/", "status_code": 200, "server": "nginx"},
        "vt": {"found": True, "malicious_count": 21, "suspicious_count": 0, "total_vendors": 91},
        "threat_feeds": {"openphish_listed": True, "feeds_checked": ["openphish", "otx"]},
        "signals": [{"severity": "high", "description": "OpenPhish: domain found in active phishing feed"}],
        "final_risk": {"risk_score": 80, "risk_level": "high"},
    },
}


def _report_run():
    report = {
        **INDICATOR_REPORT,
        "indicator": {"value": "myspotifypremium.info", "type": "domain", "observable_type": "domain"},
        "verdict": {"classification": "malicious", "risk_score": 80},
        "findings": [{"collector": "vt", "severity": "high", "summary": "21 of 91 engines"}],
        "investigation": {
            "investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "url": "/investigations/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "state": "concluded",
            "classification": "malicious",
            "risk_score": 80,
            "executive_summary": "…",
        },
    }
    ip_report = {
        "report_type": "indicator",
        "status": "skipped",
        "skip_reason": "private_or_reserved_address",
        "indicator": {"value": "10.10.30.19", "type": "ip", "observable_type": "ip"},
        "verdict": {"classification": "not_investigated", "risk_score": 0},
        "findings": [],
        "sources_checked": [],
        "errors": [],
    }
    return _run(
        result_json={
            "schema_version": "1.0",
            "ai_report": AI_REPORT,
            "indicator_reports": [report, ip_report],
            "reports": [AI_REPORT, report, ip_report],
        }
    )


def test_report_export_carries_the_soc_report_data_model(stub_run, monkeypatch):
    stub_run(_report_run())

    async def fake_load(_db, ids):
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": REPORT_OUTCOME}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    documents = json.loads(_export(format="report").body)
    assert [doc["report_type"] for doc in documents] == ["executive_summary", "indicator", "indicator"]

    soc_report = documents[1]["soc_report"]
    # Every section the SOC PDF prints, in the shape templates/soc_report.html reads.
    for key in (
        "title", "subtitle", "classification", "verdict", "case_metadata", "summary",
        "assessment_points", "key_evidence", "findings", "iocs", "recommendations",
        "derived_intelligence", "signals", "evidence_sections", "methodology",
    ):
        assert key in soc_report, key

    assert soc_report["verdict"]["classification"] == "MALICIOUS"
    assert soc_report["verdict"]["risk_score"] == 80
    assert soc_report["verdict"]["recommended_action"] == "BLOCK"
    assert any(row["label"] == "Case ID" for row in soc_report["case_metadata"])
    assert [section["title"] for section in soc_report["evidence_sections"]][:2] == [
        "DNS Resolution and Mail Authentication",
        "HTTP and Web Surface",
    ]


def test_report_export_drops_the_raw_collector_dumps(stub_run, monkeypatch):
    stub_run(_report_run())

    async def fake_load(_db, ids):
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": REPORT_OUTCOME}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    document = json.loads(_export(format="report").body)[1]

    assert "evidence" not in document["investigation"]
    assert "report" not in document["investigation"]
    assert "collector_runs" not in document
    # The investigation is still identified and linkable.
    assert document["investigation"]["investigation_id"] == "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
    assert document["investigation"]["url"].endswith("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb")


def test_report_export_caps_the_ioc_quality_table(stub_run, monkeypatch):
    stub_run(_report_run())

    async def fake_load(_db, ids):
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": REPORT_OUTCOME}

    monkeypatch.setattr(api, "load_outcomes", fake_load)
    monkeypatch.setattr(
        export_service,
        "build_soc_report_document",
        lambda **kwargs: {
            "derived_intelligence": {
                "confidence_engine": {"verdict": "malicious", "score": 80},
                "ioc_quality": {"summary": {"total_count": 103},
                                "items": [{"value": f"ioc-{i}"} for i in range(103)]},
                "evidence_timeline": [{"noise": True}] * 50,
                "investigation_graph": {"nodes": [1] * 500},
            }
        },
    )

    derived = json.loads(_export(format="report").body)[1]["soc_report"]["derived_intelligence"]

    assert sorted(derived.keys()) == ["confidence_engine", "ioc_quality"]   # timeline/graph dropped
    assert len(derived["ioc_quality"]["items"]) == export_service.IOC_QUALITY_ROWS
    assert derived["ioc_quality"]["total_items"] == 103
    assert derived["ioc_quality"]["summary"]["total_count"] == 103


def test_report_export_keeps_findings_for_indicators_without_an_investigation(stub_run, monkeypatch):
    stub_run(_report_run())

    async def fake_load(_db, ids):
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": REPORT_OUTCOME}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    ip_document = json.loads(_export(format="report").body)[2]

    assert ip_document["indicator"]["value"] == "10.10.30.19"
    assert ip_document["status"] == "skipped"
    assert ip_document["skip_reason"] == "private_or_reserved_address"
    assert "soc_report" not in ip_document
    assert "findings" in ip_document


def test_report_export_covers_reused_domains_too(stub_run, monkeypatch):
    """A domain answered from an earlier investigation still gets its SOC report."""
    reused = {
        "report_type": "indicator",
        "status": "reused",
        "schema_version": "1.0",
        "indicator": {"value": "siembiot.int", "type": "domain", "observable_type": "domain"},
        "verdict": {"classification": "benign", "risk_score": 15},
        "findings": [],
        "prior_investigation": {
            "investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "state": "concluded",
            "classification": "benign",
            "risk_score": 15,
            "age_days": 0.07,
            "total_investigations": 1,
        },
    }
    stub_run(
        _run(
            result_json={
                "schema_version": "1.0",
                "ai_report": AI_REPORT,
                "indicator_reports": [reused],
                "reports": [AI_REPORT, reused],
            }
        )
    )

    async def fake_load(_db, ids):
        assert ids == ["aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"]
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": REPORT_OUTCOME}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    document = json.loads(_export(format="report").body)[1]

    assert document["status"] == "reused"
    assert "soc_report" in document                       # the older investigation's report
    assert document["soc_report"]["verdict"]["classification"] == "MALICIOUS"
    prior = document["prior_investigation"]
    assert prior["investigation_id"] == "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
    assert prior["url"] == "/investigations/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
    assert prior["age_days"] == 0.07                      # reuse metadata is preserved

    # …and the detailed list carries its evidence under the same key.
    detailed = json.loads(_export(format="full").body)[1]
    assert detailed["prior_investigation"]["evidence"]["vt"]["malicious_count"] == 21


def test_export_shape_holds_for_an_alert_with_no_domain(stub_run, monkeypatch):
    """An alert without a domain/URL yields the same list, minus those documents."""
    ip_report = {
        "report_type": "indicator",
        "status": "completed",
        "indicator": {"value": "8.8.8.8", "type": "ip", "observable_type": "ip"},
        "verdict": {"classification": "benign", "risk_score": 5},
        "findings": [{"collector": "ip_lookup", "severity": "info", "summary": "No abuse reports"}],
        "sources_checked": ["threat_feeds", "ip_lookup"],
        "collector_runs": [{"collector": "threat_feeds", "status": "completed"}],
        "errors": [],
    }
    hash_report = {
        "report_type": "indicator",
        "status": "completed",
        "indicator": {"value": "e3b0c442", "type": "hash", "observable_type": "hash"},
        "verdict": {"classification": "benign", "risk_score": 5},
        "findings": [{"collector": "vt", "severity": "info", "summary": "No engine detections"}],
        "sources_checked": ["vt"],
        "collector_runs": [{"collector": "vt", "status": "completed"}],
        "errors": [],
    }
    stub_run(
        _run(
            result_json={
                "schema_version": "1.0",
                "ai_report": AI_REPORT,
                "indicator_reports": [ip_report, hash_report],
                "reports": [AI_REPORT, ip_report, hash_report],
            }
        )
    )

    async def fail_load(_db, ids):
        raise AssertionError("no investigations to load when the alert has no domain")

    monkeypatch.setattr(api, "load_outcomes", fail_load)

    for shape in ("report", "full"):
        documents = json.loads(_export(format=shape).body)
        assert [doc["report_type"] for doc in documents] == [
            "executive_summary",
            "indicator",
            "indicator",
        ], shape
        assert documents[0]["investigations"] == []          # nothing to link to
        for document in documents[1:]:
            assert "soc_report" not in document              # no domain → no SOC report
            assert "investigation" not in document
            assert document["findings"]                      # the inline evidence stands alone

    # The lean list is unchanged as always.
    lean = json.loads(_export().body)
    assert [doc["report_type"] for doc in lean] == ["ai_assistant", "indicator", "indicator"]


def test_report_export_of_a_running_investigation_has_no_soc_report_yet(stub_run, monkeypatch):
    stub_run(_report_run())

    async def fake_load(_db, ids):
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": {"state": "gathering", "report": {}, "evidence": {}}}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    document = json.loads(_export(format="report").body)[1]

    assert "soc_report" not in document
    assert document["investigation"]["investigation_id"] == "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"


def test_full_export_can_be_streamed_as_ndjson(stub_run, monkeypatch):
    stub_run(_run())

    async def no_outcomes(_db, ids):
        return {}

    monkeypatch.setattr(api, "load_outcomes", no_outcomes)

    response = _export(format="full", ndjson=True)
    lines = response.body.decode().strip().split("\n")

    assert [json.loads(line)["report_type"] for line in lines] == ["executive_summary", "indicator"]
    assert response.media_type == "application/x-ndjson"


def test_ndjson_export_is_one_report_per_line(stub_run):
    stub_run(_run())
    response = _export(format="ndjson")

    lines = response.body.decode().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["report_type"] == "ai_assistant"
    assert response.media_type == "application/x-ndjson"
    # format=ndjson is the lean list, streamed — the name says which list it is.
    assert response.headers["content-disposition"].endswith('-reports.ndjson"')


def test_export_can_be_served_inline(stub_run):
    stub_run(_run())
    response = _export(download=False)
    assert response.headers["content-disposition"].startswith("inline;")


def test_export_of_a_running_alert_returns_what_exists(stub_run):
    stub_run(_run(status="processing", result_json={"schema_version": "1.0", "status": "processing"}))
    response = _export()

    assert json.loads(response.body) == []
    assert response.headers["x-alert-run-status"] == "processing"
    assert response.headers["x-alert-report-count"] == "0"


def test_legacy_runs_without_a_reports_key_still_export(stub_run):
    stub_run(
        _run(
            result_json={
                "schema_version": "1.0",
                "ai_report": AI_REPORT,
                "indicator_reports": [INDICATOR_REPORT],
            }
        )
    )
    payload = json.loads(_export().body)
    assert [item["report_type"] for item in payload] == ["ai_assistant", "indicator"]


class _FakeDB:
    """Just enough AsyncSession for the hydration path."""

    def __init__(self):
        self.commits = 0
        self.rollbacks = 0

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


PENDING_REPORT = {
    "report_type": "indicator",
    "status": "investigating",
    "schema_version": "1.0",
    "indicator": {"value": "myspotifypremium.info", "type": "domain", "observable_type": "domain"},
    "investigation": {"investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb", "state": "gathering"},
    "verdict": {"classification": "not_investigated", "risk_score": 0, "confidence": 0.0, "reasons": [], "sources": []},
    "findings": [],
    "sources_checked": ["investigation"],
    "collector_runs": [],
    "errors": [],
    "started_at": "2026-08-05T11:50:00+00:00",
    "completed_at": "2026-08-05T11:55:00+00:00",
    "duration_ms": 300000,
}

CONCLUDED_OUTCOME = {
    "investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
    "state": "concluded",
    "classification": "malicious",
    "confidence": "high",
    "risk_score": 88,
    "report": {"key_evidence": ["VirusTotal: 9 of 94 engines flag this as malicious"]},
    "evidence": {"vt": {"malicious_count": 9, "total_vendors": 94}},
    "collector_runs": [{"collector": "vt", "status": "completed", "duration_ms": 900, "error": None}],
}


def _pending_run(**overrides):
    return _run(
        overall_verdict="inconclusive",
        highest_risk_score=0,
        result_json={
            "schema_version": "1.0",
            "summary": {"overall_verdict": "inconclusive", "indicators_investigating": 1},
            "ai_report": AI_REPORT,
            "indicator_reports": [PENDING_REPORT],
            "reports": [AI_REPORT, PENDING_REPORT],
        },
        **overrides,
    )


def test_reading_a_run_folds_in_a_finished_investigation(stub_run, monkeypatch):
    run = stub_run(_pending_run())
    db = _FakeDB()

    async def fake_load(_db, ids):
        assert ids == ["aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"]
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": CONCLUDED_OUTCOME}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    payload = asyncio.run(api.get_alert_investigation(db, run_id=str(run.id)))
    report = payload["indicator_reports"][0]

    assert report["status"] == "completed"
    assert report["verdict"]["risk_score"] == 88
    assert payload["summary"]["overall_verdict"] == "malicious"
    assert payload["reports"][1]["status"] == "completed"
    # The verdict is written back, so the next export is already complete.
    assert run.result_json["indicator_reports"][0]["status"] == "completed"
    assert run.overall_verdict == "malicious"
    assert run.highest_risk_score == 88
    assert db.commits == 1


def test_reading_a_run_with_a_still_running_investigation_changes_nothing(stub_run, monkeypatch):
    run = stub_run(_pending_run())
    db = _FakeDB()

    async def fake_load(_db, ids):
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": {**CONCLUDED_OUTCOME, "state": "evaluating"}}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    payload = asyncio.run(api.get_alert_investigation(db, run_id=str(run.id)))

    assert payload["indicator_reports"][0]["status"] == "investigating"
    assert db.commits == 0


def test_export_hydrates_before_serving(stub_run, monkeypatch):
    run = stub_run(_pending_run())

    async def fake_load(_db, ids):
        return {"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": CONCLUDED_OUTCOME}

    monkeypatch.setattr(api, "load_outcomes", fake_load)

    response = asyncio.run(
        api.export_alert_investigation(_FakeDB(), run_id=str(run.id), format="reports", download=True, pretty=True)
    )
    payload = json.loads(response.body)

    assert [item.get("status") for item in payload] == ["completed", "completed"]
    assert payload[1]["verdict"]["classification"] == "malicious"


def test_runs_without_pending_investigations_skip_the_lookup(stub_run, monkeypatch):
    stub_run(_run())

    async def fail_load(_db, ids):
        raise AssertionError("no pending investigations — the lookup must not run")

    monkeypatch.setattr(api, "load_outcomes", fail_load)

    payload = asyncio.run(api.get_alert_investigation(_FakeDB(), run_id="11111111-2222-3333-4444-555555555555"))
    assert payload["status"] == "completed"


def test_export_slug_falls_back_to_the_run_id():
    run = _run(title="   ")
    assert api._export_slug(run) == "alert-11111111-2222-3333-4444-555555555555"



def test_the_raw_route_takes_the_alert_as_the_body(ingest_env, monkeypatch):
    """A SIEM posts text/plain; nothing has to be escaped into JSON."""

    class _RawRequest:
        async def body(self):
            return b'Process Create: Image: C:\\Windows\\cmd.exe CommandLine: cmd /c whoami User: INT\\bob'

    db = _IngestDB()
    response = asyncio.run(
        api.create_alert_investigation_from_raw_text(
            _RawRequest(), db, title="from siem", external_ref="INC-9", run_ai=False,
            collectors="dns,vt", wait=False,
        )
    )

    assert response["status"] == "queued"
    assert response["title"] == "from siem"
    assert response["external_ref"] == "INC-9"
    assert db.added[0].alert_body.startswith("Process Create:")
    # Collectors arrive as a comma-separated query parameter.
    assert ingest_env[0][1]["requested_collectors"] == ["dns", "vt"]


def test_the_raw_route_survives_a_bad_encoding(ingest_env):
    """A log forwarder's mangled byte must not cost us the alert."""

    class _RawRequest:
        async def body(self):
            return b"Process Create: Image: C:\\bad\\\xff.exe CommandLine: run User: INT\\bob"

    response = asyncio.run(
        api.create_alert_investigation_from_raw_text(_RawRequest(), _IngestDB(), run_ai=False, wait=False)
    )
    assert response["status"] == "queued"


def test_the_router_exposes_the_raw_route():
    routes = {(route.path, tuple(sorted(route.methods or []))) for route in api.router.routes}
    assert ("/api/alert-investigations/raw", ("POST",)) in routes


# ── Synchronous ingest ────────────────────────────────────────────────────────

class _WaitDB(_IngestDB):
    """Ingest DB that also serves the run back while it 'runs' then completes."""

    def __init__(self, statuses):
        super().__init__()
        self._statuses = list(statuses)
        self.polls = 0

    def expire_all(self):
        pass


def _sync_ingest(monkeypatch, statuses, **fields):
    db = _WaitDB(statuses)
    run_holder = {}

    async def fake_get_run(_db, run_id):
        db.polls += 1
        status = db._statuses.pop(0) if db._statuses else "completed"
        run_holder["run"] = _run(
            status=status,
            result_json={
                "schema_version": "1.0",
                "ai_report": AI_REPORT,
                "indicator_reports": [INDICATOR_REPORT],
                "reports": [AI_REPORT, INDICATOR_REPORT],
            },
        )
        return run_holder["run"]

    monkeypatch.setattr(api, "_get_run", fake_get_run)
    monkeypatch.setattr(api, "WAIT_POLL_SECONDS", 0)

    async def no_outcomes(_db, ids):
        return {}

    monkeypatch.setattr(api, "load_outcomes", no_outcomes)
    # No `wait` argument: holding the request is the default for a sender.
    result = asyncio.run(api.create_alert_investigation(db, {"alert_body": "Domain evil-corp.net", **fields}))
    return result, db


def test_a_synchronous_ingest_returns_the_report_list(ingest_env, monkeypatch):
    """One call in, the finished report out — no queueing and polling."""
    documents, db = _sync_ingest(monkeypatch, ["processing", "processing", "completed"])

    assert isinstance(documents, list)
    assert [doc["report_type"] for doc in documents] == ["executive_summary", "indicator"]
    assert db.polls >= 3  # it really waited rather than answering on the first look


def test_a_synchronous_ingest_falls_back_to_the_queued_response_on_timeout(ingest_env, monkeypatch):
    """The work continues; the caller gets the links and a 202 instead of a hang."""
    monkeypatch.setattr(api, "MIN_WAIT_TIMEOUT_SECONDS", 0)
    db = _WaitDB([])

    async def always_running(_db, run_id):
        return _run(status="processing")

    monkeypatch.setattr(api, "_get_run", always_running)
    monkeypatch.setattr(api, "WAIT_POLL_SECONDS", 0)

    response = asyncio.run(
        api.create_alert_investigation(db, {"alert_body": "Domain evil-corp.net"}, wait=True, wait_timeout=0)
    )
    assert response.status_code == 202
    body = json.loads(response.body)
    assert body["status"] == "processing"
    assert body["links"]["report"].endswith("export?format=report")
    assert "wait_timeout" in body["message"]


def test_wait_false_returns_the_queued_response(ingest_env):
    """The UI opts out of waiting — it queues, navigates and polls the run page."""
    response = _ingest(_IngestDB(), alert_body="Domain evil-corp.net")
    assert response["status"] == "queued"
    assert "links" in response
