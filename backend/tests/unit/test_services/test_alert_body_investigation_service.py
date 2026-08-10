from typing import Any

import pytest

from app.config import get_settings
from app.models.enums import CollectorStatus
from app.models.schemas import CollectorMeta
from app.services import alert_body_investigation_service as svc
from app.services.exclusion_service import ExclusionMatcher


class _FakeEvidence:
    def __init__(self, payload: dict[str, Any]):
        self._payload = payload

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        return dict(self._payload)


def _fake_collector(name: str, payload: dict[str, Any], *, supported: set[str] | None = None):
    class FakeCollector:
        supported_types = frozenset(supported or {"domain", "ip", "url", "hash"})

        def __init__(self, domain: str, investigation_id: str, observable_type: str = "domain", timeout: int = 20, **_):
            self.domain = domain
            self.observable_type = observable_type

        def run(self):
            meta = CollectorMeta(collector=name, status=CollectorStatus.COMPLETED, duration_ms=12)
            return _FakeEvidence(payload), meta, {}

    return FakeCollector


@pytest.fixture(autouse=True)
def no_prior_investigations(monkeypatch):
    """Unit tests never reach the investigations table — each run starts fresh."""
    monkeypatch.setattr(svc, "find_prior_investigations_sync", lambda pairs: {})


@pytest.fixture(autouse=True)
def no_spawned_investigations(monkeypatch):
    """
    Default to the inline collector path.

    Spawning is real: it writes an Investigation row and queues the pipeline, so
    a test that forgets to stub it would start actual collector traffic. Tests
    that exercise the spawn path re-enable it explicitly via `spawning`.
    """
    monkeypatch.setattr(svc, "should_spawn", lambda observable_type, enabled=None: False)


@pytest.fixture
def spawning(monkeypatch):
    """Enable the spawn path with a stubbed investigation pipeline."""

    calls: dict[str, Any] = {"spawned": [], "waited": [], "outcome": None}

    def fake_should_spawn(observable_type, enabled=None):
        return observable_type in ("domain", "url") and enabled is not False

    def fake_spawn(value, observable_type, *, context=None):
        calls["spawned"].append((value, observable_type, context))
        return "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"

    def fake_wait(investigation_id, *, deadline, is_cancelled=None, poll_seconds=None):
        calls["waited"].append(investigation_id)
        return str((calls["outcome"] or {}).get("state") or "concluded")

    monkeypatch.setattr(svc, "should_spawn", fake_should_spawn)
    monkeypatch.setattr(svc, "spawn_investigation", fake_spawn)
    monkeypatch.setattr(svc, "wait_for_investigation", fake_wait)
    monkeypatch.setattr(
        svc,
        "load_outcomes_sync",
        lambda ids: {ids[0]: calls["outcome"]} if calls["outcome"] else {},
    )
    return calls


@pytest.fixture
def vt_everywhere(monkeypatch):
    """Lift the hash-only VT rule for tests that use VT as a generic collector."""
    monkeypatch.setattr(get_settings(), "alert_vt_hash_only", False)


@pytest.fixture
def stub_collectors(monkeypatch):
    """Replace the registry with deterministic fakes and skip IP Lookup network calls."""
    registry: dict[str, Any] = {}

    def fake_get_collector(name: str):
        return registry.get(name)

    def fake_get_collectors_for_type(observable_type: str) -> list[str]:
        return [
            name for name, cls in registry.items()
            if observable_type in cls.supported_types
        ]

    monkeypatch.setattr(svc, "get_collector", fake_get_collector)
    monkeypatch.setattr(svc, "get_collectors_for_type", fake_get_collectors_for_type)
    return registry


def test_each_indicator_produces_its_own_json_report(stub_collectors, vt_everywhere, monkeypatch):
    stub_collectors["vt"] = _fake_collector(
        "vt", {"found": True, "malicious_count": 9, "suspicious_count": 0, "total_vendors": 70}
    )
    monkeypatch.setattr(svc, "lookup_ip_with_history", lambda ip, timeout=20: {"ip": ip, "abuseipdb": {"abuse_confidence_score": 0, "total_reports": 0}, "threatfox": []})

    payload = svc.run_alert_body_investigation(
        alert_body="Contact hxxps://evil[.]com/login from 45.147.230.131",
        run_id="test-run",
        requested_collectors=["vt"],
        run_ai=False,
    )

    reports = payload["indicator_reports"]
    assert isinstance(reports, list)
    values = {report["indicator"]["value"] for report in reports}
    assert values == {"https://evil.com/login", "45.147.230.131"}
    for report in reports:
        assert report["schema_version"] == svc.ALERT_REPORT_SCHEMA_VERSION
        assert report["status"] == "completed"
        assert report["verdict"]["classification"] == "malicious"
        # Only findings by default — no raw collector dump.
        assert "evidence" not in report
        vt_finding = next(f for f in report["findings"] if f["collector"] == "vt")
        assert vt_finding["data"]["malicious"] == 9
        assert vt_finding["severity"] == "high"
    assert payload["summary"]["overall_verdict"] == "malicious"
    assert payload["summary"]["indicators_investigated"] == 2


def test_ips_also_go_through_the_ip_lookup_tool(stub_collectors, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})
    calls: list[str] = []

    def fake_lookup(ip: str, timeout: int = 20) -> dict[str, Any]:
        calls.append(ip)
        return {
            "ip": ip,
            "abuseipdb": {"abuse_confidence_score": 96, "total_reports": 44},
            "threatfox": [{"ioc_value": ip, "malware": "Cobalt Strike"}],
            "errors": [],
        }

    monkeypatch.setattr(svc, "lookup_ip_with_history", fake_lookup)

    payload = svc.run_alert_body_investigation(
        alert_body="Beaconing to 45.147.230.131 observed",
        requested_collectors=["vt"],
        run_ai=False,
    )

    assert calls == ["45.147.230.131"]
    report = payload["indicator_reports"][0]
    assert "ip_lookup" in report["sources_checked"]
    abuse = next(f for f in report["findings"] if f["collector"] == "ip_lookup" and f["type"] == "reputation")
    assert abuse["data"]["abuse_confidence_score"] == 96
    assert report["verdict"]["classification"] == "malicious"
    assert "ip_lookup" in report["verdict"]["sources"]


def test_non_ip_indicators_do_not_call_ip_lookup(stub_collectors, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})
    monkeypatch.setattr(
        svc,
        "lookup_ip_with_history",
        lambda ip, timeout=20: pytest.fail("IP Lookup must not run for non-IP indicators"),
    )

    payload = svc.run_alert_body_investigation(
        alert_body="Bare domain evil-corp.net in the alert",
        requested_collectors=["vt"],
        run_ai=False,
    )
    report = payload["indicator_reports"][0]
    assert "ip_lookup" not in report["sources_checked"]
    assert all(finding["collector"] != "ip_lookup" for finding in report["findings"])


def test_private_ip_is_reported_as_skipped(stub_collectors, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})
    monkeypatch.setattr(svc, "lookup_ip_with_history", lambda ip, timeout=20: {"ip": ip})

    payload = svc.run_alert_body_investigation(
        alert_body="Internal host 10.12.4.55 triggered the rule",
        requested_collectors=["vt"],
        run_ai=False,
    )
    report = payload["indicator_reports"][0]
    assert report["status"] == "skipped"
    assert report["skip_reason"] == "private_or_reserved_address"
    assert payload["summary"]["indicators_skipped"] == 1


def test_collector_failure_is_reported_not_raised(stub_collectors, monkeypatch):
    class BoomCollector:
        supported_types = frozenset({"domain"})

        def __init__(self, **_):
            pass

        def run(self):
            raise RuntimeError("upstream down")

    stub_collectors["whois"] = BoomCollector
    payload = svc.run_alert_body_investigation(
        alert_body="Domain evil-corp.net", requested_collectors=["whois"], run_ai=False
    )
    report = payload["indicator_reports"][0]
    assert report["status"] == "failed"
    assert report["collector_runs"][0]["status"] == "failed"
    assert "upstream down" in report["errors"][0]
    assert report["verdict"]["classification"] == "inconclusive"


def test_requested_collectors_are_filtered_by_observable_support(stub_collectors, vt_everywhere):
    stub_collectors["dns"] = _fake_collector("dns", {"a": []}, supported={"domain", "url"})
    stub_collectors["vt"] = _fake_collector("vt", {"total_vendors": 70}, supported={"domain", "ip", "url", "hash"})

    assert svc.resolve_collectors("hash", ["dns", "vt"]) == ["vt"]
    assert svc.resolve_collectors("domain", ["dns", "vt", "unknown"]) == ["dns", "vt"]


def test_vt_is_reserved_for_hashes(stub_collectors):
    """VT's free tier (4/min · 500/day) is spent on hashes only — see alert_vt_hash_only."""
    stub_collectors["dns"] = _fake_collector("dns", {"a": []}, supported={"domain", "url"})
    stub_collectors["vt"] = _fake_collector("vt", {"total_vendors": 70}, supported={"domain", "ip", "url", "hash"})

    assert svc.resolve_collectors("hash", ["dns", "vt"]) == ["vt"]
    assert svc.resolve_collectors("domain", ["dns", "vt"]) == ["dns"]
    assert svc.resolve_collectors("url", ["vt"]) == []
    assert svc.resolve_collectors("ip", ["vt"]) == []
    assert "vt" not in svc.default_collectors_for("domain")
    assert "vt" in svc.default_collectors_for("hash")


def test_vt_does_not_run_for_a_domain_indicator(stub_collectors):
    stub_collectors["vt"] = _fake_collector("vt", {"found": True, "malicious_count": 9, "total_vendors": 70})

    payload = svc.run_alert_body_investigation(
        alert_body="Bare domain evil-corp.net", requested_collectors=["vt"], run_ai=False
    )
    report = payload["indicator_reports"][0]
    assert report["sources_checked"] == []
    assert report["collector_runs"] == []
    assert report["verdict"]["classification"] == "inconclusive"


def test_recent_investigation_is_reused_instead_of_re_collected(stub_collectors, monkeypatch):
    stub_collectors["whois"] = _fake_collector(
        "whois", {"registrar": "X"}, supported={"domain"},
    )
    monkeypatch.setattr(
        svc,
        "find_prior_investigations_sync",
        lambda pairs: {
            "domain:evil-corp.net": {
                "investigation_id": "abc-123",
                "value": "evil-corp.net",
                "observable_type": "domain",
                "state": "concluded",
                "classification": "malicious",
                "confidence": "high",
                "risk_score": 88,
                "recommended_action": "block",
                "created_at": "2026-08-04T10:00:00+00:00",
                "concluded_at": "2026-08-04T10:04:00+00:00",
                "age_days": 1.0,
                "total_investigations": 2,
            }
        },
    )

    payload = svc.run_alert_body_investigation(
        alert_body="Bare domain evil-corp.net", requested_collectors=["whois"], run_ai=False
    )
    report = payload["indicator_reports"][0]
    assert report["status"] == "reused"
    assert report["collector_runs"] == []                  # no collector was spent
    assert report["sources_checked"] == ["prior_investigation"]
    assert report["verdict"]["classification"] == "malicious"
    assert report["verdict"]["risk_score"] == 88
    assert report["prior_investigation"]["investigation_id"] == "abc-123"
    assert payload["summary"]["indicators_reused"] == 1
    assert payload["summary"]["overall_verdict"] == "malicious"
    assert payload["prior_investigations"]["matched"] == 1


def test_stale_or_unfinished_investigations_are_not_reused(stub_collectors, monkeypatch):
    stub_collectors["whois"] = _fake_collector("whois", {"registrar": "X"}, supported={"domain"})
    prior = {
        "investigation_id": "abc-123",
        "state": "concluded",
        "classification": "malicious",
        "risk_score": 88,
        "age_days": 99.0,
        "total_investigations": 1,
    }
    monkeypatch.setattr(
        svc, "find_prior_investigations_sync", lambda pairs: {"domain:evil-corp.net": prior}
    )

    payload = svc.run_alert_body_investigation(
        alert_body="Bare domain evil-corp.net", requested_collectors=["whois"], run_ai=False
    )
    report = payload["indicator_reports"][0]
    assert report["status"] == "completed"                 # too old — collectors ran
    assert [run["collector"] for run in report["collector_runs"]] == ["whois"]
    # …but the analyst still sees that the platform has looked at it before.
    assert report["indicator"]["prior_investigation"]["investigation_id"] == "abc-123"
    assert report["indicator"]["prior_investigation"]["reusable"] is False


def test_domains_get_a_full_investigation_not_inline_collectors(stub_collectors, spawning):
    stub_collectors["whois"] = _fake_collector("whois", {"registrar": "X"}, supported={"domain"})
    spawning["outcome"] = {
        "investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "value": "myspotifypremium.info",
        "state": "concluded",
        "classification": "malicious",
        "confidence": "high",
        "risk_score": 88,
        "recommended_action": "block",
        "concluded_at": "2026-08-05T12:00:00+00:00",
        "report": {
            "executive_summary": "Credential phishing page impersonating Spotify.",
            "key_evidence": ["VirusTotal: 9 of 94 engines flag this as malicious"],
            "findings": [{"id": "vt", "title": "9 engines flag the domain", "severity": "high"}],
        },
        "evidence": {"vt": {"malicious_count": 9, "total_vendors": 94}},
        "collector_runs": [{"collector": "vt", "status": "completed", "duration_ms": 900, "error": None}],
    }

    payload = svc.run_alert_body_investigation(
        alert_body="User visited myspotifypremium.info",
        requested_collectors=["whois"],
        run_ai=False,
    )
    report = payload["indicator_reports"][0]

    assert spawning["spawned"] == [("myspotifypremium.info", "domain", None)]
    assert report["status"] == "completed"
    assert report["investigation"]["investigation_id"] == "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
    assert report["investigation"]["url"] == "/investigations/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
    assert report["verdict"]["classification"] == "malicious"
    assert report["verdict"]["risk_score"] == 88
    # Findings come from the investigation's own evidence and analyst findings.
    assert any(f["collector"] == "vt" for f in report["findings"])
    assert any(f["collector"] == "investigation" for f in report["findings"])
    assert payload["summary"]["investigation_ids"] == ["aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"]
    assert payload["summary"]["overall_verdict"] == "malicious"
    assert payload["spawned_investigations"]["enabled"] is True


def test_investigation_still_running_at_the_deadline_is_reported_as_investigating(
    stub_collectors, spawning
):
    spawning["outcome"] = {
        "investigation_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "state": "gathering",
        "report": {},
        "evidence": {},
        "collector_runs": [],
    }

    payload = svc.run_alert_body_investigation(
        alert_body="User visited myspotifypremium.info", run_ai=False
    )
    report = payload["indicator_reports"][0]

    assert report["status"] == "investigating"
    assert report["verdict"]["classification"] == "not_investigated"
    assert "still running" in report["verdict"]["reasons"][0]
    assert payload["summary"]["indicators_investigating"] == 1


def test_a_reusable_prior_investigation_wins_over_spawning_a_new_one(stub_collectors, spawning, monkeypatch):
    monkeypatch.setattr(
        svc,
        "find_prior_investigations_sync",
        lambda pairs: {
            "domain:myspotifypremium.info": {
                "investigation_id": "old-1",
                "state": "concluded",
                "classification": "malicious",
                "risk_score": 90,
                "age_days": 1.0,
            }
        },
    )

    payload = svc.run_alert_body_investigation(
        alert_body="User visited myspotifypremium.info", run_ai=False
    )
    assert spawning["spawned"] == []                      # nothing re-investigated
    assert payload["indicator_reports"][0]["status"] == "reused"


def test_ips_and_hashes_stay_on_the_inline_path(stub_collectors, spawning, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})
    monkeypatch.setattr(svc, "lookup_ip_with_history", lambda ip, timeout=20: {"ip": ip})

    payload = svc.run_alert_body_investigation(
        alert_body="Beacon to 45.147.230.131 with hash d41d8cd98f00b204e9800998ecf8427e",
        requested_collectors=["vt"],
        run_ai=False,
    )
    assert spawning["spawned"] == []
    assert all("investigation" not in report for report in payload["indicator_reports"])


def test_spawning_can_be_switched_off_per_run(stub_collectors, spawning):
    stub_collectors["whois"] = _fake_collector("whois", {"registrar": "X"}, supported={"domain"})

    payload = svc.run_alert_body_investigation(
        alert_body="User visited myspotifypremium.info",
        requested_collectors=["whois"],
        run_ai=False,
        spawn_investigations=False,
    )
    assert spawning["spawned"] == []
    assert [run["collector"] for run in payload["indicator_reports"][0]["collector_runs"]] == ["whois"]


def test_reuse_can_be_switched_off_per_run(stub_collectors, monkeypatch):
    stub_collectors["whois"] = _fake_collector("whois", {"registrar": "X"}, supported={"domain"})
    monkeypatch.setattr(
        svc,
        "find_prior_investigations_sync",
        lambda pairs: {
            "domain:evil-corp.net": {
                "investigation_id": "abc-123",
                "state": "concluded",
                "classification": "malicious",
                "risk_score": 88,
                "age_days": 0.5,
                "total_investigations": 1,
            }
        },
    )

    payload = svc.run_alert_body_investigation(
        alert_body="Bare domain evil-corp.net",
        requested_collectors=["whois"],
        run_ai=False,
        reuse_prior_investigations=False,
    )
    assert payload["indicator_reports"][0]["status"] == "completed"
    assert payload["summary"]["indicators_reused"] == 0


def test_assess_indicator_scores_reputation_signals():
    clean = svc.assess_indicator({"vt": {"malicious_count": 0, "suspicious_count": 0, "total_vendors": 70}})
    assert clean["classification"] == "benign"

    phishing = svc.assess_indicator({"threat_feeds": {"phishtank": {"in_database": True, "verified": True}}})
    assert phishing["classification"] == "malicious"
    assert phishing["risk_score"] >= 70

    # Unverified PhishTank listings are stale often enough to not stand alone.
    stale = svc.assess_indicator({"threat_feeds": {"phishtank": {"in_database": True, "verified": False}}})
    assert stale["classification"] == "benign"

    # VirusTotal thresholds follow the decision engine: 2-4 hits is suspicious.
    few_hits = svc.assess_indicator({"vt": {"malicious_count": 2, "total_vendors": 70}})
    assert few_hits["classification"] == "suspicious"

    unknown = svc.assess_indicator({})
    assert unknown["classification"] == "inconclusive"
    assert unknown["risk_score"] == 0


def test_summary_counts_every_report():
    reports = [
        {"status": "completed", "verdict": {"classification": "malicious", "risk_score": 90}, "indicator": {"value": "a.com"}},
        {"status": "completed", "verdict": {"classification": "benign", "risk_score": 5}, "indicator": {"value": "b.com"}},
        {"status": "skipped", "verdict": {"classification": "not_investigated", "risk_score": 0}, "indicator": {"value": "10.0.0.1"}},
    ]
    summary = svc.summarize_indicator_reports(reports)
    assert summary["indicators_total"] == 3
    assert summary["indicators_investigated"] == 2
    assert summary["indicators_skipped"] == 1
    assert summary["overall_verdict"] == "malicious"
    assert summary["highest_risk_score"] == 90
    assert summary["malicious_indicators"] == ["a.com"]


def test_ai_report_leads_the_exported_report_list(stub_collectors, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})
    seen: dict[str, Any] = {}

    def fake_ai(*, alert_body, title, context, model, schema_version, findings_digest=None):
        seen['findings_digest'] = findings_digest
        seen.update(alert_body=alert_body, title=title, context=context)
        return {
            "schema_version": schema_version,
            "report_type": "ai_assistant",
            "status": "completed",
            "report_markdown": "## Alert triage\nLooks like credential phishing.",
            "assistant_session_id": "11111111-1111-1111-1111-111111111111",
        }

    monkeypatch.setattr(svc, "run_alert_body_ai_analysis", fake_ai)

    alert = "Phishing alert\nUser clicked evil-corp.net"
    payload = svc.run_alert_body_investigation(
        alert_body=alert, context="ticket INC-1", requested_collectors=["vt"]
    )

    # The AI sees the whole alert, not just the extracted indicators.
    assert seen["alert_body"] == alert
    assert seen["context"] == "ticket INC-1"
    assert seen["title"] == "Phishing alert"

    reports = payload["reports"]
    assert reports[0]["report_type"] == "ai_assistant"
    assert reports[1:] == payload["indicator_reports"]
    assert all(report["report_type"] == "indicator" for report in reports[1:])
    assert payload["summary"]["ai_analysis"] == "completed"


def test_failed_ai_analysis_does_not_lose_indicator_reports(stub_collectors, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})
    monkeypatch.setattr(
        svc,
        "run_alert_body_ai_analysis",
        lambda **kwargs: {"report_type": "ai_assistant", "status": "failed", "error": "model timeout"},
    )

    payload = svc.run_alert_body_investigation(
        alert_body="Domain evil-corp.net", requested_collectors=["vt"]
    )
    assert payload["reports"][0]["status"] == "failed"
    assert len(payload["indicator_reports"]) == 1
    assert payload["summary"]["ai_analysis"] == "failed"


def test_ai_can_be_disabled(stub_collectors, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})
    monkeypatch.setattr(
        svc,
        "run_alert_body_ai_analysis",
        lambda **kwargs: pytest.fail("AI analysis must not run when run_ai=False"),
    )

    payload = svc.run_alert_body_investigation(
        alert_body="Domain evil-corp.net", requested_collectors=["vt"], run_ai=False
    )
    assert payload["ai_report"] is None
    assert payload["reports"] == payload["indicator_reports"]
    assert payload["summary"]["ai_analysis"] == "skipped"


def test_reports_carry_findings_not_empty_collector_dumps(stub_collectors, vt_everywhere, monkeypatch):
    # A collector that found nothing must not add noise to the report.
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0, "vendor_results": []})
    stub_collectors["whois"] = _fake_collector(
        "whois",
        {"registrar": None, "domain_age_days": None, "name_servers": [], "statuses": []},
        supported={"domain"},
    )

    payload = svc.run_alert_body_investigation(
        alert_body="Domain evil-corp.net", requested_collectors=["vt", "whois"], run_ai=False
    )
    report = payload["indicator_reports"][0]
    assert report["sources_checked"] == ["vt", "whois"]          # both ran
    assert [f["collector"] for f in report["findings"]] == []    # neither found anything


def test_raw_evidence_is_available_on_request(stub_collectors, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": True, "malicious_count": 1, "total_vendors": 70})

    payload = svc.run_alert_body_investigation(
        alert_body="SHA256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        requested_collectors=["vt"],
        run_ai=False,
        include_raw_evidence=True,
    )
    report = payload["indicator_reports"][0]
    assert report["evidence"]["vt"]["total_vendors"] == 70
    assert report["findings"]


SYSMON_BODY = (
    "Process Create: UtcTime: 2026-08-06 08:52:41.529 ProcessId: 4336 "
    "Image: C:\\Windows\\System32\\cmd.exe "
    "CommandLine: cmd.exe /c vssadmin delete shadows /all /quiet "
    "User: INT\\tmoscaliuc IntegrityLevel: High "
    "Hashes: SHA256=ACF4ECB52E601F7B4A37DB51B07650B5D0315EAFD010590E98079FA026DA4B7B "
    "ParentImage: C:\\Program Files\\Microsoft Office\\WINWORD.EXE"
)


def test_an_endpoint_event_becomes_its_own_report(stub_collectors, monkeypatch):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})

    payload = svc.run_alert_body_investigation(alert_body=SYSMON_BODY, run_ai=False)

    events = payload["event_reports"]
    assert len(events) == 1
    assert events[0]["report_type"] == "endpoint_event"
    assert events[0]["event"]["image"].endswith("cmd.exe")
    # Behaviour drives the verdict when there is nothing to look up.
    assert events[0]["verdict"]["classification"] == "malicious"
    assert payload["summary"]["overall_verdict"] == "malicious"
    assert payload["summary"]["events_total"] == 1
    assert payload["summary"]["events_flagged"] == 1
    # The exported list carries it between the AI report and the indicators.
    assert payload["reports"][0]["report_type"] == "endpoint_event"


def test_an_alert_without_endpoint_telemetry_has_no_event_reports(stub_collectors):
    stub_collectors["vt"] = _fake_collector("vt", {"found": False, "total_vendors": 0})

    payload = svc.run_alert_body_investigation(
        alert_body="User clicked https://evil-corp.net/login", run_ai=False, spawn_investigations=False
    )
    assert payload["event_reports"] == []
    assert payload["summary"]["events_total"] == 0


def test_the_ai_receives_what_the_collectors_found(stub_collectors, vt_everywhere, monkeypatch):
    """
    The narrative used to be written from the alert text alone.

    Running the analyst after the collectors is the whole point: it can now say
    that a hash was flagged, not merely that a hash was present.
    """
    stub_collectors["vt"] = _fake_collector(
        "vt", {"found": True, "malicious_count": 21, "suspicious_count": 0, "total_vendors": 91}
    )
    captured: dict[str, Any] = {}

    def fake_ai(*, alert_body, title, context, model, schema_version, findings_digest=None):
        captured["digest"] = findings_digest or ""
        captured["alert_body"] = alert_body
        return {"report_type": "ai_assistant", "status": "completed", "report_markdown": "ok"}

    monkeypatch.setattr(svc, "run_alert_body_ai_analysis", fake_ai)

    payload = svc.run_alert_body_investigation(
        alert_body="Sample SHA256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 seen",
        requested_collectors=["vt"],
    )

    digest = captured["digest"]
    assert "VERIFIED RESULTS FROM OUR OWN SOURCES" in digest
    assert "21 of 91 engines malicious" in digest
    assert "Overall verdict: malicious" in digest
    # The alert text still reaches the model unchanged.
    assert "9f86d081884c7d65" in captured["alert_body"]
    # …and the same facts are on the payload for the UI and the export.
    assert "21 of 91 engines malicious" in payload["indicator_summary"]["headline"]


def test_endpoint_event_behaviour_reaches_the_ai_too(stub_collectors, monkeypatch):
    captured: dict[str, Any] = {}

    def fake_ai(*, findings_digest=None, **kwargs):
        captured["digest"] = findings_digest or ""
        return {"report_type": "ai_assistant", "status": "completed"}

    monkeypatch.setattr(svc, "run_alert_body_ai_analysis", fake_ai)
    svc.run_alert_body_investigation(alert_body=SYSMON_BODY)

    assert "Endpoint events" in captured["digest"]
    assert "Backup or recovery tampering" in captured["digest"]


def test_the_ai_can_still_be_skipped(stub_collectors, monkeypatch):
    monkeypatch.setattr(
        svc, "run_alert_body_ai_analysis",
        lambda **kwargs: pytest.fail("AI must not run when run_ai=False"),
    )
    payload = svc.run_alert_body_investigation(alert_body="Domain evil-corp.net", run_ai=False)
    assert payload["ai_report"] is None


def test_an_alert_whose_indicators_were_all_excluded_still_gets_its_narrative(monkeypatch):
    """
    The exclusion list stops lookups, not analysis.

    A Defender or crash alert usually extracts nothing but our own domain and an
    RFC1918 address. Every indicator is then excluded or unsupported, no
    collector runs — and that is exactly the alert with no evidence to read, so
    the narrative is the only thing an analyst gets. Skipping it left those runs
    blank.
    """
    matcher = ExclusionMatcher([
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "indicator_type": "domain",
            "normalized_value": "expertware.net",
            "value": "expertware.net",
            "reason": "Our own corporate domain",
            "match_subdomains": True,
        }
    ])
    monkeypatch.setattr(svc, "load_exclusion_matcher_sync", lambda: matcher)
    monkeypatch.setattr(svc, "record_exclusion_hits_sync", lambda ids: None)

    captured: dict[str, Any] = {}

    def fake_ai(*, findings_digest=None, **kwargs):
        captured["digest"] = findings_digest or ""
        return {"report_type": "ai_assistant", "status": "completed"}

    monkeypatch.setattr(svc, "run_alert_body_ai_analysis", fake_ai)

    payload = svc.run_alert_body_investigation(
        alert_body=(
            "Windows Defender: Antimalware scan was stopped before it finished\n"
            "Computer: EXP-D07DY24.int.expertware.net\n"
            "Agent IP: 10.10.126.56\n"
        )
    )

    assert payload["extraction"]["excluded_total"] == 1
    assert payload["ai_report"]["status"] == "completed"
    assert payload["summary"]["ai_analysis"] == "completed"
    # And the model is told why nothing was collected, so the narrative cannot
    # describe our own domain as an indicator no source had heard of.
    assert "on the exclusion list" in captured["digest"]
