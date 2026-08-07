"""
VirusTotal for URL observables.

Regression cover for a phishing URL that came back benign: VT had no report for
the exact URL, we submitted it, gave up after 30s, and threw the result away —
while the URL's host sat in VT with 21 detections.
"""

import os

import pytest

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.collectors import vt_collector as mod
from app.collectors.vt_collector import VTCollector

URL = "https://myspotifypremium.info/login_up.php"
HOST = "myspotifypremium.info"


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = str(self._payload)

    def json(self):
        return self._payload


def _stats(malicious: int, suspicious: int = 0, harmless: int = 42, undetected: int = 29):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "last_analysis_results": {
                    f"Vendor{i}": {"category": "malicious", "result": "phishing"}
                    for i in range(malicious)
                },
            }
        }
    }


@pytest.fixture
def collector(monkeypatch):
    monkeypatch.setattr(mod, "record_provider_request", lambda *a, **k: None)
    monkeypatch.setattr(mod.time, "sleep", lambda *_: None)
    instance = VTCollector(domain=URL, investigation_id="test", observable_type="url", timeout=5)
    monkeypatch.setattr(instance, "_store_artifact", lambda *a, **k: None)
    return instance


def test_unknown_url_falls_back_to_the_host_reputation(collector, monkeypatch):
    calls: list[str] = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if "/urls/" in url:
            return _Resp(404)
        if f"/domains/{HOST}" in url:
            return _Resp(200, _stats(malicious=21))
        return _Resp(200, {"data": {"attributes": {"status": "queued"}}})

    monkeypatch.setattr(mod.requests, "get", fake_get)
    monkeypatch.setattr(
        mod.requests, "post", lambda *a, **k: _Resp(200, {"data": {"id": "analysis-1"}})
    )

    evidence = collector._collect_url("key")

    assert evidence.malicious_count == 21           # the verdict is no longer lost
    assert evidence.scope == "domain"
    assert evidence.scope_value == HOST
    assert any("has no report for this exact URL" in note for note in evidence.notes)
    assert any(f"host {HOST}" in note for note in evidence.notes)
    assert any(f"/domains/{HOST}" in call for call in calls)


def test_a_pending_scan_is_handed_on_instead_of_discarded(collector, monkeypatch):
    """We paid for the submission — keep the id so a later run can collect it."""
    monkeypatch.setattr(
        mod.requests,
        "get",
        lambda url, **kw: _Resp(404) if "/urls/" in url
        else _Resp(200, _stats(malicious=0, harmless=0, undetected=0)) if "/domains/" in url
        else _Resp(200, {"data": {"attributes": {"status": "queued"}}}),
    )
    monkeypatch.setattr(
        mod.requests, "post", lambda *a, **k: _Resp(200, {"data": {"id": "analysis-42"}})
    )

    evidence = collector._collect_url("key")

    assert evidence.pending_analysis_id == "analysis-42"
    assert any("still scanning" in note for note in evidence.notes)


def test_a_finished_fresh_scan_is_used(collector, monkeypatch):
    # A VT *analysis* object uses stats/results, not last_analysis_stats — parsing
    # only the latter silently turned a completed scan into "no detections".
    completed = {
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {"malicious": 7, "suspicious": 0, "harmless": 40, "undetected": 30},
                "results": {"VendorA": {"category": "malicious", "result": "phishing"}},
            }
        }
    }
    monkeypatch.setattr(
        mod.requests,
        "get",
        lambda url, **kw: _Resp(404) if "/urls/" in url
        else _Resp(404) if "/domains/" in url
        else _Resp(200, completed),
    )
    monkeypatch.setattr(mod.requests, "post", lambda *a, **k: _Resp(201, {"data": {"id": "analysis-9"}}))

    evidence = collector._collect_url("key")

    assert evidence.malicious_count == 7
    assert evidence.total_vendors == 77
    assert evidence.flagged_malicious_by == ["VendorA"]
    assert evidence.scope == "url"
    assert evidence.pending_analysis_id is None


def test_a_known_clean_url_still_reports_a_flagged_host(collector, monkeypatch):
    """'The page is clean but its domain is flagged' must not stay hidden."""
    monkeypatch.setattr(
        mod.requests,
        "get",
        lambda url, **kw: _Resp(200, _stats(malicious=0)) if "/urls/" in url
        else _Resp(200, _stats(malicious=21)),
    )

    evidence = collector._collect_url("key")

    assert evidence.scope == "url"                  # the URL's own stats stay primary
    assert evidence.malicious_count == 0
    assert any(f"flags the host {HOST}" in note for note in evidence.notes)
    assert "host-flagged" in evidence.tags


def test_a_known_flagged_url_costs_a_single_request(collector, monkeypatch):
    calls: list[str] = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return _Resp(200, _stats(malicious=21))

    monkeypatch.setattr(mod.requests, "get", fake_get)

    evidence = collector._collect_url("key")

    assert evidence.malicious_count == 21
    assert evidence.scope == "url"
    assert len(calls) == 1                          # no needless domain lookup


def test_a_transient_connection_error_is_retried_once(collector, monkeypatch):
    """A DNS blip used to fail the whole VT collector for the investigation."""
    attempts = {"n": 0}

    def flaky_get(url, **kwargs):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise mod.requests.ConnectionError("Failed to resolve 'www.virustotal.com'")
        return _Resp(200, _stats(malicious=21))

    monkeypatch.setattr(mod.requests, "get", flaky_get)

    evidence = collector._collect_for_key("key")

    assert evidence.malicious_count == 21
    assert attempts["n"] == 2


def test_a_persistent_connection_failure_still_surfaces(collector, monkeypatch):
    def always_fails(url, **kwargs):
        raise mod.requests.ConnectionError("Failed to resolve 'www.virustotal.com'")

    monkeypatch.setattr(mod.requests, "get", always_fails)

    with pytest.raises(mod.requests.ConnectionError):
        collector._collect_for_key("key")
