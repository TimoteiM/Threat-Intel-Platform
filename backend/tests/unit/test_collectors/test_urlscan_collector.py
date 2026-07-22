from app.collectors.urlscan_collector import URLScanCollector
from types import SimpleNamespace


def _collector(observable: str, observable_type: str) -> URLScanCollector:
    return URLScanCollector(
        domain=observable,
        investigation_id="00000000-0000-0000-0000-000000000000",
        observable_type=observable_type,
        timeout=5,
    )


def test_pick_best_search_result_prefers_exact_domain_match():
    collector = _collector("revantage.eu", "domain")
    results = [
        {"page": {"domain": "other.example"}, "task": {"domain": "other.example"}},
        {"page": {"domain": "revantage.eu"}, "task": {"domain": "revantage.eu"}},
    ]
    best = collector._pick_best_search_result(results)
    assert (best.get("page") or {}).get("domain") == "revantage.eu"


def test_pick_best_search_result_prefers_exact_ip_match():
    collector = _collector("1.2.3.4", "ip")
    results = [
        {"page": {"ip": "8.8.8.8"}},
        {"page": {"ip": "1.2.3.4"}},
    ]
    best = collector._pick_best_search_result(results)
    assert (best.get("page") or {}).get("ip") == "1.2.3.4"


def test_accepted_scan_is_not_resubmitted_when_result_is_still_processing(monkeypatch):
    collector = _collector("example.com", "domain")
    submitted = []
    monkeypatch.setattr(
        "app.collectors.urlscan_collector.get_settings",
        lambda: SimpleNamespace(urlscan_api_key="configured", urlscan_analysis_timeout_seconds=75),
    )
    monkeypatch.setattr(collector, "_search_existing", lambda evidence, headers: {})
    monkeypatch.setattr(
        collector,
        "_submit_scan",
        lambda **kwargs: (submitted.append(kwargs["visibility"]) or "scan-id", None),
    )
    monkeypatch.setattr(collector, "_poll_result", lambda scan_uuid, wait_seconds: {})

    evidence = collector._collect()

    assert submitted == ["public"]
    assert evidence.scan_id == "scan-id"
    assert evidence.notes == ["URLScan analysis was still processing after 75s"]
