from app.collectors.urlscan_collector import URLScanCollector


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
