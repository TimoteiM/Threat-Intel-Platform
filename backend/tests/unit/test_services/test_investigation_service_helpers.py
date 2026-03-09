from app.services.investigation_service import _ensure_baseline_collectors


def test_baseline_collectors_are_added_when_not_explicit():
    collectors = ["dns", "http", "vt"]
    supported = {"dns", "http", "vt", "threat_feeds", "urlscan"}
    out = _ensure_baseline_collectors(
        collectors,
        supported_for_type=supported,
        explicit_request=False,
    )
    assert out == ["dns", "http", "vt", "threat_feeds", "urlscan"]


def test_explicit_collector_request_is_respected():
    collectors = ["dns", "vt"]
    supported = {"dns", "vt", "threat_feeds", "urlscan"}
    out = _ensure_baseline_collectors(
        collectors,
        supported_for_type=supported,
        explicit_request=True,
    )
    assert out == ["dns", "vt"]
