from app.collectors.intel_collector import IntelCollector


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else []

    def json(self):
        return self._payload


def _collector() -> IntelCollector:
    return IntelCollector(
        domain="example.com",
        investigation_id="00000000-0000-0000-0000-000000000000",
        observable_type="domain",
        timeout=20,
    )


def test_query_crtsh_uses_explicit_timeout(monkeypatch):
    seen = {}

    def _fake_get(url, params=None, timeout=None, headers=None):
        seen["timeout"] = timeout
        return _Resp(200, [])

    monkeypatch.setattr("app.collectors.intel_collector.requests.get", _fake_get)
    c = _collector()
    c._query_crtsh("example.com", timeout=7)
    assert seen["timeout"] == 7


def test_check_urlhaus_uses_explicit_timeout(monkeypatch):
    seen = {}

    def _fake_post(url, data=None, timeout=None):
        seen["timeout"] = timeout
        return _Resp(200, {"query_status": "no_results"})

    monkeypatch.setattr("app.collectors.intel_collector.requests.post", _fake_post)
    c = _collector()
    c._check_urlhaus("example.com", timeout=5)
    assert seen["timeout"] == 5
