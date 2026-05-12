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


def test_spamhaus_public_resolver_response_is_not_blocklist_hit(monkeypatch):
    def _fake_getaddrinfo(query, port, family):
        return [(family, None, None, "", ("127.255.255.254", 0))]

    monkeypatch.setattr("app.collectors.intel_collector.DNSBL_LISTS", [("dbl.spamhaus.org", "Spamhaus DBL")])
    monkeypatch.setattr("app.collectors.intel_collector.socket.getaddrinfo", _fake_getaddrinfo)

    c = _collector()
    c._dnsbl_notes = []

    assert c._check_dns_blocklists("4castplus.com") == []
    assert c._dnsbl_notes == [
        "Spamhaus DBL lookup skipped: query via public/open resolver (response: 127.255.255.254)"
    ]


def test_spamhaus_reputation_response_is_blocklist_hit(monkeypatch):
    def _fake_getaddrinfo(query, port, family):
        return [(family, None, None, "", ("127.0.1.2", 0))]

    monkeypatch.setattr("app.collectors.intel_collector.DNSBL_LISTS", [("dbl.spamhaus.org", "Spamhaus DBL")])
    monkeypatch.setattr("app.collectors.intel_collector.socket.getaddrinfo", _fake_getaddrinfo)

    c = _collector()
    hits = c._check_dns_blocklists("listed.example")

    assert len(hits) == 1
    assert hits[0].source == "Spamhaus DBL"
    assert hits[0].details == "Listed in Spamhaus DBL (response: 127.0.1.2)"


def test_spamhaus_sia_domain_query_uses_bearer_token(monkeypatch):
    seen = {}

    class _SiaResp:
        status_code = 200

        def json(self):
            return {"domain": "example.com", "score": 0}

    def _fake_get(url, headers=None, timeout=None):
        seen.setdefault("urls", []).append(url)
        seen["authorization"] = headers.get("Authorization")
        seen["timeout"] = timeout
        return _SiaResp()

    monkeypatch.setattr("app.collectors.intel_collector.requests.get", _fake_get)

    c = _collector()
    result = c._query_spamhaus_sia_domain(
        "example.com",
        token="test-token",
        base_url="https://api.spamhaus.org",
        timeout=3,
    )

    assert result["status"] == "checked"
    assert result["general"]["score"] == 0
    assert seen["authorization"] == "Bearer test-token"
    assert seen["timeout"] == 3
    assert seen["urls"][0] == "https://api.spamhaus.org/api/intel/v2/byobject/domain/example.com"


def test_spamhaus_sia_refresh_token_uses_login_endpoint(monkeypatch):
    seen = {}

    class _LoginResp:
        status_code = 200

        def json(self):
            return {"token": "fresh-token", "expires": 4102444800}

    def _fake_post(url, json=None, timeout=None, headers=None):
        seen["url"] = url
        seen["payload"] = json
        seen["timeout"] = timeout
        return _LoginResp()

    monkeypatch.setattr("app.collectors.intel_collector.requests.post", _fake_post)

    c = _collector()
    token = c._refresh_spamhaus_sia_token(
        username="user@example.test",
        password="secret",
        base_url="https://api.spamhaus.org",
        timeout=4,
    )

    assert token == "fresh-token"
    assert seen["url"] == "https://api.spamhaus.org/api/v1/login"
    assert seen["payload"] == {"username": "user@example.test", "password": "secret", "realm": "intel"}
    assert seen["timeout"] == 4
