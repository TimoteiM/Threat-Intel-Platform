from __future__ import annotations

from app.services import hybrid_analysis_service as svc


class _DummyResponse:
    def __init__(self, payload, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise svc.requests.HTTPError(response=self)

    def json(self):
        return self._payload


def test_lookup_url_uses_search_terms_post_first(monkeypatch):
    calls: list[tuple[str, dict]] = []

    def fake_post(url: str, *, headers=None, data=None, timeout=None):
        calls.append((url, {"headers": headers, "data": data, "timeout": timeout}))
        assert url.endswith("/search/terms")
        assert (data or {}).get("url") == "https://example.test"
        return _DummyResponse(
            [
                {
                    "verdict": "malicious",
                    "threat_score": 99,
                    "id": "job-123",
                    "sha256": "abc123",
                    "submit_name": "example.test",
                }
            ]
        )

    def fail_get(*args, **kwargs):
        raise AssertionError("GET should not be used for URL search lookup path")

    monkeypatch.setattr(svc.requests, "post", fake_post)
    monkeypatch.setattr(svc.requests, "get", fail_get)

    out = svc._lookup_url("https://hybrid-analysis.com/api/v2", {"api-key": "k"}, "https://example.test")
    assert out["checked"] is True
    assert out["verdict"] == "malicious"
    assert out["analysis_id"] == "job-123"
    assert calls, "Expected /search/terms POST call"


def test_lookup_url_falls_back_to_quick_scan_when_search_empty(monkeypatch):
    calls: list[str] = []

    def fake_post(url: str, *, headers=None, data=None, timeout=None):
        calls.append(url)
        if url.endswith("/search/terms"):
            return _DummyResponse([])
        if url.endswith("/submit/url"):
            assert (data or {}).get("url") == "https://example.test"
            return _DummyResponse({"id": "qs-1", "finished": True, "sha256": "s1", "verdict": "suspicious"}, status_code=201)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(svc.requests, "post", fake_post)
    monkeypatch.setattr(
        svc.requests,
        "get",
        lambda *args, **kwargs: _DummyResponse({"state": "SUCCESS"}) if str(args[0]).endswith("/state") else _DummyResponse({"id": "qs-1", "verdict": "suspicious"}),
    )

    out = svc._lookup_url("https://hybrid-analysis.com/api/v2", {"api-key": "k"}, "https://example.test")
    assert out["checked"] is True
    assert out["analysis_id"] == "qs-1"
    assert out["verdict"] == "suspicious"
    assert calls[0].endswith("/search/terms")
    assert calls[1].endswith("/submit/url")


def test_hash_lookup_bypasses_stale_unknown_cache(monkeypatch):
    cached_unknown = {
        "checked": True,
        "indicator_type": "hash",
        "hash": "58c3a5d714336712eb504af380c72d1ad0e888b2ca593244e7ed23c0516113d4",
        "verdict": "unknown",
    }

    monkeypatch.setattr(svc, "_cache_get", lambda _key: cached_unknown)
    monkeypatch.setattr(svc, "_cache_set", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        svc,
        "_retry_lookup",
        lambda **kwargs: {
            "checked": True,
            "indicator_type": "hash",
            "hash": kwargs["indicator"],
            "verdict": "malicious",
            "analysis_id": "job-123",
        },
    )

    out = svc.lookup_hybrid_analysis(
        indicator="58c3a5d714336712eb504af380c72d1ad0e888b2ca593244e7ed23c0516113d4",
        indicator_type="hash",
    )
    assert out["checked"] is True
    assert out["verdict"] == "malicious"
    assert out["cache_hit"] is False


def test_lookup_prefers_anyrun_for_url(monkeypatch):
    monkeypatch.setattr(svc, "_cache_get", lambda _key: None)
    monkeypatch.setattr(svc, "_cache_set", lambda *args, **kwargs: None)

    class _Settings:
        anyrun_api_key = "ak"
        hybrid_analysis_api_key = "hk"
        hybrid_analysis_base_url = "https://hybrid-analysis.com/api/v2"
        hybrid_analysis_environment_id = 160

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(
        svc,
        "lookup_anyrun",
        lambda **kwargs: {
            "checked": True,
            "indicator_type": "url",
            "verdict": "malicious",
            "analysis_id": "ar-1",
            "raw_summary": {"source": "anyrun"},
        },
    )

    called = {"retry": False}
    monkeypatch.setattr(
        svc,
        "_retry_lookup",
        lambda **kwargs: called.__setitem__("retry", True) or {"checked": False, "verdict": "unknown"},
    )

    out = svc.lookup_hybrid_analysis(indicator="https://example.test", indicator_type="url")
    assert out["checked"] is True
    assert out["verdict"] == "malicious"
    assert out["raw_summary"]["source"] == "anyrun"
    assert called["retry"] is False


def test_cache_key_separates_proxy_country():
    direct = svc._cache_key(indicator="https://example.test", indicator_type="url")
    be = svc._cache_key(
        indicator="https://example.test",
        indicator_type="url",
        use_residential_proxy=True,
        proxy_country="BE",
    )
    assert direct != be
    assert direct == svc._cache_key(indicator="https://example.test", indicator_type="url", proxy_country="BE")
    assert be == svc._cache_key(
        indicator="https://example.test",
        indicator_type="url",
        use_residential_proxy=True,
        proxy_country="be",
    )


def test_lookup_falls_back_to_hybrid_when_anyrun_fails(monkeypatch):
    monkeypatch.setattr(svc, "_cache_get", lambda _key: None)
    monkeypatch.setattr(svc, "_cache_set", lambda *args, **kwargs: None)

    class _Settings:
        anyrun_api_key = "ak"
        hybrid_analysis_api_key = "hk"
        hybrid_analysis_base_url = "https://hybrid-analysis.com/api/v2"
        hybrid_analysis_environment_id = 160

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(
        svc,
        "lookup_anyrun",
        lambda **kwargs: {"checked": False, "verdict": "unknown", "error": "anyrun timeout"},
    )
    monkeypatch.setattr(
        svc,
        "_retry_lookup",
        lambda **kwargs: {"checked": True, "verdict": "suspicious", "analysis_id": "hy-1", "raw_summary": {}},
    )

    out = svc.lookup_hybrid_analysis(indicator="https://example.test", indicator_type="url")
    assert out["checked"] is True
    assert out["verdict"] == "suspicious"
    assert out["raw_summary"]["source"] == "hybrid"
    assert out["raw_summary"]["anyrun_error"] == "anyrun timeout"


def test_lookup_keeps_anyrun_when_sandbox_is_deferred(monkeypatch):
    monkeypatch.setattr(svc, "_cache_get", lambda _key: None)
    monkeypatch.setattr(svc, "_cache_set", lambda *args, **kwargs: None)

    class _Settings:
        anyrun_api_key = "ak"
        hybrid_analysis_api_key = "hk"
        hybrid_analysis_base_url = "https://hybrid-analysis.com/api/v2"
        hybrid_analysis_environment_id = 160

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(
        svc,
        "lookup_anyrun",
        lambda **kwargs: {
            "checked": True,
            "indicator_type": "url",
            "verdict": "clean",
            "analysis_id": "ar-1",
            "raw_summary": {
                "source": "anyrun",
                "mode": "lookup_deferred",
                "sandbox_deferred": True,
                "sandbox_error": "ANY.RUN sandbox submission deferred: parallel task limit reached",
            },
        },
    )

    called = {"retry": False}
    monkeypatch.setattr(
        svc,
        "_retry_lookup",
        lambda **kwargs: called.__setitem__("retry", True) or {"checked": False, "verdict": "unknown"},
    )

    out = svc.lookup_hybrid_analysis(indicator="https://example.test", indicator_type="url")
    assert out["checked"] is True
    assert out["raw_summary"]["source"] == "anyrun"
    assert out["raw_summary"]["sandbox_deferred"] is True
    assert called["retry"] is False


def test_domain_lookup_ignores_incomplete_cached_anyrun_payload(monkeypatch):
    cached = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "malicious",
        "analysis_id": "cached-task",
        "raw_summary": {
            "source": "anyrun",
            "mode": "sandbox",
            "behavior_details": {
                "dns_requests": ["example.test"],
                "http_requests": [],
                "connections": [],
                "network_threats": [],
                "processes": [],
                "process_details": [],
            },
        },
        "dynamic_io_summary": {"domains": ["example.test"], "hosts": [], "http_requests": [], "connections": []},
    }

    monkeypatch.setattr(svc, "_cache_get", lambda _key: cached)
    monkeypatch.setattr(svc, "_cache_set", lambda *args, **kwargs: None)

    class _Settings:
        anyrun_api_key = "ak"
        hybrid_analysis_api_key = "hk"
        hybrid_analysis_base_url = "https://hybrid-analysis.com/api/v2"
        hybrid_analysis_environment_id = 160

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    calls = {"anyrun": 0}

    def fake_lookup_anyrun(**kwargs):
        calls["anyrun"] += 1
        return {
            "checked": True,
            "indicator_type": "url",
            "verdict": "malicious",
            "analysis_id": "fresh-task",
            "domain_intelligence": {
                "checked": True,
                "indicator_type": "domain",
                "verdict": "malicious",
                "analysis_id": "domain-task",
            },
            "raw_summary": {"source": "anyrun", "mode": "sandbox"},
        }

    monkeypatch.setattr(svc, "lookup_anyrun", fake_lookup_anyrun)
    monkeypatch.setattr(
        svc,
        "_retry_lookup",
        lambda **kwargs: {"checked": False, "verdict": "unknown", "error": "should not be used"},
    )

    out = svc.lookup_hybrid_analysis(
        indicator="https://example.test",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert calls["anyrun"] == 1
    assert out["analysis_id"] == "fresh-task"
    assert out["domain_intelligence"]["analysis_id"] == "domain-task"
    assert out["cache_hit"] is False


def test_domain_lookup_ignores_cached_anyrun_without_companion_sandbox(monkeypatch):
    cached = {
        "checked": True,
        "indicator_type": "url",
        "verdict": "malicious",
        "analysis_id": "lookup-task",
        "domain_intelligence": {
            "checked": True,
            "indicator_type": "domain",
            "verdict": "malicious",
            "analysis_id": "domain-task",
        },
        "raw_summary": {
            "source": "anyrun",
            "mode": "lookup",
        },
    }

    monkeypatch.setattr(svc, "_cache_get", lambda _key: cached)
    monkeypatch.setattr(svc, "_cache_set", lambda *args, **kwargs: None)

    class _Settings:
        anyrun_api_key = "ak"
        hybrid_analysis_api_key = "hk"
        hybrid_analysis_base_url = "https://hybrid-analysis.com/api/v2"
        hybrid_analysis_environment_id = 160

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    calls = {"anyrun": 0}

    def fake_lookup_anyrun(**kwargs):
        calls["anyrun"] += 1
        return {
            "checked": True,
            "indicator_type": "url",
            "verdict": "malicious",
            "analysis_id": "fresh-lookup-task",
            "domain_intelligence": {
                "checked": True,
                "indicator_type": "domain",
                "verdict": "malicious",
                "analysis_id": "fresh-domain-task",
            },
            "additional_items": [
                {
                    "checked": True,
                    "indicator_type": "url",
                    "verdict": "clean",
                    "analysis_id": "fresh-sandbox-task",
                    "raw_summary": {"source": "anyrun", "mode": "sandbox"},
                }
            ],
            "raw_summary": {"source": "anyrun", "mode": "lookup"},
        }

    monkeypatch.setattr(svc, "lookup_anyrun", fake_lookup_anyrun)
    monkeypatch.setattr(
        svc,
        "_retry_lookup",
        lambda **kwargs: {"checked": False, "verdict": "unknown", "error": "should not be used"},
    )

    out = svc.lookup_hybrid_analysis(
        indicator="https://example.test",
        indicator_type="url",
        submit_on_not_found=True,
    )

    assert calls["anyrun"] == 1
    assert out["analysis_id"] == "fresh-lookup-task"
    assert out["additional_items"][0]["analysis_id"] == "fresh-sandbox-task"


def test_behavior_rich_anyrun_result_does_not_require_sandbox_first():
    result = {
        "checked": True,
        "analysis_id": "ar-1",
        "dynamic_io_summary": {"domains": ["a.example"], "hosts": [], "mitre_attcks": []},
        "raw_summary": {
            "source": "anyrun",
            "mode": "sandbox",
            "behavior_details": {
                "dns_requests": ["a.example"],
                "http_requests": [],
                "connections": [],
                "network_threats": [],
                "processes": [],
            },
        },
    }

    assert svc._has_meaningful_behavior_details(result) is True


def test_lookup_uses_sandbox_first_for_url_when_requested(monkeypatch):
    monkeypatch.setattr(svc, "_cache_get", lambda _key: None)
    monkeypatch.setattr(svc, "_cache_set", lambda *args, **kwargs: None)

    class _Settings:
        anyrun_api_key = "ak"
        hybrid_analysis_api_key = "hk"
        hybrid_analysis_base_url = "https://hybrid-analysis.com/api/v2"
        hybrid_analysis_environment_id = 160

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())

    calls = []

    def fake_lookup_anyrun(**kwargs):
        calls.append(kwargs)
        return {
            "checked": True,
            "indicator_type": "url",
            "verdict": "malicious",
            "analysis_id": "ar-2",
            "dynamic_io_summary": {"domains": ["evil.example"], "hosts": [], "mitre_attcks": []},
            "raw_summary": {
                "source": "anyrun",
                "mode": "sandbox",
                "behavior_details": {"http_requests": ["https://evil.example"], "dns_requests": [], "connections": []},
            },
        }

    monkeypatch.setattr(svc, "lookup_anyrun", fake_lookup_anyrun)
    monkeypatch.setattr(
        svc,
        "_retry_lookup",
        lambda **kwargs: {"checked": False, "verdict": "unknown", "error": "should not be used"},
    )

    out = svc.lookup_hybrid_analysis(
        indicator="https://example.test",
        indicator_type="url",
        submit_on_not_found=True,
        sandbox_first=True,
    )

    assert out["checked"] is True
    assert out["analysis_id"] == "ar-2"
    assert calls and calls[0]["submit_on_not_found"] is True


def test_lookup_preserves_lookup_when_sandbox_first_is_deferred(monkeypatch):
    monkeypatch.setattr(svc, "_cache_get", lambda _key: None)
    monkeypatch.setattr(svc, "_cache_set", lambda *args, **kwargs: None)

    class _Settings:
        anyrun_api_key = "ak"
        hybrid_analysis_api_key = "hk"
        hybrid_analysis_base_url = "https://hybrid-analysis.com/api/v2"
        hybrid_analysis_environment_id = 160

    monkeypatch.setattr(svc, "get_settings", lambda: _Settings())
    monkeypatch.setattr(
        svc,
        "lookup_anyrun",
        lambda **kwargs: {
            "checked": True,
            "indicator_type": "url",
            "verdict": "clean",
            "analysis_id": "ar-3",
            "raw_summary": {
                "source": "anyrun",
                "mode": "lookup_deferred",
                "sandbox_deferred": True,
                "sandbox_error": "ANY.RUN sandbox submission deferred: parallel task limit reached",
            },
        },
    )
    called = {"retry": False}
    monkeypatch.setattr(
        svc,
        "_retry_lookup",
        lambda **kwargs: called.__setitem__("retry", True) or {"checked": False, "verdict": "unknown"},
    )

    out = svc.lookup_hybrid_analysis(
        indicator="https://example.test",
        indicator_type="url",
        submit_on_not_found=True,
        sandbox_first=True,
    )

    assert out["checked"] is True
    assert out["raw_summary"]["sandbox_deferred"] is True
    assert called["retry"] is False
