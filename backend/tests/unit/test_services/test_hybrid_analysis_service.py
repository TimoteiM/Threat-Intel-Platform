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
        if url.endswith("/quick-scan/url"):
            assert (data or {}).get("scan_type") == "all"
            return _DummyResponse({"id": "qs-1", "finished": True, "sha256": "s1", "verdict": "suspicious"}, status_code=201)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(svc.requests, "post", fake_post)

    out = svc._lookup_url("https://hybrid-analysis.com/api/v2", {"api-key": "k"}, "https://example.test")
    assert out["checked"] is True
    assert out["analysis_id"] == "qs-1"
    assert out["verdict"] == "suspicious"
    assert calls[0].endswith("/search/terms")
    assert calls[1].endswith("/quick-scan/url")


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
