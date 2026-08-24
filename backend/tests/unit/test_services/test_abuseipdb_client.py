from __future__ import annotations

import types

import pytest

from app.services import abuseipdb_client as client


class _Settings:
    abuseipdb_api_key = "primary"
    abuseipdb_api_key2 = "spare"


class _Response:
    def __init__(self, status_code: int):
        self.status_code = status_code


def test_both_keys_are_configured_primary_first():
    assert client.configured_abuseipdb_api_keys(_Settings()) == ["primary", "spare"]


def test_duplicate_key_is_not_counted_twice():
    class _Same:
        abuseipdb_api_key = "same"
        abuseipdb_api_key2 = "same"

    assert client.configured_abuseipdb_api_keys(_Same()) == ["same"]


def test_a_spent_key_falls_through_to_the_spare(monkeypatch):
    """
    429 is the daily cap. With one key that ends AbuseIPDB until midnight UTC;
    the spare is a second allowance, so the check is retried on it.
    """
    used: list[str] = []

    def fake_get(url, headers=None, params=None, timeout=None):
        used.append(headers["Key"])
        return _Response(429 if headers["Key"] == "primary" else 200)

    monkeypatch.setattr(client, "requests", types.SimpleNamespace(get=fake_get))
    monkeypatch.setattr(client, "record_provider_request", lambda *a, **k: None)
    monkeypatch.setattr(client, "configured_abuseipdb_api_keys", lambda s=None: ["primary", "spare"])

    response = client.abuseipdb_get("check", params={"ipAddress": "8.8.8.8"}, settings=_Settings())

    assert used == ["primary", "spare"]
    assert response.status_code == 200


def test_a_rejected_key_also_falls_through(monkeypatch):
    """401/403 means this key is refused; the next one may not be."""
    used: list[str] = []

    def fake_get(url, headers=None, params=None, timeout=None):
        used.append(headers["Key"])
        return _Response(401 if headers["Key"] == "primary" else 200)

    monkeypatch.setattr(client, "requests", types.SimpleNamespace(get=fake_get))
    monkeypatch.setattr(client, "record_provider_request", lambda *a, **k: None)
    monkeypatch.setattr(client, "configured_abuseipdb_api_keys", lambda s=None: ["primary", "spare"])

    assert client.abuseipdb_get("check", params={}, settings=_Settings()).status_code == 200
    assert used == ["primary", "spare"]


def test_an_ordinary_error_does_not_burn_the_spare(monkeypatch):
    """
    A 422 is about the request, not the key. Retrying it on the spare would
    spend a second allowance to receive the same rejection.
    """
    used: list[str] = []

    def fake_get(url, headers=None, params=None, timeout=None):
        used.append(headers["Key"])
        return _Response(422)

    monkeypatch.setattr(client, "requests", types.SimpleNamespace(get=fake_get))
    monkeypatch.setattr(client, "record_provider_request", lambda *a, **k: None)
    monkeypatch.setattr(client, "configured_abuseipdb_api_keys", lambda s=None: ["primary", "spare"])

    assert client.abuseipdb_get("check", params={}, settings=_Settings()).status_code == 422
    assert used == ["primary"], "a request-level error must not consume the spare key"


def test_all_keys_spent_returns_the_real_status(monkeypatch):
    """The caller should report AbuseIPDB's own 429, not a synthetic error."""
    monkeypatch.setattr(
        client, "requests", types.SimpleNamespace(get=lambda *a, **k: _Response(429))
    )
    monkeypatch.setattr(client, "record_provider_request", lambda *a, **k: None)
    monkeypatch.setattr(client, "configured_abuseipdb_api_keys", lambda s=None: ["primary", "spare"])

    assert client.abuseipdb_get("check", params={}, settings=_Settings()).status_code == 429


def test_no_key_configured_returns_none(monkeypatch):
    monkeypatch.setattr(client, "configured_abuseipdb_api_keys", lambda s=None: [])
    assert client.abuseipdb_get("check", params={}) is None
