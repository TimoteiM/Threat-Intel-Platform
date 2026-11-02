import os

import pytest

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.config import get_settings
from app.services import alert_ingest_service as svc


def test_body_hash_ignores_whitespace_differences():
    assert svc.alert_body_hash("src=10.0.0.1  dst=8.8.8.8") == svc.alert_body_hash(
        "src=10.0.0.1\n\tdst=8.8.8.8\n"
    )
    assert svc.alert_body_hash("a") != svc.alert_body_hash("b")
    assert len(svc.alert_body_hash("a")) == 64


def test_callback_url_must_be_http_or_https():
    assert svc.validate_callback_url(None) is None
    assert svc.validate_callback_url("  ") is None
    with pytest.raises(svc.CallbackUrlError):
        svc.validate_callback_url("ftp://soc.internal/hook")
    with pytest.raises(svc.CallbackUrlError):
        svc.validate_callback_url("file:///etc/passwd")


def test_callback_url_refuses_loopback_and_metadata_addresses():
    """The ingest route is unauthenticated — it must not become a request proxy."""
    for blocked in (
        "http://127.0.0.1:9000/hook",
        "http://[::1]/hook",
        "http://169.254.169.254/latest/meta-data/",   # cloud metadata
        "http://0.0.0.0/hook",
    ):
        with pytest.raises(svc.CallbackUrlError):
            svc.validate_callback_url(blocked)


def test_private_targets_are_allowed_by_default_and_can_be_switched_off(monkeypatch):
    url = "http://10.10.30.50:8080/hook"
    assert svc.validate_callback_url(url) == url

    monkeypatch.setattr(get_settings(), "alert_callback_allow_private", False)
    with pytest.raises(svc.CallbackUrlError):
        svc.validate_callback_url(url)


def test_signature_is_produced_only_when_a_secret_is_configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "alert_callback_secret", "")
    assert svc.sign_payload(b'{"a":1}') is None

    monkeypatch.setattr(get_settings(), "alert_callback_secret", "topsecret")
    signature = svc.sign_payload(b'{"a":1}')
    assert signature.startswith("sha256=")
    # Deterministic, and different for a different body — a receiver can verify it.
    assert signature == svc.sign_payload(b'{"a":1}')
    assert signature != svc.sign_payload(b'{"a":2}')
