"""The CAPE endpoints: who may do what, and what must never come back.

The permission functions are tested directly rather than through a live app,
because what is being asserted is the rule — an ingest key may not detonate a
file — not FastAPI's ability to route. The secrecy tests go the other way and
inspect real payloads, since that is where a leak would actually appear.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.api import cape as cape_api
from app.services import cape_analysis_service as svc


class Request:
    """A Starlette request reduced to the one thing these rules read."""

    def __init__(self, identity=None):
        self.state = type("S", (), {"identity": identity})()


ADMIN = {"kind": "user", "id": "1", "username": "timotei", "role": "admin"}
ANALYST = {"kind": "user", "id": "2", "username": "alex", "role": "analyst"}
INGEST_KEY = {"kind": "api_key", "id": "3", "label": "Alert ingest", "role": "ingest"}
ODD_ROLE = {"kind": "user", "id": "4", "username": "x", "role": "contractor"}


# ── Reading ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("identity", [ADMIN, ANALYST, INGEST_KEY])
def test_any_authenticated_caller_may_read(identity):
    assert cape_api._require_signed_in(Request(identity)) is identity


def test_an_anonymous_caller_may_not_read():
    with pytest.raises(HTTPException) as caught:
        cape_api._require_signed_in(Request(None))
    assert caught.value.status_code == 401


# ── Submitting ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("identity", [ADMIN, ANALYST])
def test_a_human_analyst_or_admin_may_submit(identity):
    assert cape_api._require_human(Request(identity)) is identity


def test_the_ingest_api_key_may_not_detonate_files():
    """It reaches this API by design — it must not be able to run malware."""
    with pytest.raises(HTTPException) as caught:
        cape_api._require_human(Request(INGEST_KEY))
    assert caught.value.status_code == 403


def test_an_unrecognised_role_may_not_submit():
    with pytest.raises(HTTPException) as caught:
        cape_api._require_human(Request(ODD_ROLE))
    assert caught.value.status_code == 403


def test_an_anonymous_caller_may_not_submit():
    with pytest.raises(HTTPException) as caught:
        cape_api._require_human(Request(None))
    assert caught.value.status_code == 401


# ── Connectivity test ────────────────────────────────────────────────────────


def test_only_an_administrator_may_run_the_connectivity_test():
    assert cape_api._require_admin(Request(ADMIN)) is ADMIN
    for identity, expected in ((ANALYST, 403), (INGEST_KEY, 403), (None, 401)):
        with pytest.raises(HTTPException) as caught:
            cape_api._require_admin(Request(identity))
        assert caught.value.status_code == expected


# ── The secret never leaves ──────────────────────────────────────────────────


def test_the_status_endpoint_reports_reachability_and_no_credential():
    """An administrator needs to know whether it works, not what the token is."""
    import asyncio

    class Settings:
        cape_configured = False
        cape_enabled = False
        cape_api_base_url = "https://cape.internal.test/apiv2"
        cape_api_token = "super-secret-token"

    import app.api.cape as module

    original = module.get_settings
    module.get_settings = lambda: Settings()
    try:
        payload = asyncio.run(module.cape_status(Request(ADMIN)))
    finally:
        module.get_settings = original

    body = repr(payload).lower()
    assert "super-secret-token" not in body
    assert "authorization" not in body
    assert payload["configured"] is False


def test_no_endpoint_schema_accepts_a_cape_url_from_the_caller():
    """The base URL is administrator configuration. A request that could name
    it would make this integration an SSRF gadget."""
    fields = set(cape_api.SubmitRequest.model_fields)
    for forbidden in ("url", "base_url", "endpoint", "host", "cape_url", "api_url"):
        assert forbidden not in fields


def test_the_submit_schema_only_accepts_identifiers():
    assert set(cape_api.SubmitRequest.model_fields) == {
        "artifact_id", "investigation_id", "alert_run_id", "sha256", "force_new"
    }


def test_a_sha256_field_is_length_constrained():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        cape_api.SubmitRequest(sha256="too-short")
    assert cape_api.SubmitRequest(sha256="a" * 64).sha256 == "a" * 64


# ── Retry policy ─────────────────────────────────────────────────────────────


def test_a_reported_analysis_is_not_retryable():
    """Re-running a finished analysis is a new run, not a retry — otherwise a
    retry button quietly re-detonates samples."""
    assert svc.STATUS_REPORTED not in svc.RETRYABLE_STATUSES


def test_an_in_flight_analysis_is_not_retryable():
    for state in (svc.STATUS_QUEUED, svc.STATUS_SUBMITTED, svc.STATUS_RUNNING):
        assert state not in svc.RETRYABLE_STATUSES
