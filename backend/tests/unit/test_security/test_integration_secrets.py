"""Integration credentials are write-only, and never leave the platform.

The five-assertion pattern from the abuse.ch key work, applied to a secret
that now has a database row and an HTTP surface:

  1. it is never returned by any API response model;
  2. it is never written to a log;
  3. it is never in an error body or an exception message;
  4. it is never stored in the clear;
  5. it is never in the audit record.

The dangerous direction is a *plausible* leak — a field that looks like
metadata and carries the value, a dataclass repr in a traceback, a config
column that accepts `client_secret` as a key. Each gets its own test, because
a single "no secrets anywhere" assertion would pass while any one of them
held.
"""

from __future__ import annotations

import inspect
import json
import logging

import pytest

from app.security.secret_box import SecretBox, generate_key

SECRET = "falcon-client-secret-value-0123456789abcdef"
CLIENT_ID = "falcon-client-id-abcdef"


# ── 1. no response model carries a secret ────────────────────────────────

def test_no_response_model_declares_a_secret_field():
    """By construction, not by omission at serialisation time: a field that
    is never declared cannot be populated by a later change."""
    from app.api.integrations import IntegrationStatusOut

    fields = set(IntegrationStatusOut.model_fields)
    for name in fields:
        lowered = name.lower()
        assert not any(
            m in lowered for m in ("secret", "password", "token", "credential")
        ) or lowered in {"secret_set", "secret_set_at"}, (
            f"response model declares a credential-shaped field {name!r}"
        )
    # And the two permitted ones are booleans/timestamps, never values.
    assert IntegrationStatusOut.model_fields["secret_set"].annotation is bool


def test_the_status_payload_of_a_configured_tool_has_no_secret():
    """The real payload shape, built from a row that has one."""
    from types import SimpleNamespace

    from app.services.integration_status_service import ToolSpec, status_of

    row = SimpleNamespace(
        tool="falcon", health={}, secret_ciphertext="gAAAAABciphertext",
        secret_set_at=None, config={"cloud": "eu-1"},
        configured_by="admin", updated_at=None,
    )
    spec = ToolSpec(tool="falcon", label="CrowdStrike Falcon",
                    directions=("enrichment",),
                    secret_fields={"client_secret": "the secret"})
    payload = status_of(spec, row, "falcon")
    blob = json.dumps(payload, default=str)
    assert SECRET not in blob
    assert "gAAAAAB" not in blob, "the ciphertext itself reached the payload"
    # What a reader gets instead.
    assert payload["secret_set"] is True


def test_the_catalogue_declares_secret_field_names_not_values():
    """The UI needs to know a field exists to render an input for it. Names
    and descriptions only."""
    from app.services.integration_status_service import catalogue

    spec = catalogue()["falcon"]
    assert "client_secret" in spec.secret_fields
    assert isinstance(spec.secret_fields["client_secret"], str)
    # The description must not be a value, which a careless author could do.
    assert SECRET not in json.dumps(spec.as_json())


# ── 2. never logged ──────────────────────────────────────────────────────

def test_a_failed_falcon_call_logs_nothing_credential_shaped(caplog):
    from app.integrations import falcon_client as fc

    class _Session:
        def post(self, *a, **k):
            raise RuntimeError(
                f"body client_id={CLIENT_ID}&client_secret={SECRET}"
            )

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(fc.FalconUnavailable):
            fc.fetch_token(client_id=CLIENT_ID, client_secret=SECRET,
                           session=_Session())
    assert SECRET not in caplog.text
    assert CLIENT_ID not in caplog.text


def test_the_opened_credential_repr_is_redacted():
    """A dataclass repr is the easiest way to leak by accident: a traceback
    rendering locals, a log line interpolating the object, a debugger."""
    from app.services.integration_credential_service import OpenedCredential

    opened = OpenedCredential(
        tenant_id="c00", tool="falcon", client_id=CLIENT_ID,
        client_secret=SECRET, config={},
    )
    for rendered in (repr(opened), str(opened), f"{opened}", f"{opened!r}"):
        assert SECRET not in rendered
        assert CLIENT_ID not in rendered
        assert "[redacted]" in rendered


# ── 3. never in an error body ────────────────────────────────────────────

def test_a_verify_failure_body_carries_no_secret():
    from app.integrations import falcon_client as fc

    class _Session:
        def post(self, *a, **k):
            raise RuntimeError(f"client_secret={SECRET} refused")

    out = fc.verify(client_id=CLIENT_ID, client_secret=SECRET,
                    session=_Session())
    assert SECRET not in json.dumps(out, default=str)
    assert out["state"] == "verified_failing"
    # And the reason is still useful, not blanked.
    assert out["reason"]


# ── 4. never stored in the clear ─────────────────────────────────────────

def test_the_stored_ciphertext_is_not_the_plaintext():
    box = SecretBox([generate_key()])
    sealed = box.encrypt(json.dumps({"client_secret": SECRET}))
    assert SECRET not in sealed.ciphertext
    assert box.decrypt(sealed.ciphertext)


def test_the_config_column_refuses_a_credential_shaped_key():
    """The back door. `config` is returned through the API, so a secret put
    there would be readable and the write-only rule defeated without
    touching the sealed column."""
    from app.services.integration_credential_service import (
        _reject_secret_shaped_config,
    )

    for key in ("client_secret", "api_key", "password", "token",
                "SECRET", "Credential"):
        with pytest.raises(ValueError) as exc:
            _reject_secret_shaped_config({key: SECRET})
        assert key in str(exc.value)
        assert SECRET not in str(exc.value), (
            "the rejection message echoed the value it refused"
        )


def test_ordinary_config_is_accepted():
    """The control. A validator that refuses everything passes the test
    above and makes the feature unusable."""
    from app.services.integration_credential_service import (
        _reject_secret_shaped_config,
    )

    out = _reject_secret_shaped_config({"cloud": "eu-1", "base_url": "https://x"})
    assert out == {"cloud": "eu-1", "base_url": "https://x"}


# ── 5. never in the audit record ─────────────────────────────────────────

def test_the_audit_detail_records_what_changed_not_what_it_changed_to():
    """`detail` is readable by anyone who may read the tenant, so it carries
    field *names* only."""
    src = inspect.getsource(
        __import__("app.services.integration_credential_service",
                   fromlist=["configure"]).configure
    )
    assert "secret_fields_set" in src
    # The detail must be built from sorted keys, never from the values.
    assert "sorted(supplied)" in src
    assert "supplied.values()" not in src


def test_no_module_in_the_api_layer_decrypts():
    """`open_for_tenant` returns plaintext and its callers are connectors.
    An API serializer calling it would be the leak, so the API layer is
    asserted not to."""
    import app.api.integrations as api

    src = inspect.getsource(api)
    # The verify path opens a credential deliberately, to make a real call,
    # and passes it to the connector — never into a response.
    assert src.count("open_for_tenant") == 1, (
        "the API layer opens credentials in more than one place; each is a "
        "chance to put one in a response"
    )
    opened_line = [l for l in src.splitlines() if "open_for_tenant" in l][0]
    assert "return" not in opened_line
