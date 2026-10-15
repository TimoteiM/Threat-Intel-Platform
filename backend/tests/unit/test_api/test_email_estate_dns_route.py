"""The estate DNS route: what it answers, and what it refuses to claim.

The route's product is a sentence an analyst acts on. Its failure mode is not
an error page — it is a confident sentence with a wrong baseline. So most of
these tests check that something is *withheld*.
"""

import asyncio
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.api import email_investigations as api
from app.services import absence
from app.services import estate_lookup_service as els
from app.services import tenant_scope as ts

# Patched as module OBJECTS, not by dotted string. A sibling test
# (`test_email_investigations_history.py`) hand-loads the `app` package with
# importlib and replaces `sys.modules["app"]`, leaving a module without
# `services` bound — so `monkeypatch.setattr("app.services...")` resolves in
# isolation and raises `module 'app' has no attribute 'services'` as soon as
# the suite runs together. These tests passed alone and failed in the suite
# for exactly that reason.


UPLOADED = datetime(2026, 10, 15, 7, 45, 57, tzinfo=timezone.utc)
ARRIVED = datetime(2026, 10, 15, 7, 28, 40, tzinfo=timezone.utc)
ANCHOR_STATEMENT = (
    "the earliest Received header written by our own mail infrastructure "
    "(ourcorp-com.mail.protection.outlook.com, 2026-10-15 07:28 UTC)"
)


class _Row:
    def __init__(self, result_json):
        self.id = uuid.UUID("af85d174-0000-4000-8000-000000000000")
        self.created_at = UPLOADED
        self.result_json = result_json


class _Result:
    def __init__(self, row):
        self._row = row

    def scalars(self):
        return self

    def first(self):
        return self._row


class _DB:
    def __init__(self, row):
        self._row = row

    async def execute(self, *_a, **_k):
        return _Result(self._row)


def _call(row, monkeypatch, *, lookups=None, tenant="c00", days=7):
    """Invoke the route with the estate client and scope stubbed.

    The stub records every lookup's kwargs — the assertions are about what was
    passed to `lookup()`, because that is where a wrong baseline would enter.
    """
    recorded = []

    def _fake_lookup(value, **kwargs):
        recorded.append({"value": value, **kwargs})
        answer = {
            "observable": value,
            "kind": kwargs.get("kind"),
            "host_dns": {"observed": False},
            "perimeter": {"observed": False},
        }
        if lookups is not None:
            answer.update(lookups.get(value, {}))
        return answer

    monkeypatch.setattr(els, "lookup", _fake_lookup)
    monkeypatch.setattr(els, "estate_client_for", lambda *_a, **_k: object())
    monkeypatch.setattr(ts, "assert_can_read", lambda *_a, **_k: None)

    payload = asyncio.run(api.email_investigation_estate_dns(
        db=_DB(row), run_id=str(row.id), tenant_id=tenant, days=days,
        request=None,
    ))
    return payload, recorded


# --- the baseline -----------------------------------------------------------


def test_a_run_with_no_stored_arrival_gets_no_comparison(monkeypatch):
    """The live state of all 38 existing runs.

    They were parsed before the anchor existed and the Received chain is not
    retained, so no arrival time can be recovered. The estate is still asked
    — hits and absences are useful on their own — but every comparison is
    withheld.
    """
    row = _Row({"sender_domain": "caseware.com", "url_domains": ["aka.ms"]})
    payload, recorded = _call(row, monkeypatch)

    assert payload["comparison_available"] is False
    assert payload["baseline"]["resolved"] is False
    assert absence.is_absent(payload["baseline"]["absence"])
    assert payload["baseline"]["absence"]["kind"] == absence.CHECK_FAILED
    # The estate was still asked.
    assert len(recorded) == 2
    for call in recorded:
        assert call["reference_time"] is None
        assert call["reference_anchor"] is None


def test_the_runs_own_timestamp_is_never_used_as_the_baseline(monkeypatch):
    """`created_at` is the upload time.

    On 2026-10-15 it was reported as the message's receipt time, which made
    every estate hit read as pre-existing. The route must not reach for it
    even though it is the only timestamp on the row.
    """
    row = _Row({"sender_domain": "caseware.com"})
    payload, recorded = _call(row, monkeypatch)

    assert UPLOADED.isoformat() not in str(payload["baseline"])
    assert recorded[0]["reference_time"] is None
    assert payload["baseline"].get("at") is None


def test_an_absent_arrival_is_passed_through_as_its_own_absence(monkeypatch):
    """The reason survives to the reader.

    A `check_failed` from the anchor resolver says *why* — no configured
    identity, an unbounded trusted run, a chain that is all foreign. Replacing
    it with a generic "unavailable" loses the one thing that tells an operator
    what to fix.
    """
    stored = absence.absent(
        absence.CHECK_FAILED,
        "No mail infrastructure identity is configured for this tenant "
        "(EMAIL_OWN_MTA_IDENTITIES), so no Received header can be told apart "
        "from one the sender wrote.",
    ).as_json()
    row = _Row({"sender_domain": "caseware.com", "arrival": stored})
    payload, _ = _call(row, monkeypatch)

    assert payload["baseline"]["resolved"] is False
    assert "EMAIL_OWN_MTA_IDENTITIES" in payload["baseline"]["absence"]["reason"]


def test_a_resolved_arrival_is_passed_with_its_statement(monkeypatch):
    row = _Row({
        "sender_domain": "caseware.com",
        "arrival": {
            "anchor": "own_mta_received",
            "at": ARRIVED.isoformat(),
            "statement": ANCHOR_STATEMENT,
            "written_by": "ourcorp-com.mail.protection.outlook.com",
            "sender_date_disagrees": True,
        },
    })
    payload, recorded = _call(row, monkeypatch)

    assert payload["comparison_available"] is True
    assert payload["baseline"]["resolved"] is True
    assert payload["baseline"]["anchor"] == "own_mta_received"
    assert payload["baseline"]["sender_date_disagrees"] is True
    assert recorded[0]["reference_time"] == ARRIVED
    assert recorded[0]["reference_anchor"] == ANCHOR_STATEMENT


def test_a_stored_arrival_with_no_statement_claims_no_comparison(monkeypatch):
    """An anchor with no words for it cannot produce a sentence.

    `lookup()` refuses a reference time with no named anchor, so passing one
    through would only surface as a check_failed per indicator. Caught here
    instead, where the reason is about the baseline.
    """
    row = _Row({
        "sender_domain": "caseware.com",
        "arrival": {"anchor": "own_mta_received", "at": ARRIVED.isoformat()},
    })
    payload, recorded = _call(row, monkeypatch)

    assert payload["comparison_available"] is False
    assert recorded[0]["reference_anchor"] is None


def test_an_unparseable_stored_arrival_does_not_become_a_comparison(monkeypatch):
    row = _Row({
        "sender_domain": "caseware.com",
        "arrival": {"anchor": "own_mta_received", "at": "not a timestamp",
                    "statement": ANCHOR_STATEMENT},
    })
    payload, recorded = _call(row, monkeypatch)

    assert payload["comparison_available"] is False
    assert recorded[0]["reference_time"] is None


# --- which indicators are asked --------------------------------------------


def test_urls_are_not_asked_because_the_estate_has_no_proxy_logs(monkeypatch):
    row = _Row({
        "sender_domain": "caseware.com",
        "urls": ["https://aka.ms/x", "https://evil.test/y"],
        "url_domains": ["aka.ms", "evil.test"],
    })
    _, recorded = _call(row, monkeypatch)

    kinds = {call["kind"] for call in recorded}
    assert kinds == {"domain"}
    assert not any(str(call["value"]).startswith("http") for call in recorded)


def test_the_sender_address_is_asked_as_an_ip_not_a_domain(monkeypatch):
    row = _Row({"sender_ip": "185.9.9.9"})
    _, recorded = _call(row, monkeypatch)

    assert recorded == [{
        "value": "185.9.9.9", "kind": "ip", "tenant_id": "c00", "days": 7,
        "client": recorded[0]["client"], "reference_time": None,
        "reference_anchor": None,
    }]


def test_duplicates_are_asked_once(monkeypatch):
    row = _Row({"sender_domain": "aka.ms", "url_domains": ["aka.ms", "AKA.MS"]})
    _, recorded = _call(row, monkeypatch)

    assert [c["value"] for c in recorded] == ["aka.ms"]


def test_each_indicator_carries_where_it_came_from(monkeypatch):
    """A domain from the body and a sender domain are not the same finding."""
    row = _Row({"sender_domain": "caseware.com", "url_domains": ["aka.ms"]})
    payload, _ = _call(row, monkeypatch)

    origins = {i["observable"]: i["origin"] for i in payload["indicators"]}
    assert origins["caseware.com"] == "sender domain"
    assert origins["aka.ms"] == "domain of a link in the body"


def test_a_capped_indicator_list_says_how_many_were_not_asked(monkeypatch):
    """No silent truncation.

    A list cut to 40 with no note reads as "the estate was asked about
    everything in this email", which would make a clean panel mean nothing.
    """
    row = _Row({"url_domains": [f"d{n}.test" for n in range(55)]})
    payload, recorded = _call(row, monkeypatch)

    assert len(recorded) == api._ESTATE_INDICATOR_CAP
    assert payload["indicators_not_asked"] == 55 - api._ESTATE_INDICATOR_CAP
    assert payload["cap"] == api._ESTATE_INDICATOR_CAP


def test_an_email_with_no_indicators_is_not_an_error(monkeypatch):
    row = _Row({})
    payload, recorded = _call(row, monkeypatch)

    assert recorded == []
    assert payload["indicators"] == []
    assert payload["indicator_count"] == 0


# --- tenancy ---------------------------------------------------------------


def test_the_tenant_is_required_and_never_inferred_from_the_run():
    """`email_investigation_runs` has no tenant column.

    Inferring one would run this customer's indicators against another
    customer's logs. The parameter is required, so there is nothing to infer
    from.
    """
    route = next(r for r in api.router.routes
                 if getattr(r, "path", "").endswith("/estate-dns"))
    params = {p.name: p for p in route.dependant.query_params}
    assert "tenant_id" in params
    assert params["tenant_id"].field_info.is_required() is True, (
        "tenant_id is optional, so a caller can omit it and the endpoint has "
        "to decide a tenant for itself"
    )
    # A control on the assertion above: `days` IS optional, so the check
    # distinguishes required from not-required rather than always passing.
    assert params["days"].field_info.is_required() is False


def test_a_tenant_the_caller_cannot_read_is_a_404(monkeypatch):
    """404 and not 403: a 403 confirms the tenant exists."""
    row = _Row({"sender_domain": "caseware.com"})

    def _refuse(*_a, **_k):
        raise HTTPException(404, "Alert investigation not found")

    monkeypatch.setattr(ts, "assert_can_read", _refuse)
    monkeypatch.setattr(els, "estate_client_for", lambda *_a, **_k: object())

    with pytest.raises(HTTPException) as caught:
        asyncio.run(api.email_investigation_estate_dns(
            db=_DB(row), run_id=str(row.id), tenant_id="other",
            days=7, request=None))
    assert caught.value.status_code == 404


def test_the_scope_is_checked_before_the_run_contents_are_read(monkeypatch):
    """Order matters: a refused caller must not learn the run's indicators
    through a timing or error difference."""
    row = _Row({"sender_domain": "caseware.com", "url_domains": ["aka.ms"]})
    asked = []

    def _refuse(*_a, **_k):
        raise HTTPException(404, "not found")

    monkeypatch.setattr(ts, "assert_can_read", _refuse)
    monkeypatch.setattr(els, "lookup", lambda *a, **k: asked.append(a) or {})
    monkeypatch.setattr(els, "estate_client_for", lambda *_a, **_k: object())

    with pytest.raises(HTTPException):
        asyncio.run(api.email_investigation_estate_dns(
            db=_DB(row), run_id=str(row.id), tenant_id="other",
            days=7, request=None))
    assert asked == [], "indicators were looked up for a refused caller"


def test_an_unknown_run_is_a_404(monkeypatch):
    monkeypatch.setattr(ts, "assert_can_read", lambda *_a, **_k: None)
    with pytest.raises(HTTPException) as caught:
        asyncio.run(api.email_investigation_estate_dns(
            db=_DB(None), run_id=str(uuid.uuid4()), tenant_id="c00",
            days=7, request=None))
    assert caught.value.status_code == 404


def test_a_malformed_run_id_is_a_400(monkeypatch):
    with pytest.raises(HTTPException) as caught:
        asyncio.run(api.email_investigation_estate_dns(
            db=_DB(None), run_id="not-a-uuid", tenant_id="c00",
            days=7, request=None))
    assert caught.value.status_code == 400
