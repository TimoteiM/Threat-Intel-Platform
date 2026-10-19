"""Confirming a client the ingest created for itself.

`_provision_tenant` creates a tenant the first time an alert names an unknown
id, because a refused alert is not retried and is simply gone. It marks the row
`provisional` on purpose: **a sender naming itself in a URL is not a decision
to onboard a client.**

Until 2026-10-19 that safeguard had no exit. Clearing `provisional` meant a
hand-written UPDATE — the same shape as the owner account that could only be
disabled at the database, where a guard exists and the action that resolves it
does not.

Every test here is in the dangerous direction. The failure modes are an
analyst activating a client, a change that leaves no trace, and a rename
recorded for a name nobody typed — none of which raises anything.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api import alert_investigations as ai


class _Row:
    """A tenant row, as the route mutates it."""

    def __init__(self, tenant_id="boc", name="BOC", status=ai.PROVISIONAL):
        self.tenant_id = tenant_id
        self.name = name
        self.status = status


class _Result:
    def __init__(self, row):
        self._row = row

    def scalars(self):
        return self

    def first(self):
        return self._row


class _DB:
    """Enough session to record what the route decided."""

    def __init__(self, row):
        self._row = row
        self.added: list = []
        self.committed = False

    async def execute(self, _stmt):
        return _Result(self._row)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True

    async def refresh(self, _obj):
        return None


class _Request:
    def __init__(self, role, username="someone"):
        self.state = type("S", (), {"identity": {"role": role, "username": username}})()


async def _call(role, body, row=None):
    row = row or _Row()
    db = _DB(row)
    result = await ai.onboard_tenant("boc", db, body=body, http_request=_Request(role))
    return result, row, db


@pytest.mark.asyncio
async def test_an_analyst_cannot_onboard_a_client():
    """THE one that matters. Deciding a client is real is an administrative
    act, and the control is server-side — hiding the button is presentation,
    not a permission."""
    with pytest.raises(HTTPException) as exc:
        await _call("analyst", {"status": "active"})
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_an_unauthenticated_caller_is_refused():
    db = _DB(_Row())
    request = type("R", (), {"state": type("S", (), {"identity": None})()})()
    with pytest.raises(HTTPException) as exc:
        await ai.onboard_tenant("boc", db, body={"status": "active"}, http_request=request)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_an_admin_activates_and_the_event_records_both_sides():
    result, row, db = await _call("admin", {"status": "active", "name": "Bank of C"})

    assert row.status == "active"
    assert row.name == "Bank of C"
    assert result["provisional"] is False

    assert len(db.added) == 1, "the change was made and nothing recorded it"
    event = db.added[0]
    assert event.action == "onboarded"
    assert event.from_status == ai.PROVISIONAL and event.to_status == "active"
    assert event.from_name == "BOC" and event.to_name == "Bank of C"
    assert event.actor == "someone"
    assert event.actor_role == "admin"
    assert db.committed is True


@pytest.mark.asyncio
async def test_a_rename_that_is_not_an_activation_is_recorded_as_an_update():
    """`onboarded` is a claim about what happened. Renaming an already-active
    client is not that, and labelling it so would make the word useless."""
    _, _, db = await _call(
        "owner", {"name": "Renamed"}, row=_Row(status="active", name="Old")
    )
    assert db.added[0].action == "updated"
    assert db.added[0].from_status == "active" and db.added[0].to_status == "active"


@pytest.mark.asyncio
async def test_a_no_op_records_nothing():
    """An audit log that fills with rows where nothing changed is one nobody
    reads, and 'confirmed' would then appear for a request that confirmed
    nothing."""
    result, _, db = await _call("admin", {"name": "BOC"})
    assert db.added == []
    assert db.committed is False
    assert result["changed"] is False


@pytest.mark.asyncio
async def test_deactivating_is_refused_here():
    """Alerts are already arriving against this id. Turning the row they point
    at back off is a larger decision than confirming one, and this route is
    not where it is made."""
    with pytest.raises(HTTPException) as exc:
        await _call("admin", {"status": "disabled"})
    assert exc.value.status_code == 400
    assert "not done here" in exc.value.detail


@pytest.mark.asyncio
async def test_a_blank_name_is_refused_rather_than_stored():
    with pytest.raises(HTTPException) as exc:
        await _call("admin", {"name": "   "})
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_an_unknown_tenant_is_404_not_a_silent_create():
    """This route confirms a row the ingest made. If it created one, a typo in
    the URL would mint the very thing `provisional` exists to make visible."""
    db = _DB(None)
    with pytest.raises(HTTPException) as exc:
        await ai.onboard_tenant(
            "nope", db, body={"status": "active"}, http_request=_Request("admin")
        )
    assert exc.value.status_code == 404
    assert db.added == []
