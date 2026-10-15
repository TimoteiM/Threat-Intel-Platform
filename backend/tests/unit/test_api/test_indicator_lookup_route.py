"""The indicator-lookup route's guards.

The property that makes this endpoint safe to expose is that **the caller
supplies a value and the server decides the question**. Free-form querying is
backlog 17 and is blocked on the tenant-pin enforcement test plus the
per-customer credential work; this route is the bounded feature that serves the
real need behind the request.

So the first test here is a contract test on the signature, because the obvious
future change is "let me pass a filter too".
"""

from __future__ import annotations

import inspect

import pytest
from fastapi import HTTPException

from app.api import indicator_lookup as route
from app.api.router import api_router


# --- the contract: no query body, ever -------------------------------------


def test_the_route_accepts_no_request_body_of_any_kind():
    """A body parameter here is the whole hazard.

    FastAPI decides body-versus-query from the parameter's type and default:
    a Pydantic model or a `Body(...)` becomes a request body. This asserts
    that the route's dependant has no body field at all, which is stronger
    than reading the signature.
    """
    r = next(x for x in _underlying() if x.path == "/api/indicator-lookup")
    assert r.dependant.body_params == [], (
        f"the route accepts a body: {[p.name for p in r.dependant.body_params]}. "
        f"Free-form querying is backlog 17 — a caller-shaped query body is the "
        f"exposure this endpoint exists to avoid."
    )
    assert list(r.methods) == ["GET"], (
        "a non-GET method on this route is how a body arrives next"
    )


def test_no_parameter_lets_a_caller_name_a_field_index_or_filter():
    """Named explicitly rather than relying on review: these are the words the
    next request will use."""
    params = set(inspect.signature(route.lookup_indicator).parameters)
    for forbidden in ("query", "body", "filter", "filters", "index", "indices",
                      "field", "fields", "sort", "aggs", "dsl", "lucene", "q"):
        assert forbidden not in params, (
            f"the route takes {forbidden!r}, which lets a caller shape the "
            f"query. See the module docstring and backlog 17."
        )
    assert params == {"db", "value", "tenant_id", "days", "request"}


def test_the_reason_is_in_the_docstring_where_the_request_will_arrive():
    """A tracker item nobody opens is not an answer. The module says why."""
    doc = route.__doc__ or ""
    assert "does not and will not accept a query body" in doc
    assert "backlog 17" in doc
    # And that it is NOT blocked on the two things it was wrongly parked behind.
    assert "EMAIL_OWN_MTA_IDENTITIES" in doc
    assert "no email" in doc


# --- tenancy ---------------------------------------------------------------


def test_the_tenant_is_required_and_never_inferred():
    r = next(x for x in _underlying() if x.path == "/api/indicator-lookup")
    params = {p.name: p for p in r.dependant.query_params}
    assert params["tenant_id"].field_info.is_required() is True
    assert params["value"].field_info.is_required() is True
    # Control: `days` is optional, so the assertion above discriminates.
    assert params["days"].field_info.is_required() is False


def test_a_tenant_the_caller_cannot_read_is_refused_before_anything_is_asked(
        monkeypatch):
    """Order matters: a refused caller must not cause a lookup to run."""
    import asyncio

    from app.services import indicator_lookup_service as svc
    from app.services import tenant_scope as ts

    asked = []
    monkeypatch.setattr(ts, "assert_can_read",
                        lambda *a, **k: (_ for _ in ()).throw(
                            HTTPException(404, "not found")))
    monkeypatch.setattr(svc, "detect", lambda v: asked.append(v) or {"kind": "x"})

    with pytest.raises(HTTPException) as caught:
        asyncio.run(route.lookup_indicator(
            db=None, value="aka.ms", tenant_id="other", days=7, request=None))
    assert caught.value.status_code == 404
    assert asked == [], "the indicator was processed for a refused caller"


# --- the actor -------------------------------------------------------------


def test_the_actor_comes_from_the_identity_and_not_from_a_parameter():
    """An actor a caller can set is not an actor."""
    class _Req:
        class state:
            identity = {"username": "someone", "kind": "session"}

    assert route._actor(_Req()) == "someone"


def test_an_unidentified_caller_is_recorded_as_such_rather_than_blank():
    """A blank actor and an unauthenticated path would otherwise be the same
    bytes — the absence-as-value shape, in the audit trail."""
    class _Empty:
        class state:
            identity = {}

    assert route._actor(_Empty()) == "unidentified"
    assert route._actor(None) == "unidentified"


def test_the_actor_falls_back_through_the_identity_fields_in_order():
    class _Labelled:
        class state:
            identity = {"label": "ingest key 3"}

    assert route._actor(_Labelled()) == "ingest key 3"


# --- the record ------------------------------------------------------------


def test_the_record_stores_the_actor_and_the_question_but_not_the_results():
    """Results are re-derivable, they age, and a second copy of evidence
    brings its own staleness. The actor is the field that cannot be
    reconstructed later."""
    from app.models.database import IndicatorLookup

    columns = {c.name for c in IndicatorLookup.__table__.columns}
    assert {"actor", "tenant_id", "value", "kind", "sources_asked",
            "created_at"} <= columns
    assert not any(c in columns for c in ("results", "hits", "answer",
                                          "detections", "documents"))
    assert IndicatorLookup.__table__.c.actor.nullable is False


def _underlying():
    """Routes behind FastAPI's `_IncludedRouter` wrappers.

    `api_router.routes` holds wrappers, not routes, so filtering it on `.path`
    silently matches nothing — which cost three wrong "not registered"
    conclusions while building this. `original_router` is where the routes are.
    """
    for wrapper in api_router.routes:
        inner = getattr(wrapper, "original_router", None)
        for r in getattr(inner, "routes", []):
            yield r


def test_the_route_is_actually_registered_on_the_aggregate_router():
    """The silent registry: `api_router` is a hand-maintained list of includes,
    and a module that is never included answers 404 with nothing to explain
    it."""
    paths = [r.path for r in _underlying()]
    assert "/api/indicator-lookup" in paths, (
        "the router was written but never included in app/api/router.py"
    )
