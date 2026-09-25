"""One client must not be able to reach another's alerts.

Every test here is a way someone tries: changing a query parameter, changing a
URL, putting a tenant in a request body, or simply having an account that was
misconfigured. The rule they all test is that widening is impossible and
narrowing is the only thing a caller can do.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import Column, String, select
from sqlalchemy.orm import declarative_base

from app.services import tenant_scope as ts

Base = declarative_base()


class Row(Base):
    __tablename__ = "rows"
    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=True)


INTERNAL = {"kind": "user", "username": "tim", "all_tenants": True, "tenant_ids": []}
CLIENT_A = {"kind": "user", "username": "a", "all_tenants": False, "tenant_ids": ["c00"]}
CLIENT_B = {"kind": "user", "username": "b", "all_tenants": False, "tenant_ids": ["lin"]}
BROKEN = {"kind": "user", "username": "x", "all_tenants": False, "tenant_ids": []}


def _sql(scope: ts.TenantScope) -> str:
    return str(ts.apply(select(Row), Row.tenant_id, scope).compile(
        compile_kwargs={"literal_binds": True}))


# --- who sees what -----------------------------------------------------------

def test_internal_staff_see_every_tenant_and_the_unassigned_backlog():
    scope = ts.scope_of(INTERNAL)
    assert scope.may_read("c00") and scope.may_read("lin") and scope.may_read(None)
    assert "WHERE" not in _sql(scope)


def test_a_client_user_sees_only_their_own():
    scope = ts.scope_of(CLIENT_A)
    assert scope.may_read("c00")
    assert not scope.may_read("lin")
    # And not the unassigned backlog, which would leak other clients' alerts.
    assert not scope.may_read(None)


def test_an_account_with_no_tenants_matches_nothing_rather_than_everything():
    """The classic scoped-query failure: an empty IN () list drops the filter
    and the query silently becomes unscoped."""
    sql = _sql(ts.scope_of(BROKEN))
    assert "false" in sql.lower()


def test_an_unauthenticated_caller_is_restricted_not_privileged():
    scope = ts.scope_of(None)
    assert not scope.all_tenants
    assert not scope.may_read("c00")
    assert "false" in _sql(scope).lower()


# --- trying to widen ---------------------------------------------------------

def test_a_client_user_cannot_widen_by_naming_another_tenant():
    with pytest.raises(ts.TenantForbidden):
        ts.requested_scope(ts.scope_of(CLIENT_A), "lin")


def test_a_client_user_cannot_ask_for_the_unassigned_view():
    """Unassigned holds runs from every channel, including other clients'."""
    with pytest.raises(ts.TenantForbidden):
        ts.requested_scope(ts.scope_of(CLIENT_A), ts.UNASSIGNED)


def test_refusal_is_not_silently_substituted_with_their_own_data():
    """Substituting would put one client's alerts on screen under another
    client's name, which is worse than an error."""
    try:
        ts.requested_scope(ts.scope_of(CLIENT_B), "c00")
    except ts.TenantForbidden as exc:
        assert "c00" in str(exc)
    else:
        pytest.fail("widening must raise")


def test_internal_staff_can_narrow_to_one_tenant():
    scope = ts.requested_scope(ts.scope_of(INTERNAL), "lin")
    assert scope.may_read("lin")
    assert not scope.may_read("c00")
    assert not scope.may_read(None)


# --- single-object reads -----------------------------------------------------

def test_another_tenants_run_is_404_not_403():
    """403 confirms the run exists, which is the fact a client-restricted caller
    is not entitled to. Enumerating ids against a 403 counts a competitor's
    alerts."""
    with pytest.raises(HTTPException) as caught:
        ts.assert_can_read(ts.scope_of(CLIENT_A), "lin")
    assert caught.value.status_code == 404
    assert "not found" in str(caught.value.detail).lower()


def test_an_unassigned_run_is_invisible_to_a_client_user():
    with pytest.raises(HTTPException) as caught:
        ts.assert_can_read(ts.scope_of(CLIENT_A), None)
    assert caught.value.status_code == 404


# --- submitting --------------------------------------------------------------

def test_a_credential_cannot_acquire_a_tenant_by_naming_it():
    key = {"kind": "api_key", "tenant_ids": ["c00"], "all_tenants": False}
    ts.assert_can_submit(key, "c00")
    with pytest.raises(HTTPException) as caught:
        ts.assert_can_submit(key, "lin")
    assert caught.value.status_code == 403


class _Settings:
    alert_ingest_legacy_tenant = "c00"


def test_the_existing_c00_integration_still_posts_without_a_tenant_id():
    """The transition requirement: the current flow must not break."""
    key = {"kind": "api_key", "tenant_ids": ["c00"], "all_tenants": False}
    assignment = ts.resolve_for_ingest(identity=key, declared=None, settings=_Settings())
    assert assignment.tenant_id == "c00"
    assert assignment.assignment == "legacy_fallback"


def test_the_fallback_does_not_extend_to_a_multi_tenant_key():
    """A key holding two tenants and naming neither is ambiguous, and guessing
    is how one client's alerts land in another client's list."""
    key = {"kind": "api_key", "tenant_ids": ["c00", "lin"], "all_tenants": False}
    with pytest.raises(HTTPException) as caught:
        ts.resolve_for_ingest(identity=key, declared=None, settings=_Settings())
    assert caught.value.status_code == 400
    assert "tenant_id is required" in str(caught.value.detail)


def test_a_new_integration_must_send_tenant_id():
    key = {"kind": "api_key", "tenant_ids": [], "all_tenants": False}
    with pytest.raises(HTTPException):
        ts.resolve_for_ingest(identity=key, declared=None, settings=_Settings())


def test_an_internal_paste_without_a_tenant_is_filed_unassigned_not_defaulted():
    assignment = ts.resolve_for_ingest(identity=INTERNAL, declared=None, settings=_Settings())
    assert assignment.tenant_id is None
    assert assignment.assignment == "unassigned"


def test_turning_the_fallback_off_makes_tenant_id_mandatory_for_everyone():
    class NoLegacy:
        alert_ingest_legacy_tenant = ""

    key = {"kind": "api_key", "tenant_ids": ["c00"], "all_tenants": False}
    with pytest.raises(HTTPException):
        ts.resolve_for_ingest(identity=key, declared=None, settings=NoLegacy())


# --- the tenant in the URL path ----------------------------------------------

NIFI = {"kind": "trusted_network", "id": "172.23.10.16", "role": "ingest"}


def test_nifi_may_name_any_configured_tenant_in_the_path():
    """The new contract. NiFi cannot carry an Authorization header, so the URL
    is the only channel through which it can say whose alert this is."""
    assignment = ts.resolve_for_ingest(
        identity=NIFI, declared="c07", settings=_Settings(),
        known_tenants=("c00", "c07"), declared_via="path",
    )
    assert assignment.tenant_id == "c07"
    assert assignment.assignment == "path"


def test_an_unknown_tenant_is_still_refused_at_this_layer():
    """`resolve_for_ingest` never invents a tenant; it only accepts ones it is
    told exist.

    The API layer above now *pre-permits* a well-formed declared tenant and
    creates the row after authorisation succeeds, so in production this branch
    is reached only for a tenant the caller was not permitted to introduce.
    The rule stays here because the function must be safe on its own terms —
    see test_alert_investigations_api.py for the provisioning path.
    """
    with pytest.raises(HTTPException) as caught:
        ts.resolve_for_ingest(
            identity=NIFI, declared="c0O", settings=_Settings(),
            known_tenants=("c00", "c07"), declared_via="path",
        )
    assert caught.value.status_code == 400
    assert "Unknown or inactive tenant" in str(caught.value.detail)


def test_a_tenant_id_must_be_a_plain_identifier():
    """It arrives in a URL from an uncredentialed sender and now creates a row,
    so it must not be able to carry a path or read as another identifier."""
    from app.api.alert_investigations import _validated_tenant_id

    assert _validated_tenant_id("C07") == "c07"        # normalised, not rejected
    assert _validated_tenant_id("  c07  ") == "c07"
    assert _validated_tenant_id(None) == ""
    for bad in ("../c00", "c00/raw", "c 00", "-c00", "", "x" * 65):
        if bad == "":
            continue
        with pytest.raises(HTTPException) as caught:
            _validated_tenant_id(bad)
        assert caught.value.status_code == 400


def test_an_alert_naming_no_tenant_is_unassigned_even_with_the_marker():
    """An alert that names no tenant is filed unassigned, whatever it says.

    "Manager: Siembiot" names the Wazuh manager, not the client — every tenant
    carries it — so it never distinguished anybody. It happened to be right
    while there was one client. It is no longer consulted at ingest, and an
    alert carrying it is now treated exactly like one that does not.
    """
    assignment = ts.resolve_for_ingest(
        identity=NIFI, declared=None, settings=_Settings(),
        alert_body="Alert: X\nManager: Siembiot\n", alert_source=None, alert_client=None,
        known_tenants=("c00",),
    )
    assert assignment.tenant_id is None
    assert assignment.assignment == "unassigned"


def test_the_marker_stops_assigning_once_a_second_tenant_exists():
    """The regression this exists to prevent.

    Every tenant's alerts carry "Manager: Siembiot" — it names the manager, not
    the client. Left as the only rule, a second tenant's alerts would be filed
    into C00's list silently. Unassigned is a visible queue instead.
    """
    assignment = ts.resolve_for_ingest(
        identity=NIFI, declared=None, settings=_Settings(),
        alert_body="Alert: X\nManager: Siembiot\n", alert_source=None, alert_client=None,
        known_tenants=("c00", "c07"),
    )
    assert assignment.tenant_id is None
    assert assignment.assignment == "unassigned"


def test_a_credentialed_sender_still_cannot_claim_a_tenant_it_does_not_hold():
    """The path does not become a way around authorisation for callers that
    actually carry one."""
    key = {"kind": "api_key", "tenant_ids": ["c00"], "all_tenants": False}
    with pytest.raises(HTTPException) as caught:
        ts.resolve_for_ingest(
            identity=key, declared="c07", settings=_Settings(),
            known_tenants=("c00", "c07"), declared_via="path",
        )
    assert caught.value.status_code in (400, 403)


def test_the_tenant_path_is_reachable_by_a_network_admitted_sender():
    """The auth layer matched trusted ingest paths exactly, so a tenant in the
    URL would have been a 401 on the one caller that cannot retry."""
    from app.config import Settings

    cfg = Settings(
        ingest_trusted_paths="/api/alert-investigations,/api/alert-investigations/raw"
    )
    assert cfg.is_trusted_ingest_path("/api/alert-investigations/tenants/c00")
    assert cfg.is_trusted_ingest_path("/api/alert-investigations/tenants/c00/raw")
    # and nothing wider than that
    assert not cfg.is_trusted_ingest_path("/api/alert-investigations/tenants/c00/extra")
    assert not cfg.is_trusted_ingest_path("/api/admin/tenants/c00")


def test_both_tenant_routes_are_registered_ahead_of_the_run_id_routes():
    """`POST /{run_id}/…` would otherwise be free to shadow them."""
    from app.api import alert_investigations as mod

    posts = [r.path for r in mod.router.routes if "POST" in getattr(r, "methods", set())]
    assert "/api/alert-investigations/tenants/{tenant_id}" in posts
    assert "/api/alert-investigations/tenants/{tenant_id}/raw" in posts
    assert posts.index("/api/alert-investigations/tenants/{tenant_id}") < posts.index(
        "/api/alert-investigations/{run_id}/cancel"
    )


# --- the routes themselves ---------------------------------------------------

def test_every_run_route_is_tenant_scoped():
    """Isolation re-implemented per endpoint holds only on the endpoints someone
    remembered. Every per-run route must reach its run through the one scoped
    loader, or assert the scope itself."""
    import inspect
    import re

    import app.api.alert_investigations as api

    source = inspect.getsource(api)
    # Each `@router.<verb>("/{run_id}...")` block, up to the next decorator.
    blocks = re.split(r"\n@router\.", source)[1:]
    unscoped = []
    for block in blocks:
        header = block.split("\n", 1)[0]
        if "{run_id}" not in header:
            continue
        if "_get_run_scoped(" in block or "assert_can_read(" in block:
            continue
        unscoped.append(header.strip())
    assert not unscoped, f"these per-run routes bypass tenant scoping: {unscoped}"


def test_the_list_route_scopes_the_count_as_well_as_the_page():
    """A total that counts rows the caller may not open leaks how many there
    are, which is most of what a competitor wanted to know."""
    import inspect

    import app.api.alert_investigations as api

    source = inspect.getsource(api.list_alert_investigations)
    assert source.count("tenant_scope.apply(") == 2
    assert "count_query" in source


def test_an_in_process_call_is_only_possible_without_an_http_request():
    """The direct-call path the service tests use. It is reachable only when
    FastAPI supplied no Request at all, which cannot happen over HTTP."""
    import app.api.alert_investigations as api

    class _NoState:
        pass

    assert api._identity(None)["all_tenants"] is True
    assert api._identity(_NoState())["all_tenants"] is True

    class _Authed:
        class state:
            identity = {"kind": "user", "all_tenants": False, "tenant_ids": ["c00"]}

    assert api._identity(_Authed())["tenant_ids"] == ["c00"]


# --- the client selector -----------------------------------------------------

def test_an_all_tenants_identity_carries_no_tenant_list():
    """The bug behind the missing C00 option, pinned as the fact that caused it.

    "Everything" is not a list, so an internal account's `tenant_ids` is empty.
    A selector built from the scope therefore offered internal staff no client
    to choose — only "All clients" and "Unassigned". The options have to be
    named by the server, which is the only side that knows what exists."""
    scope = ts.scope_of(INTERNAL)
    assert scope.all_tenants is True
    assert scope.tenant_ids == ()
    # And it may nonetheless read a tenant it does not list.
    assert scope.may_read("c00")


def test_the_selector_is_built_from_the_servers_answer():
    import inspect

    import app.api.alert_investigations as api

    source = inspect.getsource(api.list_alert_investigations)
    assert "available_tenants" in source

    helper = inspect.getsource(api._selectable_tenants)
    # Only tenants the caller may read are offered...
    assert "scope.may_read(" in helper
    # ...and the counts beside them go through the same scoped filter, so the
    # selector cannot leak another client's volume after the list was locked.
    assert "tenant_scope.apply(" in helper
    assert "include_unassigned" in helper


# --- the uncredentialed ingest path ------------------------------------------
#
# NiFi delivers from a trusted source address and presents no credential,
# because the appliance cannot carry a header. Requiring a tenant grant from it
# stopped production ingest for four hours: every POST answered 400 while NiFi
# reported success, so nothing upstream noticed. These pin that it accepts.

NIFI = {"kind": "trusted_network", "id": "172.23.10.16", "role": "ingest"}

WAZUH_C00 = "Agent: EXP-47VD864 | 1015\nManager: Siembiot\nRule: 5710\n"
CLOUDFLARE = 'destinationServiceName=Cloudflare {"Policy":"Block_Bad_TLDs"}'


def test_the_uncredentialed_sender_is_never_refused_for_want_of_a_tenant():
    """The regression. It must classify, or file unassigned — never 400."""
    for body, source in ((WAZUH_C00, "Siembiot"), (CLOUDFLARE, "unknown"), ("", None)):
        assignment = ts.resolve_for_ingest(
            identity=NIFI, declared=None, alert_body=body,
            alert_source=source, alert_client=None, settings=_Settings(),
        )
        assert assignment.assignment in ("marker", "manager_source", "unassigned")


def test_a_c00_looking_alert_with_no_tenant_in_the_path_is_unassigned():
    """The cutover, stated as a test.

    This is the alert shape that produced 13,714 C00 runs. It now goes to the
    unassigned queue, because the sender did not say whose it is and nothing
    in the payload can answer that question. The flow has to post to
    /tenants/c00/raw to keep landing in C00.
    """
    assignment = ts.resolve_for_ingest(
        identity=NIFI, declared=None, alert_body=WAZUH_C00,
        alert_source="Siembiot", alert_client=None, settings=_Settings(),
    )
    assert assignment.tenant_id is None
    assert assignment.assignment == "unassigned"


def test_the_same_alert_with_the_tenant_in_the_path_still_lands_in_c00():
    """And the other half: cutting over is all it takes."""
    assignment = ts.resolve_for_ingest(
        identity=NIFI, declared="c00", alert_body=WAZUH_C00,
        alert_source="Siembiot", alert_client=None, settings=_Settings(),
        known_tenants=("c00",), declared_via="path",
    )
    assert assignment.tenant_id == "c00"
    assert assignment.assignment == "path"


def test_a_non_c00_alert_over_the_trusted_path_is_unassigned_not_mislabelled():
    """TraceCat delivers over the same path. A channel is not a tenant, and
    filing its Cloudflare and Office 365 alerts as C00 would be worse than
    leaving them unassigned."""
    assignment = ts.resolve_for_ingest(
        identity=NIFI, declared=None, alert_body=CLOUDFLARE,
        alert_source="unknown", alert_client=None, settings=_Settings(),
    )
    assert assignment.tenant_id is None
    assert assignment.assignment == "unassigned"


def test_a_payload_claiming_another_client_is_not_overridden_by_the_marker():
    assignment = ts.resolve_for_ingest(
        identity=NIFI, declared=None, alert_body=WAZUH_C00,
        alert_source="Siembiot", alert_client="LIN", settings=_Settings(),
    )
    assert assignment.tenant_id is None


def test_the_trusted_path_falls_closed_when_the_tenants_are_unknown():
    """Deliberate change of contract, and the guard that keeps it safe.

    A network-admitted sender may now name any *configured* tenant in the URL
    path — that is the point of the path, since NiFi cannot carry a header. The
    check that makes it safe is `known_tenants`, supplied by the route from the
    tenants table.

    When that list is absent the claim cannot be checked against anything, so
    this falls back to the older, narrower rule rather than accepting it. A
    parameter someone forgets to pass must not quietly widen who may file
    alerts into whose list.
    """
    ok = ts.resolve_for_ingest(identity=NIFI, declared="c00", alert_body="x", settings=_Settings())
    assert ok.tenant_id == "c00"

    with pytest.raises(HTTPException) as caught:
        ts.resolve_for_ingest(identity=NIFI, declared="lin", alert_body="x", settings=_Settings())
    assert caught.value.status_code == 403

    # With the list supplied, the same call is allowed — and is recorded as a
    # path assignment so it can be told apart from an authorised one later.
    allowed = ts.resolve_for_ingest(
        identity=NIFI, declared="lin", alert_body="x", settings=_Settings(),
        known_tenants=("c00", "lin"), declared_via="path",
    )
    assert (allowed.tenant_id, allowed.assignment) == ("lin", "path")


def test_the_marker_rule_is_the_same_one_the_migration_used():
    """Two copies of a classification rule drift. This is the live half; the
    historical half is migration 030, and both key on the same header."""
    assert ts.C00_MARKER == "manager: siembiot"
    assert ts.classify_by_marker(
        alert_body="MANAGER: SIEMBIOT", alert_source=None, alert_client=None, legacy_tenant="c00",
    ).tenant_id == "c00"
    assert ts.classify_by_marker(
        alert_body="a log that merely mentions wm-c00.siembiot.int somewhere",
        alert_source="unknown", alert_client=None, legacy_tenant="c00",
    ).tenant_id is None

