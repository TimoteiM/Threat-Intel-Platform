"""Tenant isolation on integration credentials, enforced at the query layer.

Why this test is unusually load-bearing: **all 28 users in this deployment
have `all_tenants = true` and `tenant_ids = []`.** Tenant scoping exists in
the schema, has a service, and is exercised by nobody. So an unfiltered query
returns exactly the same rows as a filtered one, no existing test would fail,
and no real account would reveal it. This test constructs a restricted
principal because nothing else can.

Two directions, and the second is the one that makes the first mean
something:

  * a restricted principal must see **nothing** outside its tenants;
  * and this test must **fail if the restriction is removed**. A test that
    passes against an unscoped query is not an isolation test — it is a
    query that happens to return the right rows today.

The second is asserted explicitly: `test_the_guard_can_fail` removes the
scope clause and checks the leak is detected.
"""

from __future__ import annotations

import pytest
from sqlalchemy import false as sql_false
from sqlalchemy import select, true as sql_true

from app.services import tenant_scope


def _restricted(*tenants: str) -> tenant_scope.TenantScope:
    """A principal that may read only the named tenants.

    No user in this deployment looks like this, which is the point.
    """
    return tenant_scope.TenantScope(
        all_tenants=False, tenant_ids=tuple(tenants),
        include_unassigned=False, actor="restricted-test-principal",
    )


def _compiled(scope: tenant_scope.TenantScope) -> str:
    from app.models.database import TenantIntegration

    stmt = select(TenantIntegration)
    stmt = tenant_scope.apply(stmt, TenantIntegration.tenant_id, scope)
    return str(stmt.compile(compile_kwargs={"literal_binds": True}))


# ─── a restricted principal is narrowed in SQL, not in Python ────────────

def test_a_restricted_principal_gets_a_tenant_clause():
    sql = _compiled(_restricted("c00"))
    assert "tenant_integrations.tenant_id IN" in sql
    assert "'c00'" in sql


def test_a_principal_with_no_tenants_matches_nothing():
    """Fail closed. An account misconfigured with no tenants must match
    nothing, not everything — and the SQL has to say `false`, because an
    empty `IN ()` is the classic way a scoped query becomes unscoped."""
    sql = _compiled(_restricted())
    assert "false" in sql.lower()
    assert "IN (" not in sql


def test_an_all_tenants_principal_is_not_narrowed():
    """The control: isolation that also blocks the internal reader is an
    outage, not a safeguard."""
    sql = _compiled(tenant_scope.TenantScope(all_tenants=True, actor="owner"))
    assert "tenant_id IN" not in sql


def test_a_restricted_principal_cannot_widen_by_asking():
    """The selector. Narrowing is always allowed; widening never is, and a
    refusal beats silently substituting their own tenant — which would show
    one customer's integrations under another customer's name."""
    scope = _restricted("c00")
    assert tenant_scope.requested_scope(scope, "c00").tenant_ids == ("c00",)
    with pytest.raises(tenant_scope.TenantForbidden):
        tenant_scope.requested_scope(scope, "c01")


def test_unassigned_is_internal_only():
    with pytest.raises(tenant_scope.TenantForbidden):
        tenant_scope.requested_scope(_restricted("c00"), tenant_scope.UNASSIGNED)


# ─── the service layer refuses, rather than returning another tenant ─────

def test_reading_another_tenant_is_404_not_403():
    """A 403 confirms the row exists, which is the fact a restricted caller
    is not entitled to. Enumerating ids against a 403 tells you how many
    integrations your competitor has."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        tenant_scope.assert_can_read(_restricted("c00"), "c01")
    assert exc.value.status_code == 404


def test_every_credential_service_read_requires_a_scope():
    """`scope` is keyword-only and has no default, so a caller who forgets it
    gets a TypeError rather than an unscoped read of a credential table."""
    import inspect

    from app.services import integration_credential_service as creds
    from app.services import integration_status_service as status

    for fn in (creds.configure, creds.open_for_tenant, creds.record_health,
               creds.remove, creds.rotate_all, status.for_tenant,
               status.matrix, status._rows):
        sig = inspect.signature(fn)
        assert "scope" in sig.parameters, f"{fn.__name__} takes no scope"
        param = sig.parameters["scope"]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, (
            f"{fn.__name__}'s scope is positional; it can be passed by "
            "accident in the wrong order"
        )
        assert param.default is inspect.Parameter.empty, (
            f"{fn.__name__}'s scope has a default — a parameter someone "
            "forgets to pass must never be the one that opens a read up"
        )


# ─── and the guard must be able to fail ──────────────────────────────────

def test_the_guard_can_fail():
    """What this test suite would print if the isolation were removed.

    A test that passes against an unscoped query is not an isolation test.
    So: build the query the way an unscoped implementation would, and assert
    this file's own detection catches it.
    """
    from app.models.database import TenantIntegration

    # The unscoped version — what a forgotten `scope` produces.
    unscoped = str(
        select(TenantIntegration).compile(compile_kwargs={"literal_binds": True})
    )
    assert "tenant_id IN" not in unscoped
    assert "false" not in unscoped.lower()

    # The assertions above, applied to it, must fail.
    scoped = _compiled(_restricted("c00"))
    assert "tenant_integrations.tenant_id IN" in scoped
    assert "tenant_integrations.tenant_id IN" not in unscoped, (
        "the unscoped query passed the restricted-principal assertion, so "
        "that assertion proves nothing"
    )

    # And the empty-scope case must differ from the unscoped one too.
    empty = _compiled(_restricted())
    assert "false" in empty.lower()
    assert empty != unscoped


def test_the_clause_itself_is_false_not_absent_for_an_empty_scope():
    """At the clause level, because `apply` could be bypassed by a caller
    composing its own where()."""
    from app.models.database import TenantIntegration

    clause = tenant_scope.clause(TenantIntegration.tenant_id, _restricted())
    assert str(clause.compile(compile_kwargs={"literal_binds": True})).lower().strip() in {
        "false", "0 = 1",
    }
    assert str(clause) != str(sql_true())
