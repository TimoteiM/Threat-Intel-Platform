"""Which tenants an identity may read, and how that becomes a WHERE clause.

One place, because tenant isolation that is re-implemented per endpoint is
isolation that holds on the endpoints someone remembered. Every alert-run read
— list, count, search, verdict filter, page, detail, logs, export, delete —
goes through `apply()` or `assert_can_read()`, and the tests assert that each
route does.

Two decisions worth stating plainly.

**A tenant a caller may not see is 404, never 403.** A 403 confirms that the
run exists, which is the fact a client-restricted caller is not entitled to.
Enumerating ids against a 403 tells you how many alerts your competitor had.

**A restricted caller with an empty tenant list matches nothing.** Not
everything. An account misconfigured with no tenants must fail closed, and the
SQL must express that as `false` rather than as an absent filter — an empty
`IN ()` list is the classic way a scoped query becomes an unscoped one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from sqlalchemy import false as sql_false
from sqlalchemy import or_


# The pseudo-tenant an internal user selects to see runs that could not be
# assigned to anyone. Never a real tenant_id, and never granted to a
# client-restricted account.
UNASSIGNED = "__unassigned__"


class TenantForbidden(Exception):
    """The caller may not act for this tenant."""


@dataclass(frozen=True)
class TenantScope:
    """What this identity may read."""

    all_tenants: bool = False
    tenant_ids: tuple[str, ...] = ()
    # Only an all-tenants identity may see runs with no tenant. A restricted
    # caller must not learn that unassigned alerts exist, let alone read them.
    include_unassigned: bool = False
    actor: str = "anonymous"

    @property
    def is_restricted(self) -> bool:
        return not self.all_tenants

    def may_read(self, tenant_id: str | None) -> bool:
        if self.all_tenants:
            return True
        if tenant_id is None:
            return self.include_unassigned
        return tenant_id in self.tenant_ids

    def describe(self) -> dict[str, Any]:
        return {
            "all_tenants": self.all_tenants,
            "tenant_ids": list(self.tenant_ids),
            "include_unassigned": self.include_unassigned,
        }


def scope_of(identity: dict[str, Any] | None) -> TenantScope:
    """The scope an authenticated identity carries.

    An absent identity gets an empty restricted scope rather than an
    all-tenants one. Reaching here unauthenticated is already a bug; it must
    not also be a disclosure.
    """
    if not identity:
        return TenantScope(all_tenants=False, tenant_ids=(), actor="anonymous")

    all_tenants = bool(identity.get("all_tenants"))
    tenant_ids = tuple(
        str(t).strip() for t in (identity.get("tenant_ids") or []) if str(t).strip()
    )
    actor = str(identity.get("username") or identity.get("label") or identity.get("kind") or "unknown")
    return TenantScope(
        all_tenants=all_tenants,
        tenant_ids=tenant_ids,
        include_unassigned=all_tenants,
        actor=actor,
    )


def requested_scope(scope: TenantScope, requested: str | None) -> TenantScope:
    """Narrow a scope to the tenant a caller asked to look at.

    This is the "All clients" selector. Narrowing is always allowed; widening
    never is — a restricted caller asking for a tenant they do not hold is
    refused here rather than silently given their own data, because silently
    substituting would make the UI show one client's alerts under another
    client's name.
    """
    if not requested:
        return scope
    requested = str(requested).strip()
    if requested == UNASSIGNED:
        if not scope.all_tenants:
            raise TenantForbidden("Unassigned alerts are visible to internal users only.")
        return TenantScope(all_tenants=False, tenant_ids=(), include_unassigned=True, actor=scope.actor)
    if not scope.may_read(requested):
        raise TenantForbidden(f"You do not have access to tenant {requested!r}.")
    return TenantScope(
        all_tenants=False, tenant_ids=(requested,), include_unassigned=False, actor=scope.actor
    )


def apply(stmt: Any, column: Any, scope: TenantScope) -> Any:
    """Add the tenant restriction to a SELECT/DELETE over alert runs.

    Used by every read of the alert-run table. An all-tenants scope adds no
    clause; everything else adds one that can only narrow.
    """
    if scope.all_tenants:
        return stmt

    clauses = []
    if scope.tenant_ids:
        clauses.append(column.in_(list(scope.tenant_ids)))
    if scope.include_unassigned:
        clauses.append(column.is_(None))

    if not clauses:
        # Fail closed. An empty IN () is the classic way a scoped query quietly
        # becomes an unscoped one.
        return stmt.where(sql_false())
    return stmt.where(or_(*clauses))


def assert_can_read(scope: TenantScope, tenant_id: str | None) -> None:
    """Guard a single-object read. Raises 404 rather than 403 — see module docstring."""
    if scope.may_read(tenant_id):
        return
    from fastapi import HTTPException

    raise HTTPException(404, "Alert investigation not found")


def assert_can_submit(identity: dict[str, Any] | None, tenant_id: str) -> None:
    """May this integration submit an alert for this tenant?

    The tenant comes from the request; the authorisation comes from the
    credential. A key that names a tenant it does not hold is refused — that is
    the whole point of the field, and without this check `tenant_id` would be a
    label the caller chooses rather than a boundary.
    """
    from fastapi import HTTPException

    if not identity:
        raise HTTPException(401, "Authentication required.")

    if bool(identity.get("all_tenants")):
        return
    held = {str(t).strip() for t in (identity.get("tenant_ids") or []) if str(t).strip()}
    if tenant_id not in held:
        raise HTTPException(
            403,
            f"This credential is not authorised to submit alerts for tenant {tenant_id!r}.",
        )


@dataclass(frozen=True)
class TenantAssignment:
    """The tenant a new run is filed under, and why."""

    tenant_id: str | None
    assignment: str          # declared | legacy_fallback | unassigned


# The C00 alert marker, verified against 13,079 stored runs: every one of the
# 12,443 from alert_source='Siembiot' carries it, none of the 630 'unknown' do,
# and it never contradicts a declared client. Migration 030 classified history
# with it; this classifies live ingest with the same rule.
C00_MARKER = "manager: siembiot"


def classify_by_marker(
    *, alert_body: str | None, alert_source: str | None, alert_client: str | None,
    legacy_tenant: str,
) -> TenantAssignment:
    """The tenant an uncredentialed but network-trusted alert belongs to.

    Not an inference from a hostname appearing somewhere in the text: the marker
    is a Wazuh header line, and a payload that declares a different client is
    refused rather than overridden.
    """
    declared_client = str(alert_client or "unknown").strip().casefold()
    if declared_client not in ("", "unknown"):
        # Something else claims this alert. Filing it under C00 would resolve a
        # contradiction silently; unassigned is the honest answer.
        return TenantAssignment(tenant_id=None, assignment="unassigned")
    if C00_MARKER in str(alert_body or "").casefold():
        return TenantAssignment(tenant_id=legacy_tenant, assignment="marker")
    if str(alert_source or "").strip() == "wm-c00.siembiot.int":
        return TenantAssignment(tenant_id=legacy_tenant, assignment="manager_source")
    return TenantAssignment(tenant_id=None, assignment="unassigned")


def resolve_for_ingest(
    *,
    identity: dict[str, Any] | None,
    declared: str | None,
    alert_body: str | None = None,
    alert_source: str | None = None,
    alert_client: str | None = None,
    settings: Any = None,
) -> TenantAssignment:
    """Decide the tenant for an incoming alert, and refuse rather than guess.

    Three paths, in order:

    1. **The request names a tenant.** It is authorised against the credential,
       not taken on trust. This is the new contract, and `tenant_id` is
       mandatory under it.

    2. **A legacy C00 integration sends nothing.** Confined, deliberately, to a
       credential that holds exactly the one configured legacy tenant. A key
       holding two tenants and naming neither is ambiguous, and guessing which
       one it meant is how a client's alerts end up in another client's list.

    3. **An internal user pastes an alert by hand** without choosing a tenant.
       Filed unassigned, visible only to internal users, assignable later. This
       is the same state the 631 historical runs are in, and it is a queue
       rather than a default.

    Anything else is refused. In particular an API key that names no tenant and
    holds no legacy grant gets a 400 telling it to send `tenant_id`.
    """
    from fastapi import HTTPException

    if settings is None:
        from app.config import get_settings

        settings = get_settings()

    declared = str(declared or "").strip()
    identity = identity or {}
    legacy = str(getattr(settings, "alert_ingest_legacy_tenant", "") or "").strip()
    held = [str(t).strip() for t in (identity.get("tenant_ids") or []) if str(t).strip()]

    # ── The network-trusted ingest path ─────────────────────────────────────
    #
    # An appliance that cannot carry a header — NiFi here — is admitted by
    # source address and presents no credential. There is therefore nothing to
    # authorise a tenant against, so this path is the legacy one by definition
    # and is classified by the same verified marker rule migration 030 used.
    #
    # It must never refuse. This check was added returning 400 to an
    # uncredentialed sender and stopped production ingest for four hours:
    # enforcing a contract the sending side has not been given yet, against the
    # one caller that cannot satisfy it, is the wrong trade in every direction.
    # The multi-client contract needs a credential, and asking for one is a
    # thing to arrange with the dev team, not to impose by rejection.
    if identity.get("kind") == "trusted_network":
        if declared:
            if legacy and declared == legacy:
                return TenantAssignment(tenant_id=legacy, assignment="declared")
            raise HTTPException(
                403,
                f"Submitting for tenant {declared!r} needs an API key granted that tenant. "
                "This sender is admitted by source address and presents no credential, "
                "so the tenant it names cannot be verified.",
            )
        return classify_by_marker(
            alert_body=alert_body, alert_source=alert_source, alert_client=alert_client,
            legacy_tenant=legacy or "",
        ) if legacy else TenantAssignment(tenant_id=None, assignment="unassigned")

    if declared:
        assert_can_submit(identity, declared)
        return TenantAssignment(tenant_id=declared, assignment="declared")

    if identity.get("kind") == "api_key":
        if legacy and held == [legacy]:
            # The existing C00 flow, unchanged, for exactly as long as it takes
            # the dev team to start sending tenant_id.
            return TenantAssignment(tenant_id=legacy, assignment="legacy_fallback")
        raise HTTPException(
            400,
            "tenant_id is required. This integration is not the configured legacy "
            "single-tenant sender, so the tenant cannot be inferred.",
        )

    if bool(identity.get("all_tenants")):
        return TenantAssignment(tenant_id=None, assignment="unassigned")

    if len(held) == 1:
        # A client-restricted person can only mean their own tenant.
        return TenantAssignment(tenant_id=held[0], assignment="declared")

    raise HTTPException(400, "tenant_id is required: your account covers more than one tenant.")

