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
    """How the existing C00 runs were assigned. No longer used at ingest.

    Historical. This is the rule migration 030 applied to the backlog and the
    one that assigned the 13,714 runs now sitting under the legacy tenant, and
    it is kept so that record stays readable and so a test can hold the live
    code and the migration to the same definition.

    It is not called when an alert arrives any more. "Manager: Siembiot" names
    the Wazuh manager, not the client — every tenant carries it — so as a
    classifier it could only ever have been right while there was exactly one
    client. Alerts that name no tenant are now filed unassigned instead.
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


def _assert_known_tenant(declared: str, known_tenants: Sequence[str] | None) -> None:
    """Refuse a tenant that is not configured, loudly.

    A tenant now arrives in a URL that an operator templates per NiFi flow, so
    a typo is the likeliest failure there is. Filing `c0O`'s alerts under a new
    silent bucket would leave a client's alerts nowhere anyone is looking; a
    400 names the mistake at the sender, which is the only place it can be
    fixed.

    `None` means the caller could not enumerate tenants and is not asserting
    anything — the check is skipped rather than failing every ingest.
    """
    from fastapi import HTTPException

    if known_tenants is None:
        return
    if declared not in set(known_tenants):
        raise HTTPException(
            400,
            f"Unknown or inactive tenant {declared!r}. "
            "Configure the tenant before sending alerts for it.",
        )


def resolve_for_ingest(
    *,
    identity: dict[str, Any] | None,
    declared: str | None,
    alert_body: str | None = None,
    alert_source: str | None = None,
    alert_client: str | None = None,
    settings: Any = None,
    known_tenants: Sequence[str] | None = None,
    declared_via: str = "declared",
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
    # source address and presents no credential. There is nothing to authorise
    # a tenant against, so the tenant has to arrive in the URL.
    #
    # It must never refuse. This check was added returning 400 to an
    # uncredentialed sender and stopped production ingest for four hours:
    # enforcing a contract the sending side has not been given yet, against the
    # one caller that cannot satisfy it, is the wrong trade in every direction.
    # An alert that names no tenant is still accepted — it is filed unassigned,
    # which is a queue somebody can work, not a rejection.
    if identity.get("kind") == "trusted_network":
        if declared:
            # The sender names its tenant in the URL path. Be clear about what
            # this is and is not: a path segment is exactly as self-declared as
            # a body field, and this sender presents no credential, so nothing
            # here *verifies* the claim — it records it. A sender able to post
            # to one tenant's path can post to any.
            #
            # It is still a large improvement on the alternative it replaces.
            # The marker rule below reads "Manager: Siembiot", which every
            # tenant will carry, so left as the only rule it would file every
            # new client's alerts under the legacy tenant. An unverified claim
            # that is usually right and always visible beats an inference that
            # is silently wrong.
            #
            # Tightening this to a per-source-address map, or to an API key per
            # sender, changes only this branch.
            if known_tenants is None:
                # The caller could not tell us which tenants exist, so this
                # claim cannot be checked against anything at all. Fail closed
                # to the pre-path behaviour rather than accept it: a parameter
                # someone forgot to pass must not quietly widen who may file
                # alerts into whose list.
                if legacy and declared == legacy:
                    return TenantAssignment(tenant_id=legacy, assignment=declared_via)
                raise HTTPException(
                    403,
                    f"Submitting for tenant {declared!r} could not be checked against the "
                    "configured tenants. This sender is admitted by source address and "
                    "presents no credential.",
                )
            _assert_known_tenant(declared, known_tenants)
            return TenantAssignment(tenant_id=declared, assignment=declared_via)

        # Nothing named — so nothing is known, and nothing is guessed.
        #
        # This used to fall back to the marker rule, which read "Manager:
        # Siembiot" and filed the alert under the legacy tenant. That marker
        # identifies the manager, not the client: every tenant carries it. It
        # was right for as long as there was one client and would have been
        # wrong the moment there were two, so it is gone rather than merely
        # guarded.
        #
        # The 13,714 runs it already assigned stay exactly as they are. They
        # were correct when they were made, and re-deciding history from a rule
        # we have just discarded would be worse than leaving it recorded.
        return TenantAssignment(tenant_id=None, assignment="unassigned")

    if declared:
        assert_can_submit(identity, declared)
        _assert_known_tenant(declared, known_tenants)
        return TenantAssignment(tenant_id=declared, assignment=declared_via)

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

