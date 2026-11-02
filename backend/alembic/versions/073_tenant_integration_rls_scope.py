"""Make the tenant_integrations policy express a SCOPE, and cover writes

Fixes an outage I caused with migration 072, which took effect on 2026-10-19
and was found on 2026-10-20 when configuring CrowdStrike returned 500.

**What 072 got wrong, in two ways.**

*It only described a single tenant.* The policy was
`tenant_id = current_setting('app.tenant_id')`, which cannot express the
accesses this table actually has: `rotate_all` re-encrypts every row across
every tenant, `credential_expiry_service` reports on all of them, and an
internal all-tenants user lists every integration. The application's own
model has always been a **scope** — `tenant_scope.TenantScope` is either
all-tenants or a set of ids — and the policy had to be written against that,
not against one id.

*Nothing bound the setting.* With `app.tenant_id` unset,
`current_setting(..., true)` is NULL, so:

* every SELECT returned **zero rows** — the one configured Falcon credential
  became invisible to the API, silently, and the integrations page showed it
  as unconfigured;
* every INSERT failed with `new row violates row-level security policy`,
  because a policy with `USING` and no `WITH CHECK` applies `USING` to new
  rows too.

The write failure was loud and is what surfaced this. The read failure was
silent and had been wrong for a day — the worse of the two, and the reason
this migration adds a read-side test rather than only fixing the write.

**What this does.** One policy, reading `app.tenant_scope`:

* `'*'` — every row. For an all-tenants identity and for the maintenance
  paths that must cross tenants by design.
* a comma-separated list — those tenants only.
* unset, or empty — **no rows**, which is the direction that has to be safe.
  `nullif(..., '')` makes "bound to an empty scope" and "never bound" the same
  closed state rather than letting an empty string match an empty tenant_id.

`WITH CHECK` is spelled out rather than inherited from `USING`, so an INSERT
or UPDATE can only write a row inside the bound scope. A caller cannot create
another tenant's credential, which is the half 072 enforced by accident and
this one enforces on purpose.

The application still filters with `tenant_scope.apply()`. This is the
backstop under it, and `app/services/tenant_scope.py:bind()` is what sets the
setting — one function, called where the scope is already in hand.

Revision ID: 073
Revises: 072
"""

from alembic import op
import sqlalchemy as sa

revision = "073"
down_revision = "072"
branch_labels = None
depends_on = None

_TABLE = "tenant_integrations"
_OLD_POLICY = "tenant_integrations_tenant_isolation"
_POLICY = "tenant_integrations_scope_isolation"
_SETTING = "app.tenant_scope"

#: Shared by USING and WITH CHECK so a read and a write cannot disagree about
#: what the scope means.
_PREDICATE = (
    f"nullif(current_setting('{_SETTING}', true), '') IS NOT NULL "
    f"AND ("
    f"current_setting('{_SETTING}', true) = '*' "
    f"OR tenant_id = ANY(string_to_array(current_setting('{_SETTING}', true), ','))"
    f")"
)


def _has_table(bind) -> bool:
    return sa.inspect(bind).has_table(_TABLE)


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind):
        return

    op.execute(sa.text(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"DROP POLICY IF EXISTS {_OLD_POLICY} ON {_TABLE}"))
    op.execute(sa.text(f"DROP POLICY IF EXISTS {_POLICY} ON {_TABLE}"))
    op.execute(sa.text(
        f"CREATE POLICY {_POLICY} ON {_TABLE} "
        f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
    ))


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind):
        return
    op.execute(sa.text(f"DROP POLICY IF EXISTS {_POLICY} ON {_TABLE}"))
    op.execute(sa.text(
        f"CREATE POLICY {_OLD_POLICY} ON {_TABLE} "
        f"USING (tenant_id = current_setting('app.tenant_id', true))"
    ))
