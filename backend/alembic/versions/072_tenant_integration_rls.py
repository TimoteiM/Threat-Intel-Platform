"""Row-level security on tenant_integrations, so a cross-tenant read is refused by Postgres

The per-client source map lives in `tenant_integrations`: one row per (tenant,
platform), carrying the connection config and the encrypted credential. The
control that matters is that a run carrying tenant X can only ever reach X's
sources, and until now that rested on every query remembering to filter.

`tenant_scope` does filter, carefully and in one place, and the credential
service takes `scope` as a required keyword for exactly this reason. But a
filter holds on the queries somebody wrote. This holds on the ones they have
not written yet.

**Why it can work now and could not before.** Row-level security does not
apply to a table's owner, and it does not apply to a role with BYPASSRLS.
Until 2026-10-19 the application connected as `threatintel` — superuser, owner
of every table — so a policy here would have been decoration. It now connects
as `tip_app`, which owns nothing and has no BYPASSRLS, so the policy binds.
See scripts/db_roles.sql.

**FORCE, not just ENABLE.** `ENABLE` exempts the owner, which is correct for
migrations. `FORCE` would apply the policy to the owner too and is deliberately
NOT used: Alembic runs as the owner and must be able to see every row to
migrate them. The protection is for the application role, which is the one
serving requests.

**The policy fails closed.** `current_setting('app.tenant_id', true)` returns
NULL when nothing has been bound, and `tenant_id = NULL` is never true, so an
unbound session sees zero rows rather than all of them. That direction is the
whole point — measured as `tip_app`:

    SET app.tenant_id = 'c00';  SELECT count(*) FROM tenant_integrations
        -> only c00's rows
    SELECT count(*) FROM tenant_integrations WHERE tenant_id = 'c01'
        -> 0, with the query explicitly asking to cross
    RESET app.tenant_id;  SELECT count(*) FROM tenant_integrations
        -> 0

**What this costs.** Every application read of this table must bind a tenant
first, through `client_sources.bind_tenant()`, which uses `SET LOCAL` so the
binding dies with the transaction instead of leaking into the next caller on a
pooled connection. A read that forgets returns nothing, which is a visible
emptiness rather than a silent leak — the failure mode worth having.

Idempotent, because `Base.metadata.create_all` runs at startup and is a second
schema authority (backlog 25).

Revision ID: 072
Revises: 071
"""

from alembic import op
import sqlalchemy as sa

revision = "072"
down_revision = "071"
branch_labels = None
depends_on = None

_TABLE = "tenant_integrations"
_POLICY = "tenant_integrations_tenant_isolation"
_SETTING = "app.tenant_id"


def _has_table(bind) -> bool:
    return sa.inspect(bind).has_table(_TABLE)


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind):
        return

    op.execute(sa.text(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY"))
    # Dropped and recreated rather than guarded with IF NOT EXISTS, which
    # CREATE POLICY does not support. Re-running this migration must leave one
    # policy with the current definition, not fail and not leave the old one.
    op.execute(sa.text(f"DROP POLICY IF EXISTS {_POLICY} ON {_TABLE}"))
    op.execute(sa.text(
        f"CREATE POLICY {_POLICY} ON {_TABLE} "
        f"USING (tenant_id = current_setting('{_SETTING}', true))"
    ))


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind):
        return
    op.execute(sa.text(f"DROP POLICY IF EXISTS {_POLICY} ON {_TABLE}"))
    op.execute(sa.text(f"ALTER TABLE {_TABLE} DISABLE ROW LEVEL SECURITY"))
