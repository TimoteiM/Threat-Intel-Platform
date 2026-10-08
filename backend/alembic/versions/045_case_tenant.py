"""Give a case the client it belongs to.

The Reports page filters by client, and the column that looked like the client
could not do it: `alert_case_spine.alert_client` reads "unknown" for 1,079 of
1,098 cases. It is the sender's own self-declared label, which this deployment
has already been burned by — see the note that moved tenant classification off
a declared value and onto `/tenants/{tenant_id}`. A filter built on it would
have offered one option, "unknown", for 98% of the estate.

The authoritative tenant is on the alerts: `alert_body_investigation_runs
.tenant_id`, which is c00 for 14,094 runs and unset for 847 legacy ones.
Correlation already knows it — the members it groups carry it, and the scope it
ran under selected them — so from here it is written onto the case directly.

History is backfilled through the host, because a case's membership is computed
on read and not stored. Measured first: 225 of 226 hosts map to exactly one
tenant, and 1,080 of 1,098 spine rows have a host that matches an alert run, so
the derivation is sound for all but the 18 pre-correlated incident rows whose
host is a composite key. Those are left null rather than guessed, and a null
tenant is offered in the UI as "Unassigned" rather than hidden.

Revision ID: 045
Revises: 044
"""

from alembic import op
import sqlalchemy as sa

revision = "045"
down_revision = "044"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alert_case_spine", sa.Column("tenant_id", sa.String(64), nullable=True))
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_case_spine_tenant_opened
        ON alert_case_spine (tenant_id, opened_at DESC)
        """
    )
    # The host's tenant, taken as the one its alerts actually carry. `mode()`
    # rather than `min()`: one host in this estate has runs under two tenants
    # — its own and the legacy unassigned set — and the answer wanted there is
    # the one it mostly is, not the alphabetically first.
    op.execute(
        """
        WITH host_tenant AS (
            SELECT entity_host,
                   mode() WITHIN GROUP (ORDER BY tenant_id) AS tenant_id
            FROM alert_body_investigation_runs
            WHERE entity_host IS NOT NULL AND tenant_id IS NOT NULL
            GROUP BY entity_host
        )
        UPDATE alert_case_spine s
           SET tenant_id = h.tenant_id
          FROM host_tenant h
         WHERE s.entity_host = h.entity_host
           AND s.tenant_id IS NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_case_spine_tenant_opened")
    op.drop_column("alert_case_spine", "tenant_id")
