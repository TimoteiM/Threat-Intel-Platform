"""
The alerts that arrived while tenancy was being deployed.

Migration 030 classified everything that existed when it ran. The code that
classifies an alert *at ingest* went live a few minutes later. Alerts kept
arriving in between, and nothing assigned them: 15 runs between 08:36 and 08:40
on 2026-09-24, all `alert_source='Siembiot'`, all carrying `Manager: Siembiot`,
all sitting unassigned with `tenant_assignment` NULL.

They are not legacy runs. They satisfy 030's marker rule exactly and would have
been assigned by it had they existed ten minutes earlier. Leaving them out would
understate C00's alert count for no reason other than deploy timing.

So this re-runs 030's two rules over anything still unclassified. It is the same
rule, not a new inference — no tenant is derived from a self-declared `client`
value, and none from a hostname merely appearing somewhere in alert text.

Idempotent and safe to run again: it only touches rows where `tenant_id IS NULL`
*and* `tenant_assignment IS NULL`, so a run deliberately left unassigned by the
ingest path (recorded as `unassigned`) is never swept up by it.

This gap cannot recur — an ingest now records an assignment for every run,
including `unassigned` — but the rules live in `tenant_backfill.py` so they can
be re-run by hand if one ever does.
"""

from alembic import op
import sqlalchemy as sa

revision = "031"
down_revision = "030"
branch_labels = None
depends_on = None

C00 = "c00"


def upgrade() -> None:
    conn = op.get_bind()

    marker = conn.execute(
        sa.text(
            "UPDATE alert_body_investigation_runs SET tenant_id = :t, tenant_assignment = 'marker' "
            "WHERE tenant_id IS NULL AND tenant_assignment IS NULL "
            "  AND alert_body ILIKE '%Manager: Siembiot%' "
            "  AND coalesce(alert_client, 'unknown') IN ('unknown', '')"
        ),
        {"t": C00},
    ).rowcount

    manager_source = conn.execute(
        sa.text(
            "UPDATE alert_body_investigation_runs SET tenant_id = :t, tenant_assignment = 'manager_source' "
            "WHERE tenant_id IS NULL AND tenant_assignment IS NULL "
            "  AND alert_source = 'wm-c00.siembiot.int' "
            "  AND coalesce(alert_client, 'unknown') IN ('unknown', '')"
        ),
        {"t": C00},
    ).rowcount

    remaining = conn.execute(
        sa.text("SELECT count(*) FROM alert_body_investigation_runs WHERE tenant_id IS NULL")
    ).scalar()
    print(
        f"[031] deploy-gap backfill — marker: {marker}, manager_source: {manager_source}, "
        f"still unassigned: {remaining}"
    )


def downgrade() -> None:
    # Nothing: 030 and 031 apply the same rule, and undoing one would have to
    # guess which of them assigned a given row.
    pass
