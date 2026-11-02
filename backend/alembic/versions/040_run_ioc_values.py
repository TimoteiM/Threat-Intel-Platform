"""Keep each alert's indicator values in a column instead of re-parsing JSON.

Case membership asks what two alerts have in common, so correlation needs the
indicator values of every alert in the window. They were projected in SQL with
a correlated subquery — `jsonb_array_elements` over `result_json` for every
row — which measured at 2,398 ms against 30 ms for the same query without it.
Two and a half seconds of every Cases page load, spent re-deriving a value
that never changes once the investigation has concluded.

A trigger rather than an application write. The value has to be correct
whichever code path wrote the row — ingest, re-analysis, a backfill — and this
repository's recurring failure is the hand-maintained list that somebody
forgets. The database keeps it in step with `result_json` by construction.

Addresses the platform already skips as private or reserved are left out here
rather than filtered later: they are the device's own address, carried by
every alert on it, and they cannot tie two alerts together.

Revision ID: 040
Revises: 039
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "040"
down_revision = "039"
branch_labels = None
depends_on = None

_RECOMPUTE = """
CREATE OR REPLACE FUNCTION alert_run_ioc_values(payload jsonb)
RETURNS text[] AS $$
    SELECT array_agg(DISTINCT lower(rep->'indicator'->>'value'))
    FROM jsonb_array_elements(coalesce(payload->'indicator_reports', '[]'::jsonb)) AS rep
    WHERE rep->'indicator'->>'value' IS NOT NULL
      AND coalesce(rep->>'skip_reason', '') <> 'private_or_reserved_address'
$$ LANGUAGE sql IMMUTABLE;
"""

_TRIGGER_FN = """
CREATE OR REPLACE FUNCTION alert_run_ioc_values_sync()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.result_json IS DISTINCT FROM OLD.result_json THEN
        NEW.ioc_values := alert_run_ioc_values(NEW.result_json);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("ioc_values", postgresql.ARRAY(sa.Text()), nullable=True),
    )
    op.execute(_RECOMPUTE)
    op.execute(_TRIGGER_FN)
    op.execute(
        """
        CREATE TRIGGER alert_run_ioc_values_trg
        BEFORE INSERT OR UPDATE OF result_json ON alert_body_investigation_runs
        FOR EACH ROW EXECUTE FUNCTION alert_run_ioc_values_sync()
        """
    )
    # One pass over history, paying the 2.4 seconds once instead of on every
    # page load for ever.
    op.execute(
        "UPDATE alert_body_investigation_runs "
        "SET ioc_values = alert_run_ioc_values(result_json) "
        "WHERE result_json IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS alert_run_ioc_values_trg ON alert_body_investigation_runs")
    op.execute("DROP FUNCTION IF EXISTS alert_run_ioc_values_sync()")
    op.execute("DROP FUNCTION IF EXISTS alert_run_ioc_values(jsonb)")
    op.drop_column("alert_body_investigation_runs", "ioc_values")
