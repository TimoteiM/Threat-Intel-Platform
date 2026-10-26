"""A tenant's feed emits alerts or incidents, and that is declared, not inferred.

`alert_correlation_service` already routes a pre-correlated payload to a case
of its own — keyed on the row id, so it can never be pooled with the alerts it
summarises, and tolerant of a missing host. The classification that feeds it is
made once at ingest by `is_pre_correlated`, which requires both `entity_type`
and `event_count` in the extracted fields.

Measured 2026-10-23 across all 111 `lin`/`pov`/`boc` runs: **both fields are
present on zero of them.** What those payloads carry is `event_name`,
`service`, `user`, `agent`, `agent_ip`, `event_id`. So "these feeds are
incidents" was true of the source systems and absent from the data, and the
detector was being asked a question the payload could not answer.

**Why a column rather than a better detector.** There is no incident-shaped
signal in those payloads to detect — no count, no entity type, nothing. The
fact is a property of the *feed*, known to whoever configured it, so it is
recorded as one. That also keeps it from becoming a rule about a tenant
buried in a branch: a tenant that later starts sending raw alerts is changed
by an UPDATE, not a deploy.

`alerts` is the default, deliberately. Treating an unknown feed as raw alerts
means it goes through correlation; treating it as incidents would mint a case
per row, and inventing cases for a feed nobody has classified is the more
expensive mistake.

Revision ID: 075
Revises: 074
"""

from alembic import op
import sqlalchemy as sa

revision = "075"
down_revision = "074"
branch_labels = None
depends_on = None

#: Closed, like `tenants.kind`. A free-text column would be a second place for
#: "incident" to be spelled differently.
FEED_KINDS = ("alerts", "incidents")


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("feed_kind", sa.String(32), nullable=False,
                  server_default=sa.text("'alerts'")),
    )
    op.create_check_constraint(
        "ck_tenants_feed_kind",
        "tenants",
        sa.text("feed_kind IN ('alerts', 'incidents')"),
    )
    # The three TraceCat-fed tenants. Declared by the person who configured
    # the feeds, which is the only place this fact exists — see the module
    # docstring for what the payloads do and do not carry.
    op.execute("""
        UPDATE tenants
           SET feed_kind = 'incidents',
               notes = COALESCE(notes, '') ||
                 ' Feed emits pre-correlated incidents (declared 2026-10-26): '
                 'each payload is already a case, so it is not pooled with '
                 'other alerts and does not need an entity_host.'
         WHERE tenant_id IN ('lin', 'pov', 'boc')
    """)


def downgrade() -> None:
    op.drop_constraint("ck_tenants_feed_kind", "tenants", type_="check")
    op.drop_column("tenants", "feed_kind")
