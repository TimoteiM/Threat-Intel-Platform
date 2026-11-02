"""
Which client an alert belongs to, and who is allowed to see it.

Until now every alert run landed in one undifferentiated list. `alert_client`
exists but is self-declared by the payload — 13,060 of 13,079 stored runs say
"unknown" — so it identifies nothing and cannot be a boundary. This adds a
verified tenant, assigned by the platform rather than asserted by the sender.

## Why a new table rather than `clients`

`clients` is the brand-monitoring register: domains, aliases, brand keywords,
"whose name should we watch for in a phishing kit". A tenant is the opposite
direction — whose estate an alert came *from*, and whose analysts may read it.
Overloading one row with both would make "delete this client" mean two
unrelated things, one of which is destroying an audit boundary.

## The historical assignment, measured before it was written

Counted against the 13,079 stored runs on 2026-09-24:

    alert_source='Siembiot'          12,443   ALL carry 'Manager: Siembiot'
    alert_source='unknown'              630   NONE carry it
    alert_source='wm-c00.siembiot.int'    5   the C00 manager naming itself
    alert_source='probe'                  1   carries it

The marker and the source agree exactly, and — the check that mattered — the
marker never contradicts a declared client: the 18 runs declaring `LIN` do not
carry it. So two rules, each recorded on the row that it assigned:

    marker          'Manager: Siembiot' AND no other client declared  → c00
    manager_source  alert_source is the C00 manager hostname          → c00

Everything else stays NULL. That is deliberate and it is 631 runs: the
`unknown` bucket is Cloudflare, Office 365, Skyformation, SentinelOne, Exabeam
and raw Windows event XML — a TraceCat-shaped mix of channels, and a channel is
not a tenant. 22 of them mention "siembiot" somewhere and 9 mention "wm-c00",
which is suggestive and is not verification; a hostname can appear in a log body
forwarded from anywhere. They are visible to internal users in the unassigned
view and assignable by hand.

The one run declaring client `Codex Desktop` *does* carry the marker. The rule
refuses it rather than resolving the contradiction silently.

## Access

`users.all_tenants` defaults TRUE, because every account that exists today is
Expertware internal staff, and migrating them into seeing nothing would be a
lockout dressed as a security improvement. A client-restricted account is
created with it FALSE and an explicit `tenant_ids`.

`api_keys.tenant_ids` is empty by default, which means an existing key may not
submit under the new multi-tenant contract. The C00 ingest key is granted `c00`
below so the existing flow keeps working unchanged.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "030"
down_revision = "029"
branch_labels = None
depends_on = None

C00 = "c00"


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        # The identifier the dev team will send. Short, stable, lower-case.
        sa.Column("tenant_id", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.add_column("alert_body_investigation_runs", sa.Column("tenant_id", sa.String(64), nullable=True))
    # How the tenant was decided, kept so a later dispute about an assignment
    # can be settled by reading the row rather than by re-deriving the rule.
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("tenant_assignment", sa.String(24), nullable=True),
    )
    op.create_index(
        "idx_alert_body_runs_tenant_created",
        "alert_body_investigation_runs",
        ["tenant_id", "created_at"],
    )

    op.add_column("users", sa.Column("all_tenants", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("users", sa.Column("tenant_ids", postgresql.JSONB(), nullable=False, server_default="[]"))
    op.add_column("api_keys", sa.Column("tenant_ids", postgresql.JSONB(), nullable=False, server_default="[]"))

    conn = op.get_bind()
    conn.execute(
        sa.text(
            "INSERT INTO tenants (id, tenant_id, name, status, notes) "
            "VALUES (gen_random_uuid(), :t, :n, 'active', :notes) "
            "ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {
            "t": C00,
            "n": "Expertware (C00)",
            "notes": "The estate behind wm-c00.siembiot.int. Created by migration 030.",
        },
    )

    marker = conn.execute(
        sa.text(
            "UPDATE alert_body_investigation_runs SET tenant_id = :t, tenant_assignment = 'marker' "
            "WHERE tenant_id IS NULL "
            "  AND alert_body ILIKE '%Manager: Siembiot%' "
            "  AND coalesce(alert_client, 'unknown') IN ('unknown', '')"
        ),
        {"t": C00},
    ).rowcount

    manager_source = conn.execute(
        sa.text(
            "UPDATE alert_body_investigation_runs SET tenant_id = :t, tenant_assignment = 'manager_source' "
            "WHERE tenant_id IS NULL "
            "  AND alert_source = 'wm-c00.siembiot.int' "
            "  AND coalesce(alert_client, 'unknown') IN ('unknown', '')"
        ),
        {"t": C00},
    ).rowcount

    unassigned = conn.execute(
        sa.text("SELECT count(*) FROM alert_body_investigation_runs WHERE tenant_id IS NULL")
    ).scalar()

    # Printed rather than logged: alembic output is what an operator watches
    # during a migration, and these three numbers are the whole outcome.
    print(
        f"[030] tenant assignment — marker: {marker}, manager_source: {manager_source}, "
        f"left unassigned: {unassigned}"
    )

    # The existing C00 ingest credential keeps working. Matched by role rather
    # than by label, because the label is operator-chosen text.
    granted = conn.execute(
        sa.text("UPDATE api_keys SET tenant_ids = :ids WHERE role = 'ingest' AND active = true"),
        {"ids": f'["{C00}"]'},
    ).rowcount
    print(f"[030] granted tenant '{C00}' to {granted} active ingest key(s)")


def downgrade() -> None:
    op.drop_column("api_keys", "tenant_ids")
    op.drop_column("users", "tenant_ids")
    op.drop_column("users", "all_tenants")
    op.drop_index("idx_alert_body_runs_tenant_created", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "tenant_assignment")
    op.drop_column("alert_body_investigation_runs", "tenant_id")
    op.drop_table("tenants")
