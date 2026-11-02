"""Per-tenant integration credentials, and who configured them.

Keyed on `tenant_id`, not on a client. Credentials must live on the axis that
carries authorisation: `users.tenant_ids`, `users.all_tenants` and
`api_keys.tenant_ids` all scope by tenant, and nothing in this schema
authorises on `clients`. A secret on an axis with no access control is a
cross-tenant leak by default rather than by bug — "may this user see this
credential?" would have no answer in the data.

Three things deliberately NOT in this schema:

  * **no `enabled` column.** "Enabled" is the word that cost seven months
    here: a ThreatFox integration that was enabled, configured and answering
    401 on every call looked healthy by every flag the platform had. State is
    derived — from whether a connector exists, whether a credential is
    stored, and what the last real authenticated call returned — never
    asserted by a boolean somebody set.
  * **no plaintext column.** `secret_ciphertext` holds Fernet output and
    `secret_key_id` names the key that sealed it, so "every row re-encrypted
    under the new key" is a query rather than a claim.
  * **no tool enum.** The catalogue is derived from the implemented
    connectors in `COLLECTOR_REGISTRY`; a database enum would be a ninth
    hand-maintained list and would need a migration to add a connector.

`health` is JSONB keyed by direction — `enrichment`, `ingest` — because an
integration that answers queries and has stopped delivering detections is
healthy by one measure and dead by the other, and one status would show green
through exactly that. Directions are a property of the connector, so the set
of keys is derived too; JSONB means ingest lands without a migration.

Revision ID: 063
Revises: 062
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "063"
down_revision = "062"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # `app/main.py` runs `Base.metadata.create_all` at startup, so a table can
    # appear from the model before its migration runs. Guarded for the same
    # reason 062 is: the two orders converge instead of racing.
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())

    if "tenant_integrations" not in existing:
        op.create_table(
            "tenant_integrations",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            # The authorisation axis. A varchar rather than an FK to
            # tenants.id so the value in a row reads as the thing operators
            # and URLs use (`c00`), matching
            # `alert_body_investigation_runs.tenant_id`.
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("tool", sa.String(length=64), nullable=False),
            # Non-secret settings only — base URL, region, a cloud name.
            # Anything secret goes in `secret_ciphertext`; a test asserts no
            # credential-shaped key appears here.
            sa.Column(
                "config",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            # Nullable: a connector may legitimately need no secret.
            sa.Column("secret_ciphertext", sa.Text(), nullable=True),
            sa.Column("secret_key_id", sa.String(length=32), nullable=True),
            sa.Column("secret_set_at", sa.DateTime(timezone=True), nullable=True),
            # Per direction: {"enrichment": {...}, "ingest": {...}}
            sa.Column(
                "health",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("configured_by", sa.String(length=255), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )
        # One configuration per tenant per tool. Re-configuring replaces,
        # rather than leaving two rows and a question about which is live.
        op.create_unique_constraint(
            "uq_tenant_integration", "tenant_integrations", ["tenant_id", "tool"]
        )
        # The matrix view's query: every tool for every tenant.
        op.create_index(
            "idx_tenant_integrations_tenant", "tenant_integrations", ["tenant_id"]
        )
        # The rotation sweep's query: rows not under the primary key.
        op.create_index(
            "idx_tenant_integrations_key", "tenant_integrations", ["secret_key_id"]
        )

    if "integration_audit" not in existing:
        op.create_table(
            "integration_audit",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("tool", sa.String(length=64), nullable=False),
            # configured | secret_set | removed | verified | rotated
            sa.Column("action", sa.String(length=32), nullable=False),
            sa.Column("actor", sa.String(length=255), nullable=True),
            sa.Column("actor_role", sa.String(length=20), nullable=True),
            # Never a secret. What changed, not what it changed to.
            sa.Column(
                "detail",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column(
                "at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )
        # Deliberately no FK to tenant_integrations: the audit of a
        # configuration must outlive the configuration being removed, which is
        # the property that let the deleted office.com investigation's alert
        # run survive and remain inspectable.
        op.create_index(
            "idx_integration_audit_subject",
            "integration_audit",
            ["tenant_id", "tool", "at"],
        )


def downgrade() -> None:
    op.drop_table("integration_audit")
    op.drop_table("tenant_integrations")
