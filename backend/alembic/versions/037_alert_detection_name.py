"""
The detection an alert names, beside the Wazuh rule that carried it.

    Alert: exprevpxy002 - Shell Execution Of Process Located In Tmp Directory | Unknown problem somewhere in the system.
    Rule: 1002

Left of the pipe is the detection; right of it is the base rule's description.
Both were being collapsed into one field, and for generic base rules the one
that survived was the one that says nothing:

    rule 81640  "Fortigate: URL belongs to an allowed category"   2,523 runs
                actually: Shell Execution Of Process Located In Tmp Directory
    rule 1002   "Unknown problem somewhere in the system"         2,686 runs
                actually: Disable Or Stop Services, Shell Execution, ...

5,209 of 14,541 runs — 36% — carried a rule name that contradicts the alert.

The rule id and description are left alone: they are the rule's identity and
what a tuning change acts on, and they are accurate for every rule that is not
a generic carrier. This column is what the alert is *about*.

Backfilled from the stored bodies, so detection quality and correlation see the
history as well as what arrives next.
"""

from alembic import op
import sqlalchemy as sa

revision = "037"
down_revision = "036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("detection_name", sa.String(512), nullable=True),
    )
    # Same parse as alert_field_service.detection_name_of: the Alert: line, up
    # to the pipe, with the "<agent> - " prefix removed.
    op.execute(
        """
        UPDATE alert_body_investigation_runs
        SET detection_name = NULLIF(trim(
                regexp_replace(
                    split_part(
                        substring(alert_body from '(?n)^[ \\t]*Alert[ \\t]*:[ \\t]*(.+)$'),
                        '|', 1),
                    '^[^-]{1,80}? - ', '')
            ), '')
        WHERE alert_body IS NOT NULL
          AND alert_body ~ '(?n)^[ \\t]*Alert[ \\t]*:'
        """
    )
    op.create_index(
        "idx_alert_runs_detection_name",
        "alert_body_investigation_runs",
        ["detection_name"],
    )


def downgrade() -> None:
    op.drop_index("idx_alert_runs_detection_name", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "detection_name")
