"""Remember which kind of alert each run was, so an empty graph can say why.

A case whose alerts this platform cannot read must say so by name. The graph
is a join on the extracted rows, and an alert that produced no rows is
invisible to that join — so an all-empty case could only report "nothing",
which reads as "no attack here". That is the exact failure the first version
of this feature had, and it is not going to be reintroduced one layer down.

Writing the source type during extraction keeps the message a join rather
than a re-parse. Measured mix over the 15,212 stored alerts:

    windows_eventchannel     9,055   59.5%   mapped
    appsec-agent             2,685   17.7%   not mapped
    fortigate-firewall-v5    2,533   16.6%   not mapped
    (none: PAN-OS, syslog)     865    5.7%   not mapped
    syscheck_*, macOS, json     76    0.5%   not mapped

Revision ID: 051
Revises: 050
"""

from alembic import op
import sqlalchemy as sa

revision = "051"
down_revision = "050"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_body_investigation_runs",
        sa.Column("graph_source_type", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_runs_graph_source_type",
        "alert_body_investigation_runs",
        ["graph_source_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_runs_graph_source_type", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "graph_source_type")
