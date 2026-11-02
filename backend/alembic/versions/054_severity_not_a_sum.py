"""Separate "how severe" from "how bad did an indicator look", and stop
calling an unscored alert a zero.

Three faults, one shape. A 0-100 number was travelling in a field named
`rule_level`, read against thresholds of 13/10/7 written for Wazuh's 1-16
scale, with 0 meaning both "scored zero" and "never scored".

What `highest_risk_score` actually is: the maximum, over an alert's extracted
indicators, of a seven-component weighted sum in risk_aggregator.py. Five of
those seven components are URL, email, attachment or sandbox signals, so a
Sysmon process-creation event has five structural zeros and can reach 30 at
most unless the OpenCTI step-floor fires. Measured by source:

    windows_eventchannel    9,062 runs   77.7% zero   mean  8.8
    fortigate-firewall-v5   2,533 runs    0.0% zero   mean 62.0
    appsec-agent            2,685 runs    0.4% zero   mean 57.5
    macOS_loginwindow          10 runs  100.0% zero   mean  0.0

It tracks whether an alert happens to carry an externally-resolvable
indicator, which is a property of the source, not of severity. Case #1440 —
the richest true positive in the estate and the whole acceptance suite — has a
median of 0 against Wazuh levels of 6 to 13. So this column is renamed to say
what it is and is no longer the severity input.

Zero means unscored. 7,260 of 15,255 runs read 0 and the smallest real score
is 5, which the upgrade asserts before converting rather than leaving the next
reader to infer it. 47.6% of the estate being unscored is a fact about
coverage, not about those alerts' severity, so it becomes NULL and renders as
its own state.

`source_severity` is the alert's native severity, normalised across sources —
Wazuh `rule.level` is 1-16, Fortigate carries its own, Palo Alto another, and
#1106 has no Wazuh level at all. Populated by the graph extractor, which
already parses every body.

Revision ID: 054
Revises: 053
"""

from alembic import op
import sqlalchemy as sa

revision = "054"
down_revision = "053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The assumption, asserted rather than assumed: if any alert had ever been
    # scored 1-4, then 0 could not safely be read as "unscored" and this
    # migration would be wrong. Fail loudly instead of silently converting.
    smallest = op.get_bind().execute(
        sa.text(
            "select min(highest_risk_score) from alert_body_investigation_runs "
            "where highest_risk_score > 0"
        )
    ).scalar()
    if smallest is not None and smallest < 5:
        raise RuntimeError(
            "This migration converts highest_risk_score = 0 to NULL on the "
            f"grounds that the smallest real score is 5, but it is {smallest}. "
            "A score that low means 0 may be a measurement rather than a blank, "
            "and converting it would destroy data. Re-check the aggregator's "
            "reachable values before proceeding."
        )

    op.add_column(
        "alert_body_investigation_runs",
        # The alert's own severity, as its source states it, normalised to
        # 0-100 so sources with different native scales can be ranked
        # together. Null where the source states none — never 0, which is what
        # this migration is fixing elsewhere.
        sa.Column("source_severity", sa.Integer, nullable=True),
    )
    op.add_column(
        "alert_body_investigation_runs",
        # The native value and scale, kept so a normalised number can always be
        # traced back to what the source actually said.
        sa.Column("source_severity_raw", sa.String(32), nullable=True),
    )
    op.create_index(
        "ix_runs_source_severity", "alert_body_investigation_runs", ["source_severity"]
    )

    # `rule_level` on the graph entity never held a rule level.
    op.alter_column(
        "alert_graph_entity", "rule_level", new_column_name="indicator_risk_score"
    )
    op.add_column(
        "alert_graph_entity", sa.Column("source_severity", sa.Integer, nullable=True)
    )
    op.execute("update alert_graph_entity set indicator_risk_score = null "
               "where indicator_risk_score = 0")


def downgrade() -> None:
    op.drop_column("alert_graph_entity", "source_severity")
    op.alter_column(
        "alert_graph_entity", "indicator_risk_score", new_column_name="rule_level"
    )
    op.drop_index("ix_runs_source_severity", table_name="alert_body_investigation_runs")
    op.drop_column("alert_body_investigation_runs", "source_severity_raw")
    op.drop_column("alert_body_investigation_runs", "source_severity")
