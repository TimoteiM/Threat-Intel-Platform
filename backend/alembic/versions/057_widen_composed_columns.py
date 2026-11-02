"""Widen the bounded columns whose length tracks what the value says.

Prompted by `source_severity_raw` at 32 characters failing on the six
Fortigate alerts the firewall graded as attacks — the value grew because the
event was interesting, so the insert failure selected for severity.

Swept all 152 bounded character columns in the schema, comparing each one's
longest stored value against its ceiling. 18 sit within 20% of it; 16 of those
are fixed-width by construction (sha256 keys and fingerprints at 64, md5 at
32, sha1 at 40, an IPv6 column at 45) and cannot overflow. Two are real:

`alert_body_investigation_runs.title` — 771 rows stored at exactly 255.
Sender-supplied free text, and the case label is derived from the first
alert's title, so a truncated title becomes a truncated case name. Worth
noting what the correlation actually is rather than assuming it repeats the
Fortigate shape: all 771 have `source_severity = NULL`, so this tracks the
*source* — the Palo Alto syslog that already has no field map — and not
severity. Widened to text, because a display string has no natural ceiling.

`iocs.value` — 5 rows at exactly 512, both sampled ones long tracking URLs.
A truncated indicator is worse than an absent one: it will never match
anything, while still appearing to have been recorded. Widened to 2048.

Nothing is truncated to fit. A value cut short is a value that cannot be
matched, traced, or recognised, which is the failure this migration undoes.

Revision ID: 057
Revises: 056
"""

from alembic import op
import sqlalchemy as sa

revision = "057"
down_revision = "056"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "alert_body_investigation_runs", "title",
        type_=sa.Text(), existing_type=sa.String(255),
    )
    op.alter_column(
        "iocs", "value",
        type_=sa.String(2048), existing_type=sa.String(512),
    )


def downgrade() -> None:
    # Deliberately not reversible by truncation: narrowing these would destroy
    # the values the upgrade exists to preserve.
    raise RuntimeError(
        "Narrowing these columns would truncate stored values. Restore from a "
        "backup instead."
    )
