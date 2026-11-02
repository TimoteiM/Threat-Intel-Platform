"""A URL observable does not fit in 512 characters.

Reported 2026-10-26: submitting a Hornetsecurity ATP-scan URL returned an
internal error. The URL is **819 characters** — an ATP wrapper carrying a
Barracuda `linkprotect` URL, which in turn carries the real destination,
double-percent-encoded. Mail-security rewriting routinely produces URLs of
this length, and a SOC is sent them constantly: the wrapper is exactly what
arrives in a phishing report.

What happened, traced rather than guessed:

    investigations.domain is varchar(512)
    the insert raised psycopg2.errors.StringDataRightTruncation
    SQLAlchemy surfaced it as DataError
    DataError is NOT a ValueError
    api/investigations.create_investigation catches only ValueError
    -> unhandled -> 500

So a too-long input — a client error, and an obvious one — was reported as an
internal failure, and the analyst had no way to tell that shortening the URL
would have worked.

**2048 is not a new number.** `iocs.value` and `indicator_lookups.value` are
already varchar(2048); `soc_indicators.value` is 1024. The two columns widened
here were the outliers, not the standard. That also keeps the indexed
`investigations.domain` inside the btree row limit (~2704 bytes), which a
`text` column would not guarantee.

`exclusions.value` and `normalized_value` carry the same observables and had
the same 512, so excluding a long URL would have failed the same way. Fixed
here rather than left for someone to rediscover from a second 500.

Revision ID: 076
Revises: 075
"""

from alembic import op
import sqlalchemy as sa

revision = "076"
down_revision = "075"
branch_labels = None
depends_on = None

#: Matches `iocs.value` and `indicator_lookups.value`, which already hold
#: observables of this kind.
WIDTH = 2048


def upgrade() -> None:
    op.alter_column(
        "investigations", "domain",
        existing_type=sa.String(512), type_=sa.String(WIDTH),
        existing_nullable=False,
    )
    for column in ("value", "normalized_value"):
        op.alter_column(
            "exclusions", column,
            existing_type=sa.String(512), type_=sa.String(WIDTH),
            existing_nullable=True,
        )


def downgrade() -> None:
    # Narrowing would fail on any row already holding a longer value, which is
    # the point of the change. Left deliberately lossy-by-refusal: Postgres
    # raises rather than truncating, so a downgrade on real data stops instead
    # of destroying the observable it cannot fit.
    op.alter_column(
        "investigations", "domain",
        existing_type=sa.String(WIDTH), type_=sa.String(512),
        existing_nullable=False,
    )
    for column in ("value", "normalized_value"):
        op.alter_column(
            "exclusions", column,
            existing_type=sa.String(WIDTH), type_=sa.String(512),
            existing_nullable=True,
        )
