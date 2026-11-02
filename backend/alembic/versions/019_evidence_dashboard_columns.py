"""surface the two evidence fields the dashboard aggregates, so it stops reading TOAST

Revision ID: 019
Revises: 018
Create Date: 2026-08-12

The dashboard's "top registrars" and "top hosting providers" panels each ran a
GROUP BY over `evidence_json->'whois'->>'registrar'` and
`evidence_json->'hosting'->>'asn_org'`. Reading one short string out of a JSONB
column means Postgres fetches and decompresses the whole value, and these
average ~300 KB — 435 rows came to 133 MB of detoasting for two strings apiece.
Each aggregate took ~3 seconds, and the dashboard took 6.

An expression index does not fix it. The planner sees a 435-row table, costs a
sequential scan at 98 pages and takes it, because the cost model has no notion
of TOAST access; forcing the index still left 588 ms, since the SELECT list
re-evaluates the expression against the heap tuple.

Stored generated columns move the extraction to write time. The values live
inline in the row, so the scan never opens the TOAST table, and Postgres keeps
them in step with `evidence_json` itself — there is no write path to update and
no way for them to drift.

Measured on the same query: 2988 ms -> 1.4 ms.
"""

from __future__ import annotations

from alembic import op


revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE evidence
          ADD COLUMN IF NOT EXISTS whois_registrar text
            GENERATED ALWAYS AS (evidence_json->'whois'->>'registrar') STORED,
          ADD COLUMN IF NOT EXISTS hosting_asn_org text
            GENERATED ALWAYS AS (evidence_json->'hosting'->>'asn_org') STORED
        """
    )
    # The dashboard filters these to non-null before grouping, so the partial
    # index stays small — most investigations carry neither field.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_evidence_whois_registrar
          ON evidence (whois_registrar) WHERE whois_registrar IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_evidence_hosting_asn_org
          ON evidence (hosting_asn_org) WHERE hosting_asn_org IS NOT NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_evidence_hosting_asn_org")
    op.execute("DROP INDEX IF EXISTS idx_evidence_whois_registrar")
    op.execute("ALTER TABLE evidence DROP COLUMN IF EXISTS hosting_asn_org")
    op.execute("ALTER TABLE evidence DROP COLUMN IF EXISTS whois_registrar")
