"""Give the stored alerts the account that ran the command.

Three defects in one field, all of them in how the value's boundaries were
decided, and all of them visible in the stored column:

**The colon forms were never tried.** `extract_alert_fields` asked for the
account as `user=` (CEF) or `"user":` (JSON). A Sysmon process-creation alert
writes neither: it says `User: INT\\echelarasu` on its own line, and
`data.win.eventdata.user:` in the flattened block. Every other identity field
in that function passes a header label — "Agent IP", "Manager", "Rule" — and
this one passed None. Measured over 14,906 stored runs: 3,511 carried an
account in the body that was never extracted, against 344 that had one.

**A lone backslash ended a value.** The `user=` pattern terminated on
`[\\"]`, which is right for the `\\"` that closes CEF embedded in escaped
JSON and wrong for `DOMAIN\\user`, where the backslash is inside the name.
`suser=CORP\\jdoe` yielded `CORP`.

That second one did more than lose data. On host Alpha-UMa, **30 distinct
people were all stored as `povgrp`** — the domain half — so correlation saw
one account and linked thirty users' activity into one session. A case there
asserted that one person did all of it. Fixing it splits that host from 2
clusters into 8, which is 6 fabricated links removed.

**One account had several spellings.** The flattened block is JSON that was
printed rather than parsed, so it doubles the separator: the same person
arrived as `INT\\echelarasu` and `INT\\\\echelarasu`, and the column still
holds `CORP\\\\jdoe` beside `CORP`. Correlation links on this value, so one
person split several ways.

Measured effect of the whole change on case formation, over 11,705 alerts on
226 hosts: 260 clusters become 263. One host merges (Windows-Test-Device,
23 -> 15, where a real named account now links its own alerts) and four split
(the fabricated `povgrp` links above, and three alerts whose account was the
literal string "N/A"). It is not a mass re-grouping, which is the point of
having measured it.

Revision ID: 043
Revises: 042
"""

import re

from alembic import op
import sqlalchemy as sa

revision = "043"
down_revision = "042"
branch_labels = None
depends_on = None

# Self-contained, not imported from app.services: a migration has to produce
# the same result in five years against whatever the extractor has become.
_HEADER = re.compile(r"^[ \t]*User[ \t]*:[ \t]*(?P<v>[^\n]{1,200})", re.MULTILINE | re.IGNORECASE)
_KV = re.compile(
    r"(?:^|[\s|\"\\])(?:suser|duser|user|userName|srcuser)=(?P<v>[^=\n]{1,200}?)"
    r"(?=[\s\\\"]+[A-Za-z_][\w.]*=|\\\"|\"|\s*$)",
    re.MULTILINE | re.IGNORECASE,
)
_JSON = re.compile(r'"(?:suser|duser|user|userName|srcuser)"\s*:\s*"?(?P<v>[^",}{\[\]\n]{1,200})"?', re.IGNORECASE)
_DOTTED = re.compile(
    r"(?:^|\n)[ \t]*[\w.]*\.(?:suser|duser|user|userName|srcuser)[ \t]*:[ \t]*(?P<v>[^\n]{1,200})",
    re.IGNORECASE,
)

_NOT_AN_ACCOUNT = frozenset({"", "\\", "-", "n/a", "unknown", "null", "none"})


def _account_in(body: str) -> str | None:
    for pattern in (_HEADER, _KV, _JSON, _DOTTED):
        match = pattern.search(body or "")
        if not match:
            continue
        text = (match.group("v") or "").strip().strip('"').strip()
        if not text or text in ("{", "[", "}", "]", "null", "None", "-"):
            continue
        while "\\\\" in text:
            text = text.replace("\\\\", "\\")
        text = text.strip().rstrip(",;:").strip()
        if text.casefold() in _NOT_AN_ACCOUNT:
            continue
        if text.endswith("\\") or not text.replace("\\", "").strip():
            continue
        return text[:255]
    return None


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, alert_body, entity_user FROM alert_body_investigation_runs "
            "WHERE alert_body IS NOT NULL"
        )
    ).fetchall()
    for run_id, body, stored in rows:
        found = _account_in(body)
        # Only written when it differs, so a backfill over 14,906 rows does not
        # issue 14,906 no-op UPDATEs — the same mistake that put 673 of them in
        # one correlation pass.
        if found != stored:
            bind.execute(
                sa.text(
                    "UPDATE alert_body_investigation_runs SET entity_user = :user WHERE id = :id"
                ),
                {"user": found, "id": run_id},
            )


def downgrade() -> None:
    # Not reversible: the values replaced were a domain half, a doubled
    # separator or nothing at all, and none of them were recorded.
    pass
