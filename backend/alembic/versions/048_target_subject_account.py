"""Record the account a Windows security event is about.

Reported as: the alert "EXPDC402 - User account locked out" names the locked
account, the case shows no account at all.

A Sysmon alert names one principal — `User: INT\\echelarasu` — and that is the
one that ran the command. A Windows security event names two, and which one
matters depends on the event:

    Event ID: 4740  (a user account was locked out)
      data.win.eventdata.subjectUserName: EXPDC402$   <- the domain controller,
                                                         which performed it
      data.win.eventdata.targetUserName:  gmaciuc     <- the person it happened
                                                         to

Neither field was tried. 513 stored alerts name an account this way and carry
none, so a case titled "User account locked out" could not say who.

Taking the target always would be wrong too. Across those alerts the target is
a machine account 204 times and the subject is one 300 times, so neither field
is reliably the person: the rule is to prefer whichever names one. A machine
account is still recorded when it is all there is — "the domain controller did
this" is worth knowing — and is separately barred from linking cases together.

Measured over all 15,058 stored bodies before running: 517 gain an account,
9 change, **none lose one**, and 62 distinct real people are named who were
not named before.

Revision ID: 048
Revises: 047
"""

import re

from alembic import op
import sqlalchemy as sa

revision = "048"
down_revision = "047"
branch_labels = None
depends_on = None

# Self-contained, as every backfill here is: a migration has to produce the
# same result in five years against whatever the extractor has become.
_TARGET = re.compile(r"targetUserName[ \t]*[:=][ \t]*\"?([^\s\n\",]{1,120})", re.IGNORECASE)
_SUBJECT = re.compile(r"subjectUserName[ \t]*[:=][ \t]*\"?([^\s\n\",]{1,120})", re.IGNORECASE)

_MACHINE = frozenset({
    "system", "local system", "localsystem", "local service", "localservice",
    "network service", "networkservice", "anonymous", "anonymous logon",
    "nt authority", "iusr", "iwam",
})
_NOT_AN_ACCOUNT = frozenset({"", "\\", "-", "n/a", "unknown", "null", "none"})


def _is_machine(value: str) -> bool:
    text = value.strip().casefold()
    account = text.rsplit("\\", 1)[-1].strip()
    if account in _MACHINE or text in _MACHINE:
        return True
    return account.endswith("$") or "$@" in account


def _clean(value: str | None) -> str | None:
    text = str(value or "").strip().strip('"').strip()
    while "\\\\" in text:
        text = text.replace("\\\\", "\\")
    text = text.strip().rstrip(",;:").strip()
    if text.casefold() in _NOT_AN_ACCOUNT:
        return None
    if text.endswith("\\") or not text.replace("\\", "").strip():
        return None
    return text[:255]


def _account_in(body: str) -> str | None:
    """Target first, then subject, preferring whichever names a person."""
    found = []
    for pattern in (_TARGET, _SUBJECT):
        match = pattern.search(body or "")
        cleaned = _clean(match.group(1)) if match else None
        if cleaned:
            found.append(cleaned)
    if not found:
        return None
    return next((f for f in found if not _is_machine(f)), found[0])


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT id, alert_body FROM alert_body_investigation_runs
            WHERE alert_body IS NOT NULL
              AND (entity_user IS NULL OR entity_user = '')
              AND alert_body ~* '(target|subject)UserName[ \t]*[:=][ \t]*[^[:space:]]'
            """
        )
    ).fetchall()
    for run_id, body in rows:
        account = _account_in(body)
        if not account:
            continue
        bind.execute(
            sa.text(
                "UPDATE alert_body_investigation_runs SET entity_user = :u WHERE id = :id"
            ),
            {"u": account, "id": run_id},
        )


def downgrade() -> None:
    # Only ever filled a column that was empty; emptying it again would lose
    # accounts the other backfills put there too.
    pass
