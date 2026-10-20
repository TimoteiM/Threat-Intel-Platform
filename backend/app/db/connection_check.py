"""Every database connection this application can open, and who it opens as.

Three times now a connection has been wrong in the same way, and each time the
mechanism was a **variable that was not set**:

* `DATABASE_SYNC_URL` pointed at the owning superuser on the host while the
  containers used `tip_app`, so row-level security — which exempts an owner —
  protected the containers and nothing run from a laptop;
* `DATABASE_MIGRATION_URL` did not exist in `.env` at all and fell back to a
  default that happened to work, which is worse than one that does not;
* `DATABASE_SANITIZER_URL` was missed when the other three were set, so
  host-side code fell back to a default password and could not open the token
  map at all.

A default is what makes this class of fault quiet. The application starts, the
connection works, and it is the wrong principal — so **presence is checked
separately from role**, because a variable that is absent and a variable that
is wrong need different fixes and only one of them is visible from the
database.

**The set is derived, not listed.** `Settings` is asked which
`database_*_url` fields exist, and a field with no entry in `CONNECTION_ROLES`
is a failure rather than something unchecked. Adding a fourth connection
without saying who it connects as fails this check — which is the point, and
is what a hand-maintained list would not do.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

#: field name -> the role it must resolve to.
#:
#: Reviewed with the code that adds a connection, because that is when
#: somebody knows the answer. See scripts/db_roles.sql for what each may do.
CONNECTION_ROLES: dict[str, str] = {
    "database_url": "tip_app",
    "database_sync_url": "tip_app",
    "database_sanitizer_url": "tip_sanitizer",
    "database_migration_url": "threatintel",
}

#: Which settings fields are database connections at all.
_FIELD_RE = re.compile(r"^database(_\w+)?_url$")


@dataclass(frozen=True)
class Problem:
    field: str
    kind: str          # undeclared | absent | unreachable | wrong_role
    detail: str

    def __str__(self) -> str:
        return f"{self.field}: {self.kind} — {self.detail}"


def declared_connections() -> set[str]:
    """The `database_*_url` fields `Settings` actually has."""
    from app.config import Settings

    return {name for name in Settings.model_fields if _FIELD_RE.match(name)}


def env_name(field: str) -> str:
    """The environment variable a field reads.

    Pydantic upper-cases the field name unless an alias says otherwise, and
    an alias is honoured here rather than assumed away — a check that looked
    for the wrong variable would report every connection absent.
    """
    from app.config import Settings

    info = Settings.model_fields.get(field)
    alias = getattr(info, "validation_alias", None) if info else None
    choices = getattr(alias, "choices", None)
    if choices:
        for choice in choices:
            if isinstance(choice, str):
                return choice
    if isinstance(alias, str):
        return alias
    return field.upper()


def _as_sync(url: str) -> str:
    """The same credentials over a synchronous driver.

    The role is a property of the credentials, not of the driver, so the
    async connection is checked by opening it with psycopg2. Running an event
    loop inside a liveness probe to learn a username would be a lot of
    machinery for the same answer.
    """
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    if parsed.drivername in ("postgresql+asyncpg", "postgresql"):
        parsed = parsed.set(drivername="postgresql+psycopg2")
    return parsed.render_as_string(hide_password=False)


def check() -> list[Problem]:
    """Every connection: declared, present, reachable, and the right role."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import NullPool

    from app.config import get_settings

    problems: list[Problem] = []
    fields = declared_connections()

    # A connection nobody has said anything about. Checked first, because an
    # unreviewed connection is the fault this whole module exists to make
    # loud rather than something to skip over.
    for field in sorted(fields - set(CONNECTION_ROLES)):
        problems.append(Problem(
            field, "undeclared",
            "this connection has no entry in CONNECTION_ROLES, so nothing "
            "says which role it should open as and nothing is checking it",
        ))
    for field in sorted(set(CONNECTION_ROLES) - fields):
        problems.append(Problem(
            field, "undeclared",
            "CONNECTION_ROLES names a setting that no longer exists",
        ))

    settings = get_settings()
    for field in sorted(fields & set(CONNECTION_ROLES)):
        variable = env_name(field)
        if not (os.environ.get(variable) or "").strip():
            # The quiet one. The application will start, the default will
            # work or half-work, and the principal will be wrong.
            problems.append(Problem(
                field, "absent",
                f"{variable} is not set, so the default in Settings is in "
                f"use — which is how this went wrong three times",
            ))
            continue

        url = str(getattr(settings, field, "") or "")
        expected = CONNECTION_ROLES[field]
        try:
            engine = create_engine(_as_sync(url), poolclass=NullPool)
            with engine.connect() as conn:
                actual = conn.execute(text("SELECT current_user")).scalar()
            engine.dispose()
        except Exception as exc:  # noqa: BLE001
            problems.append(Problem(
                field, "unreachable",
                f"could not connect ({type(exc).__name__}) — not checked, "
                f"which is not the same as correct",
            ))
            continue
        if actual != expected:
            problems.append(Problem(
                field, "wrong_role",
                f"resolves to {actual!r}, expected {expected!r}",
            ))
    return problems


def summary() -> str:
    """One line per problem, or a line saying there are none."""
    problems = check()
    if not problems:
        return (
            f"{len(CONNECTION_ROLES)} database connection(s) present and "
            f"resolving to the declared role"
        )
    return "\n".join(str(p) for p in problems)
