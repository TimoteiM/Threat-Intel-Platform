"""Who caused this, as the attribution pair — one implementation.

`docs/design/submitter-attribution.md` sets the shape: a `kind` plus an
optional user id, plus the string that was recorded when it cannot be
resolved. A single name, or a `NULL`, collapses four conditions that mean
different things to someone reading an investigation.

**One implementation, because there are already three call sites.** The
indicator lookup had its own copy of this logic; the email upload needs it;
the investigation record consumes it. A second copy kept in agreement by
discipline is the shape that produced the weaker of two actor columns on the
same day the stronger one was specified.

The actor is never taken from a parameter. An actor a caller can set is not
an actor.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.models.database import (
    ACTOR_AUTOMATED_INGEST,
    ACTOR_HUMAN,
    ACTOR_RECORDED_UNRESOLVABLE,
)

#: The identity fields to read, in order. `username` first because it is what
#: resolves against `users`; `label` is an API key's principal; `kind` is the
#: last resort and names a class of caller rather than one.
_IDENTITY_FIELDS = ("username", "label", "kind")


def recorded_name(request: Any) -> str | None:
    """The name on the request, or None. No database access."""
    identity = getattr(getattr(request, "state", None), "identity", None) or {}
    for field in _IDENTITY_FIELDS:
        value = str(identity.get(field) or "").strip()
        if value:
            return value[:255]
    return None


def unresolved(request: Any) -> dict[str, Any]:
    """The pair without resolving against `users`, for a sync call site.

    A name that is present but unresolved is `recorded_unresolvable`, which is
    honest: an actor *was* recorded and has not been matched. It can be
    promoted later by the same rule migration 066 uses — resolve, promote
    only, never demote.
    """
    name = recorded_name(request)
    if not name:
        return {"actor_kind": ACTOR_AUTOMATED_INGEST, "actor_user_id": None,
                "actor_recorded": None}
    return {"actor_kind": ACTOR_RECORDED_UNRESOLVABLE, "actor_user_id": None,
            "actor_recorded": name}


async def resolve(request: Any, db: Any) -> dict[str, Any]:
    """The pair, resolved against `users` where it can be.

    No name at all is `automated_ingest` — there was no human actor, which is
    a different claim from one having been recorded and lost.
    """
    from app.models.database import User

    name = recorded_name(request)
    if not name:
        return {"actor_kind": ACTOR_AUTOMATED_INGEST, "actor_user_id": None,
                "actor_recorded": None}
    try:
        user_id = (await db.execute(
            select(User.id).where(User.username == name)
        )).scalars().first()
    except Exception:  # noqa: BLE001
        user_id = None
    if user_id is not None:
        return {"actor_kind": ACTOR_HUMAN, "actor_user_id": user_id,
                "actor_recorded": name}
    return {"actor_kind": ACTOR_RECORDED_UNRESOLVABLE, "actor_user_id": None,
            "actor_recorded": name}
