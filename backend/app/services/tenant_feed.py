"""Does this tenant's feed send alerts, or incidents?

A **declaration**, read from `tenants.feed_kind`, not a guess made from the
payload. The distinction matters enough to state:

`is_pre_correlated` in `alert_field_service` asks whether a payload *looks*
pre-correlated — it needs `entity_type` and `event_count` in the extracted
fields. That is the right question for a sender that marks its own incidents,
and it is unanswerable for one that does not. Measured 2026-10-23 across all
111 `lin`/`pov`/`boc` runs: **both fields present on zero.** Those payloads
carry `event_name`, `service`, `user`, `agent`, `agent_ip`, `event_id` — no
count, no entity type, nothing incident-shaped at all.

So there is no better detector to write. The fact lives with whoever
configured the feed, and this module is where they record it.

**Why not key on `tenant_id` in a branch somewhere.** A hard-coded
`tenant_id in ("lin", "pov", "boc")` is a fact about today's configuration
compiled into code: a tenant that starts sending raw alerts, or a fourth
incident feed, becomes a deploy instead of an `UPDATE`. It is also exactly the
shape of the hand-maintained lists this codebase keeps finding, which fail
silently when someone forgets them.

The closed set is enforced by a CHECK constraint, so an unrecognised value is
refused by the database rather than defaulted to something plausible here.
"""

from __future__ import annotations

#: The complete set. Mirrors `ck_tenants_feed_kind` in migration 075.
ALERTS = "alerts"
INCIDENTS = "incidents"
FEED_KINDS = (ALERTS, INCIDENTS)

#: What a tenant with no row, or no answer, is treated as.
#:
#: `alerts` deliberately. An unclassified feed goes through correlation, which
#: is reversible and produces nothing new; treating it as incidents would mint
#: one case per row, and inventing cases for a feed nobody has classified is
#: the more expensive direction to be wrong in.
DEFAULT = ALERTS


class UnknownFeedKind(ValueError):
    """A value outside the closed set reached the application.

    Raised rather than coerced. The database refuses these, so seeing one here
    means something wrote around the constraint, and quietly reading it as
    `alerts` would hide that.
    """


def normalise(value: str | None) -> str:
    """The stored value, checked against the closed set.

    `None` and `""` are the default — a tenant row that predates the column.
    Anything else unrecognised raises: absent is not the same as wrong.
    """
    if value is None or not str(value).strip():
        return DEFAULT
    candidate = str(value).strip().lower()
    if candidate not in FEED_KINDS:
        raise UnknownFeedKind(
            f"{value!r} is not a feed kind; expected one of {FEED_KINDS}"
        )
    return candidate


def emits_incidents(value: str | None) -> bool:
    """True when every payload from this feed is already a case."""
    return normalise(value) == INCIDENTS


def describe(value: str | None) -> str:
    """One line for a human, so the two kinds are never summarised the same."""
    if emits_incidents(value):
        return ("this feed sends pre-correlated incidents — each payload is "
                "already a case, is never pooled with other alerts, and does "
                "not need an entity_host")
    return ("this feed sends single alerts, which are correlated into cases "
            "by host and session")
