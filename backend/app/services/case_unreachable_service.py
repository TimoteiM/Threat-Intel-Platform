"""Why a case key cannot be re-derived — the real reason, not the likely one.

A case page whose key no longer derives already says something rather than
rendering blank; that was fixed when a dead key returned a bare 404. But it
said the same thing in every case:

    "This case cannot be re-derived over the last 720 hours, so there is
     nothing to draw. Its alerts have either aged out of the window or been
     re-grouped under a different case."

For most of the estate's unreachable keys that sentence is false in both of its
halves. Measured on `alert_case_spine` — the right table because the key and
its components are what is stored there, and the question is why *this stored
key* cannot be recomputed:

    61 of 1,074 live cases do not derive at the endpoint's 720h default
     9 of those are explained by age
    54 cases are keyed on the retired composite host form
     0 alert runs still carry that host form
     0 of the 54 carry a supersession pointer
     6 of the 54 carry a close count; 48 carry neither

So for 51 of the 61 the alerts did not age out, nothing re-grouped them, and
no wider window will ever help: the key's host component is
`{host}\\x1f incident:{uuid}`, a form the extractor stopped producing, and
nothing in `alert_body_investigation_runs` carries it any more. Telling an
analyst to expect a redirect that does not exist, or to widen a window that
cannot work, is worse than saying nothing — it is a wrong explanation where a
right one is cheap.

Naming the reason rather than guessing it also keeps the two genuinely
different populations apart. A case whose alerts aged out of retention is a
normal end state. A case whose key format was retired is a migration that was
never finished, and it is the one that could still be repaired.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

#: The separator the old key format put between a host and the incident id it
#: was scoped to. A key carrying it cannot be recomputed from today's alerts,
#: because `entity_host` is no longer written in that shape.
COMPOSITE_SEPARATOR = "\x1f"

#: Reasons, each a distinct claim. None of them is "probably the window".
REGROUPED = "regrouped"                  # a supersession pointer exists
RETIRED_KEY_FORMAT = "retired_key_format"  # a key component is no longer written
AGED_OUT = "aged_out"                    # its alerts are older than the window
NO_ALERTS_REMAIN = "no_alerts_remain"    # nothing on its triple is stored now
UNDETERMINED = "undetermined"            # measured, and still not explained

_RUNS_ON_TRIPLE = """
select count(*) as runs,
       max(coalesce(event_time, created_at)) as newest
from alert_body_investigation_runs
where alert_source = :source
  and coalesce(alert_client, '') = coalesce(:client, '')
  and entity_host = :host
"""


@dataclass(frozen=True)
class Unreachable:
    reason: str
    note: str
    #: True when no window, however wide, can recover this key. The page must
    #: not invite the analyst to retry with more hours in that case.
    window_cannot_help: bool
    detail: dict[str, Any]

    def as_json(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "note": self.note,
            "window_cannot_help": self.window_cannot_help,
            "detail": self.detail,
        }


async def why_unreachable(
    db: AsyncSession,
    *,
    spine: Any,
    hours: int,
    pointer: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> Unreachable:
    """The reason this stored key does not re-derive, measured not guessed.

    `pointer` is the supersession lookup the caller has already done, passed in
    so this does not repeat it.
    """
    now = now or datetime.now(timezone.utc)

    if pointer and pointer.get("state") not in (None, "live"):
        return Unreachable(
            reason=REGROUPED,
            note=(
                pointer.get("note")
                or "This case was re-grouped under another key, which is where "
                "its alerts now live."
            ),
            window_cannot_help=True,
            detail={"state": pointer.get("state")},
        )

    host = getattr(spine, "entity_host", None) or ""
    if COMPOSITE_SEPARATOR in host:
        label, _, scoped = host.partition(COMPOSITE_SEPARATOR)
        return Unreachable(
            reason=RETIRED_KEY_FORMAT,
            note=(
                "This case cannot be re-derived at all, and widening the "
                "window will not change that. Its key was built from a host "
                f"written as {label!r} scoped to one incident "
                f"({scoped[:40]!r}), a form this platform stopped producing, "
                "and no stored alert carries it any more. The case record "
                "below is what remains of it; its alerts are still stored, "
                "but they now group under a different key that this one "
                "cannot be matched to."
            ),
            window_cannot_help=True,
            detail={"host_label": label, "scoped_to": scoped[:80]},
        )

    source = getattr(spine, "alert_source", None)
    client = getattr(spine, "alert_client", None)
    row = None
    if source and host:
        row = (
            await db.execute(
                text(_RUNS_ON_TRIPLE),
                {"source": source, "client": client, "host": host},
            )
        ).first()
    runs = int((row.runs if row else 0) or 0)

    if runs == 0:
        return Unreachable(
            reason=NO_ALERTS_REMAIN,
            note=(
                "No alerts are stored for this case's source, client and host "
                "any more, so there is nothing left to re-derive it from. A "
                "wider window will not help."
            ),
            window_cannot_help=True,
            detail={"runs_on_triple": 0},
        )

    opened = getattr(spine, "opened_at", None)
    if opened is not None:
        if opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        if now - opened > timedelta(hours=hours):
            age = (now - opened).total_seconds() / 3600.0
            return Unreachable(
                reason=AGED_OUT,
                note=(
                    f"This case opened {age / 24:.0f} days ago, beyond the "
                    f"{hours}-hour window this page used, so its alerts are "
                    "outside it. The window normally stretches to reach a "
                    "case's own opening; if it did not here, the case's stored "
                    "opening time is the thing to check."
                ),
                window_cannot_help=False,
                detail={"opened_hours_ago": round(age, 1), "runs_on_triple": runs},
            )

    return Unreachable(
        reason=UNDETERMINED,
        note=(
            f"This case does not re-derive, and the reason is not its age, a "
            f"re-grouping, or a retired key format: {runs} alerts are still "
            "stored on its source, client and host. Something about the key's "
            "other components no longer matches, and that has not been "
            "diagnosed."
        ),
        window_cannot_help=False,
        detail={"runs_on_triple": runs, "newest_alert": (
            row.newest.isoformat() if row is not None and row.newest else None
        )},
    )
