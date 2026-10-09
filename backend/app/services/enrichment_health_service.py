"""A feed that has never once answered must not report a zero.

ThreatFox is the instance this generalises. `ip_lookups.result_json` records
`ThreatFox: HTTPError` on 800 of the 800 most recent rows, and
`threatfox_count` is 0 on all 6,259: the request sends an empty `API-KEY`
header and abuse.ch requires an Auth-Key. It failed at `debug` level for 6,259
consecutive lookups, and what surfaced was a zero — indistinguishable from
"checked, nothing found".

The specific fix was a `check_failed` absence at that call site. This is the
general one: any enrichment source whose recent calls contain no successes
reports `check_failed` rather than a count, and says so loudly enough to be
noticed. A dependency that has never worked is not a quiet signal; it is an
outage that happens to look like good news.

The asymmetry worth stating: a feed with *some* successes and a zero for this
indicator is a real negative result, and this must not overwrite it. Only a
feed with no successes at all across its recent window is reporting on its own
availability rather than on the indicator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from app.services.absence import CHECK_FAILED, Absent, absent

logger = logging.getLogger(__name__)

#: How many recent calls to judge a source on. Small enough to notice a new
#: outage, large enough that two timeouts in a row do not condemn a feed that
#: works: ThreatFox failed 800 consecutive times, so any window in this range
#: would have caught it on the first day.
WINDOW = 25

#: Below this many successes in the window, the source is reporting on itself.
#: Zero, deliberately — one success proves the integration works, and a feed
#: that answers sometimes is giving real negative results the rest of the time.
MIN_SUCCESSES = 1


@dataclass
class _Health:
    outcomes: list[bool] = field(default_factory=list)
    successes: int = 0
    failures: int = 0
    last_error: str | None = None
    first_seen: datetime | None = None
    alarmed: bool = False


_state: dict[str, _Health] = {}
_lock = Lock()


def record(source: str, *, ok: bool, error: str | None = None) -> None:
    """One call's outcome. Cheap enough to call on every lookup."""
    name = str(source or "unknown")
    with _lock:
        health = _state.setdefault(name, _Health())
        if health.first_seen is None:
            health.first_seen = datetime.now(timezone.utc)
        health.outcomes.append(bool(ok))
        if len(health.outcomes) > WINDOW:
            health.outcomes.pop(0)
        if ok:
            health.successes += 1
            if health.alarmed:
                logger.warning(
                    "enrichment_source_recovered source=%s after_failures=%d",
                    name, health.failures,
                )
                health.alarmed = False
        else:
            health.failures += 1
            health.last_error = error
            # Alarm once per outage, not once per call: 6,259 identical lines
            # is how the original failure stayed invisible.
            if (
                not health.alarmed
                and len(health.outcomes) >= WINDOW
                and sum(health.outcomes) < MIN_SUCCESSES
            ):
                health.alarmed = True
                logger.error(
                    "enrichment_source_never_succeeded source=%s window=%d "
                    "failures=%d last_error=%s — results from this source are "
                    "being reported as absent, not as zero",
                    name, WINDOW, health.failures, error,
                )


def is_unavailable(source: str) -> bool:
    """Whether this source's recent calls contain no successes at all."""
    with _lock:
        health = _state.get(str(source or ""))
        if health is None or len(health.outcomes) < WINDOW:
            return False
        return sum(health.outcomes) < MIN_SUCCESSES


def result_or_absence(source: str, value: Any) -> Any:
    """The value, or an absence when the source has never answered.

    Only substitutes for a *falsy* result. A source with no successes that
    somehow returned data is contradicting its own health record, and the data
    wins — the point of this module is to stop a zero being read as a finding,
    not to suppress findings.
    """
    if value or not is_unavailable(source):
        return value
    with _lock:
        health = _state.get(str(source or ""))
        last = health.last_error if health else None
    return absent(
        CHECK_FAILED,
        (
            f"{source} has not answered a single one of its last {WINDOW} "
            "calls, so this indicator was not checked against it. This is not "
            "a clean result — the source is unavailable."
        ),
        raw=last,
    ).as_json()


def snapshot() -> dict[str, dict[str, Any]]:
    """Per-source health, for a status page or a test."""
    with _lock:
        return {
            name: {
                "window": len(health.outcomes),
                "successes_in_window": sum(health.outcomes),
                "total_successes": health.successes,
                "total_failures": health.failures,
                "unavailable": (
                    len(health.outcomes) >= WINDOW
                    and sum(health.outcomes) < MIN_SUCCESSES
                ),
                "last_error": health.last_error,
            }
            for name, health in _state.items()
        }


def reset() -> None:
    """For tests only."""
    with _lock:
        _state.clear()
