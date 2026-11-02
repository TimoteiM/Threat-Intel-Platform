"""How far back an open case derives.

There is no fixed window that is right, and the distribution is the argument.
Measured over 1,014 derived cases, each span taken as max-min event_time over
that case's OWN members (the spine cannot answer this: `opened_at` was the
session origin, shared by 79.3% of rows with a sibling):

    0s, a single instant      68.4%   of all cases
    1-6 hours                 11.1%
    over 1 day                 0.7%
    p90 3.4h   p99 16.5h   max 2.0 days

    multi-alert cases only:   median 33 min, p90 8h, p99 28.5h

A one-hour window would cut off 42.2% of multi-alert cases mid-accretion; a
window wide enough for p99 is 24 hours, which is absurd for the 68.4% that
finish instantly. So an open case derives from its own first alert to now, and
the ceiling below exists only to stop a runaway.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

#: The runaway guard, not a belief about accretion. The widest case observed in
#: this estate spans 2.0 days, so this clears it with a day of margin.
OPEN_CASE_CEILING = timedelta(hours=72)


def window_for_open_case(
    first_alert_at: datetime | None,
    *,
    now: datetime | None = None,
    case_number: int | None = None,
) -> tuple[datetime, bool]:
    """(window start, whether the ceiling clipped it).

    A clip is reported, never absorbed. A case still accreting after three days
    is either a host-wide bucket — 24 cases hold 74.5% of all alert
    memberships — or a derivation defect, and both are things to look at
    rather than quietly truncate.
    """
    moment = now or datetime.now(timezone.utc)
    if first_alert_at is None:
        return moment - OPEN_CASE_CEILING, False
    start = (
        first_alert_at
        if first_alert_at.tzinfo
        else first_alert_at.replace(tzinfo=timezone.utc)
    )
    floor = moment - OPEN_CASE_CEILING
    if start >= floor:
        return start, False
    logger.warning(
        "open_case_window_clipped case=%s first_alert_at=%s age_hours=%.1f "
        "ceiling_hours=%d — a case still accreting past the ceiling is either a "
        "host-wide bucket or a derivation defect, not a long incident",
        case_number, start.isoformat(),
        (moment - start).total_seconds() / 3600.0,
        int(OPEN_CASE_CEILING.total_seconds() // 3600),
    )
    return floor, True
