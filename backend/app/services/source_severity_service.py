"""How severe an alert's own source says it is, on one scale.

This exists because the platform was using `highest_risk_score` as severity and
that is not what it measures. That column is the maximum, over an alert's
indicators, of a seven-component weighted sum; five of the seven components are
URL, email, attachment or sandbox signals. Measured by source:

    windows_eventchannel    9,062 runs   77.7% zero   mean  8.8
    fortigate-firewall-v5   2,533 runs    0.0% zero   mean 62.0
    appsec-agent            2,685 runs    0.4% zero   mean 57.5

It tracks whether an alert happens to carry an externally-resolvable
indicator, which is a property of the source rather than of severity. Case
#1440 — the richest true positive in the estate — has a median of 0 against
Wazuh levels of 6 to 13.

The normalisation, stated plainly
---------------------------------
One scale, 0-100, so sources with different native ranges can be ranked
together. Every mapping below is linear against the source's documented range,
with no judgement added:

    Wazuh `rule.level`      1-16    -> round(level / 16 * 100)

That covers 14,363 of 15,255 alerts (94.2%), and 100% of every
Wazuh-decoded source. The remainder are Palo Alto syslog arriving outside
Wazuh.

What this cannot do, said out loud
----------------------------------
Within two sources the native severity is a constant and therefore cannot
rank anything:

    fortigate-firewall-v5   rule.level = 1 on 2,527 of 2,533
    appsec-agent            rule.level = 2 on 2,685 of 2,685

Wazuh assigns those a fixed level per decoder. So this normalisation ranks
Windows telemetry against firewall traffic correctly — a level 15 Sysmon
detection above a level 1 traffic log — but gives no ordering *inside* those
two sources. Inventing one would mean inventing severity, so it does not.

And the fallback is not zero
----------------------------
An alert whose source states no severity gets NULL, never 0. The bug being
fixed here is precisely a blank encoded as a measurement: 7,260 of 15,255
runs read `highest_risk_score = 0` where the smallest real score is 5, so
nearly half the estate was being ranked as "least severe" when it had simply
never been scored. 892 alerts (5.8%) have no native severity, and they are
handled by `reserve_for_unrated` below rather than sorted to the bottom.
"""

from __future__ import annotations

from typing import Any

#: Wazuh's rule levels run 1-16 inclusive. 0 is not a level the agent emits.
WAZUH_MAX_LEVEL = 16

#: Sources whose Wazuh level is a per-decoder constant and so cannot order
#: anything within themselves. Recorded here so a caller can say why a ranking
#: inside one of these sources is arbitrary, rather than presenting it as
#: meaningful.
FLAT_SEVERITY_SOURCES = {
    "fortigate-firewall-v5": "Wazuh assigns level 1 to 2,527 of its 2,533 alerts",
    "appsec-agent": "Wazuh assigns level 2 to all 2,685 of its alerts",
}


def normalise(fields: dict[str, Any]) -> tuple[int | None, str | None]:
    """The alert's native severity as (0-100, raw value).

    Returns (None, None) when the source states no severity. Never 0 for an
    absent value.
    """
    raw = fields.get("rule.level")
    if raw is None:
        return None, None
    # The text form joins aggregated values with " | ": `Rule level: 15 | 3`.
    first = str(raw).split("|")[0].strip()
    try:
        level = int(first)
    except ValueError:
        return None, None
    if level <= 0 or level > WAZUH_MAX_LEVEL:
        # Outside the documented range, so this is not a Wazuh level and
        # guessing its scale would be inventing severity.
        return None, f"rule.level={first}"
    return round(level / WAZUH_MAX_LEVEL * 100), f"rule.level={level}/16"


def is_flat(source_type: str | None) -> str | None:
    """Why a ranking within this source means nothing, if it doesn't."""
    return FLAT_SEVERITY_SOURCES.get(str(source_type or ""))


def reserve_for_unrated(total: int, unrated: int, bound: int) -> int:
    """How many of a bounded read's slots to keep for unrated alerts.

    Sorting them last is the error this module exists to undo: an alert whose
    source states no severity is a gap in coverage, not a quiet alert, and
    excluding every one of them from a bounded graph would reproduce exactly
    the failure that made 47.6% of the estate rank as least severe.

    So they keep their share. If a fifth of a case's alerts are unrated, a
    fifth of the bound goes to them, newest first — enough that an unreadable
    source cannot vanish from a case it is half of.
    """
    if total <= 0 or unrated <= 0 or bound <= 0:
        return 0
    share = unrated / total
    return max(1, min(unrated, int(round(bound * share))))
