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

from app.services.absence import UNRATED, Absent, absent

#: Wazuh's rule levels run 1-16 inclusive. 0 is not a level the agent emits.
WAZUH_MAX_LEVEL = 16

#: FortiOS syslog severity, lowest number most severe. From Fortinet's own
#: documented set; the two that actually occur in this estate are `notice`
#: (2,527 alerts) and `alert` (6).
_FORTIOS_LEVELS = {
    "emergency": 0, "alert": 1, "critical": 2, "error": 3,
    "warning": 4, "notification": 5, "notice": 5, "information": 6,
    "informational": 6, "debug": 7,
}
_FORTIOS_MAX = 7

#: FortiGuard IPS severity, where the firewall has actually classified an
#: attack. More specific than the syslog level, so preferred when present.
_FORTIOS_IPS = {"critical": 100, "high": 86, "medium": 57, "low": 29, "info": 14}

#: Sources whose Wazuh level is a per-decoder constant and so cannot order
#: anything within themselves. Recorded here so a caller can say why a ranking
#: inside one of these sources is arbitrary, rather than presenting it as
#: meaningful.
#:
#: `fortigate-firewall-v5` is no longer in this set: Wazuh flattens every one
#: of its alerts to `rule.level = 1`, but FortiOS states its own severity in
#: `data.level`, and reading that instead gives the source a real signal. The
#: bug this fixes is live — every Fortigate alert normalised to 6/100 and the
#: 300-alert bound therefore ranked all 2,533 of them as uniformly trivial.
FLAT_SEVERITY_SOURCES = {
    "appsec-agent": "Wazuh assigns level 2 to all 2,685 of its alerts",
}


def _scaled(level: int, maximum: int) -> int:
    """An ordinal severity onto 1-100, lowest number most severe.

    Never 0. A severity of 0 would be indistinguishable from an absent one,
    which is the error this whole module exists to undo.
    """
    return max(1, round((maximum - level) / maximum * 100))


def _fortios_signals(fields: dict[str, Any]) -> list[tuple[int, str]]:
    """Every severity FortiOS states about one event, with its own wording."""
    found: list[tuple[int, str]] = []
    ips = str(fields.get("data.crlevel") or "").strip().lower()
    if ips in _FORTIOS_IPS:
        found.append((_FORTIOS_IPS[ips], f"crlevel={ips}"))
    native = str(fields.get("data.level") or "").strip().lower()
    if native in _FORTIOS_LEVELS:
        found.append(
            (_scaled(_FORTIOS_LEVELS[native], _FORTIOS_MAX), f"data.level={native}")
        )
    return found


def _loudest_of(signals: list[tuple[int, str]]) -> tuple[int, str] | None:
    """LOUDEST WINS: when one source grades an event more than once, take the
    most severe grading and keep every grading in the raw value.

    A named rule rather than inline logic, because the next source with two
    severity fields will face the same question and should not have to
    rediscover the answer.

    The rule exists because the obvious alternative is wrong. Preferring the
    *more specific* signal let `crlevel=low` (29) override `data.level=alert`
    (86) and under-rank an event the firewall itself had shouted about. Neither
    field subsumes the other — `crlevel` grades the attack signature,
    `data.level` grades the log record — so the only defensible resolution is
    to take the louder and show both, because a source disagreeing with itself
    is something an analyst should see rather than something to average away.
    """
    if not signals:
        return None
    score, raw = max(signals, key=lambda pair: pair[0])
    others = ", ".join(r for _s, r in signals if r != raw)
    return score, raw + (f" (also {others})" if others else "")


def normalise(fields: dict[str, Any]) -> tuple[int | None, str | None]:
    """The alert's native severity as (1-100, raw value).

    Returns (None, None) when the source states no severity. Never 0 for an
    absent value — `severity_absence` turns that into a reason.

    Order of preference, most specific first. Each is the source's own
    statement about its own event; none is inferred:

      FortiGuard IPS severity   `data.crlevel`   critical/high/medium/low/info
      FortiOS syslog severity   `data.level`     emergency..debug, 8 levels
      Wazuh rule level          `rule.level`     1-16
    """
    native = _loudest_of(_fortios_signals(fields))
    if native is not None:
        return native

    raw = fields.get("rule.level")
    if raw is None:
        return None, None
    # The text form joins aggregated values with " | ": `Rule level: 15 | 3`.
    first = str(raw).split("|")[0].strip()
    try:
        wazuh = int(first)
    except ValueError:
        return None, None
    if wazuh <= 0 or wazuh > WAZUH_MAX_LEVEL:
        # Outside the documented range, so this is not a Wazuh level and
        # guessing its scale would be inventing severity.
        return None, f"rule.level={first}"
    return max(1, round(wazuh / WAZUH_MAX_LEVEL * 100)), f"rule.level={wazuh}/16"


def severity_absence(source_type: str | None) -> Absent:
    """Why this alert has no severity, for the places that must say so.

    892 of 15,255 alerts are in this position — measured on
    `alert_body_investigation_runs.source_severity` after the backfill, which
    is the right table because it is the one the graph and the bounded read
    both consume.
    """
    name = str(source_type or "an unrecognised source")
    return absent(
        UNRATED,
        (
            f"{name} states no severity this platform knows how to read, so "
            "this alert has no severity rather than a low one. Nothing was "
            "assessed."
        ),
        raw=name,
    )


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
