"""What Falcon knows about one host, for the alert surface.

An alert names a host. That is the key Falcon's device endpoint actually
takes, it is the one field the Devices API *validates*, and on this estate
160 of 179 Wazuh agent names resolve to a Falcon hostname on a plain
case-insensitive compare (measured 2026-10-15, 0 needing suffix
normalisation). Email has no host, and every Falcon question an email's
indicators could ask is either a 403 or a field that does not exist — so this
is where Falcon becomes visible.

Two sections, and they fail differently
---------------------------------------
**A, coverage.** Is there a sensor on this host? `/devices/queries/devices/v1`
on `hostname`. An invented field name here returns *400 Invalid filter
expression*, so an empty result is a real negative: Falcon has no sensor on
this host. That is a finding, not an empty panel.

**B, detections.** `/alerts/queries/alerts/v2` on `device.hostname`. The
Alerts API does **not** validate field names — it answers 200 with zero
resources — so an empty result here is only a negative once the standing
field control has passed. Until then it is `check_failed`.

The number that must not be the headline
----------------------------------------
`EXP-22MY264` returned **1,432** alert rows in 30 days. That is 546
`aggregate_id`s, **12** distinct (name, filename) pairs, 996 of 1,000 sampled
already closed, and 936 rows of one developer running `wsl.exe`. "1,432
detections" reads as a compromised machine; the truth is a handful of events,
mostly triaged, with 56 rows where prevention actually blocked a process.

So the headline is **distinct open detections**, grouped by name, and the raw
row count lives behind the collapse where it cannot be mistaken for severity.
A count of raw rows is a ranking number, and this platform has already shipped
one of those as a verdict once.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.services import absence

#: How far back detections are fetched. 30 days because that is the window an
#: analyst reading today's alert asks about; longer makes the open/closed
#: ratio meaningless and costs a page of results.
DETECTION_DAYS = 30

#: Rows pulled per host before grouping. The grouping is what the panel
#: shows, so this bounds cost rather than content — but when it bites the
#: response says so, because a silently truncated group count would read as
#: the whole picture.
DETECTION_ROW_CAP = 500

#: A sensor that has not reported is not a sensor that saw nothing. Measured
#: distribution over 182 devices: 153 within a day, 10 within a week, 10
#: within a month, 9 beyond 31 days. So "stale" starts at a week — inside
#: that, silence is ordinary.
STALE_AFTER_DAYS = 7

#: Statuses that mean a human has already dealt with it. Everything else is
#: open and belongs in the headline.
CLOSED_STATUSES = frozenset({"closed", "reopened_closed", "false_positive"})

#: Device-record fields the panel shows. Named rather than passing the whole
#: 62-field record through: a device record carries serial numbers, MAC
#: addresses, external IPs and the last login user, none of which this panel
#: needs and all of which would then be in an API response.
DEVICE_FIELDS = (
    "hostname", "platform_name", "os_version", "os_build", "agent_version",
    "status", "reduced_functionality_mode", "first_seen", "last_seen",
    "product_type_desc", "site_name", "machine_domain", "provision_status",
)


def _parse(stamp: Any) -> datetime | None:
    if not stamp:
        return None
    try:
        return datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None


def coverage(device: Any, *, hostname: str, now: datetime,
             superseded: Any = None) -> dict[str, Any]:
    """Section A. Is there a sensor on this host, and is it reporting?

    `superseded` lists retired enrolments for the same hostname. 5 of 175
    hostnames have them (measured 2026-10-15): a sensor re-install mints a new
    device id, so the hostname matches two or three records whose lifetimes
    abut. The live one is already chosen upstream by newest `last_seen`; this
    reports the rest, because a host whose `first_seen` is three weeks ago on a
    two-year-old machine otherwise reads as a brand-new asset.
    """
    if device is None:
        return {
            "managed": False,
            "hostname": hostname,
            # A real negative, and the reason it can be stated as one: the
            # Devices API rejects an unknown field with 400, so this empty
            # result cannot be a typo. Contrast section B.
            "basis": (
                "Falcon's device search returned no match for this hostname. "
                "The Devices API rejects unknown field names with HTTP 400, "
                "so this is a real negative rather than a possible typo."
            ),
            "finding": (
                f"No CrowdStrike sensor is installed on {hostname}, or it is "
                f"registered under a different name. This host is generating "
                f"alerts with no EDR coverage."
            ),
        }

    out: dict[str, Any] = {"managed": True, "hostname": hostname}
    for field in DEVICE_FIELDS:
        if field in device:
            out[field] = device.get(field)

    policies = device.get("device_policies") or {}
    prevention = policies.get("prevention") if isinstance(policies, dict) else None
    out["prevention_applied"] = (
        (prevention or {}).get("applied") if isinstance(prevention, dict) else None
    )

    last_seen = _parse(device.get("last_seen"))
    if last_seen is None:
        out["reporting"] = absence.absent(
            absence.CHECK_FAILED,
            "Falcon returned no last_seen for this device, so whether the "
            "sensor is still reporting is unknown.",
        ).as_json()
    else:
        quiet_hours = (now - last_seen).total_seconds() / 3600.0
        stale = quiet_hours > STALE_AFTER_DAYS * 24
        out["last_seen_hours_ago"] = round(quiet_hours, 1)
        out["sensor_stale"] = stale
        out["reporting"] = (
            f"Sensor last reported {round(quiet_hours, 1)}h ago."
            + (f" That is beyond {STALE_AFTER_DAYS} days: a sensor that has "
               f"not reported is not a sensor that saw nothing, so the "
               f"detections below may be incomplete." if stale else "")
        )
    # Reduced functionality mode is a sensor that is installed and not fully
    # protecting. Surfaced as its own flag because "managed: true" hides it.
    rfm = str(device.get("reduced_functionality_mode") or "").strip().lower()
    out["degraded"] = rfm not in ("", "no", "none", "false")
    retired = list(superseded or [])
    if retired:
        out["re_enrolled"] = True
        out["superseded_enrolments"] = retired
        out["re_enrolled_note"] = (
            f"This hostname has {len(retired)} earlier Falcon enrolment(s); "
            f"the sensor was reinstalled or the machine re-imaged. The record "
            f"shown is the one reporting most recently, so `first_seen` dates "
            f"the current enrolment and not the asset."
        )
    return out


def group_detections(records: Any, *, truncated_at: int | None = None) -> dict[str, Any]:
    """Section B. Distinct open detections, grouped — never a raw row count.

    Grouped on (name, filename) because that is what a reader recognises as
    "the same thing happening again": 1,432 rows collapsed to 12 pairs on the
    measured host, and 936 of those rows were one `wsl.exe`.

    `aggregate_id` is kept as a second count because it is Falcon's own idea
    of one event and sits between the two — 546 on that host. Reported beside
    the group count rather than instead of it, since neither is wrong and the
    gap between them is itself informative.
    """
    rows = [r for r in (records or []) if isinstance(r, dict)]
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    aggregates: set[str] = set()

    for record in rows:
        name = str(record.get("name") or record.get("display_name") or "unnamed")
        filename = str(record.get("filename") or "")
        status = str(record.get("status") or "").strip().lower()
        agg = record.get("aggregate_id")
        if agg:
            aggregates.add(str(agg))
        key = (name, filename)
        group = groups.setdefault(key, {
            "name": name,
            "filename": filename or None,
            "rows": 0,
            "open_rows": 0,
            "tactic": record.get("tactic"),
            "technique": record.get("technique"),
            "severity_dispositions": set(),
            "users": set(),
            "latest": None,
            "statuses": set(),
            "prevented": False,
        })
        group["rows"] += 1
        group["statuses"].add(status or "unknown")
        if status not in CLOSED_STATUSES:
            group["open_rows"] += 1
        disposition = record.get("pattern_disposition_description")
        if disposition:
            group["severity_dispositions"].add(str(disposition))
            if "prevent" in str(disposition).lower() or "block" in str(disposition).lower():
                group["prevented"] = True
        if record.get("user_name"):
            group["users"].add(str(record["user_name"]))
        stamp = _parse(record.get("created_timestamp") or record.get("timestamp"))
        if stamp and (group["latest"] is None or stamp > group["latest"]):
            group["latest"] = stamp

    out = []
    for group in groups.values():
        out.append({
            "name": group["name"],
            "filename": group["filename"],
            "tactic": group["tactic"],
            "technique": group["technique"],
            "rows": group["rows"],
            "open_rows": group["open_rows"],
            "open": group["open_rows"] > 0,
            "prevented": group["prevented"],
            "dispositions": sorted(group["severity_dispositions"]),
            "users": sorted(group["users"]),
            "statuses": sorted(group["statuses"]),
            "latest": group["latest"].isoformat() if group["latest"] else None,
        })
    # Open first, then most recent. An analyst reads the top of this list and
    # nothing else, so the ordering is the product.
    out.sort(key=lambda g: (not g["open"], g["latest"] or ""), reverse=False)
    out.sort(key=lambda g: (g["open"], g["latest"] or ""), reverse=True)

    open_groups = [g for g in out if g["open"]]
    # A count derived from a truncated fetch is a LOWER BOUND, not a count.
    # Caught live on 2026-10-15: EXP-22MY264 hit the 500-row cap and the panel
    # reported "9 distinct" as a fact. Grouping makes this easy to miss —
    # the collapse from 500 rows to 9 groups looks like the whole picture
    # precisely because the number got small.
    bounded = truncated_at is not None
    return {
        # THE headline. Distinct and open.
        "open_detection_count": len(open_groups),
        "distinct_detection_count": len(out),
        # Whether those two are exact or floors, as a field rather than a
        # sentence, so a renderer cannot show the number without the caveat.
        "counts_are_lower_bounds": bounded,
        "counts_basis": (
            f"At least {len(open_groups)} open of at least {len(out)} distinct: "
            f"the newest {truncated_at} alert rows were fetched and older rows "
            f"in the window were not read, so a detection kind that only "
            f"occurs further back is not counted here."
            if bounded else
            f"Exact: every alert row in the window was read and grouped."
        ),
        "groups": out,
        # Behind the collapse, explicitly labelled, so it cannot be read as
        # severity. See the module docstring.
        "raw": {
            "rows": len(rows),
            "aggregate_ids": len(aggregates),
            "note": (
                f"{len(rows)} raw alert rows collapse to {len(out)} distinct "
                f"detections ({len(aggregates)} of Falcon's own aggregates). "
                f"The row count is repetition, not severity — one process run "
                f"repeatedly produces hundreds of rows."
            ),
            "truncated_at": truncated_at,
        },
    }


def unjoinable(reason: str, *, hostname: str | None = None) -> dict[str, Any]:
    """A host that cannot be looked up at all — not one Falcon does not manage.

    7 of 182 Falcon device records carry no hostname, so they can be joined to
    nothing. Rendering those as "unmanaged" would be an absence of a join key
    reported as an absence of coverage, and they are opposite findings: one is
    a missing sensor, the other is a sensor we cannot match.
    """
    return absence.absent(
        absence.CHECK_FAILED,
        f"This host cannot be matched against Falcon: {reason} That is a "
        f"missing join key and NOT a report that Falcon has no sensor on it — "
        f"the two are opposite findings and must not render alike.",
        raw=hostname,
    ).as_json() | {"cannot_join": True}


def panel(
    *,
    hostname: str | None,
    device: Any,
    detections: Any,
    control: Any,
    now: datetime | None = None,
    truncated_at: int | None = None,
    superseded: Any = None,
) -> dict[str, Any]:
    """Both sections, each carrying its own basis or its own absence.

    `control` is the result of `falcon_client.alerts_field_control` for
    `device.hostname`. Section B's negative is withheld unless it passed —
    which is the entire reason the control exists, since the Alerts API
    answers an unknown field with 200 and no rows.
    """
    at = now or datetime.now(timezone.utc)
    host = str(hostname or "").strip()
    if not host:
        return {
            "hostname": None,
            "coverage": unjoinable(
                "the alert names no host.", hostname=None),
            "detections": unjoinable(
                "the alert names no host.", hostname=None),
            "window_days": DETECTION_DAYS,
        }

    passed = bool((control or {}).get("passed"))
    if passed:
        detections_section: Any = group_detections(
            detections, truncated_at=truncated_at)
        detections_section["basis"] = (
            f"Searched `device.hostname` over {DETECTION_DAYS} days. The field "
            f"was confirmed filterable at "
            f"{(control or {}).get('checked_at')}, so an empty result here is "
            f"a real negative."
        )
    else:
        # Not an empty list. The Alerts API cannot distinguish "no detections"
        # from "a field name I am ignoring", so neither can this.
        detections_section = absence.absent(
            absence.CHECK_FAILED,
            f"Falcon's alert field could not be confirmed to filter, so no "
            f"detection search was run: "
            f"{(control or {}).get('reason') or 'the control did not report.'} "
            f"An empty result from an unconfirmed field reads as 'the EDR has "
            f"nothing', which is why it is withheld.",
        ).as_json()

    return {
        "hostname": host,
        "window_days": DETECTION_DAYS,
        "coverage": coverage(device, hostname=host, now=at,
                             superseded=superseded),
        "detections": detections_section,
        "field_control": {
            "passed": passed,
            "field": (control or {}).get("field"),
            "checked_at": (control or {}).get("checked_at"),
            "reason": (control or {}).get("reason"),
            # Shown, not hidden. Every negative in section B depends on it, so
            # it is not a debug detail.
            "why_it_matters": (
                "The Falcon Alerts API returns HTTP 200 with zero results for "
                "a field name that does not exist, so a negative is only "
                "meaningful while this control passes."
            ),
        },
    }
