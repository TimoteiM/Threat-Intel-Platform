"""The gathering record, in the shape the analysis stage already consumes.

The pipeline reads a `log_context` dict — status, reason, window, selectors,
sources, logs — builds a digest from it and hands that to the model. So the
record is **projected into that shape** rather than given a path of its own:
a second way into the analysis stage is a second thing to keep in step, and
this codebase has eight registries that prove how that ends.

Everything here is tokenised, because the record is. The model reads
`[HOST_a3f9c1_1]`, the same as it reads an alert's own fields today.

**Three things a reader cannot infer, so the projection carries them
explicitly:**

* **what came from the alert against what gathering added.** Every gathered
  event is stamped with its origin, because "the alert said this" and "we went
  and found this" are different kinds of claim and a flat list of events
  erases the difference.
* **which sources were read, and which could not be.** A source that returned
  `check_failed` appears in the projection **by name**. It is never silently
  absent, because an absent source reads as a source with nothing to say.
* **which queries the playbook ran against the one the agent chose, and why.**
  The agent's reason travels with its query.
"""

from __future__ import annotations

from typing import Any

#: Stamped onto each gathered event. Not a vendor field — this is the
#: platform's own record of where the event came from, and the report needs it
#: to tell "the alert said" from "we found".
PROVENANCE_FIELD = "gathered_by"


def to_log_context(record: Any) -> dict[str, Any]:
    """The record as a `log_context` dict.

    `status` follows the same vocabulary the pipeline already uses, and the
    distinctions in it are the ones that matter:

    * `collected` — at least one source answered with events;
    * `empty` — sources were read and held nothing. A real negative;
    * `partial` — some events, and at least one source that could not be read.
      The events are usable and the picture is incomplete, and both are true;
    * `unavailable` — nothing was gathered AND something could not be read.
      **Not `empty`**: "we could not look" and "we looked and there was
      nothing" are different answers, and merging them is the defect that had
      the DNS collector reporting an outage as "no DNS records" for 2,602
      runs.
    """
    outcomes = list(getattr(record, "outcomes", ()) or ())
    failed = [o for o in outcomes if o.status == "check_failed"]
    events = _with_provenance(record)

    if events and failed:
        status = "partial"
    elif events:
        status = "collected"
    elif failed:
        status = "unavailable"
    elif outcomes:
        status = "empty"
    else:
        status = "skipped"

    selectors = dict(getattr(record, "selectors", None) or _selectors(record))
    return {
        "status": status,
        "tenant_id": getattr(record, "tenant_id", None),
        "reason": _reason(status, record, failed),
        "log_count": len(events),
        "truncated": False,
        "window": {},
        "selectors": selectors,
        "sources": sources_block(record),
        "logs": events,
        # What the digest builder reads. Without `alert_time` it refuses with
        # `no_alert_time`, because it selects events by their distance from
        # the alert — a projection that omitted it produced a context the
        # analysis stage accepted and then declined to use.
        "alert_time": getattr(record, "alert_time", None),
        # Tokens, like everything else here. These are the pivots the
        # selection logic keys on, and it reads them as opaque strings.
        "entity_host": selectors.get("host"),
        "entity_user": selectors.get("user"),
    }


def _reason(status: str, record: Any, failed: list[Any]) -> str | None:
    """Why, when the status is not a plain success.

    A reason that names the sources rather than counting them. "2 sources
    failed" beside a verdict is how a number drifts upward with nobody
    noticing which ones.
    """
    if status == "collected":
        return None
    names = sorted({o.source for o in failed})
    if status == "unavailable":
        return (
            f"nothing could be gathered: {', '.join(names)} could not be read, "
            f"so what they hold about this alert is unknown rather than absent"
        )
    if status == "partial":
        return (
            f"gathered what {', '.join(sorted(_answering(record)))} held; "
            f"{', '.join(names)} could not be read, so this picture is "
            f"incomplete in a known way"
        )
    if status == "empty":
        return (
            "every source was read and none held anything matching — a real "
            "negative, not a failure to look"
        )
    return "no query was run for this alert"


def _answering(record: Any) -> set[str]:
    return {o.source for o in getattr(record, "outcomes", ()) if o.status == "collected"}


def _selectors(record: Any) -> dict[str, str]:
    """The join keys the stage pivoted on, as tokens."""
    out: dict[str, str] = {}
    for outcome in getattr(record, "outcomes", ()) or ():
        out.update(outcome.arguments)
    return out


def _with_provenance(record: Any) -> list[dict[str, Any]]:
    """Every gathered event, stamped with how it was found.

    The record holds events once, deduplicated, and holds outcomes that each
    know which events they produced. The stamp is taken from the FIRST
    outcome that returned an event, because that is the query that found it —
    a later query returning the same event did not discover it.
    """
    by_key: dict[str, dict[str, str]] = {}
    for outcome in getattr(record, "outcomes", ()) or ():
        for event in outcome.events:
            key = str(event.get("key") or "")
            if key and key not in by_key:
                by_key[key] = {
                    "origin": outcome.origin,
                    "template": outcome.template,
                    "source": outcome.source,
                    "purpose": outcome.purpose,
                }

    stamped: list[dict[str, Any]] = []
    for event in getattr(record, "events", ()) or ():
        copy = dict(event)
        found = by_key.get(str(event.get("key") or ""))
        if found:
            copy[PROVENANCE_FIELD] = dict(found)
        stamped.append(copy)
    return stamped


def sources_block(record: Any) -> dict[str, Any]:
    """What was asked of whom, with every failure named.

    This is the part a reader cannot reconstruct from the events: a source
    that could not be read contributes no events, and so is invisible in a
    list of events. It has to be stated.
    """
    answered: dict[str, dict[str, Any]] = {}
    unreadable: list[dict[str, Any]] = []

    for outcome in getattr(record, "outcomes", ()) or ():
        if outcome.status == "check_failed":
            unreadable.append({
                "source": outcome.source,
                "template": outcome.template,
                "asked": outcome.purpose,
                "reason": outcome.reason,
                "absence": outcome.absence,
            })
            continue
        entry = answered.setdefault(outcome.source, {
            "queries": 0, "events": 0, "empty_queries": 0,
        })
        entry["queries"] += 1
        entry["events"] += outcome.kept
        if outcome.status == "empty":
            entry["empty_queries"] += 1

    playbook = [o for o in getattr(record, "outcomes", ()) if o.origin == "playbook"]
    agent = [o for o in getattr(record, "outcomes", ()) if o.origin == "agent"]

    return {
        "answered": answered,
        # Named, never counted. The whole point of this key is that an
        # unreadable source is in the report rather than missing from it.
        "unreadable": unreadable,
        "playbook_queries": [_query_json(o) for o in playbook],
        "agent_queries": [_query_json(o) for o in agent],
        "skipped": list(getattr(record, "skipped", ()) or ()),
        "notes": list(getattr(record, "notes", ()) or ()),
        "event_class": getattr(record, "event_class", "") or None,
    }


def _query_json(outcome: Any) -> dict[str, Any]:
    return {
        "template": outcome.template,
        "source": outcome.source,
        "asked": outcome.purpose,
        "status": outcome.status,
        "events_kept": outcome.kept,
        # For an agent query this is why it chose this one. For a playbook
        # query it is why the source answered as it did, or empty.
        "reason": outcome.reason or None,
        "arguments": dict(outcome.arguments),
    }
