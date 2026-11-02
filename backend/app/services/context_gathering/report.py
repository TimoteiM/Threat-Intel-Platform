"""The analyst-facing report, detokenised once at the very end.

**The whole report is composed in tokens and detokenised in one call.** Not
per field, not per section, not as values are read out of the record — once,
on the finished text, immediately before it is handed to a reader. Every
intermediate string in this module contains `[HOST_a3f9c1_1]` and never a
hostname, so there is exactly one line in the codebase where a report's real
names come into existence and it is the last one.

That is what makes the claim checkable rather than aspirational: a test can
assert that the function building the text returns tokens, and that the one
that renders returns names.

`restore()` rather than `detokenize_query()`, deliberately. A query has to be
refused if a token will not resolve, because the alternative is running it
against a literal and getting a confident answer about the wrong estate. A
report has the opposite trade: a narrative with `[HOST_9]` standing in it is a
visible defect a reader can report, where a refused report is no report.

**Three things the report states because a reader cannot infer them:**

1. what the alert carried, against what gathering went and found;
2. which sources answered, and which **could not be read** — named, never
   left out, because a source that is absent from a report reads as a source
   with nothing to say;
3. which queries the playbook ran, against the one the agent chose and why.
"""

from __future__ import annotations

from typing import Any

from app.services.context_gathering.projection import PROVENANCE_FIELD


def render(*, record: Any, boundary: Any,
           analysis: dict[str, Any] | None = None) -> str:
    """The report, with real names. The only detokenising call in the stage."""
    return boundary.restore(compose(record=record, analysis=analysis))


def compose(*, record: Any, analysis: dict[str, Any] | None = None) -> str:
    """The report **in tokens**. Separate from `render` so it is testable.

    A test asserting "no real hostname reaches the model" has to be able to
    look at what the model was given. If composing and detokenising were one
    function there would be nothing to look at.
    """
    from app.services.context_gathering.projection import (
        sources_block, to_log_context,
    )

    context = to_log_context(record)
    sources = sources_block(record)
    lines: list[str] = []

    lines.append("CONTEXT GATHERING")
    lines.append("=" * 60)
    lines.append(f"Event class    : {sources['event_class'] or '(absent from the alert)'}")
    lines.append(f"Status         : {context['status']}")
    if context.get("reason"):
        lines.append(f"                 {context['reason']}")

    cost = record.as_json()["cost"] if hasattr(record, "as_json") else {}
    if cost:
        lines.append(
            f"Cost           : {cost['queries_run']} quer(ies) of a maximum "
            f"{cost['max_queries']}, {cost['elapsed_seconds']}s of "
            f"{cost['deadline_seconds']:.0f}s"
        )
        lines.append(f"Stopped because: {cost['stop_reason']}")

    # ── 1. what the alert carried, against what gathering added ──
    lines.append("")
    lines.append("WHAT THE ALERT CARRIED")
    lines.append("-" * 60)
    # The record's TOKENISED selectors, never the raw alert fields.
    #
    # The first version printed `alert_fields` straight through and put a
    # real hostname into the text the model reads — in the one section whose
    # job is to say what the alert carried. The alert's own values are no
    # less sensitive for having arrived with the alert.
    # **Provenance first, before any of the alert's own values.** 69 bodies
    # are a sender-declared reconstruction rather than a log line, and a
    # reader comparing gathered events against "what the alert carried" has
    # to know which of the two they are reading. The sender said so; we used
    # to drop it here.
    provenance = (record.as_json().get("body_provenance") or {}
                  if hasattr(record, "as_json") else {})
    if provenance.get("derived"):
        lines.append(
            f"  !! THE ALERT BODY IS NOT A VERBATIM LOG LINE. The sender "
            f"declared: \"{provenance.get('declaration')}\""
        )
        lines.append(
            "     The keys below are its reconstruction from event metadata, "
            "so treat them as the sender's reading rather than as observed "
            "values."
        )
        lines.append("")

    carried = dict(context.get("selectors") or {})
    if carried:
        for key in sorted(carried):
            lines.append(f"  {key:14s} {carried[key]}")
    else:
        lines.append("  (the alert carried no join key this stage can pivot on)")

    lines.append("")
    lines.append("WHAT GATHERING ADDED")
    lines.append("-" * 60)
    events = context["logs"]
    if not events:
        # The distinction this whole stage exists to keep: nothing found is
        # not the same as could not look, and the status above says which.
        lines.append(
            "  No events. See the sources below for whether that is because "
            "they held nothing or because they could not be read."
        )
    else:
        by_origin: dict[str, int] = {}
        for event in events:
            origin = (event.get(PROVENANCE_FIELD) or {}).get("origin", "unknown")
            by_origin[origin] = by_origin.get(origin, 0) + 1
        summary = ", ".join(f"{n} from the {o}" for o, n in sorted(by_origin.items()))
        lines.append(f"  {len(events)} event(s): {summary}")
        lines.append("")
        for event in events:
            found = event.get(PROVENANCE_FIELD) or {}
            host = (event.get("agent") or {}).get("name", "?")
            process = (event.get("process") or {}).get("image") or ""
            lines.append(
                f"  [{found.get('origin', '?'):8s}] {event.get('event_id', '?'):>6} "
                f"on {host}" + (f" — {process}" if process else "")
            )

    # ── 2. which sources were read, and which could not be ──
    lines.append("")
    lines.append("SOURCES")
    lines.append("-" * 60)
    if sources["answered"]:
        for name in sorted(sources["answered"]):
            entry = sources["answered"][name]
            empty = (f", {entry['empty_queries']} of which held nothing"
                     if entry["empty_queries"] else "")
            lines.append(
                f"  {'READ':13s}{name}: {entry['queries']} quer(ies){empty}, "
                f"{entry['events']} event(s) kept"
            )
    if sources["unreadable"]:
        for entry in sources["unreadable"]:
            # **Named, and never omitted.** A source missing from a report
            # reads as a source with nothing to say.
            #
            # "NOT READ" only when the source answered nothing at all. A
            # source that answered two queries and failed a third is not
            # unread, and labelling it so put `READ mock-edr` directly above
            # `NOT READ mock-edr` — precise, and reading as a contradiction.
            partial = entry["source"] in sources["answered"]
            label = "QUERY FAILED" if partial else "NOT READ"
            lines.append(f"  {label:13s}{entry['source']}: {entry['reason']}")
            lines.append(f"              asked for: {entry['asked']}")
            lines.append(
                "              This is unknown, not absent — treat it as a gap "
                "in the evidence rather than a clean result."
            )
    if not sources["answered"] and not sources["unreadable"]:
        lines.append("  (no source was queried)")

    for entry in sources["skipped"]:
        lines.append(f"  {'NOT ASKED':13s}{entry['template']}: {entry['reason']}")

    # ── 3. playbook against agent, and why the agent chose ──
    lines.append("")
    lines.append("QUERIES")
    lines.append("-" * 60)
    if sources["playbook_queries"]:
        lines.append("  From the playbook — fixed for this event class, no model involved:")
        for query in sources["playbook_queries"]:
            lines.append(
                f"    {query['template']:22s} {query['status']:12s} "
                f"+{query['events_kept']} — {query['asked']}"
            )
    else:
        lines.append("  From the playbook: none.")
        if sources["event_class"]:
            lines.append(
                f"    No fixed row covers event class {sources['event_class']}."
            )

    if sources["agent_queries"]:
        lines.append("")
        lines.append("  Chosen by the agent — one hop, from the same fixed template set:")
        for query in sources["agent_queries"]:
            lines.append(
                f"    {query['template']:22s} {query['status']:12s} "
                f"+{query['events_kept']} — {query['asked']}"
            )
            if query.get("reason"):
                lines.append(f"      chose it because: {query['reason']}")
    else:
        lines.append("")
        lines.append(
            "  Chosen by the agent: none — the playbook covered this alert "
            "with the keys it carried."
        )

    for note in sources["notes"]:
        lines.append(f"  note: {note}")

    if analysis:
        lines.append("")
        lines.append("ANALYSIS")
        lines.append("-" * 60)
        for key in sorted(analysis):
            lines.append(f"  {key}: {analysis[key]}")

    return "\n".join(lines)
