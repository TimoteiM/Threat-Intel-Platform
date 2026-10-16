"""One template per claim. No branching, and the line is drawn deliberately.

Every step's sentence comes from a template over structured fields. The model
is called once, at the very end, for the summary only — so the chain itself is
never a paraphrase of anything.

What is banned, and what is not
-------------------------------
**Allowed: declared formatting helpers.** Pluralisation, number agreement,
date formatting. "1 host" and "2 hosts" is formatting, and a rule that blocks
it is a rule nobody keeps — it gets routed around on the first real case.

**Banned: branching in the template body that adds or removes a clause
carrying a claim.** "No detections" and "no detections, and one of the hosts
has no sensor" are two different claims and get two different templates. A
clause bolted onto a sentence reads as a footnote; today it *was* the finding.

Enforced rather than intended: `test_investigation_templates.py` parses every
template for branching constructs and permits only calls into `HELPERS`.

A kind with no template renders raw JSON. That is the silent-registry shape —
a step quietly becoming unreadable instead of failing — so the registry test
asserts every kind used by a recorder has one.
"""

from __future__ import annotations

from typing import Any, Callable

# --- the declared formatting helpers --------------------------------------


def plural(n: Any, singular: str, many: str | None = None) -> str:
    """`1 host` / `2 hosts`. Formatting, not a claim."""
    count = int(n or 0)
    word = singular if count == 1 else (many or f"{singular}s")
    return f"{count:,} {word}"


def count(n: Any) -> str:
    """A number with thousands separators and nothing else."""
    return f"{int(n or 0):,}"


def date_only(value: Any) -> str:
    return str(value or "")[:10]


def minute(value: Any) -> str:
    text = str(value or "").replace("T", " ")
    return text[:16]


def duration(ms: Any) -> str:
    milliseconds = int(ms or 0)
    if milliseconds < 1000:
        return f"{milliseconds} ms"
    return f"{milliseconds / 1000:.1f} s"


def listing(values: Any, limit: int = 3) -> str:
    """`a, b and c`, or `a, b and 4 others`. The truncation is stated, never
    silent — a list cut short and read as the whole list is the floor-as-fact
    shape."""
    items = [str(v) for v in (values or []) if str(v).strip()]
    if not items:
        return "none"
    # One over the limit lists everything. "a, b, c and 1 others" is both
    # ungrammatical and sillier than just naming the fourth item.
    if len(items) <= limit + 1:
        if len(items) == 1:
            return items[0]
        return ", ".join(items[:-1]) + f" and {items[-1]}"
    shown = ", ".join(items[:limit])
    return f"{shown} and {len(items) - limit:,} others"


#: The only names a template body may call. The test enforces this set.
HELPERS: dict[str, Callable[..., str]] = {
    "plural": plural,
    "count": count,
    "date_only": date_only,
    "minute": minute,
    "duration": duration,
    "listing": listing,
}


# --- the templates ---------------------------------------------------------
#
# Keyed by step kind. Each is a format string over a step's structured fields
# plus the helpers, and each states ONE claim. Where two outcomes are
# different claims they are different kinds, which is why there are more of
# these than there are pipeline stages.

EMAIL_PARSE = "email.parse"
EMAIL_PARSE_NO_INDICATORS = "email.parse.none"
EMAIL_ATTACHMENT_INSPECT = "email.attachment.inspect"
EMAIL_ATTACHMENT_INSPECT_NONE = "email.attachment.inspect.none"
EMAIL_ATTACHMENT_INSPECT_CLEAN = "email.attachment.inspect.clean"
EMAIL_ATTACHMENT_CONTENT = "email.attachment.content"
EMAIL_ATTACHMENT_CONTENT_UNREADABLE = "email.attachment.content.unreadable"
EMAIL_URL_TRIAGE = "email.url.triage"
EMAIL_URL_TRIAGE_NONE = "email.url.triage.none"
EMAIL_ENRICH = "email.enrich"
EMAIL_SANDBOX = "email.sandbox"
EMAIL_SANDBOX_SKIPPED = "email.sandbox.skipped"
EMAIL_RISK = "email.risk"
EMAIL_RISK_NO_DRIVERS = "email.risk.no_drivers"
EMAIL_INTERPRET = "email.interpret"
STEP_NOT_ASKED = "step.not_asked"

# --- the alert surface ----------------------------------------------------
#
# Written against measured statuses, not a presence boolean. `log_context` is
# present as an OBJECT on 2,833 of 2,833 post-cutover runs and carries logs on
# only 2,138 of them: `unavailable` 613, `empty` 75, `skipped` 7 — and its own
# `status` field recorded which all along.
#
# `partial` is 1,654 of those 2,138 — 77% — and is a *collapse* that had to be
# split before anything could claim "ten minutes either side":
# `window.complete` is False on **all** 1,654, with truncation layered on top
# (639 window-only, 433 truncated below the 500 cap, 582 truncated at it).
# So the window claim and the truncation claim are separate kinds rather than
# one sentence with a clause bolted on.
ALERT_WHY = "alert.why"
ALERT_EXTRACT = "alert.extract"
ALERT_EXTRACT_NONE = "alert.extract.none"
ALERT_PRIOR = "alert.prior"
ALERT_PRIOR_NONE = "alert.prior.none"
ALERT_LOGS_COLLECTED = "alert.logs.collected"
ALERT_LOGS_PARTIAL_WINDOW = "alert.logs.partial_window"
ALERT_LOGS_PARTIAL_TRUNCATED = "alert.logs.partial_truncated"
ALERT_LOGS_PARTIAL_AT_CAP = "alert.logs.partial_at_cap"
ALERT_LOGS_UNAVAILABLE = "alert.logs.unavailable"
ALERT_LOGS_EMPTY = "alert.logs.empty"
ALERT_LOGS_NO_HOST = "alert.logs.no_host"
ALERT_LOGS_PREDATES = "alert.logs.predates"
ALERT_ATTACK = "alert.attack"
ALERT_ATTACK_NONE = "alert.attack.none"
ALERT_INDICATORS = "alert.indicators"
ALERT_INDICATORS_NONE = "alert.indicators.none"

TEMPLATES: dict[str, str] = {
    EMAIL_PARSE: (
        "Read the message and extracted {plural(found, 'indicator')}: "
        "{listing(kinds)}."
    ),
    EMAIL_PARSE_NO_INDICATORS: (
        "Read the message and found no indicators to investigate — no links, "
        "no attachments and no sender address that could be looked up."
    ),
    EMAIL_ATTACHMENT_INSPECT: (
        "Inspected {plural(attachments, 'attachment')} for what the files "
        "are, rather than what they are named: {listing(findings)}."
    ),
    EMAIL_ATTACHMENT_INSPECT_CLEAN: (
        "Inspected {plural(attachments, 'attachment')} for what the files "
        "are, rather than what they are named, and found nothing structurally "
        "unexpected."
    ),
    EMAIL_ATTACHMENT_INSPECT_NONE: "The message carried no attachments.",
    EMAIL_ATTACHMENT_CONTENT: (
        "Read the contents of {plural(files, 'attachment')} without anyone "
        "opening the file by hand: {listing(summaries)}."
    ),
    EMAIL_ATTACHMENT_CONTENT_UNREADABLE: (
        "The attachment contents could not be read, so what the files say is "
        "unknown rather than harmless: {reason}"
    ),
    EMAIL_URL_TRIAGE: (
        "Triaged {plural(seen, 'link')} down to {count(selected)} worth "
        "checking, by unwrapping rewritten links to their real destinations "
        "and dropping duplicates."
    ),
    EMAIL_URL_TRIAGE_NONE: "The message carried no links.",
    # `source_names` holds CHECK categories — sender_domain, sender_ip, urls,
    # attachments, email_security, content_ml — not external services. The
    # sentence said "6 external sources: sender_domain, …", which is false
    # about both halves: those are not sources and they are not named sources.
    # Corrected to say what the values are. Which external services answered
    # is a different question this step does not currently record.
    EMAIL_ENRICH: (
        "Ran {plural(sources, 'enrichment check')} over "
        "{plural(observables, 'indicator')}: {listing(source_names)}."
    ),
    EMAIL_SANDBOX: (
        "Detonated the message in a sandbox: {verdict_text}, with "
        "{plural(artifacts, 'artifact')} observed."
    ),
    EMAIL_SANDBOX_SKIPPED: (
        "The message was not detonated. A sandbox run was not requested for "
        "this investigation, so what it would do when opened is unknown "
        "rather than safe."
    ),
    EMAIL_RISK: (
        "Combined every source's answer into one score: {verdict_text}. The "
        "largest contributors were {listing(drivers)}."
    ),
    EMAIL_RISK_NO_DRIVERS: (
        "Combined every source's answer into one score: {verdict_text}. No "
        "single source contributed materially to it."
    ),
    EMAIL_INTERPRET: (
        "Interpreted the evidence above as {verdict_text}, with "
        "{confidence} confidence, resting on {plural(signals, 'named signal')}."
    ),
    # --- the alert surface ------------------------------------------------
    ALERT_WHY: (
        "This investigation exists because an alert arrived from "
        "{source_text} naming {subject_text}, and no exclusion suppressed it."
    ),
    ALERT_EXTRACT: (
        "Extracted {plural(investigable, 'indicator')} worth investigating "
        "from {count(characters)} characters of alert text, setting aside "
        "{count(excluded)} already excluded."
    ),
    ALERT_EXTRACT_NONE: (
        "Found no investigable indicator in the alert text — nothing in it "
        "could be looked up anywhere."
    ),
    ALERT_PRIOR: (
        "Checked what this platform already knew and found "
        "{plural(prior, 'earlier investigation')} of the same indicators, so "
        "they were reused rather than paid for again."
    ),
    ALERT_PRIOR_NONE: (
        "Checked what this platform already knew about these indicators and "
        "found nothing."
    ),
    # One claim each. `window.complete` is false on every `partial` run, and
    # truncation is an additional, separate fact — so three kinds, not one
    # sentence with two optional clauses.
    ALERT_LOGS_COLLECTED: (
        "Read the host's own logs around the alert: "
        "{plural(logs, 'event')} from {host}, over the full window asked for."
    ),
    ALERT_LOGS_PARTIAL_WINDOW: (
        "Read {plural(logs, 'event')} from {host}, but the window asked for "
        "was not fully available — so this is some of what happened around "
        "the alert, not all of it."
    ),
    ALERT_LOGS_PARTIAL_TRUNCATED: (
        "Read {plural(logs, 'event')} from {host}. The window was incomplete "
        "AND the result was truncated before the row limit, so events were "
        "dropped for a reason this step cannot name."
    ),
    ALERT_LOGS_PARTIAL_AT_CAP: (
        "Read {plural(logs, 'event')} from {host} — the row limit. The window "
        "was incomplete and the limit was reached, so this is a floor: there "
        "were more events than were read."
    ),
    ALERT_LOGS_UNAVAILABLE: (
        "The host's logs could not be read for {host}, so what happened "
        "around the alert is unknown rather than uneventful."
    ),
    ALERT_LOGS_EMPTY: (
        "Read the host's logs around the alert for {host} and the window held "
        "nothing. The store was asked and answered; this is a real negative."
    ),
    ALERT_LOGS_NO_HOST: (
        "No host logs were read, because the alert names no host — there is "
        "nothing to fetch a window around."
    ),
    ALERT_LOGS_PREDATES: (
        "No host logs were read. This investigation predates log-context "
        "collection, which began on {started_text}, so none was ever "
        "gathered for it."
    ),
    ALERT_ATTACK: (
        "Mapped the alert to MITRE ATT&CK: {listing(techniques)}."
    ),
    ALERT_INDICATORS: (
        "Investigated {plural(investigated, 'indicator')} against external "
        "sources and reused {count(reused)} already known, finding "
        "{count(malicious)} malicious and {count(suspicious)} suspicious."
    ),
    ALERT_INDICATORS_NONE: (
        "No indicator was investigated against an external source — every one "
        "extracted was either excluded or already known."
    ),
    ALERT_ATTACK_NONE: (
        "No ATT&CK technique could be attributed to this alert from the "
        "evidence gathered."
    ),
}


#: Kinds that deliberately have no template, with the reason they don't.
#:
#: `step.not_asked` is the generic "this could not be asked at all" step, and
#: its only content is the question and the reason — both of which the step
#: already carries in its own columns, and both of which the page already
#: renders. A template for it was a third copy of the same two strings: it
#: produced "No claim. {question_text} was not asked, because {reason}"
#: directly beneath the question, above the reason. It is still a step in the
#: chain and still rendered — dropping it would silently shorten the
#: investigation — it just has no sentence of its own to render.
#:
#: This set exists so the registry guards stay exhaustive rather than gaining
#: an exemption each time one of these appears. Anything added here needs its
#: reason written next to it.
NO_SENTENCE_KINDS: frozenset[str] = frozenset({STEP_NOT_ASKED})


def template_for(kind: str) -> str | None:
    """The template for a step kind, or None.

    `None` is handled by the renderer as *render the raw JSON*, which is
    deliberately ugly: a step with no template must be visibly wrong rather
    than quietly plausible.
    """
    return TEMPLATES.get(kind)
