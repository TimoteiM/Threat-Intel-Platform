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
    if len(items) <= limit:
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
EMAIL_ATTACHMENT_CONTENT = "email.attachment.content"
EMAIL_ATTACHMENT_CONTENT_UNREADABLE = "email.attachment.content.unreadable"
EMAIL_URL_TRIAGE = "email.url.triage"
EMAIL_URL_TRIAGE_NONE = "email.url.triage.none"
EMAIL_ENRICH = "email.enrich"
EMAIL_SANDBOX = "email.sandbox"
EMAIL_SANDBOX_SKIPPED = "email.sandbox.skipped"
EMAIL_RISK = "email.risk"
EMAIL_INTERPRET = "email.interpret"
STEP_NOT_ASKED = "step.not_asked"

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
        "Inspected {plural(attachments, 'attachment')} for what they really "
        "are: {listing(findings)}."
    ),
    EMAIL_ATTACHMENT_INSPECT_NONE: "The message carried no attachments.",
    EMAIL_ATTACHMENT_CONTENT: (
        "Read the contents of {plural(files, 'attachment')} without opening "
        "them by hand: {listing(summaries)}."
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
    EMAIL_ENRICH: (
        "Asked {plural(sources, 'external source')} about "
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
        "Combined every source's answer into one score: {verdict_text}, driven "
        "by {listing(drivers)}."
    ),
    EMAIL_INTERPRET: (
        "Asked the model to interpret the evidence gathered above. This is "
        "the only model call in the investigation, and it saw the recorded "
        "steps rather than the raw responses."
    ),
    # Rendered for a step that could not be asked at all. Present in the chain
    # on purpose: dropping it would silently shorten the investigation.
    STEP_NOT_ASKED: (
        "No claim. {question_text} was not asked, because {reason}"
    ),
}


def template_for(kind: str) -> str | None:
    """The template for a step kind, or None.

    `None` is handled by the renderer as *render the raw JSON*, which is
    deliberately ugly: a step with no template must be visibly wrong rather
    than quietly plausible.
    """
    return TEMPLATES.get(kind)
