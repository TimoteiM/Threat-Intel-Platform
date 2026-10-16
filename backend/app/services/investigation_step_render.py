"""Render one step's sentence from its structured fields — or refuse to.

**A slot whose field is absent from the payload fails. It does not render.**

That is the whole point of this module, and it exists because the opposite was
true: `fields.get(name)` followed by `"" if value is None else str(value)`
turned a field I had imagined into an empty string inside an otherwise
well-formed sentence. Three times in one day — `filename`, `selected_count`,
`final_risk.verdict` — none of those keys exists in the payload at all. There
was no misleading source and no source: the template was written against an
interface I imagined, and `.get()` made the silence the *language's* rather
than the data's.

**A field you did not read is a field that does not exist.**

So the guard lives here rather than in a rule. A rule was tried: the
pluralisation helper existed, was declared, and the first producer written
against it — mine — built the phrase with an f-string and rendered "1
attachments". A rule is advice; the renderer is where it holds.

Absent is `check_failed` with the key named, like every other absence in this
platform. Present-but-`None` counts as absent, because `.get()` returning
`None` is the exact mechanism; present-but-falsy does not, because `0` links
and an empty list are answers.

Evaluation stays narrow: a slot interpolates a field or calls one declared
helper. No `eval`, no attribute access, no arithmetic — a template language
that can compute is one that can branch.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.services.investigation_step_templates import HELPERS, template_for

#: `{helper(arg, 'literal')}` or `{field}`.
_SLOT = re.compile(r"\{([a-z_]+)(?:\(([^)]*)\))?\}")
_LITERAL = re.compile(r"^'([^']*)'$")


def _is_literal(token: str) -> bool:
    token = token.strip()
    return bool(_LITERAL.match(token)) or token.isdigit()


def field_names(kind: str) -> list[str]:
    """Every field name a template reads, including helper arguments.

    Derived from the template rather than declared beside it: a declared list
    is a second copy that drifts, and this one cannot.
    """
    template = template_for(kind)
    if template is None:
        return []
    names: list[str] = []
    for slot_name, args in _SLOT.findall(template):
        if args == "" and slot_name not in HELPERS:
            names.append(slot_name)
            continue
        for arg in args.split(","):
            if arg.strip() and not _is_literal(arg):
                names.append(arg.strip())
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(names))


def missing_fields(kind: str, fields: Any) -> list[str]:
    """Field names the template needs that the payload does not supply.

    Absent means *not a key*, or a key whose value is `None`. A falsy value
    that is present — `0`, `[]`, `""` — is an answer and is left alone.
    """
    supplied = fields if isinstance(fields, dict) else {}
    return [
        name for name in field_names(kind)
        if name not in supplied or supplied[name] is None
    ]


def refusal_reason(kind: str, missing: list[str]) -> str:
    """Why this step has no sentence, naming the keys."""
    keys = ", ".join(f"`{m}`" for m in missing)
    return (
        f"This step could not be rendered: the template for {kind!r} reads "
        f"{keys}, which the recorded fields do not supply. That is a defect in "
        f"the step's own code rather than an absence in the evidence — a "
        f"template written against a field that does not exist. It is reported "
        f"instead of rendered, because rendering it would produce a "
        f"well-formed sentence with a hole in it."
    )


def render(kind: str, fields: Any) -> dict[str, Any]:
    """The step's sentence, or a refusal naming what is missing.

    Three outcomes, and a caller must handle all three:

    * `templated: False` — the kind has no template; the raw fields are shown
      as JSON, so an unregistered kind looks wrong rather than plausible.
    * `renderable: False` — the template reads fields the payload lacks;
      `missing` names them and `reason` says so. No sentence is produced.
    * otherwise — `text` is the sentence.
    """
    supplied = fields if isinstance(fields, dict) else {}
    template = template_for(kind)
    if template is None:
        return {
            "kind": kind, "templated": False, "renderable": False,
            "missing": [], "reason": None,
            "text": json.dumps(supplied, default=str, indent=2, sort_keys=True),
        }

    missing = missing_fields(kind, supplied)
    if missing:
        return {
            "kind": kind, "templated": True, "renderable": False,
            "missing": missing, "reason": refusal_reason(kind, missing),
            "text": None,
        }

    def _arg(token: str) -> Any:
        token = token.strip()
        literal = _LITERAL.match(token)
        if literal:
            return literal.group(1)
        if token.isdigit():
            return int(token)
        # Guaranteed present: `missing_fields` ran first. Indexed rather than
        # `.get()`, so a future path that skips the check raises instead of
        # rendering a hole.
        return supplied[token]

    def _sub(match: re.Match[str]) -> str:
        name, args = match.group(1), match.group(2)
        if args is None:
            return str(supplied[name])
        helper = HELPERS.get(name)
        if helper is None:
            # Left verbatim: a template calling an undeclared helper is
            # visibly broken, which the template test also catches.
            return match.group(0)
        parsed = [_arg(a) for a in args.split(",")] if args.strip() else []
        try:
            return str(helper(*parsed))
        except Exception:  # noqa: BLE001
            return match.group(0)

    return {
        "kind": kind, "templated": True, "renderable": True,
        "missing": [], "reason": None, "text": _SLOT.sub(_sub, template),
    }
