"""Render one step's sentence from its structured fields.

Evaluation is deliberately narrow: a template may interpolate a field or call
one of the declared helpers, and nothing else. No `eval`, no attribute access,
no arithmetic — a template is data, and a template language that can compute
is a template language that can branch.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.services.investigation_step_templates import HELPERS, template_for

#: `{helper(arg, 'literal')}` or `{field}`. Anything else is not substituted
#: and surfaces as itself, which is visible rather than silently empty.
_SLOT = re.compile(r"\{([a-z_]+)(?:\(([^)]*)\))?\}")
_LITERAL = re.compile(r"^'([^']*)'$")


def _arg(token: str, fields: dict[str, Any]) -> Any:
    token = token.strip()
    literal = _LITERAL.match(token)
    if literal:
        return literal.group(1)
    if token.isdigit():
        return int(token)
    return fields.get(token)


def render(kind: str, fields: dict[str, Any]) -> dict[str, Any]:
    """The step's sentence, plus whether it came from a template at all.

    `templated: False` means the kind has no template and the raw fields are
    shown. That is the silent-registry shape made loud — the page renders it
    as JSON so nobody mistakes an unregistered kind for a considered one.
    """
    template = template_for(kind)
    if template is None:
        return {
            "text": json.dumps(fields, default=str, indent=2, sort_keys=True),
            "templated": False,
            "kind": kind,
        }

    def _sub(match: re.Match[str]) -> str:
        name, args = match.group(1), match.group(2)
        if args is None:
            value = fields.get(name)
            return "" if value is None else str(value)
        helper = HELPERS.get(name)
        if helper is None:
            # Unknown helper: left verbatim rather than silently dropped, so
            # the template is visibly broken instead of quietly short.
            return match.group(0)
        parsed = [_arg(a, fields) for a in args.split(",")] if args.strip() else []
        try:
            return str(helper(*parsed))
        except Exception:  # noqa: BLE001
            return match.group(0)

    return {"text": _SLOT.sub(_sub, template), "templated": True, "kind": kind}
