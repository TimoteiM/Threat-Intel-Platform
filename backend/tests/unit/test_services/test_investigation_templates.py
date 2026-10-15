"""The two guards I verified by hand, which is not the same as having them.

1. **Every step kind has a template.** A kind without one renders raw JSON —
   the silent-registry shape, where a step quietly becomes unreadable instead
   of failing.
2. **No template branches on a claim.** Formatting helpers are allowed,
   because "1 host / 2 hosts" is formatting and a rule that blocks it is a
   rule nobody keeps. What is banned is a slot that adds or removes a clause
   carrying a claim — the "and one host has no sensor" case, which reads as a
   footnote and *was* the finding.

The branching check works on **slot contents only**, not on the prose. A
template is a literal string with `{...}` slots, so the only place a
conditional can enter is a slot; banning words like "or" in the prose would
false-positive on "no links or attachments" and get the rule routed around.
"""

from __future__ import annotations

import re

import pytest

from app.services import email_investigation_steps as steps
from app.services import investigation_step_templates as T
from app.services.investigation_step_render import render

#: Every `{...}` occurrence, valid or not, so a malformed slot is visible
#: rather than skipped by the renderer's narrower pattern.
_ANY_SLOT = re.compile(r"\{([^}]*)\}")
#: A slot the renderer will actually substitute.
_VALID_SLOT = re.compile(r"^([a-z_]+)(?:\(([^)]*)\))?$")
#: An argument: a quoted literal, an integer, or a field name.
_VALID_ARG = re.compile(r"^(?:'[^']*'|\d+|[a-z_]+)$")


def _kind_constants() -> dict[str, str]:
    """The declared step-kind constants, by attribute name."""
    return {
        name: value for name, value in vars(T).items()
        if name.isupper() and isinstance(value, str) and "." in value
    }


# --- guard 1: the registry -------------------------------------------------


def test_every_declared_step_kind_has_a_template():
    constants = _kind_constants()
    assert constants, "no step-kind constants found — the test is looking in the wrong place"
    missing = sorted(v for v in constants.values() if v not in T.TEMPLATES)
    assert missing == [], (
        f"these step kinds have no template and would render raw JSON: {missing}"
    )


def test_every_template_corresponds_to_a_declared_kind():
    """The other direction. A template keyed on a string no constant names is
    unreachable, and an unreachable template is one nobody maintains."""
    declared = set(_kind_constants().values())
    orphans = sorted(k for k in T.TEMPLATES if k not in declared)
    assert orphans == [], f"templates with no declared constant: {orphans}"


def test_every_kind_the_email_deriver_uses_is_declared():
    """The registry only helps if the producers go through it.

    `email_investigation_steps` must pass `T.<CONSTANT>`, never a bare string
    — a literal typo'd at a call site is exactly the kind that renders JSON.
    """
    from pathlib import Path

    source = Path(steps.__file__).read_text()
    # Any quoted string that looks like a step kind, i.e. dotted lowercase.
    literals = set(re.findall(r"""["']([a-z]+(?:\.[a-z_]+)+)["']""", source))
    declared = set(_kind_constants().values())
    smuggled = sorted(literals & declared)
    assert smuggled == [], (
        f"these kinds are written as literals rather than T.<CONSTANT>: "
        f"{smuggled} — a literal bypasses the registry when it is typo'd"
    )


def test_an_unregistered_kind_renders_raw_json_rather_than_an_empty_step():
    """The failure mode, asserted rather than trusted. It must look wrong."""
    out = render("email.not.a.real.kind", {"a": 1})
    assert out["templated"] is False
    assert '"a": 1' in out["text"]


# --- guard 2: no branching on a claim --------------------------------------


@pytest.mark.parametrize("kind", sorted(T.TEMPLATES))
def test_no_template_branches_on_a_claim(kind: str):
    template = T.TEMPLATES[kind]
    for slot in _ANY_SLOT.findall(template):
        match = _VALID_SLOT.match(slot.strip())
        assert match, (
            f"{kind}: slot {{{slot}}} is not a field or a helper call. A slot "
            f"the renderer cannot parse is where a conditional would enter — "
            f"and it would render verbatim on the page."
        )
        name, args = match.group(1), match.group(2)
        if args is None:
            continue
        assert name in T.HELPERS, (
            f"{kind}: slot calls {name!r}, which is not a declared formatting "
            f"helper. Allowed: {sorted(T.HELPERS)}"
        )
        for arg in (a.strip() for a in args.split(",")) if args.strip() else []:
            assert _VALID_ARG.match(arg), (
                f"{kind}: argument {arg!r} to {name} is not a literal, an "
                f"integer or a field name — anything else is computation, and "
                f"computation is how branching arrives"
            )


@pytest.mark.parametrize("token", [" if ", " else ", "?", "&&", "||", "lambda"])
def test_no_template_contains_a_branching_construct(token: str):
    """Belt as well as braces: even inside prose, these do not belong in a
    template whose whole premise is that one template states one claim."""
    offenders = sorted(k for k, v in T.TEMPLATES.items() if token in v)
    assert offenders == [], f"{token!r} appears in templates: {offenders}"


def test_formatting_helpers_are_still_allowed():
    """The control. Without this, the rule above could be satisfied by
    banning helpers entirely — which blocks "1 host / 2 hosts" and is the
    version of the rule that gets routed around on the first real case.
    """
    assert "plural" in T.HELPERS
    assert T.plural(1, "host") == "1 host"
    assert T.plural(2, "host") == "2 hosts"
    used = {
        _VALID_SLOT.match(s.strip()).group(1)
        for v in T.TEMPLATES.values() for s in _ANY_SLOT.findall(v)
        if _VALID_SLOT.match(s.strip())
    }
    assert used & set(T.HELPERS), (
        "no template calls a formatting helper, so the permissive half of the "
        "rule is untested and could have been dropped without anything failing"
    )


def test_two_outcomes_of_one_stage_are_two_kinds_not_one_template():
    """The rule's purpose, asserted on the shape of the registry.

    Each of these pairs is one pipeline stage with two outcomes. They are
    separate kinds — which is the whole point: a clause bolted onto a sentence
    reads as a footnote.
    """
    pairs = [
        (T.EMAIL_PARSE, T.EMAIL_PARSE_NO_INDICATORS),
        (T.EMAIL_ATTACHMENT_INSPECT, T.EMAIL_ATTACHMENT_INSPECT_NONE),
        (T.EMAIL_ATTACHMENT_CONTENT, T.EMAIL_ATTACHMENT_CONTENT_UNREADABLE),
        (T.EMAIL_URL_TRIAGE, T.EMAIL_URL_TRIAGE_NONE),
        (T.EMAIL_SANDBOX, T.EMAIL_SANDBOX_SKIPPED),
    ]
    for claim, counter_claim in pairs:
        assert claim != counter_claim
        assert T.TEMPLATES[claim] != T.TEMPLATES[counter_claim]
