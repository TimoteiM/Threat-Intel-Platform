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


# --- a slot must not be able to receive free text -------------------------


def test_risk_drivers_are_computed_from_discrete_fields_not_quoted_prose():
    """The defect: `rationale` is prose.

    It read "No strong malicious signal; monitor and corroborate with external
    context" — a capital mid-clause, and a *recommendation* in the place a
    driver belongs. A slot that can receive free text has the same hazard as a
    model, which is the thing templates were chosen to avoid.
    """
    risk = {
        "risk_level": "low", "risk_score": 10, "confidence": "low",
        "rationale": ["No strong malicious signal; monitor and corroborate."],
        "components": {"lexical_score": 0.5713, "sandbox_score": 0.1,
                       "infrastructure_score": 0.092, "opencti_score": 0.0},
        "weights": {"lexical_score": 0.2, "sandbox_score": 0.1,
                    "infrastructure_score": 0.15, "opencti_score": 0.15},
    }
    drivers = steps._risk_drivers(risk)
    assert drivers == ["lexical 0.11", "infrastructure 0.01", "sandbox 0.01"]
    joined = " ".join(drivers)
    for word in ("monitor", "corroborate", "signal", ";"):
        assert word not in joined, f"prose leaked into a driver: {word!r}"


def test_a_component_with_no_contribution_is_not_named():
    """`opencti_score: 0.0` contributes nothing, so naming it would assert it
    was a driver."""
    risk = {"components": {"a_score": 0.0, "b_score": 0.5},
            "weights": {"a_score": 0.9, "b_score": 0.2}}
    assert steps._risk_drivers(risk) == ["b 0.10"]


def test_a_score_with_no_drivers_is_a_different_template():
    """Not the same sentence with an empty list bolted in — that renders "the
    largest contributors were none", which is a clause carrying a claim."""
    assert T.EMAIL_RISK_NO_DRIVERS in T.TEMPLATES
    assert T.TEMPLATES[T.EMAIL_RISK] != T.TEMPLATES[T.EMAIL_RISK_NO_DRIVERS]
    assert "largest contributors" not in T.TEMPLATES[T.EMAIL_RISK_NO_DRIVERS]


def test_the_interpretation_step_states_a_conclusion_not_a_method():
    """It described how the call was made and omitted its output, on the one
    step whose output IS the conclusion. The method claim belongs in the
    footer, which already makes it."""
    body = T.TEMPLATES[T.EMAIL_INTERPRET]
    assert "{verdict_text}" in body and "{confidence}" in body
    for method_word in ("only model call", "raw responses", "Asked the model"):
        assert method_word not in body


def test_model_prose_is_counted_and_never_interpolated():
    """`primary_signals` is model output. It is counted so the step has
    texture, and the signals themselves render where they are attributed to
    the model rather than to a template."""
    body = T.TEMPLATES[T.EMAIL_INTERPRET]
    assert "{plural(signals, 'named signal')}" in body
    assert "{listing(signals)}" not in body
    assert "{signals}" not in body


# --- strict rendering: a field you did not read does not exist ------------
#
# The guard, not the rule. A rule was tried: the pluralisation helper existed,
# was declared, and the first producer written against it — mine — built the
# phrase with an f-string and rendered "1 attachments". A rule is advice; the
# renderer is where it holds.
#
# The three real bugs this closes at once, none of which had a misleading
# source because none of the keys exists at all: `filename` (payload has
# `path`), `selected_count` (payload has `looked_up`), `final_risk.verdict`
# (payload has `risk_level`).


from app.services.investigation_step_render import (  # noqa: E402
    field_names, missing_fields, render as strict_render,
)


def test_a_slot_whose_field_is_absent_refuses_to_render():
    out = strict_render(T.EMAIL_URL_TRIAGE, {"seen": 14, "selected_count": 1})
    assert out["renderable"] is False
    assert out["text"] is None, "a hole was rendered instead of refused"
    assert out["missing"] == ["selected"]
    assert "`selected`" in out["reason"]
    assert "do not supply" in out["reason"]


def test_the_reason_calls_it_a_defect_in_the_step_not_an_absence_in_evidence():
    """These are different claims. A template reading a field that does not
    exist is our bug; the evidence is fine."""
    out = strict_render(T.EMAIL_URL_TRIAGE, {"seen": 1})
    assert "defect in the step's own code" in out["reason"]


def test_a_present_but_falsy_value_still_renders():
    """`0` links and an empty list are answers, not absences. Without this the
    guard would refuse every true zero — the absence-as-value bug inverted."""
    out = strict_render(T.EMAIL_URL_TRIAGE, {"seen": 0, "selected": 0})
    assert out["renderable"] is True
    assert "0 links" in out["text"]
    listed = strict_render(T.EMAIL_PARSE, {"found": 0, "kinds": []})
    assert listed["renderable"] is True
    assert "none" in listed["text"]


def test_a_present_but_none_value_is_treated_as_absent():
    """`.get()` returning None into a slot is the exact mechanism."""
    out = strict_render(T.EMAIL_URL_TRIAGE, {"seen": 14, "selected": None})
    assert out["renderable"] is False
    assert out["missing"] == ["selected"]


def test_helper_arguments_are_checked_too():
    """`{plural(signals, 'named signal')}` reads `signals`. A missing helper
    argument was the other half of the same silence."""
    assert "signals" in field_names(T.EMAIL_INTERPRET)
    out = strict_render(T.EMAIL_INTERPRET,
                        {"verdict_text": "clean", "confidence": "low"})
    assert out["renderable"] is False
    assert out["missing"] == ["signals"]


def test_quoted_literals_and_integers_are_not_treated_as_fields():
    """The control: without it every template with a literal argument would
    refuse, and the guard would be useless rather than strict."""
    names = field_names(T.EMAIL_PARSE)
    assert "indicator" not in names and "3" not in names
    assert names == ["found", "kinds"]


def test_field_names_are_derived_from_the_template_not_declared_beside_it():
    """A declared list is a second copy that drifts. Every template's reads
    must be discoverable from the template itself."""
    for kind in T.TEMPLATES:
        derived = field_names(kind)
        complete = {name: 1 for name in derived}
        assert missing_fields(kind, complete) == [], (
            f"{kind}: field_names() missed something missing_fields() wants"
        )


#: A sample value per helper, so the registry sweep below supplies something
#: each slot can actually consume. `listing` wants a sequence and `plural`
#: wants a number — filling every field with `1` made `listing(kinds)` raise
#: and render verbatim, which is a fault in the test rather than the renderer.
_SAMPLE_BY_HELPER = {
    "listing": ["a", "b"],
    "plural": 2,
    "count": 2,
    "duration": 1500,
    "date_only": "2026-10-16T09:00:00Z",
    "minute": "2026-10-16T09:00:00Z",
}


def _sample_payload(kind: str) -> dict:
    """Fields for one template, typed by the helper that reads each one."""
    import re as _re

    template = T.TEMPLATES[kind]
    consumer: dict[str, str] = {}
    for slot_name, args in _re.findall(r"\{([a-z_]+)(?:\(([^)]*)\))?\}", template):
        if not args:
            continue
        for arg in args.split(","):
            arg = arg.strip()
            if arg and not arg.startswith("'") and not arg.isdigit():
                consumer[arg] = slot_name
    return {
        name: _SAMPLE_BY_HELPER.get(consumer.get(name, ""), "x")
        for name in field_names(kind)
    }


def test_every_template_renders_from_the_fields_its_own_name_says_it_needs():
    """End to end over the whole registry: supply exactly what each template
    reads, typed to the helper reading it, and every one must produce a
    sentence with no slot left behind."""
    for kind in T.TEMPLATES:
        out = strict_render(kind, _sample_payload(kind))
        assert out["renderable"] is True, f"{kind}: {out['reason']}"
        assert out["text"], f"{kind} produced no text"
        assert "{" not in out["text"], (
            f"{kind} left an unsubstituted slot: {out['text']}"
        )
