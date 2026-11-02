"""A sender's declaration that the body is a substitute must survive us.

69 alert bodies begin `[SYNTHETIC - Exabeam raw log unavailable; derived from
event metadata, not a verbatim log line]`. The sender tried to fetch the raw
log, could not, and said so in band. Nothing read it: the derived metadata was
parsed as log text, reached the model as evidence, and the report gave a
reader no way to tell.

The control the user asked for is the first test here, because a marker
detector that fires on everything is worse than none — it would relabel
17,748 bodies as derived and destroy the distinction it exists to make.
"""

from __future__ import annotations

import pytest

from app.services import body_provenance as bp
from app.services.alert_field_service import extract_alert_fields as extract

REAL = ("[SYNTHETIC - Exabeam raw log unavailable; derived from event "
        "metadata, not a verbatim log line] host=h user=u src_ip=10.0.0.1")


# ── the control: a normal body must not be flagged ──────────────────────────

@pytest.mark.parametrize("body", [
    "Event ID: 4688\nA new process has been created.",
    "<Event><System><EventID>4697</EventID></System></Event>",
    "[ALERT] A service was installed in the system.",
    "host=h user=u src_ip=10.0.0.1",
    "Some prose mentioning confidence and a sample of the data.",
    "host=h [SYNTHETIC something] the bracket is mid-body, not a declaration",
    "",
])
def test_an_ordinary_body_is_not_flagged(body):
    """`[ALERT]` is in here deliberately.

    It is a real sender prefix on 6 bodies and it is **not** a statement about
    content. A detector that keyed on "starts with a bracket" would flag it,
    and a detector that keyed on a word like `confidence` would flag 24.5% of
    the corpus — measured, which is why the rule is a bracketed prefix whose
    contents name a substitution.
    """
    assert bp.declared_substitution(body) is None
    assert bp.note_for_model(body) == ""
    assert bp.provenance_of(body)["derived"] is False


def test_the_real_marker_is_flagged_and_keeps_its_words():
    """And the declaration travels, not just the flag.

    "derived" without "derived from what, and why" is the same loss one level
    down.
    """
    declared = bp.declared_substitution(REAL)
    assert declared["derived"] is True
    assert declared["declared_by"] == "sender"
    assert "Exabeam raw log unavailable" in declared["declaration"]
    assert declared["matched"] in bp.SUBSTITUTION_WORDS


def test_absence_of_a_declaration_is_a_value_not_a_missing_key():
    """`verbatim_as_received`, so "the sender said nothing" and "nobody
    looked" are different bytes."""
    p = bp.provenance_of("Event ID: 4688")
    assert p["declaration"] == bp.VERBATIM
    assert p["derived"] is False


def test_it_generalises_beyond_the_one_sender_we_have_seen():
    """A truncation declaration should be caught too.

    No sender currently emits one — measured, `truncat` and `partial` appear
    only as prose across 17,748 bodies — so this is the forward-looking half,
    and it costs nothing because the anchor and the word list still exclude
    `[ALERT]`.
    """
    assert bp.declared_substitution("[TRUNCATED - first 4KB only] host=h")
    assert bp.declared_substitution("[PARTIAL FETCH - 2 of 9 events] host=h")


# ── it reaches the three places that consume the body ──────────────────────

def test_the_extractor_records_it_on_every_alert():
    assert extract(REAL)[bp.FIELD]["derived"] is True
    assert extract("Event ID: 4688")[bp.FIELD]["derived"] is False


def test_the_model_is_told_before_it_reads_the_evidence():
    note = bp.note_for_model(REAL)
    assert "NOT a verbatim log line" in note
    assert "Exabeam raw log unavailable" in note
    # and it says what to do with that, not merely that it is true
    assert "say so in any conclusion" in note


def test_the_model_note_is_absent_for_an_ordinary_body():
    """The positive control for the note: a rule that always prefixed a
    warning would make the warning meaningless."""
    assert bp.note_for_model("Event ID: 4688") == ""


def test_the_report_states_it_beside_the_evidence():
    from app.services import token_boundary as tb
    from app.services.context_gathering import loop as gl, mock_source as ms, report

    for body, expected in ((REAL, True), ("Event ID: 10", False)):
        fields = {"event_id": "10", bp.FIELD: bp.provenance_of(body)}
        boundary = tb.in_memory(tenant_id="t", investigation_id="i")
        record = gl.gather(
            tenant_id="t", investigation_id="i", alert_fields=fields,
            selectors={"host": "EXPDC001"}, registry=ms.default_registry(),
            boundary=boundary, budget=gl.Budget(max_queries=2))
        composed = report.compose(record=record)
        assert ("NOT A VERBATIM LOG LINE" in composed) is expected
        # the control: the section exists either way, so the assertion above
        # is about the warning and not about the report being empty
        assert "WHAT THE ALERT CARRIED" in composed
