r"""CEF header parsing, and the escaped pipe that would have shifted it.

Field 4 of a CEF header is Device Version by specification, which is what
makes `6.0.4.27` attributable rather than a judgement — 97 of 97 bodies
containing it have it there.

But CEF escapes a literal pipe inside a header field as `\|`, and a naive
`split("|")` on such a body **silently shifts every later field by one** and
reads Device Event Class ID as the Device Version. No exception, no empty
value, just the wrong field under the right name.

That is the eleventh instance of this codebase's delimiter-boundary family,
and it would have been latent *inside the parser written to fix the tenth*.
Measured: 0 of 257 CEF bodies in the corpus contain an escaped pipe today —
so this is written before it is live rather than after, which is the whole
point.
"""

from __future__ import annotations

import pytest

from app.services.cef_header_service import (
    HEADER_FIELDS,
    NON_OBSERVABLE_FIELDS,
    parse,
    provenance,
    split_header,
    unescape,
)

# The real shape, from a stored body.
REAL = (
    "<134>Aug 25 09:38:44 sf-tower "
    "CEF:0|Silverfort|Admin Console|6.0.4.27|Authentication|"
    "Authentication request|2|server_name=\"Exabeam\" rt=\"1787650723273\""
)


def test_the_real_body_puts_the_version_in_field_4():
    header = parse(REAL)
    assert header is not None
    assert header.fields["device_vendor"] == "Silverfort"
    assert header.fields["device_product"] == "Admin Console"
    assert header.fields["device_version"] == "6.0.4.27"
    assert header.fields["device_event_class_id"] == "Authentication"
    assert header.fields["severity"] == "2"


# ─── the escaped pipe: the eleventh instance, caught before it is live ───

def test_an_escaped_pipe_in_field_3_does_not_shift_field_4():
    r"""The test the parser exists to pass.

    Device Product is `Firewall | Edge`, escaped as `Firewall \| Edge`. A
    `split("|")` yields `Firewall \` as field 3 and ` Edge` as field 4 — so
    the version reads as ` Edge` and every later field is wrong too.
    """
    body = r"CEF:0|Acme|Firewall \| Edge|9.9.9.9|Blocked|Blocked a thing|5|src=1.2.3.4"
    header = parse(body)
    assert header is not None
    assert header.fields["device_product"] == "Firewall | Edge"
    assert header.fields["device_version"] == "9.9.9.9", (
        "an escaped pipe in Device Product shifted the Device Version"
    )
    assert header.fields["device_event_class_id"] == "Blocked"
    assert header.fields["severity"] == "5"

    # And the naive form really does get it wrong, so this test is not
    # passing for want of a failure mode.
    naive = body.split("|")
    assert naive[3] != "9.9.9.9"


@pytest.mark.parametrize("product,expected", [
    (r"Firewall \| Edge", "Firewall | Edge"),
    (r"A \| B \| C", "A | B | C"),
    (r"back\\slash", "back\\slash"),
    # A trailing escaped backslash must not swallow the real separator.
    (r"ends with backslash\\", "ends with backslash\\"),
])
def test_escapes_in_a_header_field_resolve_without_shifting(product, expected):
    body = f"CEF:0|Acme|{product}|7.7.7.7|Class|Name|3|src=1.2.3.4"
    header = parse(body)
    assert header.fields["device_product"] == expected
    assert header.fields["device_version"] == "7.7.7.7"


def test_unescape_handles_the_documented_sequences():
    assert unescape(r"a\|b") == "a|b"
    assert unescape(r"a\\b") == "a\\b"
    assert unescape(r"a\nb") == "a\nb"
    # An unknown escape keeps the character rather than dropping it: losing
    # a character silently is how a value becomes a different value.
    assert unescape(r"a\qb") == "aqb"


# ─── the controls ────────────────────────────────────────────────────────

def test_a_body_with_no_cef_header_returns_none():
    """`None`, not an empty header. An empty header would let a caller read
    "no fields" as "no non-observable fields" and admit everything."""
    assert parse("A user account was created. Subject: Security ID: X") is None
    assert parse("") is None
    assert provenance("just prose", 3) is None


def test_the_extension_is_not_part_of_the_header():
    """Observables live in the extension — `src=`, `dst=`, `request=`. The
    header must not claim them, or every CEF indicator would be suppressed."""
    header = parse(REAL)
    src_at = REAL.index("Exabeam")
    assert header.field_at(src_at) is None
    assert header.is_observable_position(src_at) is None, (
        "the header claimed an offset in the extension"
    )


def test_a_position_outside_the_header_has_no_opinion():
    """`None` must not read as permission. An unknown position is for the
    caller to decide, which is the absence convention applied to a parser."""
    header = parse(REAL)
    assert header.is_observable_position(len(REAL) + 50) is None


# ─── what the field map is for ───────────────────────────────────────────

def test_the_version_field_is_marked_non_observable():
    header = parse(REAL)
    pos = REAL.index("6.0.4.27")
    assert header.field_at(pos) == "device_version"
    assert header.is_observable_position(pos) is False

    prov = provenance(REAL, pos)
    assert prov["format"] == "cef"
    assert prov["field"] == "device_version"
    assert prov["could_be_observable"] is False
    # The vendor and product travel too, so a reader knows which source
    # produced the value without re-parsing.
    assert prov["device_vendor"] == "Silverfort"


def test_the_non_observable_set_is_field_meanings_not_values():
    """Not a list of bad values — a list of what the format says each
    position means, which is fixed by the specification and identical for
    every CEF source. That is why it generalises."""
    assert NON_OBSERVABLE_FIELDS <= set(HEADER_FIELDS)
    # `name` is the one header field that can carry an observable: vendors
    # put hostnames and URLs in the event name.
    assert "name" not in NON_OBSERVABLE_FIELDS
    assert "device_version" in NON_OBSERVABLE_FIELDS


def test_a_truncated_header_does_not_invent_fields():
    """Truncated bodies are common — the masker's docstring says so. A short
    header must not report a Device Version it never had."""
    header = parse("CEF:0|Acme|Product")
    assert header is not None
    assert header.fields.get("device_vendor") == "Acme"
    assert "device_event_class_id" not in header.fields
    assert header.field_at(len("CEF:0|Acme|Product") - 1) == "device_product"
