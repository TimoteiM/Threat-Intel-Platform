r"""`Label: value` parsing — the biggest format and the most fragile.

7,386 of 16,969 bodies (43.5%). The failure it is built around: a value
containing spaces.

    Account Name:  adm_lbyfszaa   Display Name:  Zakaria El Bouyafsakh adm

Read "value = up to the next whitespace" and you get `Zakaria`, lose the
rest, and the discarded tail is then available to be read as the next
label — so the real label gets swallowed into a field called
`El Bouyafsakh adm   Home Directory`.

Eleventh delimiter-boundary instance, in the largest format in the corpus.
Its test is written first, and it asserts both halves: the value survives
whole **and** the following label is not absorbed. Each is also checked
against the naive reading, so neither can pass for want of a failure mode.
"""

from __future__ import annotations

import pytest

from app.services.label_value_service import (
    NON_OBSERVABLE_LABELS,
    parse,
    provenance,
)

# From a real stored body.
REAL = (
    "A user account was created.    Subject:   Security ID:  ONENET\\adm_bschmtom   "
    "Account Name:  adm_bschmtom   Account Domain:  ONENET   "
    "Logon ID:  0x540DDC521    New Account:   Security ID:  ONENET\\adm_lbyfszaa   "
    "Account Name:  adm_lbyfszaa   Account Domain:  ONENET    "
    "Attributes:   SAM Account Name: adm_lbyfszaa   "
    "Display Name:  Zakaria El Bouyafsakh adm   "
    "User Principal Name: adm_lbyfszaa@onenet.be   Home Directory:  -   "
    "Password Last Set: <never>   Primary Group ID: 513"
)


# ─── the eleventh instance: a value with spaces ─────────────────────────

def test_a_value_containing_spaces_survives_whole():
    fields = parse(REAL).fields
    assert fields["display name"] == "Zakaria El Bouyafsakh adm", (
        "a multi-word value was truncated at the first space"
    )


def test_the_label_after_a_spaced_value_is_not_absorbed():
    """The second half, and the one that does the quiet damage: the
    discarded tail becomes available to be read as the next label."""
    fields = parse(REAL).fields
    assert "user principal name" in fields
    assert fields["user principal name"] == "adm_lbyfszaa@onenet.be"
    # No field name may contain the swallowed tail.
    for label in fields:
        assert "bouyafsakh" not in label, (
            f"the tail of a spaced value was read as part of a label: {label!r}"
        )


def test_the_naive_reading_really_does_get_it_wrong():
    """So neither assertion above passes for want of a failure mode.

    The naive output on this body is worse than "truncated at the space":

        {'subject': 'Security', 'id': '513', 'name': 'adm_lbyfszaa@onenet.be',
         'domain': 'ONENET', ...}

    Eight fields from a body carrying twelve. Multi-word labels collapse to
    their last word, so `Account Name`, `SAM Account Name`, `Display Name`
    and `User Principal Name` all become `name` and overwrite each other —
    and `Zakaria El Bouyafsakh adm` is lost entirely.
    """
    naive: dict[str, str] = {}
    tokens = REAL.split()
    for i, tok in enumerate(tokens):
        if tok.endswith(":") and i + 1 < len(tokens):
            naive[tok.rstrip(":").lower()] = tokens[i + 1]

    # The spaced value is gone from the naive parse altogether.
    assert "Zakaria El Bouyafsakh adm" not in naive.values()
    assert not any("Bouyafsakh" in v for v in naive.values())

    # Four distinct labels have collapsed into one key, so three values are
    # silently lost rather than merely truncated.
    assert "name" in naive
    correct = parse(REAL).fields
    assert {"account name", "sam account name", "display name",
            "user principal name"} <= set(correct)
    assert len(correct) > len(naive), (
        "the correct parse must recover more fields than the naive one"
    )


@pytest.mark.parametrize("value", [
    "C:\\Program Files\\Some App\\thing.exe -flag --arg=1",
    "Zakaria El Bouyafsakh adm",
    "powershell.exe -enc JABFAHIAcgBvAHIA",
    "a value with  doubled  spaces inside",
    "trailing and leading trimmed",
])
def test_values_that_contain_spaces_or_colons_are_kept_intact(value):
    body = f"Process Name:  {value}   Account Domain:  ONENET"
    fields = parse(body).fields
    assert fields["process name"] == value.strip()
    assert fields["account domain"] == "ONENET", (
        "the following label was absorbed into the spaced value"
    )


def test_a_windows_path_is_not_read_as_a_label():
    """`C:\\Windows` has a colon and must not become a field, or every path
    would shred the body into fragments."""
    body = "Image:  C:\\Windows\\System32\\cmd.exe   Account Name:  bob"
    fields = parse(body).fields
    assert fields["image"] == "C:\\Windows\\System32\\cmd.exe"
    assert fields["account name"] == "bob"
    assert "c" not in fields


def test_a_timestamp_inside_a_value_is_not_a_label():
    body = "Logon Time:  Aug 25 09:38:44 UTC   Account Name:  bob"
    fields = parse(body).fields
    assert fields["logon time"] == "Aug 25 09:38:44 UTC"
    assert fields["account name"] == "bob"


def test_a_url_inside_a_value_is_not_a_label():
    body = "Request URL:  https://login.lineas.net/path   Account Name:  bob"
    fields = parse(body).fields
    assert fields["request url"] == "https://login.lineas.net/path"
    assert fields["account name"] == "bob"
    assert "https" not in fields


# ─── repeated labels are ambiguous and the first wins ───────────────────

def test_a_repeated_label_takes_the_first_occurrence():
    """Windows events repeat `Security ID:` for Subject and New Account.
    Taking the later one silently would attribute a value to the wrong
    section."""
    fields = parse(REAL).fields
    assert fields["security id"] == "ONENET\\adm_bschmtom"
    assert fields["account name"] == "adm_bschmtom"


# ─── offsets, so an indicator can be attributed ─────────────────────────

def test_an_offset_inside_a_value_names_its_field():
    pos = REAL.index("adm_lbyfszaa@onenet.be")
    parsed = parse(REAL)
    assert parsed.field_at(pos) == "user principal name"
    assert parsed.is_observable_position(pos) is True


def test_an_offset_in_a_non_observable_field_says_so():
    """`Primary Group ID: 513` and `Logon ID: 0x540DDC521` are field
    meanings that never carry observables — the same principle as the CEF
    header, generalising to any source using these standard labels."""
    parsed = parse(REAL)
    pos = REAL.index("513")
    assert parsed.field_at(pos) == "primary group id"
    assert parsed.is_observable_position(pos) is False

    pos = REAL.index("0x540DDC521")
    assert parsed.is_observable_position(pos) is False


def test_an_offset_outside_every_value_has_no_opinion():
    """`None`, not permission. The absence convention applied to a parser."""
    parsed = parse(REAL)
    assert parsed.is_observable_position(0) is None
    assert parsed.is_observable_position(len(REAL) + 10) is None
    assert provenance("no labels here at all", 5) is None


def test_the_gap_between_fields_is_attributed_to_neither():
    body = "Account Name:  bob      Account Domain:  ONENET"
    parsed = parse(body)
    gap = body.index("bob") + 4
    assert parsed.field_at(gap) is None


# ─── the controls ───────────────────────────────────────────────────────

def test_a_body_with_no_labels_yields_nothing_rather_than_guessing():
    parsed = parse("Host CORP\\dom29 on WKS-01 resolved 8.8.8.8")
    assert parsed.fields == {}


def test_lowercase_prose_is_not_mistaken_for_labels():
    """A narrow label shape matters: `note: something` in prose would
    otherwise shred a sentence into fields."""
    parsed = parse("the operation failed and then: it was retried")
    assert parsed.fields == {}


def test_the_non_observable_set_is_label_meanings_not_values():
    assert "logon id" in NON_OBSERVABLE_LABELS
    assert "primary group id" in NON_OBSERVABLE_LABELS
    # A field that genuinely carries observables must not be in it.
    assert "user principal name" not in NON_OBSERVABLE_LABELS
    assert "image" not in NON_OBSERVABLE_LABELS


# --- the twelfth instance: the fix for the eleventh over-extended ----------
#
# Bounding a value by "the next label" and nothing else makes a newline
# invisible. Measured against 25,186 materialised account nodes, this parser
# disagreed with the live line-anchored one on 12,421 — and in 9,963 of them
# (80.2%) the live value was a PREFIX of mine, because mine had joined the
# next line onto the value. The live parser was right and the fix was worse.

WITH_TRAILING_LINE = (
    "Account Name:  WINDOWS-TEST-DE\\Attck_User\n"
    "\n"
    "Mitre.Sub_technique.\n"
)


def test_a_value_does_not_absorb_the_following_line():
    """The failure that 9,963 live account nodes demonstrated."""
    fields = parse(WITH_TRAILING_LINE).fields
    assert fields["account name"] == "WINDOWS-TEST-DE\\Attck_User"
    assert "\n" not in fields["account name"]
    assert "Mitre" not in fields["account name"]


def test_no_parsed_value_anywhere_spans_a_newline():
    """A line end is a hard boundary in this corpus, for every field."""
    body = (
        "A service was installed in the system.\n"
        "Service Name:  My Long Service Name\n"
        "Service Account:  LocalSystem\n"
        "\n"
        "Some trailing prose that is not a field at all.\n"
    )
    for label, value in parse(body).fields.items():
        assert "\n" not in value, f"{label!r} spans a line break: {value!r}"


def test_same_line_pairs_still_split_after_the_newline_fix():
    """The newline bound must not cost the behaviour it was built for.

    63.8% of bodies carry 2+ pairs on one line, so this is the common case,
    not the edge one.
    """
    body = "Account Name:  adm_lbyfszaa   Display Name:  Zakaria El Bouyafsakh adm"
    fields = parse(body).fields
    assert fields["account name"] == "adm_lbyfszaa"
    assert fields["display name"] == "Zakaria El Bouyafsakh adm"


def test_the_live_line_anchored_parser_agrees_on_the_windows_sample():
    """Where the live parser is right, this one must not differ from it.

    Not a tautology: before the newline bound, this assertion failed on
    9,963 real rows.
    """
    mine = parse(WITH_TRAILING_LINE).fields["account name"]
    naive_line_anchored = None
    for line in WITH_TRAILING_LINE.splitlines():
        if line.startswith("Account Name:"):
            naive_line_anchored = line.split(":", 1)[1].strip()
    assert naive_line_anchored == "WINDOWS-TEST-DE\\Attck_User"
    assert mine == naive_line_anchored
