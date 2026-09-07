"""The three pieces of extraction infrastructure, tested independently.

Each rejection reason has at least one test, because the value of a reason
vocabulary is that it can be counted — and a reason nothing ever produces is a
reason that will be wrong the first time something does.
"""

from __future__ import annotations

import pytest

from app.services.ioc_extraction_rules import (
    DOMAIN_VALIDATOR,
    REJECTION_REASONS,
    ConsumedSpans,
    DomainValidator,
    DroppedLog,
)


def why(candidate: str, text: str | None = None) -> str | None:
    """The reason a candidate was refused, or None if it passed."""
    if text is None:
        return DOMAIN_VALIDATOR.check(candidate).reason
    start = text.index(candidate)
    return DOMAIN_VALIDATOR.check(
        candidate, masked_text=text, start=start, end=start + len(candidate)
    ).reason


# ─────────────────────────────────────────────────────────────────────────────
# ConsumedSpans
# ─────────────────────────────────────────────────────────────────────────────

def test_a_free_span_is_claimed():
    spans = ConsumedSpans()
    assert spans.claim(0, 10, kind="url", value="https://a.example") is True
    assert len(spans) == 1


def test_an_overlapping_span_is_refused():
    spans = ConsumedSpans()
    spans.claim(0, 10, kind="url", value="https://a.example")
    assert spans.claim(5, 15, kind="domain", value="a.example") is False
    assert len(spans) == 1, "the refused claim must not be stored"


def test_an_adjacent_span_is_not_an_overlap():
    """[0,10) and [10,20) share no character."""
    spans = ConsumedSpans()
    spans.claim(0, 10, kind="url", value="u")
    assert spans.claim(10, 20, kind="domain", value="d") is True


def test_the_earlier_pass_keeps_ownership():
    spans = ConsumedSpans()
    spans.claim(4, 20, kind="url", value="https://evil.example/x")
    assert spans.claimed_by(11, 18) == "url"
    assert spans.is_consumed(11, 18) is True


def test_a_span_inside_a_larger_claim_is_consumed():
    """The domain pass finding a host inside an already-claimed URL."""
    spans = ConsumedSpans()
    spans.claim(0, 40, kind="url", value="url")
    assert spans.is_consumed(8, 20) is True


def test_a_span_containing_a_smaller_claim_is_consumed():
    spans = ConsumedSpans()
    spans.claim(10, 12, kind="hash", value="h")
    assert spans.is_consumed(0, 40) is True


def test_an_empty_or_inverted_span_is_refused():
    spans = ConsumedSpans()
    assert spans.claim(5, 5, kind="url", value="") is False
    assert spans.claim(9, 3, kind="url", value="") is False


def test_claims_are_reported_in_text_order():
    spans = ConsumedSpans()
    spans.claim(30, 40, kind="hash", value="c")
    spans.claim(0, 10, kind="url", value="a")
    spans.claim(15, 20, kind="ip", value="b")
    assert [s[3] for s in spans.spans()] == ["a", "b", "c"]


def test_spans_are_returned_as_a_copy():
    spans = ConsumedSpans()
    spans.claim(0, 5, kind="url", value="a")
    spans.spans().clear()
    assert len(spans) == 1


# ─────────────────────────────────────────────────────────────────────────────
# DroppedLog — one test per reason
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("reason", sorted(REJECTION_REASONS))
def test_every_reason_can_be_recorded_and_counted(reason):
    log = DroppedLog()
    log.reject("candidate", reason, 12)
    assert log.counts() == {reason: 1}
    assert log.entries() == [{"value": "candidate", "reason": reason, "offset": 12}]


def test_an_unknown_reason_is_refused_rather_than_stored():
    """A free-text reason is how nine reasons become forty uncountable ones."""
    log = DroppedLog()
    with pytest.raises(ValueError, match="unknown rejection reason"):
        log.reject("x", "looked_wrong", 0)
    assert len(log) == 0


def test_the_offset_is_kept():
    log = DroppedLog()
    log.reject("user.email", "field_path", 4213)
    assert log.entries()[0]["offset"] == 4213


def test_the_same_rejection_at_two_offsets_is_two_entries():
    log = DroppedLog()
    log.reject("user.email", "field_path", 10)
    log.reject("user.email", "field_path", 90)
    assert len(log.entries()) == 2


def test_an_identical_rejection_is_not_recorded_twice():
    log = DroppedLog()
    log.reject("user.email", "field_path", 10)
    log.reject("user.email", "field_path", 10)
    assert len(log.entries()) == 1
    assert log.counts()["field_path"] == 2, "but it still counts"


def test_entries_are_capped_while_counts_stay_complete():
    """An 11MB body can reject thousands; a report nobody reads is not a report."""
    log = DroppedLog(limit=3)
    for offset in range(50):
        log.reject(f"v{offset}.exe", "file_extension", offset)
    assert len(log.entries()) == 3
    assert log.counts()["file_extension"] == 50
    assert log.as_dict()["truncated"] is True


def test_nothing_rejected_reads_as_nothing_rejected():
    assert DroppedLog().as_dict() == {
        "total": 0, "by_reason": {}, "entries": [], "truncated": False
    }


# ─────────────────────────────────────────────────────────────────────────────
# DomainValidator
# ─────────────────────────────────────────────────────────────────────────────

def test_a_real_domain_passes():
    assert why("example.com") is None
    assert why("evil-host.example.co.uk") is None


def test_one_off_three_ru_passes():
    """A real malicious domain in this deployment, and the reason the

    "reject any purely numeric label" rule could not be taken literally: its
    first label is `1`. Digits in a label are ordinary; a name made only of
    digits is not a name.
    """
    assert why("1.off3.ru") is None


def test_an_all_numeric_name_is_refused():
    assert why("192.168.1.co") == "purely_numeric_label"


def test_a_numeric_suffix_is_refused():
    assert why("10.0.17763.1") in {"version_string", "purely_numeric_label"}


def test_a_version_string_is_refused():
    assert why("v2.0.1") in {"version_string", "purely_numeric_label"}


def test_a_bare_word_is_refused():
    assert why("localhost") == "too_few_labels"


def test_an_illegal_label_is_refused():
    assert why("core.message_sent.com") == "malformed_label"
    assert why("a..b.com") == "malformed_label"


def test_a_file_is_refused_and_named_as_one():
    assert why("payload.exe") == "file_extension"
    assert why("Newtonsoft.Json.DLL") == "file_extension"


def test_an_unreal_suffix_is_refused():
    assert why("alert.category") == "no_public_suffix"


# ── context checks, on the masked text ──────────────────────────────────────

def test_a_field_path_is_refused_in_context():
    """`.email` is a genuine gTLD, so only the surroundings can tell."""
    text = '"legacyEventType":"core.user.email.message_sent.mfa_enroll"'
    assert why("core.user.email", text) == "field_path"


def test_user_email_alone_is_not_judged_without_context():
    """Standalone it is a legitimate domain shape and must not be guessed at."""
    assert why("user.email") is None


def test_a_filename_after_a_path_separator_is_refused():
    assert why("evil.dll", r"C:\Windows\evil.dll ran") == "file_extension"


def test_the_domain_half_of_an_email_is_refused():
    assert why("lineas.net", "herve.jarosinski@lineas.net") == "field_path"


def test_a_domain_ending_a_sentence_still_passes():
    """A dot then a space is punctuation, not another label."""
    assert why("example.com", "see example.com. Next line") is None


def test_a_cef_value_is_not_penalised_for_its_delimiter():
    """The constraint that makes this whole class work.

    36% of real indicators here sit immediately after `"` or `=`, because CEF
    and JSON put values there. Judging a candidate by the character in front of
    it would reject the values and keep the keys — exactly backwards.
    """
    assert why("evil.example.com", 'dvchost=evil.example.com end=1') is None
    assert why("evil.example.com", '"host": "evil.example.com"') is None


def test_ipv6_is_not_a_domain_and_is_not_claimed_as_one():
    """It must fall through to the IP pass, not be refused as a bad domain."""
    verdict = DOMAIN_VALIDATOR.check("2a06:98c1:54::1f:db3b")
    assert verdict.ok is False
    assert verdict.reason in REJECTION_REASONS


def test_a_cef_source_address_is_left_to_the_ip_pass():
    """`src=185.220.101.45` is an address; the domain validator must decline it."""
    assert why("185.220.101.45", "src=185.220.101.45 dst=10.0.0.1") == "purely_numeric_label"


def test_the_validator_holds_no_state_between_calls():
    """Determinism: the same question twice must give the same answer."""
    validator = DomainValidator()
    first = [validator.check(c).reason for c in ("example.com", "payload.exe", "1.off3.ru")]
    second = [validator.check(c).reason for c in ("example.com", "payload.exe", "1.off3.ru")]
    assert first == second
