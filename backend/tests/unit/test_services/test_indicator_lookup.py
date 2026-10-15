"""Type detection and routing for the on-demand indicator lookup.

The two things that make this feature safe rather than dangerous:

1. **Detection is shown, and a near-miss is refused.** A mistyped hash is a
   syntactically valid hostname, so routing it as one asks Falcon "is a
   machine called this?", gets a true negative, and renders "not found" — the
   wrong question answered correctly.
2. **Every source, for every kind, renders an answer, a named absence, or a
   statement that it cannot be asked.** A source shown an empty section where
   it has no field to look in is false exculpation with a search box on it.
"""

from __future__ import annotations

import pytest

from app.services import absence
from app.services import indicator_lookup_service as ind


# --- detection -------------------------------------------------------------


@pytest.mark.parametrize("value,kind", [
    ("a" * 64, ind.SHA256),
    ("A" * 64, ind.SHA256),
    ("b" * 40, ind.SHA1),
    ("c" * 32, ind.MD5),
    ("d41d8cd98f00b204e9800998ecf8427e", ind.MD5),
])
def test_digest_lengths_are_detected_before_anything_else(value, kind):
    """Order matters: a 32-character hex string is also a valid hostname."""
    assert ind.detect(value)["kind"] == kind


def test_a_near_miss_hash_is_refused_rather_than_read_as_a_hostname():
    """The case this guard exists for.

    31 hex characters is one short of an MD5 and a perfectly good machine
    name. Routed as a hostname it produces a confident answer to a question
    nobody asked.
    """
    out = ind.detect("d41d8cd98f00b204e9800998ecf8427")   # 31
    assert out["kind"] == ind.UNPARSED
    assert "31 hexadecimal characters" in out["reason"]
    assert "SHA-256 is 64" in out["reason"]
    assert "mistyped hash" in out["reason"]


@pytest.mark.parametrize("length", [16, 31, 33, 39, 41, 63, 65, 128])
def test_no_hex_string_of_a_non_digest_length_becomes_a_hostname(length):
    assert ind.detect("a" * length)["kind"] == ind.UNPARSED


def test_a_short_hex_string_is_still_allowed_to_be_a_hostname():
    """The control on the rule above: it must not swallow every hex-ish name.
    `abc` is a plausible machine name and nobody's hash."""
    assert ind.detect("abc")["kind"] == ind.HOSTNAME


@pytest.mark.parametrize("value", ["10.66.66.12", "8.8.8.8", "2001:db8::1"])
def test_addresses_are_parsed_not_pattern_matched(value):
    out = ind.detect(value)
    assert out["kind"] == ind.IP
    assert "parsed as an IPv" in out["how"]


def test_a_private_address_is_flagged_as_such():
    assert ind.detect("10.66.66.12")["is_private"] is True
    assert ind.detect("8.8.8.8")["is_private"] is False


@pytest.mark.parametrize("value", [
    "https://evil.test/a?b=c", "http://x.test", "ftp://host.test/f",
])
def test_urls_are_detected_by_scheme(value):
    assert ind.detect(value)["kind"] == ind.URL


def test_a_dotted_name_is_a_domain_and_a_bare_name_is_a_host():
    assert ind.detect("aka.ms")["kind"] == ind.DOMAIN
    assert ind.detect("em.caseware.com")["kind"] == ind.DOMAIN
    # The estate's own hosts look like this.
    assert ind.detect("EXP-22MY264")["kind"] == ind.HOSTNAME
    assert ind.detect("DC")["kind"] == ind.HOSTNAME


def test_detection_reports_how_it_decided():
    """Shown, not assumed — the reader has to be able to catch a misroute."""
    for value in ("aka.ms", "EXP-1", "8.8.8.8", "a" * 64):
        out = ind.detect(value)
        assert out.get("how"), f"{value!r} did not say how it was detected"


@pytest.mark.parametrize("value", ["", "   ", "!!!", "a b c", "-"])
def test_nothing_unrecognisable_is_guessed_at(value):
    out = ind.detect(value)
    assert out["kind"] == ind.UNPARSED
    assert out["reason"]


def test_whitespace_is_stripped_and_case_normalised_where_it_is_safe():
    assert ind.detect("  AKA.MS  ")["value"] == "aka.ms"
    assert ind.detect("  " + "A" * 64 + " ")["value"] == "a" * 64
    # A hostname's case is NOT normalised: Falcon matches it case-insensitively
    # but the value is shown back to the reader, who typed it.
    assert ind.detect("EXP-22MY264")["value"] == "EXP-22MY264"


# --- routing ---------------------------------------------------------------


def test_every_kind_has_a_decision_for_every_source():
    """The silent-registry guard.

    A kind added without a decision per source gets an empty section, which
    reads as "that source found nothing". This fails instead.
    """
    kinds = {ind.SHA256, ind.SHA1, ind.MD5, ind.IP, ind.URL, ind.DOMAIN,
             ind.HOSTNAME, ind.UNPARSED}
    assert kinds == set(ind.ROUTING), (
        f"routing table and kinds disagree: "
        f"{kinds ^ set(ind.ROUTING)} has no decision"
    )
    for kind, row in ind.ROUTING.items():
        for source in ind.SOURCES:
            assert source in row, f"{kind} has no decision for {source}"


def test_an_unknown_kind_raises_rather_than_asking_everything():
    with pytest.raises(KeyError) as caught:
        ind.plan("something_new")
    assert "no routing decision" in str(caught.value)


def test_a_domain_is_never_asked_of_falcon_and_says_why():
    """Measured: no Falcon alert field holds a domain. An empty Falcon section
    for a domain would mean the field, not the domain."""
    decision = ind.plan(ind.DOMAIN)["falcon"]
    assert decision is not ind.ASK
    rendered = ind.refusal(decision, raw=ind.DOMAIN)
    assert rendered["kind"] == absence.NO_FIELD_MAP
    assert "data_domains" in rendered["reason"]
    assert "403" in rendered["reason"]


def test_an_ip_is_out_of_scope_for_falcon_with_the_structural_reason():
    """Not `no_field_map`: the fields exist and cannot match. Different claim,
    different wording."""
    rendered = ind.refusal(ind.plan(ind.IP)["falcon"], raw=ind.IP)
    assert rendered["kind"] == absence.OUT_OF_SCOPE
    assert "source_ips" in rendered["reason"]
    assert "local_ip" in rendered["reason"]
    assert "structurally" in rendered["reason"]


def test_a_url_is_out_of_scope_for_the_estate_with_the_proxy_log_reason():
    rendered = ind.refusal(ind.plan(ind.URL)["estate"], raw=ind.URL)
    assert rendered["kind"] == absence.OUT_OF_SCOPE
    assert "no proxy logs" in rendered["reason"]


def test_a_urls_host_is_offered_as_the_narrower_claim_and_labelled():
    """Offered, never substituted. "A host resolved this name" is not "a host
    fetched this URL"."""
    out = ind.url_fallback("https://evil.test/path?q=1")
    assert out["asked_instead"] == "evil.test"
    assert out["kind"] == ind.DOMAIN
    assert "narrower claim" in out["claim"]
    assert "not whether anything fetched" in out["claim"]


def test_a_url_with_no_host_offers_no_fallback():
    assert ind.url_fallback("https://") == {}


def test_hashes_go_to_falcon_and_not_to_the_estate():
    for kind in (ind.SHA256, ind.SHA1, ind.MD5):
        row = ind.plan(kind)
        assert row["falcon"] is ind.ASK
        assert row["estate"] is not ind.ASK
        assert ind.refusal(row["estate"])["kind"] == absence.OUT_OF_SCOPE


def test_a_hostname_goes_to_falcon_devices_and_not_to_estate_dns():
    row = ind.plan(ind.HOSTNAME)
    assert row["falcon"] is ind.ASK
    rendered = ind.refusal(row["estate"], raw=ind.HOSTNAME)
    assert rendered["kind"] == absence.OUT_OF_SCOPE
    assert "names a host" in rendered["reason"]


def test_an_unparsed_value_is_asked_of_nothing():
    row = ind.plan(ind.UNPARSED)
    assert all(v is not ind.ASK for v in row.values())
    for source in ind.SOURCES:
        assert ind.refusal(row[source])["kind"] == absence.UNPARSED


def test_at_least_one_source_is_asked_for_every_usable_kind():
    """A usable kind that nothing can answer is a kind that should not be
    offered. This catches a routing table that refuses everything."""
    for kind in set(ind.ROUTING) - {ind.UNPARSED, ind.URL}:
        row = ind.plan(kind)
        assert any(v is ind.ASK for v in row.values()), (
            f"{kind} is refused by every source, so it has no answer at all"
        )
