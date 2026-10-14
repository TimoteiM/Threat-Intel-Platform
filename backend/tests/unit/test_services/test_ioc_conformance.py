"""Does a stored value parse as the type it claims to be?

One structural assertion replacing an indefinite series of discoveries. Ten
delimiter-and-shape defects were found in this corpus one at a time, each
after it had already distorted something.

The dangerous direction is **rejecting a real observable**. A validator that
refuses too much turns working enrichment into silent absences, which is the
failure every other test in this suite exists to prevent — so every defect
class below is paired with a control: a genuine value of that type that must
pass.

And two of the four cited defect classes are **not** caught, deliberately
and with reasons. They are asserted as passing, because a test file that
implied otherwise would be the more expensive error.
"""

from __future__ import annotations

import pytest

from app.services.ioc_conformance_service import check, infer_type


# ─── what it catches ─────────────────────────────────────────────────────

@pytest.mark.parametrize("value,kind", [
    # The silent-negative generator. `::ffff:192` parses as a VALID IPv6
    # address (::ffff:0.0.0.192), so it is not the address it came from —
    # every lookup returns nothing found, which reads as clean.
    ("::ffff:192", "mapped_ipv4_truncated"),
    ("::ffff:10", "mapped_ipv4_truncated"),
    ("::ffff:172", "mapped_ipv4_truncated"),
    ("::ffff:52", "mapped_ipv4_truncated"),
    ("not-an-ip", "not_an_address"),
    ("127.0.0.1", "unroutable_as_indicator"),
    ("0.0.0.0", "unroutable_as_indicator"),
])
def test_an_ip_that_is_not_an_address(value, kind):
    nc = check("ip", value)
    assert nc is not None and nc.kind == kind


@pytest.mark.parametrize("value,kind", [
    ("00000000000000000000000000000000", "degenerate"),
    ("f" * 64, "degenerate"),
    ("abc", "wrong_length"),
    ("a" * 33, "wrong_length"),
    ("tls.cert_sha256:81101cf4a7d226dcda9a2951b4dc6371", "not_hex"),
    ("224.0.0.251", "not_hex"),
])
def test_a_hash_that_is_not_a_hash(value, kind):
    nc = check("hash", value)
    assert nc is not None and nc.kind == kind


@pytest.mark.parametrize("value,kind", [
    ("192.168.21.18", "address_as_domain"),
    ("2a02:2350:6::fb15:59af", "single_label"),
    ("localhost", "single_label"),
    ("cert_sha256:9fde822f7a2e2cbf932ecb32a1bb9928", "single_label"),
    ("cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js", "not_a_domain"),
    ("CN=evantage.eu (TLS subject)", "no_public_suffix"),
    ("description.@metadata.beat", "no_public_suffix"),
    ("accrt-coastnorth-5.amazonaws.com-we-hospital", "no_public_suffix"),
])
def test_a_domain_that_is_not_a_domain(value, kind):
    nc = check("domain", value)
    assert nc is not None and nc.kind == kind


@pytest.mark.parametrize("value,kind", [
    ("olx.ro-confirm.site/v5BclV", "no_scheme"),
    ("lb.eu-1-id5-sync.com/lb/v1", "no_scheme"),
    ("ldap://pov05.povgrp.oost-vlaanderen.be/cn=", "non_web_scheme"),
])
def test_a_url_that_is_not_a_url(value, kind):
    nc = check("url", value)
    assert nc is not None and nc.kind == kind


# ─── the controls: a real observable must pass ──────────────────────────

@pytest.mark.parametrize("ioc_type,value", [
    ("ip", "185.30.254.124"),
    ("ip", "8.8.8.8"),
    ("ip", "2a02:2350:6:1:2:3:4:5"),
    ("hash", "7df64ae9a0def9c161dcc89b5b6cfc87"),
    # A real sha256 — 64 hex characters. The first version of this fixture
    # had 65 and the check correctly refused it, which is the control
    # working on the test rather than the subject.
    ("hash", "398a72f0a6999794a7e3de0e16a3413f118ea3bc12341d664e2b7a8402f34b4e"),
    ("domain", "expertware.net"),
    ("domain", "nlahtc.theluxehomeoffice.com"),
    ("domain", "grupobiopar.com.br"),
    ("domain", "raw.githubusercontent.com"),
    ("url", "https://login.lineas.net"),
    ("url", "http://sdoffice.com.br/wp-content/plugins/verify/proxy.php"),
])
def test_a_genuine_observable_is_not_rejected(ioc_type, value):
    """The direction that does damage. A validator refusing real values
    turns working enrichment into silent absences."""
    assert check(ioc_type, value) is None


def test_an_unknown_type_is_not_a_defect():
    """A type this check has never been taught must not be reported as
    nonconforming — that would be the absence convention's own failure mode
    committed inside a validator."""
    assert check("email", "someone@example.com") is None
    assert check("registry_key", r"HKLM\Software\Foo") is None
    assert check("", "anything") is None


# ─── the two it does NOT catch, and why ─────────────────────────────────

def test_a_version_string_that_is_a_valid_address_passes():
    """`6.0.4.27` was cited as one of four classes this check would catch.
    It does not, and cannot.

    6.0.0.0/8 is allocated and routable, so `6.0.4.27` is a syntactically
    and semantically valid public IPv4 address. **Nothing structural can
    distinguish it from a real one** — the evidence that it is a version
    string is contextual: it appears beside a product name in the alert
    body, not in the value.

    So this is not a type-conformance failure. It is semantic
    misclassification — a valid value of its type that is not an
    observable — and it needs a different assertion with different
    evidence. Asserted here so the limit is recorded rather than assumed
    away.
    """
    assert check("ip", "6.0.4.27") is None
    assert check("ip", "2.0.57.0") is None


def test_a_namespace_url_that_is_a_valid_url_passes():
    """The second of the two. A schema URL is a well-formed http URL with a
    host under a real public suffix; it is simply never fetched. Structure
    cannot reach that, and a list of namespace hosts would be the ninth
    hand-maintained list."""
    assert check("url", "http://schemas.microsoft.com/win/2004/08/events/event") is None
    assert check("url", "http://schemas.xmlsoap.org/soap/envelope/") is None


# ─── the inferred-type path, for the untyped array ──────────────────────

@pytest.mark.parametrize("value,expected", [
    ("https://example.com/p", "url"),
    ("::ffff:192", "ip"),
    ("2a02:2350:6::fb15:59af", "ip"),
    ("185.30.254.124", "ip"),
    ("00000000000000000000000000000000", "hash"),
    ("expertware.net", "domain"),
])
def test_type_inference_for_untyped_values(value, expected):
    assert infer_type(value) == expected


@pytest.mark.parametrize("value", ["", "   ", "a single word", "CN=x (TLS)"])
def test_an_ambiguous_value_is_skipped_rather_than_guessed(value):
    """`ioc_values` has no type column, so the claim is inferred. Anything
    ambiguous returns None and is not checked — which makes the sweep's
    counts a FLOOR rather than a number inflated by guessing."""
    assert infer_type(value) is None
