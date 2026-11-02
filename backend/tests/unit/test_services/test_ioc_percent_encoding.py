"""Percent-encoded text must be read as what it means, not as what it spells.

A Cloudflare log line carrying `cf_user_email=herve.jarosinski%40lineas.net`
produced the domain `40lineas.net`: the matcher split on the literal `%40`, took
the `40` as a first label, and sent a host that does not exist for full
investigation. Both real indicators — the address, and lineas.net — were missed.

Measured across 4,216 stored alert bodies, that fabricated domain had been
extracted 13 times and `2fartel-solutions.biz` (from `%2F`, a slash) twice.
"""

from __future__ import annotations

import pytest

from app.services.alert_ioc_extraction_service import (
    extract_alert_indicators,
    percent_decode,
)


def extracted(text: str) -> set[tuple[str, str]]:
    return {
        (i["type"], i["value"])
        for i in (extract_alert_indicators(text, max_indicators=50).get("indicators") or [])
    }


# —— the reported bug ——————————————————————————————————————————————————————

def test_an_encoded_at_sign_does_not_invent_a_domain():
    found = extracted("cf_user_email=herve.jarosinski%40lineas.net&cf_rule_id=00fa")
    assert ("domain", "40lineas.net") not in found, "the fabricated host"
    assert ("email", "herve.jarosinski@lineas.net") in found
    assert ("domain", "lineas.net") in found


def test_an_encoded_slash_does_not_invent_a_domain():
    found = extracted("cf_site_uri=https%3A%2F%2Fartel-solutions.biz/x")
    assert ("domain", "2fartel-solutions.biz") not in found
    assert ("url", "https://artel-solutions.biz/x") in found


def test_a_value_encoded_in_transit_is_reported_as_defanged():
    """It was not written literally, and the report should say so."""
    result = extract_alert_indicators("u=a.b%40example.com", max_indicators=20)
    email = [i for i in result["indicators"] if i["type"] == "email"][0]
    assert email["defanged_in_source"] is True


# —— what decoding must not do ——————————————————————————————————————————————

def test_a_plus_is_not_turned_into_a_space():
    """These lines are logs, not form posts. unquote_plus would mangle them."""
    assert percent_decode("file+name.exe") == "file+name.exe"


def test_an_invalid_escape_is_left_exactly_as_it_was():
    for text in ("100%complete", "50% off", "%zz", "%4", "ends with %"):
        assert percent_decode(text) == text


def test_control_characters_are_not_decoded():
    """A %00 in a log is noise; decoding it would corrupt the line."""
    assert percent_decode("a%00b") == "a%00b"
    assert percent_decode("a%0Ab") == "a%0Ab"


def test_text_without_a_percent_is_returned_unchanged():
    body = "nothing to decode here"
    assert percent_decode(body) is body or percent_decode(body) == body


def test_empty_input_is_safe():
    assert percent_decode("") == ""
    assert percent_decode(None) == ""


@pytest.mark.parametrize("encoded,decoded", [
    ("%40", "@"), ("%2F", "/"), ("%3A", ":"), ("%2f", "/"), ("%20", " "),
])
def test_the_escapes_that_matter_decode(encoded, decoded):
    assert percent_decode(f"x{encoded}y") == f"x{decoded}y"


def test_a_powershell_property_is_still_not_a_domain():
    """ExecutionContext.Run is a language construct, not a .run host."""
    assert ("domain", "executioncontext.run") not in extracted(
        "if ($ExecutionContext.Run(x)) { }"
    )


# —— a dotted identifier is not a domain ——————————————————————————————————

def test_an_okta_event_type_is_not_a_domain():
    """`core.user.email.message_sent.mfa_enroll_notification`.

    The matcher stopped at `core.user.email`, which passed validation because
    `.email` is a real gTLD, and the registrable-domain collapse turned it into
    `user.email` — a field path sent for investigation as a host.
    """
    found = extracted('"legacyEventType":"core.user.email.message_sent.mfa_enroll_notification"')
    assert not [v for t, v in found if t == "domain"]


def test_a_cef_field_value_is_not_a_domain():
    found = extracted("flexString1=system.email.mfa_enroll_notification.sent_message")
    assert ("domain", "system.email") not in found


def test_an_oauth_scope_is_not_a_domain():
    assert not [v for t, v in extracted("scopes=Authenticators.Read.All") if t == "domain"]


def test_a_real_domain_still_extracts():
    assert ("domain", "example.com") in extracted("connect to evil-host.example.com now")


def test_a_domain_at_the_end_of_a_sentence_still_extracts():
    """A dot followed by a space is punctuation, not another label."""
    assert ("domain", "example.com") in extracted("see example.com. Next line")


def test_a_multi_label_suffix_still_extracts():
    assert ("url", "https://sub.example.co.uk/path?a=1") in extracted(
        "https://sub.example.co.uk/path?a=1"
    )
