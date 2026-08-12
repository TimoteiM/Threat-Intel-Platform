"""
Which URLs in an email earn an external lookup, and which are answered locally.

The numbers in these tests come from this platform's own corpus: 98 emails,
1,706 URL instances, 449 domain mentions, 39 unique domains. Checking each URL
spent ~20 VirusTotal requests per email to re-learn the same handful of facts.
"""

import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services.email_url_triage import triage_email_urls, unwrap_url


# ── Unwrapping ────────────────────────────────────────────────────────────────


def test_microsoft_safe_links_resolves_to_the_real_destination():
    """
    The wrapper is always Microsoft, so checking it can only ever return clean.

    44 of the corpus's 98 emails carried Safe Links. Every one of them was being
    checked as `safelinks.protection.outlook.com` — a reputation lookup on
    Microsoft, not on the link the recipient would land on.
    """
    destination, wrapper = unwrap_url(
        "https://eur04.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fevil-login%2Ecom%2Fverify%3Fid%3D9&data=05%7C02"
    )
    assert destination == "https://evil-login.com/verify?id=9"
    assert wrapper == "eur04.safelinks.protection.outlook.com"


def test_proofpoint_urldefense_encodes_the_target_in_the_path():
    destination, wrapper = unwrap_url("https://urldefense.com/v3/__https://phish.example/login__;!!abc$")
    assert destination == "https://phish.example/login"
    assert wrapper == "urldefense.com"


def test_a_link_wrapped_twice_is_unwrapped_to_the_end():
    destination, _ = unwrap_url(
        "https://eur04.safelinks.protection.outlook.com/?url="
        "https%3A%2F%2Furldefense.com%2Fv3%2F__https%3A%2F%2Freal-phish.test%2Fgo__%3B%21%21x"
    )
    assert destination == "https://real-phish.test/go"


def test_an_ordinary_link_is_left_exactly_as_it_was():
    destination, wrapper = unwrap_url("https://legitimate.example/newsletter/article")
    assert destination == "https://legitimate.example/newsletter/article"
    assert wrapper is None


# ── Triage ────────────────────────────────────────────────────────────────────


def test_many_urls_on_one_host_become_one_question():
    """106 URLs across 5 destinations is 5 questions, not 106."""
    urls = [f"https://news.example/article/{n}" for n in range(40)]
    result = triage_email_urls(urls, sender_domain="sender.test", budget=6)
    assert result["summary"]["urls_in_email"] == 40
    assert result["summary"]["distinct_destinations"] == 1
    assert result["summary"]["looked_up"] == 1


def test_xml_namespace_urls_are_not_treated_as_links():
    """Office HTML declares namespaces as http:// URIs. Nothing ever fetches them."""
    result = triage_email_urls(
        [
            "http://www.w3.org/1999/xhtml",
            "http://schemas.microsoft.com/office/2004/12/omml",
            "https://real-destination.test/offer",
        ],
        sender_domain="sender.test",
    )
    assert result["summary"]["markup_artefacts_dropped"] == 2
    assert [entry.domain for entry in result["selected"]] == ["real-destination.test"]


def test_bulk_mail_infrastructure_is_recognised_rather_than_looked_up():
    """A verdict on Mailchimp describes the sender's mailer, not the email."""
    result = triage_email_urls(
        [
            "https://track.list-manage.com/click/abc",
            "https://fonts.googleapis.com/css?family=Inter",
            "https://unknown-destination.test/pay",
        ],
        sender_domain="sender.test",
    )
    assert result["summary"]["recognised_infrastructure"] == 2
    assert [entry.domain for entry in result["selected"]] == ["unknown-destination.test"]


def test_the_riskiest_destinations_are_the_ones_that_get_the_budget():
    result = triage_email_urls(
        [
            "https://sender.test/about",                 # the sender's own site
            "https://plain-marketing.test/news",
            "https://bit.ly/xyz",                        # hides its destination
            "https://secure-account.test/login/verify",  # credential path
        ],
        sender_domain="sender.test",
        budget=2,
    )
    chosen = [entry.domain for entry in result["selected"]]
    assert "bit.ly" in chosen
    assert "secure-account.test" in chosen
    assert result["summary"]["deferred_over_budget"] == 2


def test_what_was_not_checked_is_still_reported():
    """
    A budget that hides its own decisions is indistinguishable from a miss.

    Everything skipped stays in the output with the reason, so an analyst can
    see the difference between "clean" and "not looked at".
    """
    urls = [f"https://host{n}.test/page" for n in range(10)]
    result = triage_email_urls(urls, sender_domain="sender.test", budget=3)
    assert result["summary"]["looked_up"] == 3
    assert result["summary"]["deferred_over_budget"] == 7
    assert len(result["deferred"]) == 7
    assert all(entry.domain for entry in result["deferred"])


def test_an_unwrapped_destination_outranks_ordinary_links():
    """Something thought this link needed rewriting; the destination is the point."""
    result = triage_email_urls(
        [
            "https://ordinary-marketing.test/page",
            "https://eur04.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwrapped-target.test%2Fgo",
        ],
        sender_domain="sender.test",
        budget=1,
    )
    assert [entry.domain for entry in result["selected"]] == ["wrapped-target.test"]
    assert result["selected"][0].unwrapped_from == "eur04.safelinks.protection.outlook.com"


def test_a_bare_ip_and_a_punycode_host_are_always_prioritised():
    result = triage_email_urls(
        [
            "https://normal-site.test/a",
            "http://192.0.2.44/login",
            "https://xn--80ak6aa92e.test/account",
        ],
        sender_domain="sender.test",
        budget=2,
    )
    chosen = {entry.domain for entry in result["selected"]}
    assert "192.0.2.44" in chosen
    assert "xn--80ak6aa92e.test" in chosen
