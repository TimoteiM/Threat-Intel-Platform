"""
Does the message claim to be from someone it is not?

Business email compromise is the case every reputation and authentication check
misses: a real, newly-registered, correctly-configured domain passes SPF, DKIM
and DMARC, and nothing has been reported about it. The signal is the shape of
the identity, and it sits in headers the extractor already parsed.
"""

import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from app.services.email_sender_identity import analyse_sender_identity


def _ids(result):
    return {finding["id"] for finding in result["findings"]}


def test_a_display_name_claiming_a_brand_it_does_not_own_is_flagged():
    result = analyse_sender_identity({
        "sender_email": "billing@invoice-portal-updates.test",
        "sender_name": "Microsoft Account Team",
        "sender_domain": "invoice-portal-updates.test",
    })
    assert "display_name_brand_mismatch" in _ids(result)
    assert result["risk"] == "high"


def test_replies_routed_to_another_domain_are_flagged():
    """Redirecting the conversation is the core mechanic of BEC."""
    result = analyse_sender_identity({
        "sender_email": "finance@supplier.test",
        "sender_name": "Accounts",
        "reply_to": "payments@supplier-invoices.test",
        "sender_domain": "supplier.test",
    })
    assert "reply_to_divergence" in _ids(result)
    assert result["risk"] == "high"


def test_an_address_hidden_inside_the_display_name_is_flagged():
    """Mail clients show the friendly name; the real address is easy to miss."""
    result = analyse_sender_identity({
        "sender_email": "attacker@random.test",
        "sender_name": "IT Helpdesk <helpdesk@expertware.net>",
        "sender_domain": "random.test",
    })
    assert "display_name_contains_address" in _ids(result)
    assert result["risk"] == "high"


def test_a_typosquatted_sender_domain_is_flagged():
    result = analyse_sender_identity({
        "sender_email": "no-reply@micosoft.com",
        "sender_name": "Microsoft",
        "sender_domain": "micosoft.com",
    })
    assert "lookalike_sender_domain" in _ids(result)


def test_confusable_characters_in_the_sender_domain_are_flagged():
    """`pаypal.com` with a Cyrillic а renders identically to the real thing."""
    result = analyse_sender_identity({
        "sender_email": "support@pаypal.com",
        "sender_name": "PayPal",
        "sender_domain": "pаypal.com",
    })
    assert "confusable_sender_domain" in _ids(result)
    assert result["risk"] == "high"


def test_a_brand_claim_from_a_consumer_mailbox_is_weaker_than_a_lookalike_domain():
    """Still worth saying, but it is not the same as a domain built to deceive."""
    result = analyse_sender_identity({
        "sender_email": "ceo.office2024@gmail.com",
        "sender_name": "Microsoft Support",
        "sender_domain": "gmail.com",
    })
    assert result["risk"] == "medium"


def test_legitimate_brand_mail_produces_no_findings():
    """The check has to be quiet on real mail or nobody will trust it."""
    result = analyse_sender_identity({
        "sender_email": "no-reply@microsoft.com",
        "sender_name": "Microsoft",
        "sender_domain": "microsoft.com",
    })
    assert result["findings"] == []
    assert result["risk"] == "none"


def test_a_bulk_senders_bounce_address_is_only_a_weak_signal():
    """
    Return-Path on the ESP's domain is how every mailing list works.

    Treating it as suspicious on its own would flag every newsletter, so it is
    reported at low severity and never raises the overall risk by itself.
    """
    result = analyse_sender_identity({
        "sender_email": "news@socprime.com",
        "sender_name": "SOC Prime",
        "return_path": "bounce@sendgrid.net",
        "sender_domain": "socprime.com",
    })
    assert _ids(result) == {"return_path_divergence"}
    assert result["risk"] == "low"


def test_a_subdomain_of_the_brand_is_not_a_mismatch():
    result = analyse_sender_identity({
        "sender_email": "noreply@email.microsoft.com",
        "sender_name": "Microsoft 365",
        "sender_domain": "email.microsoft.com",
    })
    assert result["risk"] == "none"
