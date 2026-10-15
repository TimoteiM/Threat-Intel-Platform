"""Which timestamp dates an email — and the three that must never.

Every test here is written in the dangerous direction: the failures are all
cases where a *plausible* anchor is available and must still be refused.
A missing anchor is visible; a forged one is a confident sentence.
"""

from datetime import datetime, timezone

import pytest

from app.services import absence
from app.services import email_anchor as ea

OURS = ["mail.ourcorp.example", "ourcorp-com.mail.protection.outlook.com"]

# A realistic chain, newest first, as `Message.get_all("Received")` returns it.
OUR_HOP = (
    "from NAM12-MW2-obe.outbound.protection.outlook.com (104.47.66.46) "
    "by mail.ourcorp.example (10.1.1.5) with Microsoft SMTP Server id "
    "15.2.1544.4; Thu, 15 Oct 2026 07:30:12 +0000"
)
OUR_EDGE = (
    "from mx-edge.outbound.example (1.2.3.4) by "
    "ourcorp-com.mail.protection.outlook.com (10.9.9.9) with Microsoft SMTP "
    "Server id 15.20.7000.9; Thu, 15 Oct 2026 07:28:40 +0000"
)
FOREIGN_HOP = (
    "from attacker-vps.example (unknown [185.9.9.9]) by "
    "mx.sender-side.example (Postfix) with ESMTPS id 4ABCDE; "
    "Thu, 15 Oct 2026 07:20:00 +0000"
)


def test_the_anchor_is_the_earliest_hop_our_own_infrastructure_wrote():
    resolved = ea.resolve_anchor(
        [OUR_HOP, OUR_EDGE, FOREIGN_HOP], own_mta_identities=OURS)
    assert not absence.is_absent(resolved)
    assert resolved["anchor"] == ea.ANCHOR_OWN_MTA
    # 07:28:40 — our edge, not 07:30:12 (later, ours) and not 07:20:00
    # (earlier, but written by the sender's side).
    assert resolved["at"] == datetime(2026, 10, 15, 7, 28, 40,
                                      tzinfo=timezone.utc)
    assert resolved["own_hops"] == 2
    assert resolved["trusted_prefix_ended_at"] == 2
    assert "ourcorp-com.mail.protection.outlook.com" in resolved["statement"]


def test_a_forged_hop_below_a_foreign_one_cannot_move_the_anchor():
    """The attack this function exists to refuse.

    Everything below the first foreign hop arrived with the message, so an
    attacker can write a header naming our own MX with any date they like. A
    `min()` over every header that matches our identity takes it, and the
    panel then reports a domain as resolved "4 months before this email".
    """
    forged = (
        "from nowhere.example by mail.ourcorp.example with ESMTP id FORGED; "
        "Mon, 01 Jun 2026 00:00:00 +0000"
    )
    resolved = ea.resolve_anchor(
        [OUR_HOP, OUR_EDGE, FOREIGN_HOP, forged], own_mta_identities=OURS)
    assert resolved["at"] == datetime(2026, 10, 15, 7, 28, 40,
                                      tzinfo=timezone.utc), (
        "a Received header below a foreign hop was trusted because it named us"
    )


def test_no_configured_identity_is_check_failed_and_never_the_date_header():
    resolved = ea.resolve_anchor(
        [OUR_HOP, FOREIGN_HOP], own_mta_identities=[],
        date_header="Thu, 15 Oct 2026 07:30:00 +0000")
    assert absence.is_absent(resolved)
    assert resolved["kind"] == absence.CHECK_FAILED
    assert "EMAIL_OWN_MTA_IDENTITIES" in resolved["reason"]
    assert "at" not in resolved, "a time was returned with no trusted source"


def test_a_chain_whose_newest_hop_is_not_ours_is_check_failed():
    """Not a search for ours further down: the trusted run starts at the top.

    If the most recent hop is not ours, the message did not reach us by a path
    we can see, and any header claiming us is below foreign ones.
    """
    resolved = ea.resolve_anchor(
        [FOREIGN_HOP, OUR_HOP], own_mta_identities=OURS)
    assert absence.is_absent(resolved)
    assert resolved["kind"] == absence.CHECK_FAILED
    assert "mx.sender-side.example" in resolved["reason"]


def test_no_received_headers_at_all_is_check_failed():
    resolved = ea.resolve_anchor([], own_mta_identities=OURS)
    assert absence.is_absent(resolved)
    assert resolved["kind"] == absence.CHECK_FAILED


def test_a_lookalike_identity_is_not_ours():
    """Suffix matching on a dot boundary.

    `notourcorp.example` ends with our identity as a substring. An unanchored
    `in` test is how an attacker-registered lookalike gets read as our own
    mail infrastructure — and then dates the message.
    """
    lookalike = (
        "from x by mail.ourcorp.example.notourcorp.example with ESMTP id Z; "
        "Thu, 15 Oct 2026 07:00:00 +0000"
    )
    resolved = ea.resolve_anchor([lookalike], own_mta_identities=OURS)
    assert absence.is_absent(resolved)


def test_a_dotted_prefix_of_our_domain_is_ours():
    assert ea._is_ours("mx1.mail.ourcorp.example", frozenset(OURS)) is True
    assert ea._is_ours("mail.ourcorp.example", frozenset(OURS)) is True
    assert ea._is_ours("evilourcorp.example", frozenset(OURS)) is False


def test_a_received_date_with_no_zone_is_not_an_anchor():
    """A floating timestamp is not a moment.

    Reading it as UTC is a silent error of up to fourteen hours, in the exact
    quantity the sentence reports as a gap.
    """
    floating = (
        "from x by mail.ourcorp.example with ESMTP id Q; "
        "Thu, 15 Oct 2026 07:30:12"
    )
    assert ea._received_timestamp(floating) is None
    resolved = ea.resolve_anchor([floating], own_mta_identities=OURS)
    assert absence.is_absent(resolved)


def test_the_timestamp_is_taken_after_the_last_semicolon():
    """`id` and `for` clauses contain semicolons on some stacks.

    Splitting on the first yields a fragment that parses to None — an absence
    manufactured by the parser rather than reported by the message.
    """
    header = (
        "from x by mail.ourcorp.example (envelope-from <a@b>; helo=x) with "
        "ESMTP id ab;cd; Thu, 15 Oct 2026 07:30:12 +0000"
    )
    assert ea._received_timestamp(header) == datetime(
        2026, 10, 15, 7, 30, 12, tzinfo=timezone.utc)


def test_a_trailing_parenthetical_after_the_date_is_tolerated():
    header = (
        "from x by mail.ourcorp.example with ESMTP id Q; "
        "Thu, 15 Oct 2026 07:30:12 +0000 (UTC)"
    )
    assert ea._received_timestamp(header) == datetime(
        2026, 10, 15, 7, 30, 12, tzinfo=timezone.utc)


def test_an_undated_hop_of_ours_does_not_end_the_trusted_run():
    """Ours but undated is not foreign. Treating it as the end of the run
    would discard the dated hops below it and report check_failed on a
    message we can perfectly well date."""
    undated = "from x by mail.ourcorp.example with ESMTP id Q"
    resolved = ea.resolve_anchor(
        [undated, OUR_EDGE, FOREIGN_HOP], own_mta_identities=OURS)
    assert not absence.is_absent(resolved)
    assert resolved["at"] == datetime(2026, 10, 15, 7, 28, 40,
                                      tzinfo=timezone.utc)
    assert resolved["own_hops"] == 1


def test_the_sender_date_is_reported_as_a_disagreement_not_used():
    resolved = ea.resolve_anchor(
        [OUR_HOP, OUR_EDGE, FOREIGN_HOP], own_mta_identities=OURS,
        date_header="Mon, 01 Jun 2026 00:00:00 +0000")
    assert resolved["anchor"] == ea.ANCHOR_OWN_MTA
    assert resolved["at"].month == 10, "the sender's Date displaced the anchor"
    assert resolved["sender_date_disagrees"] is True
    assert resolved["sender_date_skew_seconds"] > 0


def test_a_small_sender_skew_is_not_flagged():
    resolved = ea.resolve_anchor(
        [OUR_HOP, OUR_EDGE, FOREIGN_HOP], own_mta_identities=OURS,
        date_header="Thu, 15 Oct 2026 07:28:00 +0000")
    assert resolved["sender_date_disagrees"] is False


def test_an_unparseable_sender_date_does_not_break_the_anchor():
    resolved = ea.resolve_anchor(
        [OUR_HOP, OUR_EDGE, FOREIGN_HOP], own_mta_identities=OURS,
        date_header="not a date at all")
    assert resolved["anchor"] == ea.ANCHOR_OWN_MTA
    assert "sender_date_skew_seconds" not in resolved


@pytest.mark.parametrize("rejected", [ea.ANCHOR_DATE_HEADER,
                                      ea.ANCHOR_UPLOAD_TIME])
def test_the_rejected_anchors_are_named_with_their_reason(rejected):
    """Enumerated rather than merely absent.

    Both were used at some point: the upload time was reported as a receipt
    time on 2026-10-15. A rejected option with a written reason is harder to
    reintroduce than one that is simply not there.
    """
    assert rejected in ea.REJECTED_ANCHORS
    assert len(ea.REJECTED_ANCHORS[rejected]) > 40
    assert rejected != ea.ANCHOR_OWN_MTA


def test_anchor_statement_is_none_for_an_absence():
    """The estate lookup refuses a reference time with no statement, so this
    returning a string for a failed resolution would reinstate the bug."""
    failed = ea.resolve_anchor([], own_mta_identities=OURS)
    assert ea.anchor_statement(failed) is None
