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


# ---------------------------------------------------------------------------
# Hosted mail: the receiving MTA belongs to the provider, not to us.
#
# This is the half that makes the whole mechanism safe or useless. Under M365
# the inbound host is `<tenant>.mail.protection.outlook.com`, and the suffix
# is identical for every Microsoft tenant on earth. A phisher sending from
# their own M365 tenant produces a chain of hops that ALL match that suffix,
# so the trusted run never meets a foreign hop, walks the length of the
# attacker's infrastructure, and reads a header they wrote as one of ours.


M365_OURS = "ourcorp-com.mail.protection.outlook.com"
M365_THEIRS = "attackerco-com.mail.protection.outlook.com"


def _m365_hop(by, when, frm="mail-am6eur05on2103.outbound.protection.outlook.com"):
    return (f"from {frm} ([40.107.22.103]) by {by} (10.1.1.5) with Microsoft "
            f"SMTP Server id 15.20.7000.9; {when}")


def test_a_shared_provider_suffix_is_refused_as_an_identity():
    """The configuration that quietly trusts every Microsoft tenant."""
    resolved = ea.resolve_anchor(
        [_m365_hop(M365_OURS, "Thu, 15 Oct 2026 07:28:40 +0000")],
        own_mta_identities=["mail.protection.outlook.com"])
    assert absence.is_absent(resolved)
    assert resolved["kind"] == absence.CHECK_FAILED
    assert "shared with every" in resolved["reason"]
    assert "tenant-qualified" in resolved["reason"]


@pytest.mark.parametrize("entry", [
    "mail.protection.outlook.com",
    "protection.outlook.com",
    "outlook.com",
    "google.com",
    "googlemail.com",
    "mimecast.com",
    "pphosted.com",
    "com",                       # a bare parent of every suffix
])
def test_provider_and_parent_suffixes_are_all_caught(entry):
    assert ea.over_broad_identities([entry]) == [entry]


@pytest.mark.parametrize("entry", [
    M365_OURS,
    "mail.ourcorp.example",
    "ourcorp.example",
    "mx1-eu.pphosted.com",       # customer-specific Proofpoint host
])
def test_a_tenant_qualified_host_is_not_over_broad(entry):
    assert ea.over_broad_identities([entry]) == []


def test_one_over_broad_entry_poisons_the_whole_list():
    """Not partially honoured.

    Dropping the bad entry and proceeding on the good one leaves an operator
    believing the list is what they wrote, and the next person widens it
    again. The refusal names the entry.
    """
    resolved = ea.resolve_anchor(
        [_m365_hop(M365_OURS, "Thu, 15 Oct 2026 07:28:40 +0000"), FOREIGN_HOP],
        own_mta_identities=[M365_OURS, "outlook.com"])
    assert absence.is_absent(resolved)
    assert "outlook.com" in (resolved.get("raw") or "")


def test_a_tenant_qualified_identity_does_not_match_another_m365_tenant():
    """The attack the tenant label prevents.

    The whole chain is Microsoft 365, so a suffix identity matches every hop.
    With the tenant-qualified host the attacker's own inbound hop is foreign,
    which both bounds the run and — here — ends it immediately, because the
    topmost hop is theirs.
    """
    chain = [
        _m365_hop(M365_THEIRS, "Mon, 01 Jun 2026 00:00:00 +0000"),
        _m365_hop(M365_THEIRS, "Mon, 01 Jun 2026 00:00:00 +0000"),
    ]
    resolved = ea.resolve_anchor(chain, own_mta_identities=[M365_OURS])
    assert absence.is_absent(resolved)
    assert M365_THEIRS in resolved["reason"]


def test_an_all_internal_chain_with_no_foreign_hop_is_check_failed():
    """M365-to-M365 internal, and the case that must not become an
    unbounded run.

    An internal message and a chain that matched someone else's
    infrastructure all the way down are indistinguishable from the chain
    alone. An unbounded run returns the bottom-most hop, which on a forged
    chain is the attacker's chosen timestamp wearing our name.

    The cost is accepted and real: internal-origin mail — a compromised
    account — gets no before/after sentence.
    """
    chain = [
        _m365_hop(M365_OURS, "Thu, 15 Oct 2026 07:30:12 +0000"),
        _m365_hop(M365_OURS, "Thu, 15 Oct 2026 07:28:40 +0000"),
        _m365_hop(M365_OURS, "Mon, 01 Jun 2026 00:00:00 +0000"),   # the bait
    ]
    resolved = ea.resolve_anchor(chain, own_mta_identities=[M365_OURS])
    assert absence.is_absent(resolved), (
        "an unbounded trusted run returned an arrival time"
    )
    assert resolved["kind"] == absence.CHECK_FAILED
    assert "no end" in resolved["reason"]


def test_a_bounded_m365_chain_resolves_to_our_inbound_hop():
    """The normal case: external sender, our tenant-qualified hop on top."""
    chain = [
        _m365_hop(M365_OURS, "Thu, 15 Oct 2026 07:28:40 +0000"),
        FOREIGN_HOP,
    ]
    resolved = ea.resolve_anchor(chain, own_mta_identities=[M365_OURS])
    assert not absence.is_absent(resolved)
    assert resolved["at"] == datetime(2026, 10, 15, 7, 28, 40,
                                      tzinfo=timezone.utc)
    assert resolved["written_by"] == M365_OURS


def test_the_platform_is_named_before_any_suffix_is_proposed():
    p = ea.describe_platform([M365_OURS, "mx.sender-side.example"])
    assert "Microsoft 365" in p["platform"]
    assert p["tenant_qualified_identity_available"] is True
    assert "tenant label" in p["note"]


def test_google_workspace_has_no_tenant_qualified_host_to_configure():
    """So Workspace gets check_failed, not a broader suffix.

    Workspace inbound hops are `mx.google.com` for every customer. There is
    no tenant label, so this anchor cannot be configured safely at all — the
    honest outcome is no sentence rather than trusting all of Google.
    """
    p = ea.describe_platform(["mx.google.com"])
    assert "Google Workspace" in p["platform"]
    assert p["tenant_qualified_identity_available"] is False
    assert ea.over_broad_identities(["google.com", "mx.google.com"]) == \
        ["google.com"]


def test_self_hosted_mail_is_recognised_as_configurable():
    p = ea.describe_platform(["mail.ourcorp.example"])
    assert p["tenant_qualified_identity_available"] is True
    assert p["shared_suffix"] is None


# ---------------------------------------------------------------------------
# The shape a REAL M365 chain has, which no synthetic chain above had.


M365_INTERNAL_A = (
    "from AM6PR05MB1234.eurprd05.prod.outlook.com (2603:10a6::1) by "
    "AM0PR05MB4567.eurprd05.prod.outlook.com (2603:10a6::9) with Microsoft "
    "SMTP Server id 15.20.7000.9; Thu, 15 Oct 2026 07:30:12 +0000"
)
M365_INTERNAL_B = (
    "from AM0PR05MB9999.eurprd05.prod.outlook.com (2603:10a6::4) by "
    "AM6PR05MB1234.eurprd05.prod.outlook.com (2603:10a6::1) with Microsoft "
    "SMTP Server id 15.20.7000.9; Thu, 15 Oct 2026 07:29:50 +0000"
)


def test_internal_exchange_hops_above_our_gateway_do_not_end_the_run():
    """The defect a real chain exposed.

    Hop 0 of a genuine M365 message is an internal mailbox-server hop, not
    the inbound gateway. Requiring hop 0 to be identifiably ours refused
    every real Microsoft 365 message — the common case — while passing every
    synthetic chain written with our gateway on top.
    """
    chain = [M365_INTERNAL_A, M365_INTERNAL_B,
             _m365_hop(M365_OURS, "Thu, 15 Oct 2026 07:28:40 +0000"),
             FOREIGN_HOP]
    resolved = ea.resolve_anchor(chain, own_mta_identities=[M365_OURS])
    assert not absence.is_absent(resolved), resolved.get("reason")
    assert resolved["at"] == datetime(2026, 10, 15, 7, 28, 40,
                                      tzinfo=timezone.utc)
    assert resolved["written_by"] == M365_OURS
    assert resolved["provider_internal_hops_above"] == 2
    assert resolved["own_hops"] == 1
    assert resolved["trusted_prefix_ended_at"] == 3


def test_an_internal_hop_cannot_itself_be_the_anchor():
    """`*.prod.outlook.com` is shared across every Microsoft tenant.

    It is trusted only for its POSITION — above our gateway, so written by
    our provider after delivery. If it could anchor, a chain with no
    identifiable hop of ours would still produce a time, and the tenant
    label would stop meaning anything.
    """
    chain = [M365_INTERNAL_A, M365_INTERNAL_B, FOREIGN_HOP]
    resolved = ea.resolve_anchor(chain, own_mta_identities=[M365_OURS])
    assert absence.is_absent(resolved)
    assert resolved["kind"] == absence.CHECK_FAILED
    assert "shared provider-internal" in resolved["reason"]
    assert "mx.sender-side.example" in resolved["reason"]


def test_the_walk_does_not_cross_into_a_sending_tenants_gateway():
    """Why `mail.protection.outlook.com` is not a post-receipt suffix.

    Admitting the inbound-gateway namespace as "provider internal" would let
    the run step past our own gateway and into the sending tenant's hops,
    which is precisely the crossing the tenant label prevents.
    """
    chain = [
        M365_INTERNAL_A,
        _m365_hop(M365_OURS, "Thu, 15 Oct 2026 07:28:40 +0000"),
        _m365_hop(M365_THEIRS, "Mon, 01 Jun 2026 00:00:00 +0000"),
    ]
    resolved = ea.resolve_anchor(chain, own_mta_identities=[M365_OURS])
    assert resolved["at"] == datetime(2026, 10, 15, 7, 28, 40,
                                      tzinfo=timezone.utc), (
        "the run crossed into the sending tenant and took their timestamp"
    )
    assert resolved["trusted_prefix_ended_at"] == 2


def test_a_chain_of_only_internal_hops_has_no_end_and_no_anchor():
    """Both refusals can apply; either is correct, neither returns a time."""
    resolved = ea.resolve_anchor([M365_INTERNAL_A, M365_INTERNAL_B],
                                 own_mta_identities=[M365_OURS])
    assert absence.is_absent(resolved)
    assert resolved["kind"] == absence.CHECK_FAILED


def test_post_receipt_suffixes_exclude_the_inbound_gateway_namespace():
    assert ea._is_post_receipt_internal(
        "AM0PR05MB4567.eurprd05.prod.outlook.com") is True
    assert ea._is_post_receipt_internal(M365_OURS) is False
    assert ea._is_post_receipt_internal(M365_THEIRS) is False
    assert "mail.protection.outlook.com" not in \
        ea.POST_RECEIPT_INTERNAL_SUFFIXES
