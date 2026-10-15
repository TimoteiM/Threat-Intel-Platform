"""Which timestamp means "when this email arrived" — and which never do.

Every sentence of the form "first resolved *before this email*" rests on one
timestamp. Three candidates are available and two of them are wrong:

* the **`Date` header** is written by the sender's client. It is attacker
  controlled. A phishing message can carry any Date at all, and a Date set a
  year in the past turns every estate hit into `pre_existing` — the panel then
  says "ordinary infrastructure" about the attacker's own domain. This is the
  worst available anchor precisely because it is the most obvious one.
* the **upload time** of the investigation is when an analyst got round to
  looking. For a message reported a week later it is a week late, so a domain
  the attacker registered *after* the mail but *before* the upload reads as
  pre-existing. It is wrong for every retrospective investigation, which is
  most of them.
* the **earliest `Received` header written by our own infrastructure** is the
  one timestamp here that our side wrote. That is the anchor.

"Earliest Received" on its own is *also* wrong, and wrong in the same
direction as `Date`. Received headers are prepended, so the bottom of the
chain is the oldest — and the bottom hops were written by the sender's own
MTA, which is to say by the attacker. A `min()` over the whole chain is a
forgeable value wearing the costume of a measurement. Worse, an attacker can
inject a header that *claims* `by mx.ourcorp.example` with any date, so
matching our identity anywhere in the chain is forgeable too.

What is not forgeable is position. Our MTA prepends its header above
everything that arrived with the message, so the headers our infrastructure
wrote are a contiguous run at the *top* of the chain. This module walks down
from the top while the receiving host is ours and stops at the first hop that
is not — the earliest header in that run is the anchor. Anything below the
first foreign hop is outside our trust even when it names us.

When no anchor can be established the answer is `check_failed`. There is
deliberately no fallback: falling back to `Date` would substitute an
attacker-controlled value for a missing trustworthy one and keep the
confident wording, which is the failure this module exists to prevent.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from app.services import absence

#: The anchor this platform will act on, named in every sentence built from it
#: so a reader can tell which of the three was used.
ANCHOR_OWN_MTA = "own_mta_received"

#: Named only to be reported as rejected. Never returned as an anchor.
ANCHOR_DATE_HEADER = "date_header"
ANCHOR_UPLOAD_TIME = "upload_time"

REJECTED_ANCHORS = {
    ANCHOR_DATE_HEADER: (
        "the Date header is written by the sender's mail client and a phishing "
        "message can set it to any value"
    ),
    ANCHOR_UPLOAD_TIME: (
        "the upload time is when an analyst opened the investigation, which is "
        "later than arrival for every retrospective report"
    ),
}

#: `Received: from x ([1.2.3.4]) by HOST (...) with ESMTP id ...; <date>`
#: The receiving host follows `by`. Captured up to whitespace, `(` or `;`
#: because the parenthetical and the id are not part of the hostname.
_BY_HOST = re.compile(r"\bby\s+([A-Za-z0-9._-]+)", re.IGNORECASE)
_FROM_HOST = re.compile(r"\bfrom\s+([A-Za-z0-9._-]+)", re.IGNORECASE)


#: Hosts under these suffixes are the **provider's**, shared across every
#: customer on the platform. They are not identities.
#:
#: This is the trap under hosted mail. On Microsoft 365 the receiving MTA is
#: `<tenant>.mail.protection.outlook.com`; the suffix
#: `mail.protection.outlook.com` is common to every Microsoft tenant in the
#: world. Configure the suffix and a phisher sending from *their own* M365
#: tenant produces a chain whose hops all match it — so the trusted run never
#: meets a foreign hop and walks the whole way into the attacker's
#: infrastructure, where it reads an attacker-written timestamp as ours. The
#: identity has to be the tenant-qualified host, which is the one label the
#: attacker cannot claim.
#:
#: Google Workspace is the same shape with a worse surface: inbound hops are
#: `mx.google.com` and `*.google.com` for every Workspace customer, so there
#: is no tenant-qualified receiving host to configure at all — the
#: `Received-SPF`/ARC path has to be used instead, which this module does not
#: do. A Workspace deployment therefore has no usable identity here and must
#: stay `check_failed` rather than be given a suffix that trusts all of
#: Google.
SHARED_MTA_SUFFIXES = (
    "mail.protection.outlook.com",
    "protection.outlook.com",
    "outlook.com",
    "office365.com",
    "google.com",
    "googlemail.com",
    "gmail.com",
    "pphosted.com",          # Proofpoint
    "mimecast.com",
    "barracudanetworks.com",
    "messagelabs.com",       # Symantec/Broadcom
    "amazonses.com",
    "sendgrid.net",
)


def over_broad_identities(identities: Any) -> list[str]:
    """Configured identities that are a provider's rather than a customer's.

    Returned rather than silently dropped, and the caller refuses on a
    non-empty list. Dropping would leave an operator believing the anchor was
    configured while every run reported `check_failed` for a different reason;
    using it would trust every tenant on the provider.
    """
    bad: list[str] = []
    for raw in (identities or []):
        host = str(raw).strip().lower().lstrip(".").rstrip(".")
        if not host:
            continue
        for suffix in SHARED_MTA_SUFFIXES:
            # Equal to the shared suffix, or a bare parent of it. A
            # tenant-qualified host — one that has its own label in front of
            # the shared part — is fine and is what should be configured.
            if host == suffix:
                bad.append(host)
                break
            if suffix.endswith("." + host) or suffix == host:
                bad.append(host)
                break
    return bad


def _received_timestamp(header: str) -> datetime | None:
    """The date at the tail of one Received header, in UTC.

    RFC 5321 puts it after the final `;`. The final one, not the first: the
    `id` and `for` clauses can contain semicolons, and splitting on the first
    yields a fragment that parses to None — an absence produced by the parse
    rather than by the message.
    """
    if ";" not in header:
        return None
    tail = header.rsplit(";", 1)[1].strip()
    # A trailing `(envelope-from ...)` or comment follows some stacks' dates.
    tail = re.sub(r"\s*\([^)]*\)\s*$", "", tail).strip()
    if not tail:
        return None
    try:
        parsed = parsedate_to_datetime(tail)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        # A floating timestamp is not a moment. Guessing UTC would be a
        # silent up-to-14-hour error in the gap the sentence reports.
        return None
    return parsed.astimezone(timezone.utc)


#: Hops our mail provider writes *after* the message is already ours.
#:
#: On Microsoft 365 the top of a real chain is not the inbound gateway — it is
#: one or more internal mailbox-server hops, `*.<region>.prod.outlook.com`,
#: prepended during delivery inside the tenant. The tenant-qualified gateway
#: hop sits below them. A walk that required hop 0 to be identifiably ours
#: therefore refused every genuine M365 message, which is how this was found:
#: the first synthetic chain in the tests put our gateway at hop 0, and no
#: real one does.
#:
#: Safe to trust *in this position* for a reason that is about position, not
#: about the hostname: a header above our inbound gateway was written by our
#: provider after delivery, so a sender cannot place one there. The namespace
#: is shared across Microsoft tenants, so these hops may appear in the trusted
#: run but can never *be* the anchor and can never satisfy the requirement
#: that the run contain a tenant-qualified hop of ours.
#:
#: `mail.protection.outlook.com` is deliberately NOT here. That is the inbound
#: gateway namespace, it carries the tenant label, and admitting it would let
#: the walk cross from our tenant into a sending tenant's hops — the exact
#: failure the tenant label exists to prevent.
POST_RECEIPT_INTERNAL_SUFFIXES = (
    "prod.outlook.com",
    "outlook.office365.com",
)


def _is_post_receipt_internal(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    return any(host == s or host.endswith("." + s)
               for s in POST_RECEIPT_INTERNAL_SUFFIXES)


def _is_ours(host: str, identities: frozenset[str]) -> bool:
    """Whether a receiving host is one of ours.

    Suffix match on a dot boundary, so `ourcorp.example` covers
    `mx1.ourcorp.example` but `notourcorp.example` matches nothing. An
    unanchored `in` test is how a lookalike domain gets treated as our own
    infrastructure.
    """
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    for identity in identities:
        if host == identity or host.endswith("." + identity):
            return True
    return False


def resolve_anchor(
    received_headers: list[str],
    *,
    own_mta_identities: Any,
    date_header: str | None = None,
) -> dict[str, Any]:
    """The arrival anchor, or a named absence.

    `received_headers` must be in message order — index 0 is the topmost
    header, the last hop before delivery. `email.message.Message.get_all`
    returns them that way; a caller that reverses them inverts the trust
    direction and gets the attacker's end of the chain, so the order is part
    of this function's contract rather than something it tries to detect.

    Returns either `{"anchor": ANCHOR_OWN_MTA, "at": datetime, ...}` or an
    `Absent.as_json()`. Never a `Date`-derived time, under any circumstances.
    """
    identities = frozenset(
        str(v).strip().lower().lstrip(".") for v in (own_mta_identities or [])
        if str(v).strip()
    )
    if not identities:
        return absence.absent(
            absence.CHECK_FAILED,
            "No mail infrastructure identity is configured for this tenant "
            "(EMAIL_OWN_MTA_IDENTITIES), so no Received header can be told "
            "apart from one the sender wrote. Without that list the arrival "
            "time is unknown — not the Date header, which the sender chooses.",
        ).as_json()

    # A provider's shared host is not an identity. Refused rather than
    # dropped: see `over_broad_identities`.
    shared = over_broad_identities(identities)
    if shared:
        return absence.absent(
            absence.CHECK_FAILED,
            f"EMAIL_OWN_MTA_IDENTITIES contains {', '.join(sorted(shared))}, "
            f"which is the mail provider's host and is shared with every "
            f"other customer on that platform. An attacker sending from their "
            f"own tenant produces hops that all match it, so the trusted run "
            f"would never end and would read their timestamp as ours. "
            f"Configure the tenant-qualified host instead.",
            raw=",".join(sorted(shared)),
        ).as_json()

    if not received_headers:
        return absence.absent(
            absence.CHECK_FAILED,
            "The message carries no Received headers, so nothing our own "
            "infrastructure wrote is available to date it. An email with no "
            "Received chain was not delivered through a path we can see.",
        ).as_json()

    # Walk down from the top while the hop is either identifiably ours or a
    # hop our provider wrote after delivery. The first hop that is neither
    # ends our trust: everything below it arrived with the message.
    ours: list[tuple[str, datetime]] = []
    internal_hops = 0
    foreign_at: int | None = None
    for position, header in enumerate(received_headers):
        match = _BY_HOST.search(header or "")
        host = match.group(1) if match else ""
        if host and _is_post_receipt_internal(host):
            # Above our gateway, so written by our provider — but shared, so
            # it cannot anchor and does not count as a hop of ours.
            internal_hops += 1
            continue
        if not host or not _is_ours(host, identities):
            foreign_at = position
            break
        stamp = _received_timestamp(header or "")
        if stamp is None:
            # Ours, but undated. It cannot anchor; keep walking, because a
            # lower hop of ours may still be dated.
            continue
        ours.append((host, stamp))

    if not ours:
        # Name the hop that ended the trusted run, not hop 0 — with internal
        # hops above it, hop 0 is our provider's and saying so misleads.
        blocking = foreign_at if foreign_at is not None else 0
        match = _BY_HOST.search(received_headers[blocking] or "") \
            if blocking < len(received_headers) else None
        blocking_host = match.group(1) if match else "(no `by` clause)"
        internal_note = (
            f" The {internal_hops} hop(s) above it are shared "
            f"provider-internal hosts, which cannot identify a tenant."
            if internal_hops else ""
        )
        return absence.absent(
            absence.CHECK_FAILED,
            f"No Received header above the first foreign hop was written by "
            f"configured mail infrastructure — the run ends at `by "
            f"{blocking_host}`, which is not one of ours.{internal_note} "
            f"Headers further down arrived with the message and may be "
            f"forged, so none of them is read as an arrival time.",
            raw=blocking_host,
        ).as_json()

    # No foreign hop anywhere: the trusted run was never bounded.
    #
    # Two worlds produce this and nothing in the chain separates them. Either
    # the message really is internal — M365 tenant to the same M365 tenant,
    # every hop genuinely ours — or an identity matched the whole of somebody
    # else's chain and the walk ran off the end of our infrastructure into
    # theirs. The second is not hypothetical: it is precisely what a shared
    # provider suffix produces, and the `over_broad_identities` guard above
    # covers only the misconfigurations we can name.
    #
    # The cost of refusing is real and worth stating: internal-origin mail —
    # which is what a compromised-account investigation looks like — gets no
    # before/after sentence. That is the lesser error. An unbounded run yields
    # the bottom-most hop in the message, and on a forged chain that is the
    # attacker's chosen timestamp, reported as the one our infrastructure
    # wrote.
    if foreign_at is None:
        return absence.absent(
            absence.CHECK_FAILED,
            f"Every one of the {len(received_headers)} Received hops matches "
            f"configured mail infrastructure, so the trusted run has no end. "
            f"An internal message and a chain that matched somebody else's "
            f"infrastructure all the way down look identical here, and the "
            f"second would date this email from a header the sender wrote. "
            f"No arrival time is claimed.",
            raw=str(len(received_headers)),
        ).as_json()

    # The earliest of our own run: the first moment our side held the message.
    host, at = min(ours, key=lambda pair: pair[1])

    result: dict[str, Any] = {
        "anchor": ANCHOR_OWN_MTA,
        "at": at,
        "written_by": host,
        "own_hops": len(ours),
        "provider_internal_hops_above": internal_hops,
        "trusted_prefix_ended_at": foreign_at,
        "statement": (
            f"the earliest Received header written by our own mail "
            f"infrastructure ({host}, {at:%Y-%m-%d %H:%M} UTC)"
        ),
    }

    # The Date header is parsed for one purpose: to report a disagreement. A
    # large gap between what the sender claims and when we received it is
    # itself worth an analyst's attention, and it is reported as a difference
    # rather than ever being used to fill in for a missing anchor.
    if date_header:
        claimed = None
        try:
            claimed = parsedate_to_datetime(str(date_header).strip())
        except (TypeError, ValueError, IndexError):
            claimed = None
        if claimed is not None and claimed.tzinfo is not None:
            skew = (at - claimed.astimezone(timezone.utc)).total_seconds()
            result["sender_date_skew_seconds"] = skew
            result["sender_date_disagrees"] = abs(skew) > 86_400
    return result


#: Which platform a receiving host belongs to, and whether that platform
#: offers a tenant-qualified host that can be configured as an identity.
#: `tenant_qualified` False means there is nothing safe to configure for that
#: platform here — not that a suffix should be used anyway.
_PLATFORMS = (
    ("mail.protection.outlook.com", "Microsoft 365 / Exchange Online", True,
     "the `<tenant>.mail.protection.outlook.com` host, with the tenant label"),
    ("outlook.com", "Microsoft 365 (internal Exchange Online hop)", False,
     "an internal Exchange Online hop — shared, with no tenant label"),
    ("google.com", "Google Workspace", False,
     "Workspace inbound hops are `mx.google.com` / `*.google.com` for every "
     "customer; there is no tenant-qualified receiving host to configure"),
    ("googlemail.com", "Google Workspace / Gmail", False,
     "shared across all Google customers"),
    ("pphosted.com", "Proofpoint Essentials/Enterprise gateway", True,
     "the customer-specific `mx*-*.pphosted.com` host"),
    ("mimecast.com", "Mimecast gateway", False,
     "Mimecast regional hosts are shared between customers"),
    ("messagelabs.com", "Symantec/Broadcom Email Security.cloud", False,
     "shared regional hosts"),
    ("barracudanetworks.com", "Barracuda Email Gateway", False,
     "shared regional hosts"),
)


def describe_platform(by_hosts: Any) -> dict[str, Any]:
    """Name the mail platform the receiving hops belong to.

    Called before anyone proposes an identity, because the answer decides
    whether an identity is available at all. A hosted platform's receiving
    MTA belongs to the provider, not to the customer, and on some platforms
    there is no tenant-qualified host to configure — in which case the honest
    outcome is that this anchor cannot be used, not a broader suffix.
    """
    hosts = [str(h).strip().lower().rstrip(".") for h in (by_hosts or [])
             if str(h).strip()]
    for suffix, name, qualified, note in _PLATFORMS:
        for host in hosts:
            if host == suffix or host.endswith("." + suffix):
                return {
                    "platform": name,
                    "matched_host": host,
                    "tenant_qualified_identity_available": qualified,
                    "note": note,
                    "shared_suffix": suffix,
                }
    return {
        "platform": "not a recognised hosted platform",
        "matched_host": hosts[0] if hosts else None,
        "tenant_qualified_identity_available": bool(hosts),
        "note": (
            "the receiving hosts match no known provider, which usually means "
            "self-hosted or on-premises mail — the host or its domain is then "
            "genuinely ours and is safe to configure"
        ),
        "shared_suffix": None,
    }


def anchor_statement(resolved: Any) -> str | None:
    """The clause naming the anchor, for the sentence the analyst reads."""
    if absence.is_absent(resolved):
        return None
    return (resolved or {}).get("statement")
