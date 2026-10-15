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

    if not received_headers:
        return absence.absent(
            absence.CHECK_FAILED,
            "The message carries no Received headers, so nothing our own "
            "infrastructure wrote is available to date it. An email with no "
            "Received chain was not delivered through a path we can see.",
        ).as_json()

    # Walk down from the top while the hop is ours. The first foreign hop ends
    # our trust: everything below it arrived with the message.
    ours: list[tuple[str, datetime]] = []
    foreign_at: int | None = None
    for position, header in enumerate(received_headers):
        match = _BY_HOST.search(header or "")
        host = match.group(1) if match else ""
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
        first_host = ""
        if received_headers:
            match = _BY_HOST.search(received_headers[0] or "")
            first_host = match.group(1) if match else "(no `by` clause)"
        return absence.absent(
            absence.CHECK_FAILED,
            f"No Received header at the top of the chain was written by "
            f"configured mail infrastructure — the most recent hop reports "
            f"`by {first_host}`, which is not one of ours. Headers further "
            f"down arrived with the message and may be forged, so none of "
            f"them is read as an arrival time.",
            raw=first_host,
        ).as_json()

    # The earliest of our own run: the first moment our side held the message.
    host, at = min(ours, key=lambda pair: pair[1])

    result: dict[str, Any] = {
        "anchor": ANCHOR_OWN_MTA,
        "at": at,
        "written_by": host,
        "own_hops": len(ours),
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


def anchor_statement(resolved: Any) -> str | None:
    """The clause naming the anchor, for the sentence the analyst reads."""
    if absence.is_absent(resolved):
        return None
    return (resolved or {}).get("statement")
