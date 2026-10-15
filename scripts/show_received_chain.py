#!/usr/bin/env python3
"""Print one message's Received chain top-down, so a human can say which
hops are ours.

Why this exists rather than asking someone to recall a domain:
`EMAIL_OWN_MTA_IDENTITIES` decides which headers are trusted to date a
message, and a wrong or over-broad entry fails silently in the direction that
lets a sender backdate their own mail. A real chain, read top-down with each
hop's receiving host, is checkable. A domain typed from memory is not.

**It prints structure, never content.** Hop index, the `from` and `by` hosts,
the timestamp, and whether the hop matches whatever is currently configured.
No subject, no body, no addresses: the `for` and `envelope-from` clauses carry
recipient addresses and are redacted, because the question here is about hosts
and this output gets pasted into a conversation.

Usage:
    backend/.venv/bin/python scripts/show_received_chain.py <path-to.eml>

The message itself is customer evidence: keep it under ~/evidence/ with an
INVENTORY.md entry naming the question it answers and its deletion trigger.
"""

from __future__ import annotations

import os
import re
import sys
from email import message_from_bytes
from email.policy import default as default_policy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.services import email_anchor as ea  # noqa: E402

#: Clauses that carry addresses. Removed before anything is printed.
_REDACT = (
    re.compile(r"\bfor\s+<[^>]*>", re.IGNORECASE),
    re.compile(r"\benvelope-from\s*=?\s*<?[^\s;)]*>?", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", re.NOFLAG),
)


def _redact(text: str) -> str:
    for pattern in _REDACT:
        text = pattern.sub("<redacted>", text)
    return text


def main(path: str) -> int:
    with open(path, "rb") as handle:
        raw = handle.read()
    msg = message_from_bytes(raw, policy=default_policy)
    chain = [str(h) for h in (msg.get_all("Received") or [])]

    if not chain:
        print("No Received headers in this message. Nothing our own "
              "infrastructure wrote is available to date it — check_failed, "
              "and no identity can be derived from it either.")
        return 1

    try:
        from app.config import get_settings
        configured = get_settings().email_own_mta_identity_set
    except Exception:
        configured = frozenset()

    by_hosts = []
    rows = []
    for index, header in enumerate(chain):
        by_match = ea._BY_HOST.search(header)
        from_match = ea._FROM_HOST.search(header)
        by_host = by_match.group(1).lower() if by_match else ""
        from_host = from_match.group(1).lower() if from_match else ""
        stamp = ea._received_timestamp(header)
        by_hosts.append(by_host)
        rows.append({
            "i": index,
            "by": by_host or "(no `by` clause)",
            "from": from_host or "(no `from` clause)",
            "at": stamp.isoformat() if stamp else "(undated)",
            # Three states, not two. A provider-internal hop above our
            # gateway is trusted for its position and not for its name, and
            # printing it as "no" invites someone to add its shared suffix to
            # the identity list — the one change that breaks everything.
            "role": (
                "provider-internal"
                if ea._is_post_receipt_internal(by_host)
                else ("OURS" if configured and ea._is_ours(by_host, configured)
                      else ("foreign" if configured else "?"))
            ),
        })

    print(f"{len(chain)} Received hops, top-down (hop 0 is the most recent, "
          f"i.e. the last hop before delivery).")
    print("The hops OUR infrastructure wrote are a contiguous run starting at "
          "hop 0; the run ends at the first hop that is not ours.\n")
    width = max(len(r["by"]) for r in rows)
    print(f"{'hop':>3}  {'by (receiving host)':<{width}}  {'timestamp':<25}  "
          f"{'role':<18}  from (claimed sender host)")
    for row in rows:
        print(f"{row['i']:>3}  {row['by']:<{width}}  {row['at']:<25}  "
              f"{row['role']:<18}  {_redact(row['from'])}")
    print("\n  OURS              = identifiably ours; can anchor")
    print("  provider-internal = our provider's shared host, trusted only "
          "because it sits ABOVE our gateway; can never anchor, and must "
          "NOT be added to the identity list")
    print("  foreign           = arrived with the message; untrusted")

    platform = ea.describe_platform(by_hosts)
    print(f"\nPlatform: {platform['platform']}")
    print(f"  matched on: {platform['matched_host']}")
    print(f"  a tenant-qualified identity is available: "
          f"{platform['tenant_qualified_identity_available']}")
    print(f"  {platform['note']}")
    if platform["shared_suffix"]:
        print(f"  NOT configurable: {platform['shared_suffix']} — shared with "
              f"every other customer on this platform.")

    print("\nCurrently configured EMAIL_OWN_MTA_IDENTITIES: "
          f"{sorted(configured) or '(empty)'}")
    bad = ea.over_broad_identities(configured)
    if bad:
        print(f"  REFUSED as over-broad: {bad}")

    resolved = ea.resolve_anchor(chain, own_mta_identities=configured,
                                 date_header=msg.get("Date"))
    print("\nAnchor as things stand:")
    if resolved.get("kind"):
        print(f"  {resolved['kind']}: {resolved['reason']}")
    else:
        print(f"  {resolved['anchor']} = {resolved['at'].isoformat()} "
              f"(written by {resolved['written_by']}, "
              f"{resolved['own_hops']} own hop(s), trusted run ended at hop "
              f"{resolved['trusted_prefix_ended_at']})")
        if resolved.get("sender_date_disagrees"):
            print(f"  sender's Date disagrees by "
                  f"{resolved['sender_date_skew_seconds']/3600:.1f} h")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
