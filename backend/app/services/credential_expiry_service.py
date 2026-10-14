"""One place that knows which credentials are near expiry.

From `docs/BACKLOG.md` item 7: **no credential in this system had an expiry
check.** The Spamhaus SIA token was a JWT whose `exp` claim decoded to
2026-05-12 — the same day the integration was committed — and the intel
collector then failed on 2,198 consecutive runs for 98 days. The expiry was
in the token, in the database, readable, and nothing read it. Same shape as
`meta.status`, `feeds_skipped` and `sources_checked`: the information was
there and no consumer existed.

So this is the consumer, and it is deliberately **central**. An integration
keeping a private refresh timer is how the first one became invisible: each
would know its own expiry and nothing would know the set. One register means
"which credentials are near expiry" is a question with an answer.

Why in-process rather than a table
----------------------------------
A token expiry is a fact about a *live* credential, re-derived every time one
is fetched, so storing it would create a second copy that goes stale the
moment a token refreshes. What is durable — the last verification and its
reason — already lives in `tenant_integrations.health`, and
`falcon_client.Token.as_status()` puts the expiry there too. This register is
the read-time view across all of them, in the same spirit as
`source_coverage_service`: derived, never stored.

It holds no secret. `record()` takes a token *status* — expiry, seconds
remaining, scopes — and the token itself is never passed in.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

#: Report a credential as near expiry this far ahead. Deliberately generous:
#: the cost of knowing early is a line in a report, and the cost of knowing
#: late was 98 days.
NEAR_EXPIRY_DAYS = 14

#: A credential whose whole lifetime is under this is an access token,
#: refreshed in the ordinary course of work. Falcon's are 1,800 seconds. It
#: is not something an operator renews, so it is excluded from the report
#: rather than filling it — and the count of exclusions is reported, so the
#: exclusion is visible rather than silent.
SHORT_LIVED_SECONDS = 3600

_LOCK = threading.Lock()
#: (tenant_id, tool) -> the last token status seen for it.
_SEEN: dict[tuple[str, str], dict[str, Any]] = {}


@dataclass(frozen=True)
class ExpiringCredential:
    tenant_id: str
    tool: str
    expires_at: str | None
    expires_in_seconds: int | None
    near_expiry: bool
    observed_at: str

    def as_json(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tool": self.tool,
            "expires_at": self.expires_at,
            "expires_in_seconds": self.expires_in_seconds,
            "near_expiry": self.near_expiry,
            "observed_at": self.observed_at,
        }


def record(*, tenant_id: str, tool: str, token_status: dict[str, Any]) -> None:
    """Note what a credential's token said about its own expiry.

    Called by whatever just fetched a token. Never given the token: a
    `token_status` carries `expires_at`, `expires_in_seconds`, `near_expiry`
    and `scopes`, and `Token.as_status()` is built to exclude the value.
    """
    if "access_token" in (token_status or {}):
        # Defensive: the one key that must never arrive here.
        token_status = {k: v for k, v in token_status.items() if k != "access_token"}
    with _LOCK:
        _SEEN[(str(tenant_id), str(tool))] = {
            **(token_status or {}),
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }


def _seconds_to(expires_at: Any) -> int | None:
    if not expires_at:
        return None
    try:
        when = datetime.fromisoformat(str(expires_at))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return int((when - datetime.now(timezone.utc)).total_seconds())


def report() -> dict[str, Any]:
    """Every credential whose expiry has been observed, and which are near it.

    Short-lived access tokens (Falcon's are 30 minutes) are *expected* to be
    near expiry constantly, so they are separated from long-lived credentials
    rather than filling the report: a token refreshed on every call is not a
    finding, and listing it would bury the one that is. The threshold is
    `NEAR_EXPIRY_DAYS`, so only a credential that will not be refreshed in the
    ordinary course of work reaches `near_expiry`.
    """
    with _LOCK:
        seen = dict(_SEEN)

    horizon = NEAR_EXPIRY_DAYS * 86400
    rows: list[ExpiringCredential] = []
    short_lived = 0
    for (tenant_id, tool), status in sorted(seen.items()):
        remaining = _seconds_to(status.get("expires_at"))
        if remaining is None:
            remaining = status.get("expires_in_seconds")
            remaining = int(remaining) if isinstance(remaining, (int, float)) else None
        # A credential that renews itself inside an hour is an access token,
        # not something an operator has to act on.
        #
        # Keyed on the observed LIFETIME, not on the token's own
        # `near_expiry` flag. The first version checked that flag, which a
        # freshly-issued 30-minute token sets to False — so the token fell
        # through and was then reported near-expiry against the 14-day
        # horizon. Every Falcon access token would have appeared in this
        # report, for ever, which is the cry-wolf failure that makes a field
        # people stop reading. Caught on the first live run.
        # `0 < remaining`, not just `remaining <=`: a negative value means
        # the credential has ALREADY expired, and `-86400 <= 3600` is true,
        # so the first version silently excluded exactly the credentials this
        # register exists to find. An absence bug inside the fix for a
        # cry-wolf bug — caught by the test for the dangerous direction,
        # which is the only reason it is not in production.
        if remaining is not None and 0 < remaining <= SHORT_LIVED_SECONDS:
            short_lived += 1
            continue
        rows.append(ExpiringCredential(
            tenant_id=tenant_id, tool=tool,
            expires_at=status.get("expires_at"),
            expires_in_seconds=remaining,
            near_expiry=remaining is not None and remaining <= horizon,
            observed_at=str(status.get("observed_at") or ""),
        ))

    near = [r for r in rows if r.near_expiry]
    return {
        "horizon_days": NEAR_EXPIRY_DAYS,
        "observed": [r.as_json() for r in rows],
        # Named, not counted: a count tells nobody which credential to renew.
        "near_expiry": [r.as_json() for r in near],
        "short_lived_tokens_excluded": short_lived,
        "note": (
            "Observed expiries only. A credential this process has never "
            "fetched a token for is absent from here rather than reported as "
            "healthy — absence is not agreement. The Spamhaus SIA token "
            "expired on the day its integration was committed and nothing "
            "read it for 98 days; this register exists so that question has "
            "one place to be asked."
        ),
    }


def forget(*, tenant_id: str, tool: str) -> None:
    """Drop an observation — when a configuration is removed."""
    with _LOCK:
        _SEEN.pop((str(tenant_id), str(tool)), None)
