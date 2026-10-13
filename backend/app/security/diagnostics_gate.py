"""The shared gate on every diagnostic surface.

Two surfaces expose internals: the case-graph debug route, and the
`diagnostics` block on `/health`. They use one gate so there is one place to
turn off and one place to rotate, rather than two that drift.

Why `/health`'s diagnostics need a credential at all
----------------------------------------------------
They were briefly behind `?diagnostics=1`, which is not a credential: a query
parameter is discoverable in source, guessable, and ends up in access logs,
proxy logs and bookmarks. Anyone who could reach `/health` could reach the
diagnostics one query string away.

And on this platform the **cron periods are the sensitive part**, more than
the code fingerprint. A fingerprint says which version is deployed. The
periods say the width of the unobservation windows — how long ingestion can
stop before anything notices, how long a sweep can fail before a backlog
becomes visible. For a system whose job is watching whether security
telemetry is flowing, the schedule of the watchers is a map of its blind
spots, and that is not something to serve unauthenticated.

How it differs from the debug route's use
-----------------------------------------
The debug route *denies* — 404 on any failure, so a caller cannot learn the
feature exists. `/health` must stay 200 for TraceCat's preflight whatever
happens, so it *omits* instead: no header, no diagnostics, same liveness
answer as always. Deny and omit are different responses to the same gate, and
the caller is never told which it got.
"""

from __future__ import annotations

import secrets

from app.config import get_settings

#: The header both surfaces read.
#:
#: `GRAPH_DEBUG_*` is now a misnomer — these gate diagnostics generally, not
#: one debug route. Renaming the env var is a one-line change here and a
#: coordinated edit to `.env` on every deployment, so it is flagged rather
#: than done unasked: a rename is not a deployment.
HEADER = "X-Graph-Debug"


def enabled() -> bool:
    """Whether diagnostics are switched on at all. Defaults to off."""
    flag = str(getattr(get_settings(), "graph_debug_route", "") or "").strip().lower()
    return flag in {"1", "true", "yes", "on"}


def authorised(presented: str | None) -> bool:
    """Whether this caller holds the diagnostics credential. Never raises.

    The **token alone** is the authorisation. `enabled()` is deliberately not
    consulted here, because the two surfaces carry different risk and need
    different switches:

      * `/health`'s diagnostics report whether the watches ran. Presenting a
        valid secret is sufficient — requiring the kill switch as well would
        mean an operator had to enable the case-data route in order to ask
        whether ingestion monitoring is alive, which trades a larger exposure
        for a smaller one.
      * the case-graph debug route returns actual case contents, so it checks
        `enabled()` *as well*: a kill switch that defaults off, for a surface
        whose blast radius is data rather than configuration.

    An unset token denies everything rather than matching unset input: a
    blank secret must never be a secret that matches blank.
    """
    expected = str(getattr(get_settings(), "graph_debug_token", "") or "")
    if not expected or not presented:
        return False
    return secrets.compare_digest(presented, expected)
