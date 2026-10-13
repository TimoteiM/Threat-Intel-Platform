"""The case graph payload, over HTTP, without a session.

This exists to answer one question that could not be asked for four days:
**does the payload carry technique names on the path the page actually
calls?** The case graph endpoint is behind the session, there is no dev
account, and so every check fell back to a layer underneath it — which is how
"verified" came to mean something narrower than it sounded, twice.

Why it must be an HTTP route and not a test or a script
-------------------------------------------------------
`TestClient` and `docker compose exec api python` both construct the
application inside a **new interpreter**, importing current source from the
bind mount. They answer "what does this code do", which was never in doubt.
They cannot answer "what is the running server doing", and on 2026-10-12 the
two differed for the whole afternoon while every such check reported success.
Only a request over the published port reaches the process that is serving.

How it is gated
---------------
Two independent conditions, both required:

1. `GRAPH_DEBUG_ROUTE` must be truthy. It defaults to off, so the route does
   not exist unless someone deliberately turned it on.
2. `X-Graph-Debug` must equal `GRAPH_DEBUG_TOKEN`, compared in constant time.
   An empty or unset token disables the route outright — a blank secret must
   never be a secret that matches blank input.

Deliberately **no client-IP check**. Under Docker's userland proxy a request
from this host and a request from another machine both arrive as the bridge
gateway address, so an app-layer "loopback only" rule would be a boundary in
name and not in fact — and a control that looks like a boundary is worse than
an honest one. If network-level restriction is wanted it belongs on the port
publish (`127.0.0.1:8000:8000`), and note that `/health` is reached by
TraceCat from elsewhere, so that change is not free.

A failed or absent token returns 404, the same as the route being switched
off, so a caller cannot learn whether the feature exists on this deployment.
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.detections import CASE_LOOKUP_HOURS
from app.config import get_settings
from app.db.session import get_db

router = APIRouter(prefix="/api/debug", tags=["debug"])

#: The one path the auth middleware lets through for this router. Listed there
#: too — that list is hand-maintained, and this route carries its own secret
#: rather than relying on the session it is deliberately bypassing.
GRAPH_PATH = "/api/debug/case-graph"


def _enabled() -> bool:
    settings = get_settings()
    flag = str(getattr(settings, "graph_debug_route", "") or "").strip().lower()
    return flag in {"1", "true", "yes", "on"}


def _authorise(presented: str | None) -> None:
    """404 on every failure, including "switched off" and "no token set".

    Not 401: a 401 tells an unauthenticated caller that the route exists here,
    which is information a debug surface should not volunteer.
    """
    if not _enabled():
        raise HTTPException(status_code=404, detail="Not Found")
    expected = str(getattr(get_settings(), "graph_debug_token", "") or "")
    if not expected:
        # An unset token would otherwise match an unset header.
        raise HTTPException(status_code=404, detail="Not Found")
    if not presented or not secrets.compare_digest(presented, expected):
        raise HTTPException(status_code=404, detail="Not Found")


@router.get("/case-graph")
async def case_graph_debug(
    request: Request,
    case_key: str,
    hours: int = CASE_LOOKUP_HOURS,
    db: AsyncSession = Depends(get_db),
    x_graph_debug: str | None = Header(default=None),
) -> dict[str, Any]:
    """The same graph `GET /api/detections/case/{key}/graph` returns.

    Calls `detections.get_case_graph` rather than reassembling anything, so
    what this reports is what the page receives. A debug route that built its
    own payload would be a second implementation of the thing being checked —
    the defect this codebase has paid for repeatedly — and would be capable of
    passing while the real endpoint failed.
    """
    _authorise(x_graph_debug)

    from app.api import detections

    graph = await detections.get_case_graph(
        case_key=case_key, db=db, hours=hours, request=None
    )

    # A small summary beside the payload, so the question this route exists
    # for is answered by reading the first few lines rather than by grepping
    # a few hundred kilobytes of JSON.
    techniques = [
        node for node in (graph.get("nodes") or []) if node.get("kind") == "technique"
    ]
    named = [
        node for node in techniques
        if isinstance((node.get("attrs") or {}).get("name"), str)
    ]
    from app.code_version import code_version

    graph["_debug"] = {
        "served_by": code_version(),
        "technique_nodes": len(techniques),
        "with_a_resolved_name": len(named),
        "example": (
            {
                "id": (named[0].get("attrs") or {}).get("id"),
                "name": (named[0].get("attrs") or {}).get("name"),
                "short_name": (named[0].get("attrs") or {}).get("short_name"),
                "tactic": (named[0].get("attrs") or {}).get("tactic"),
                "retired": (named[0].get("attrs") or {}).get("retired"),
            }
            if named
            else None
        ),
    }
    return graph
