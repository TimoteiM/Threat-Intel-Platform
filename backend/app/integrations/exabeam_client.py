"""Exabeam Search API — `POST {base_url}/search/v2/events`.

Built against Exabeam's own API reference rather than against a model of the
product. The previous Exabeam spec in this repo was guessed, and an operator
was sent looking for a "search base URL" and a "site id" that were not real
settings; this module only implements what the documentation states:

* `POST https://api.<region>.exabeam.cloud/search/v2/events`
* **OAuth2, `Authorization: Bearer <token>`**
* body: `fields` (required), `startTime` (required, ISO-8601), `endTime`
  (required, ISO-8601), `filter` (required), and optional `limit` (default
  3000), `groupBy`, `orderBy`, `distinct`

Verified from this deployment on 2026-10-20, before any credential existed:
`api.eu.exabeam.cloud` resolves, TLS completes, and the search endpoint
answers **403** to an unauthenticated POST — so egress works and the endpoint
is live. The only thing between here and a working query is a credential.

**What is still unconfirmed, and is marked as such rather than guessed.**
Whether the stored `token` is a long-lived bearer that goes straight into the
header, or a client id and secret to exchange at a token endpoint first. The
API reference pane shows a Bearer token field, and the operator's existing
TraceCat automation uses "a username and a token", so this sends the token
directly. If an exchange is required, `verify()` will say so in words rather
than fail obscurely — see `_UNAUTHORISED_HINT`.

Nothing here logs a credential, a query result or an event. `httpx` is given
the token in a header built at call time and the response body is never
echoed into an exception message.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

#: The documented path, appended to the tenant's base URL.
SEARCH_PATH = "/search/v2/events"

#: Exabeam's documented default. Sent explicitly so a change to their default
#: cannot silently change how much this platform asks for.
DEFAULT_LIMIT = 3000

#: Long enough for a multi-year search to start returning, short enough that a
#: verification does not hold a request open. Exabeam's own console warns that
#: wide searches are slow, so a verify uses the narrowest possible window
#: rather than a longer timeout.
TIMEOUT_SECONDS = 30.0

_UNAUTHORISED_HINT = (
    "Exabeam rejected the credential (HTTP {status}). Two things produce this "
    "and they need different fixes: a token that is simply wrong or expired, "
    "or a key/secret pair that has to be exchanged for a bearer token first — "
    "this platform sends the stored token straight through as "
    "`Authorization: Bearer`. If your credential is an API key id and secret "
    "rather than a bearer token, that exchange is the missing step and the "
    "spec needs a token endpoint adding."
)


def _base_url(config: dict[str, Any]) -> str:
    raw = str((config or {}).get("base_url") or "").strip()
    return raw.rstrip("/")


def search(
    *,
    token: str,
    base_url: str,
    filter_expression: str,
    fields: list[str],
    start_time: datetime,
    end_time: datetime,
    limit: int = DEFAULT_LIMIT,
    group_by: list[str] | None = None,
    order_by: list[str] | None = None,
    distinct: bool = False,
    timeout: float = TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """One search, as the API documents it.

    Returns the decoded body. Raises `httpx.HTTPStatusError` on a non-2xx,
    with the response body deliberately **not** attached to the message: a
    search response carries customer log events.
    """
    if not base_url:
        raise ValueError("no base_url configured for this tenant's Exabeam")

    payload: dict[str, Any] = {
        "fields": list(fields),
        "startTime": start_time.astimezone(timezone.utc).isoformat(),
        "endTime": end_time.astimezone(timezone.utc).isoformat(),
        "filter": filter_expression,
        "limit": int(limit),
        "distinct": bool(distinct),
    }
    # Omitted rather than sent empty: the documented defaults are `[]`, and
    # sending an explicit empty list asserts a choice nobody made.
    if group_by:
        payload["groupBy"] = list(group_by)
    if order_by:
        payload["orderBy"] = list(order_by)

    response = httpx.post(
        f"{base_url}{SEARCH_PATH}",
        json=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "accept": "application/json",
            "content-type": "application/json",
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def verify(*, client_id: str = "", client_secret: str = "",
           config: dict[str, Any] | None = None,
           secrets: dict[str, str] | None = None) -> dict[str, Any]:
    """A real authenticated search, narrow enough to cost nothing.

    The contract `app.api.integrations._verifier_for` expects: a dict with
    `state`, `direction` and `reason`. Never raises — a failed verification is
    a state the page has to be able to show, with the reason an operator needs
    to fix it.

    **The window is one minute and the limit is one.** A verification exists
    to prove the credential works, not to retrieve anything, and a wide search
    against years of logs is both slow and rude to the customer's cluster.
    """
    from app.services import integration_status_service as status

    config = config or {}
    secrets = secrets or {}
    base_url = _base_url(config)
    token = str(secrets.get("token") or client_secret or "").strip()

    if not base_url:
        return {
            "state": status.VERIFIED_FAILING,
            "direction": status.INGEST,
            "reason": "No base_url is configured for this tenant's Exabeam.",
            "failure_kind": "not_configured",
        }
    if not token:
        return {
            "state": status.VERIFIED_FAILING,
            "direction": status.INGEST,
            "reason": "No token is stored for this tenant's Exabeam.",
            "failure_kind": "not_configured",
        }

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=1)
    try:
        body = search(
            token=token,
            base_url=base_url,
            # The cheapest filter that is still a real query. `filter` is a
            # required parameter, so there is no "empty search" to send.
            filter_expression="*",
            fields=["id"],
            start_time=start,
            end_time=end,
            limit=1,
        )
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        if code in (401, 403):
            reason = _UNAUTHORISED_HINT.format(status=code)
            kind = "unauthorised"
        elif code == 404:
            reason = (
                f"{base_url}{SEARCH_PATH} returned 404. The base URL is "
                f"probably not this tenant's Exabeam API host — the search "
                f"API lives at https://api.<region>.exabeam.cloud, which is "
                f"not the Advanced Analytics web address."
            )
            kind = "wrong_host"
        else:
            # The body is NOT included: a search response carries customer log
            # events, and this string reaches the page and the audit row.
            reason = f"Exabeam answered HTTP {code} to a one-minute search."
            kind = "http_error"
        return {"state": status.VERIFIED_FAILING, "direction": status.INGEST,
                "reason": reason, "failure_kind": kind}
    except httpx.RequestError as exc:
        return {
            "state": status.VERIFIED_FAILING,
            "direction": status.INGEST,
            "reason": (
                f"Could not reach {base_url} ({type(exc).__name__}). This is "
                f"a network or DNS answer, not a credential one."
            ),
            "failure_kind": "unreachable",
        }
    except Exception as exc:  # noqa: BLE001
        return {"state": status.VERIFIED_FAILING, "direction": status.INGEST,
                "reason": f"Unexpected {type(exc).__name__} during verification.",
                "failure_kind": "error"}

    # A count, never the events. The number of rows a one-minute window
    # happened to hold says nothing anybody needs and the rows are customer
    # log data.
    rows = body.get("rows") if isinstance(body, dict) else None
    shape = "rows" if isinstance(rows, list) else ",".join(
        sorted(body)[:4]) if isinstance(body, dict) else type(body).__name__
    return {
        "state": status.VERIFIED_OK,
        "direction": status.INGEST,
        "reason": (
            f"Authenticated search against {base_url}{SEARCH_PATH} succeeded "
            f"(response shape: {shape})."
        ),
    }
