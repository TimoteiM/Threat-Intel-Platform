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

**The exchange is required, and that is confirmed rather than assumed.**
Exabeam's documentation (developers.exabeam.com/exabeam/docs/api-keys and
/reference/get-access-token) states it plainly: an administrator creates an
API **Key** and **Secret** under Settings > API Keys, and those are exchanged
for a bearer token at `POST {base_url}/auth/v1/token` with
`grant_type=client_credentials`. **There is no bearer token to copy out of
the console.** The earlier version of this module sent a stored token
straight through, which was my inference from a sentence rather than a read
of the contract; its 401 message named this exact possibility.

**The token is cached because Exabeam asks for it to be.** A token is valid
for 4 hours, they recommend no more than ~6 token requests per 24 hours, and
"do not request a token on every API call". Fetching one per search would
breach that within a working morning.

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

#: Where the Key and Secret are exchanged for a bearer token.
TOKEN_PATH = "/auth/v1/token"

#: Exabeam issues 4-hour tokens and asks for no more than ~6 token requests a
#: day. Refreshed this far before expiry so a long search cannot start with a
#: token that dies mid-flight, without turning every call into a fetch.
TOKEN_REFRESH_MARGIN = timedelta(minutes=15)

#: Their documented default when the response omits one.
TOKEN_DEFAULT_LIFETIME = timedelta(hours=4)

_UNAUTHORISED_HINT = (
    "Exabeam rejected the API key (HTTP {status}) when exchanging it for a "
    "token. The Key and Secret come from Settings > API Keys in the Exabeam "
    "console, the Secret is shown in full only once when the key is created, "
    "and the key needs a permission set that allows search."
)


#: Cached bearer tokens, keyed by (base_url, a hash of the key id).
#:
#: **In-process.** The api and the worker therefore hold one each, which is 2
#: processes x 6 tokens a day at worst — at the edge of Exabeam's guidance.
#: A shared cache would fix that and means putting a bearer token in Redis,
#: which is a credential in a new place and a decision for the deployment
#: owner rather than a detail of this module. Recorded rather than chosen.
#:
#: The key id is hashed so a cache dump, a debugger or a repr cannot show it.
_TOKEN_CACHE: dict[tuple[str, str], tuple[str, datetime]] = {}


def _cache_key(base_url: str, client_id: str) -> tuple[str, str]:
    import hashlib

    return (base_url, hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:16])


def clear_token_cache() -> None:
    """Forget every cached token. For tests, and for a credential rotation."""
    _TOKEN_CACHE.clear()


def bearer_token(*, base_url: str, client_id: str, client_secret: str,
                 timeout: float = TIMEOUT_SECONDS) -> str:
    """A bearer token for this key, from cache when one is still good.

    Raises `httpx.HTTPStatusError` if Exabeam refuses the key. The response
    body is never attached to an exception: a token response contains a
    token.
    """
    key = _cache_key(base_url, client_id)
    cached = _TOKEN_CACHE.get(key)
    now = datetime.now(timezone.utc)
    if cached and cached[1] - TOKEN_REFRESH_MARGIN > now:
        return cached[0]

    response = httpx.post(
        f"{base_url}{TOKEN_PATH}",
        json={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        },
        headers={"accept": "application/json", "content-type": "application/json"},
        timeout=timeout,
    )
    response.raise_for_status()
    body = response.json() if response.content else {}
    token = str((body or {}).get("access_token") or "").strip()
    if not token:
        # A 2xx with no token is not a success. Reported as a shape problem
        # rather than letting an empty Bearer header produce a confusing 401
        # from the search endpoint one call later.
        raise ValueError("Exabeam returned no access_token in a successful response")
    try:
        lifetime = timedelta(seconds=int((body or {}).get("expires_in")))
    except (TypeError, ValueError):
        lifetime = TOKEN_DEFAULT_LIFETIME
    _TOKEN_CACHE[key] = (token, now + lifetime)
    return token


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
    # `client_id`/`client_secret` are the API Key and API Key Secret from
    # Settings > API Keys. The positional arguments are accepted so this still
    # works through the generic call path, which fills them from the same blob.
    key_id = str(secrets.get("client_id") or client_id or "").strip()
    key_secret = str(secrets.get("client_secret") or client_secret or "").strip()

    if not base_url:
        return {
            "state": status.VERIFIED_FAILING,
            "direction": status.INGEST,
            "reason": "No base_url is configured for this tenant's Exabeam.",
            "failure_kind": "not_configured",
        }
    missing = [n for n, v in (("client_id", key_id), ("client_secret", key_secret)) if not v]
    if missing:
        return {
            "state": status.VERIFIED_FAILING,
            "direction": status.INGEST,
            "reason": (
                f"No {' and '.join(missing)} stored for this tenant's Exabeam. "
                f"Both come from Settings > API Keys in the Exabeam console."
            ),
            "failure_kind": "not_configured",
        }

    # The exchange, before the search. A failure here is about the key; a
    # failure after it is about the query or the host, and the reasons below
    # keep those apart.
    try:
        token = bearer_token(base_url=base_url, client_id=key_id,
                             client_secret=key_secret)
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code
        return {
            "state": status.VERIFIED_FAILING,
            "direction": status.INGEST,
            "reason": (_UNAUTHORISED_HINT.format(status=code)
                       if code in (400, 401, 403)
                       else f"Exabeam answered HTTP {code} to the token request. "
                            f"The token endpoint is {base_url}{TOKEN_PATH}."),
            "failure_kind": "unauthorised" if code in (400, 401, 403) else "token_error",
        }
    except httpx.RequestError as exc:
        return {
            "state": status.VERIFIED_FAILING,
            "direction": status.INGEST,
            "reason": (
                f"Could not reach {base_url}{TOKEN_PATH} ({type(exc).__name__}). "
                f"This is a network or DNS answer, not a credential one."
            ),
            "failure_kind": "unreachable",
        }
    except ValueError as exc:
        return {"state": status.VERIFIED_FAILING, "direction": status.INGEST,
                "reason": str(exc), "failure_kind": "token_error"}

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
            # The token was issued a moment ago, so this is about what the key
            # is ALLOWED to do rather than whether it is valid.
            reason = (
                f"The token was issued but the search was refused (HTTP {code}). "
                f"The API key authenticates but its permission set does not "
                f"allow search — change it under Settings > API Keys."
            )
            kind = "forbidden"
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
