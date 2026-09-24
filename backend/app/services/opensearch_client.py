"""A small, bounded OpenSearch client for reading logs around an alert.

Written rather than pulled in as `opensearch-py` for the same reasons
`cape_client` is hand-written: this platform talks to one cluster, needs two
query shapes, and needs total control over three things a general client does
not give — what is logged, how much is read, and what happens when a node is
down.

**Credentials never leave this module.** They are read from settings, passed to
httpx as basic auth, and are absent from every string this module produces:
`redact()` scrubs them out of exception text before anything is logged, and no
method returns them. The cluster is reached with an admin account, so a password
in a traceback is a real incident, not an untidy log line.

**An unavailable node is not an unavailable cluster.** Nodes are tried in a
rotating order and a node that fails is skipped for a cooldown. When every node
fails the caller gets `OpenSearchUnavailable`, which the log-context service
treats as missing evidence rather than a failed alert — alert processing must
never stop because a search cluster is down.

**Reads are bounded twice over.** `search_all` pages with `search_after` rather
than `from`/`size`, because deep paging over an index holding 23 million
documents a day is how a search cluster is taken down by a report. Every page is
capped, the total is capped, and the cap being hit is reported in the result
instead of being silently dropped.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

import httpx

logger = logging.getLogger(__name__)


class OpenSearchError(Exception):
    """Any failure talking to OpenSearch."""


class OpenSearchNotConfigured(OpenSearchError):
    """No nodes or no credentials."""


class OpenSearchUnavailable(OpenSearchError):
    """Every configured node failed. The caller carries on without logs."""


@dataclass
class SearchPage:
    hits: list[dict[str, Any]]
    sort_cursor: list[Any] | None
    total: int | None
    node: str


@dataclass
class SearchResult:
    """Hits plus everything needed to say where they came from."""

    hits: list[dict[str, Any]] = field(default_factory=list)
    total_available: int | None = None
    truncated: bool = False
    pages: int = 0
    indices_searched: list[str] = field(default_factory=list)
    nodes_used: list[str] = field(default_factory=list)
    node_failures: list[str] = field(default_factory=list)
    took_ms: int = 0


# A node that just failed is skipped for this long rather than being retried on
# every query. Long enough to matter during one alert, short enough that a node
# coming back is noticed within a minute.
_NODE_COOLDOWN_SECONDS = 60.0

_cooldowns: dict[str, float] = {}
_cooldown_lock = threading.Lock()


def _node_is_cool(node: str) -> bool:
    with _cooldown_lock:
        until = _cooldowns.get(node)
        if until is None:
            return True
        if time.monotonic() >= until:
            _cooldowns.pop(node, None)
            return True
        return False


def _mark_node_down(node: str) -> None:
    with _cooldown_lock:
        _cooldowns[node] = time.monotonic() + _NODE_COOLDOWN_SECONDS


def reset_node_health() -> None:
    """Forget which nodes are in cooldown. For tests and for operator use."""
    with _cooldown_lock:
        _cooldowns.clear()


def redact(text: Any, *, username: str | None = None, password: str | None = None) -> str:
    """Remove anything credential-shaped from a string bound for a log.

    httpx puts the URL in most of its exception messages and some proxies echo
    the Authorization header back in an error body, so this runs over every
    string this module logs or raises, not only the ones expected to carry one.
    """
    value = str(text)
    for secret in (password, username):
        if secret and len(str(secret)) >= 3:
            value = value.replace(str(secret), "***")
    # basic-auth embedded in a URL: https://user:pass@host
    import re

    value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1***:***@", value)
    # The optional first token is the scheme: `Authorization: Basic <secret>`
    # otherwise redacts the word "Basic" and leaves the secret in the log.
    value = re.sub(r"(?i)(authorization\s*[:=]\s*)(?:\S+\s+)?\S+", r"\1***", value)
    return value


class OpenSearchClient:
    """One cluster, several nodes, read-only.

    Used as a context manager so the connection pool is closed; a collector that
    leaks pooled connections into a Celery thread pool exhausts the worker long
    before it exhausts the cluster.
    """

    def __init__(self, *, settings: Any = None) -> None:
        if settings is None:
            from app.config import get_settings

            settings = get_settings()
        self.settings = settings

        self._nodes: list[str] = [
            str(node).strip().rstrip("/")
            for node in (
                getattr(settings, "opensearch_node1", ""),
                getattr(settings, "opensearch_node2", ""),
                getattr(settings, "opensearch_node3", ""),
            )
            if str(node or "").strip()
        ]
        self._username = str(getattr(settings, "opensearch_username", "") or "")
        # The one place the password is unwrapped. It is a pydantic SecretStr,
        # so str() on it yields "**********" — which reaches OpenSearch as a
        # wrong password and comes back 401, not as an obvious bug. Anything
        # else that needs it is wrong; nothing else needs it.
        raw_password = getattr(settings, "opensearch_password", "")
        self._password = str(
            raw_password.get_secret_value()
            if hasattr(raw_password, "get_secret_value")
            else (raw_password or "")
        )
        if not self._nodes:
            raise OpenSearchNotConfigured("No OPENSEARCH_NODE* is configured.")
        if not self._username or not self._password:
            raise OpenSearchNotConfigured("OPENSEARCH_USERNAME/PASSWORD are not configured.")

        verify: Any = bool(getattr(settings, "opensearch_verify_tls", True))
        bundle = str(getattr(settings, "opensearch_ca_bundle", "") or "").strip()
        if verify and bundle:
            # Said plainly, because httpx raises a bare FileNotFoundError here
            # and the caller would otherwise report "OpenSearch is not
            # configured" for a cluster that is configured and reachable.
            import os

            if not os.path.exists(bundle):
                raise OpenSearchNotConfigured(
                    f"The CA bundle {bundle} does not exist, so the cluster's certificate "
                    "cannot be verified. Put the internal CA certificate there, or set "
                    "OPENSEARCH_VERIFY_TLS=false to accept an unverified connection "
                    "(which sends the admin password over a connection nobody has checked)."
                )
            verify = bundle
        self._client = httpx.Client(
            timeout=httpx.Timeout(
                float(getattr(settings, "opensearch_request_timeout_seconds", 20) or 20),
                connect=float(getattr(settings, "opensearch_connect_timeout_seconds", 5) or 5),
            ),
            verify=verify,
            follow_redirects=False,
            auth=(self._username, self._password),
        )

    # -- lifecycle -----------------------------------------------------------

    def __enter__(self) -> "OpenSearchClient":
        return self

    def __exit__(self, *_exc: Any) -> bool:
        self.close()
        return False

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 — closing must not raise into a caller
            pass

    # -- plumbing ------------------------------------------------------------

    def _scrub(self, text: Any) -> str:
        return redact(text, username=self._username, password=self._password)

    def _candidate_nodes(self) -> list[str]:
        """Healthy nodes first, in a rotated order, then the ones in cooldown.

        Rotated so concurrent alerts do not all land on node 1, and cooled nodes
        are kept as a last resort rather than dropped: a cluster where every node
        recently failed is still worth one attempt before giving up on logs.
        """
        healthy = [n for n in self._nodes if _node_is_cool(n)]
        cooling = [n for n in self._nodes if not _node_is_cool(n)]
        if healthy:
            offset = random.randrange(len(healthy))
            healthy = healthy[offset:] + healthy[:offset]
        return healthy + cooling

    def _request(self, method: str, path: str, *, json_body: dict | None = None,
                 params: dict | None = None) -> tuple[dict[str, Any], str, list[str]]:
        """Try each node until one answers. Returns (payload, node, failures)."""
        failures: list[str] = []
        last: Exception | None = None
        for node in self._candidate_nodes():
            url = f"{node}{path}"
            try:
                response = self._client.request(method, url, json=json_body, params=params)
            except httpx.HTTPError as exc:
                _mark_node_down(node)
                failures.append(f"{node}: {type(exc).__name__}")
                logger.info("OpenSearch node unavailable: %s", self._scrub(exc)[:200])
                last = exc
                continue

            if response.status_code in (401, 403):
                # Not a node problem, and trying the others repeats a failed
                # login twice more — which is how an account gets locked out.
                raise OpenSearchError(
                    f"OpenSearch rejected the credentials ({response.status_code})."
                )
            if response.status_code >= 500:
                _mark_node_down(node)
                failures.append(f"{node}: HTTP {response.status_code}")
                last = OpenSearchError(f"HTTP {response.status_code}")
                continue
            if response.status_code >= 400:
                raise OpenSearchError(
                    f"OpenSearch refused the query (HTTP {response.status_code}): "
                    f"{self._scrub(response.text)[:300]}"
                )
            try:
                return response.json(), node, failures
            except ValueError as exc:
                failures.append(f"{node}: malformed response")
                last = exc
                continue

        raise OpenSearchUnavailable(
            "No OpenSearch node answered: " + "; ".join(failures or ["no nodes tried"])
        ) from (last if isinstance(last, Exception) else None)

    # -- reads ---------------------------------------------------------------

    def ping(self) -> dict[str, Any]:
        payload, node, _ = self._request("GET", "/")
        return {
            "node": node,
            "cluster": payload.get("cluster_name"),
            "version": (payload.get("version") or {}).get("number"),
        }

    def concrete_indices(self, pattern: str) -> list[str]:
        """The indices a pattern currently resolves to, newest last.

        Asked for so a 20-minute window can name the two or three daily indices
        it actually needs. Searching `wazuh-alerts-4.x-*` puts 120 indices into
        every query when the window spans at most two of them.
        """
        payload, _, _ = self._request(
            "GET", "/_cat/indices/" + pattern, params={"format": "json", "h": "index"}
        )
        if not isinstance(payload, list):
            return []
        return sorted(str(row.get("index")) for row in payload if row.get("index"))

    def search_all(
        self,
        *,
        indices: Sequence[str],
        query: dict[str, Any],
        sort: list[dict[str, Any]],
        source_fields: Sequence[str] | None = None,
        page_size: int = 100,
        max_hits: int = 500,
    ) -> SearchResult:
        """Every matching hit up to `max_hits`, paged with `search_after`.

        `sort` must end in a tiebreaker that is unique per document, or paging
        can loop or skip. The caller passes `_id`; this is not enforced here
        because a caller may have a better one, but it is the reason `_id` is in
        every sort this module is given.
        """
        result = SearchResult(indices_searched=list(indices))
        if not indices or max_hits <= 0:
            return result

        target = ",".join(indices)
        seen: set[str] = set()
        cursor: list[Any] | None = None
        started = time.monotonic()

        while len(result.hits) < max_hits:
            body: dict[str, Any] = {
                "size": min(page_size, max_hits - len(result.hits)),
                "query": query,
                "sort": sort,
                # Exact totals over billions of documents cost more than the
                # answer is worth; the cap is what the reader needs to know.
                "track_total_hits": False,
            }
            if source_fields:
                body["_source"] = list(source_fields)
            if cursor is not None:
                body["search_after"] = cursor

            payload, node, failures = self._request(
                "POST", f"/{target}/_search", json_body=body,
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            )
            result.pages += 1
            if node not in result.nodes_used:
                result.nodes_used.append(node)
            for failure in failures:
                if failure not in result.node_failures:
                    result.node_failures.append(failure)

            hits = ((payload.get("hits") or {}).get("hits")) or []
            if not hits:
                break

            for hit in hits:
                key = f"{hit.get('_index')}:{hit.get('_id')}"
                if key in seen:
                    continue
                seen.add(key)
                result.hits.append(hit)
                if len(result.hits) >= max_hits:
                    break

            cursor = hits[-1].get("sort")
            if cursor is None:
                # Without a cursor the next page would repeat this one.
                break
            if len(hits) < body["size"]:
                break

        result.truncated = len(result.hits) >= max_hits
        result.took_ms = int((time.monotonic() - started) * 1000)
        return result


def safe_client(settings: Any = None) -> OpenSearchClient | None:
    """A client, or None when the cluster is not configured.

    Returning None rather than raising is deliberate: every caller of this
    module is in an alert path that must complete whether or not logs can be
    read, and a `try/except ImportError`-shaped dance at each call site is how
    one of them ends up not having it.
    """
    try:
        return OpenSearchClient(settings=settings)
    except OpenSearchNotConfigured as exc:
        logger.info("OpenSearch log context unavailable: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("OpenSearch client could not be built: %s", redact(exc)[:200])
        return None


def describe_indices(
    *, pattern: str, start: Any, end: Any, client: OpenSearchClient
) -> list[str]:
    """Daily indices overlapping [start, end], falling back to the pattern.

    Wazuh writes one index per UTC day, named `<prefix>-YYYY.MM.DD`. A window of
    twenty minutes touches one of them, or two when it straddles midnight. The
    fallback matters: an operator who changes the rollover scheme should get a
    slower query, not an empty one.
    """
    from datetime import timedelta

    prefix = pattern.rstrip("*").rstrip("-")
    available = set(client.concrete_indices(pattern))
    if not available:
        return [pattern]

    wanted: list[str] = []
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    while day <= end:
        name = f"{prefix}-{day:%Y.%m.%d}"
        if name in available:
            wanted.append(name)
        day += timedelta(days=1)
    return wanted or [pattern]
