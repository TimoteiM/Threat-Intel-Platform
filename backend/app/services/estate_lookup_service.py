"""Did anything in this customer's estate touch this indicator?

This is the query that turns an intel hit into an incident. An analyst reads
`malicious` on a domain and the next question is always the same: *did it
reach us?* Until now that question had no answer in this platform, so the
reputation verdict stood alone.

Why every absence here is named rather than returned as zero
------------------------------------------------------------
A reader who sees "no host resolved this domain" **de-escalates**. That makes
a false negative here worse than a false positive, and worse than a missing
panel: it closes a ticket. So each way this lookup can fail to answer gets its
own named absence and never a count of 0 —

  * a **URL**, because this estate has no proxy logs at all
  * a window beyond **120-day retention**, which is *unknown*, not no contact
  * the cluster unreachable, or the tenant having no pinned integration

That is the same rule the ThreatFox and intel-collector failures came down to,
applied before the fact instead of after: `not hits` is true both when nothing
was seen and when nothing was asked.

The two questions this estate can answer, and why they never merge
------------------------------------------------------------------
Measured over the last 7 days, 164.6M documents, 180 agents:

    data.win.eventdata.queryName   2,599,670 docs   175 hosts  (97.2%)
    data.dstip                   126,708,398 docs     1 host

`queryName` is Sysmon event 22 — a host asking DNS for a name. `dstip` is
**one network appliance**, and it is the largest field in the store by two
orders of magnitude. "Did any endpoint resolve this name" and "did the
perimeter carry traffic to this address" are different facts, and the document
count is exactly the gravity well that makes them look like one answer.

**A perimeter hit with no corresponding host query is the more suspicious
shape**, not the same shape — traffic to an address no endpoint resolved. A
union would report one `yes` meaning neither, so this module returns both
separately and has no combined field at all. A test asserts that no key named
`seen`, `any`, `observed_anywhere` or `estate_hit` ever appears in the
payload.

What a negative answer is worth
-------------------------------
"No host resolved it" is a claim about **175 of 180 hosts**, not the estate, so
the DNS answer carries its own coverage. 97.2% is a strong negative and not a
complete one, and the five hosts without Sysmon DNS logging are exactly where
an operator would want to look next.

Cost, measured: 209 ms for a domain with 44,669 documents across 5 hosts;
28 ms for one with none.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from app.services import absence

#: Sysmon event 22. A host asked DNS for a name — endpoint telemetry, on
#: 175 of 180 agents.
HOST_DNS_FIELD = "data.win.eventdata.queryName"

#: One network appliance. Perimeter traffic to an address, NOT endpoint
#: telemetry, and never to be read as estate-wide.
PERIMETER_FIELD = "data.dstip"

#: Oldest document 2026-06-16, measured 2026-10-14. Beyond this the store has
#: nothing to say, which is not the same as having nothing to report.
RETENTION_DAYS = 120

#: 175 of 180 agents carry Sysmon DNS query logging.
HOSTS_WITH_DNS_LOGGING = 175
HOSTS_TOTAL = 180

DEFAULT_DAYS = 7

_DOMAIN = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _coverage() -> dict[str, Any]:
    return {
        "hosts_with_dns_logging": HOSTS_WITH_DNS_LOGGING,
        "hosts_total": HOSTS_TOTAL,
        "fraction": round(HOSTS_WITH_DNS_LOGGING / HOSTS_TOTAL, 4),
        "note": (
            f"Sysmon DNS query logging is on {HOSTS_WITH_DNS_LOGGING} of "
            f"{HOSTS_TOTAL} agents. A negative answer covers those hosts, not "
            f"the whole estate; the {HOSTS_TOTAL - HOSTS_WITH_DNS_LOGGING} "
            f"without it are where to look next."
        ),
    }


_NO_PROXY_LOGS = (
    "This estate has no proxy logs: `data.proxy.url` and `data.http.url` are "
    "both empty across the full 120-day window, and `data.url` comes from a "
    "single appliance. The estate question cannot be asked at URL grain here, "
    "so this is an absence of capability and not an absence of contact. Ask "
    "the domain instead."
)


def lookup(
    value: str,
    *,
    kind: str,
    tenant_id: str | None,
    days: int = DEFAULT_DAYS,
    client: Any = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Both estate facts for one indicator, each with its own absence.

    `client` must already be pinned to this tenant's cluster. It is passed in
    rather than resolved here so a caller cannot accidentally reach another
    tenant's store, and `tenant_id` travels with every query as a second
    guard.
    """
    at = now or datetime.now(timezone.utc)
    observable = str(value or "").strip()
    tenant = str(tenant_id or "").strip()
    queried: list[str] = []

    window = {
        "days": int(days),
        "retention_days": RETENTION_DAYS,
        "within_retention": int(days) <= RETENTION_DAYS,
        "since": (at - timedelta(days=int(days))).isoformat(),
        "until": at.isoformat(),
    }

    def both(reason_absence: absence.Absent) -> dict[str, Any]:
        """One reason that defeats both questions at once."""
        return {
            "observable": observable,
            "kind": kind,
            "tenant_id": tenant or None,
            "window": window,
            "host_dns": reason_absence.as_json(),
            "perimeter": reason_absence.as_json(),
            "queried": queried,
        }

    # ---- the refusals, before any query --------------------------------
    if not tenant:
        return both(absence.absent(
            absence.CHECK_FAILED,
            "No customer was named, so no cluster could be chosen. This "
            "platform never runs an estate query without a pinned tenant: an "
            "unpinned query would answer about somebody else's estate.",
        ))

    if client is None:
        return both(absence.absent(
            absence.CHECK_FAILED,
            f"No log-store integration is configured for {tenant!r}, so the "
            f"estate was not searched. There is deliberately no fallback "
            f"cluster — answering from another customer's logs would be worse "
            f"than not answering.",
            raw=tenant,
        ))

    if int(days) > RETENTION_DAYS:
        return both(absence.absent(
            absence.TOO_LITTLE_HISTORY,
            f"The window asked for is {days} days and the log store's "
            f"retention is {RETENTION_DAYS} days. Outside it the store holds "
            f"nothing, which is unknown and not 'no contact'. Treating an "
            f"aged-out window as clean is how a feed outage reads as safety.",
            raw=str(days),
        ))

    if kind == "url":
        return both(absence.absent(absence.OUT_OF_SCOPE, _NO_PROXY_LOGS,
                                   raw=observable))

    # ---- which question can this observable even ask? ------------------
    ask_dns = kind == "domain" and bool(_DOMAIN.match(observable))
    ask_perimeter = kind == "ip" and _is_ip(observable)

    if not ask_dns and not ask_perimeter:
        return both(absence.absent(
            absence.NO_FIELD_MAP,
            f"No estate field answers for an observable of kind {kind!r}. "
            f"The store can be asked about a domain (host DNS queries) and an "
            f"address (perimeter traffic); nothing else is mapped, and a zero "
            f"from an unmapped field would read as 'never seen'.",
            raw=kind,
        ))

    def ask(field: str, basis: str) -> Any:
        queried.append(field)
        try:
            docs, hosts = client.count_and_hosts(
                field=field, value=observable,
                since=window["since"], until=window["until"],
                tenant_id=tenant,
            )
        except Exception as exc:
            return absence.absent(
                absence.CHECK_FAILED,
                f"The log store could not be queried, so whether this was "
                f"seen is unknown rather than no. ({type(exc).__name__})",
                raw=field,
            ).as_json()
        return {
            "observed": bool(docs),
            "documents": int(docs),
            "hosts": list(hosts),
            "host_count": len(hosts),
            "field": field,
            "basis": basis,
            "window_days": int(days),
        }

    host_dns: Any = absence.absent(
        absence.OUT_OF_SCOPE,
        "Host DNS telemetry answers for domains. An address is not a name a "
        "host resolves, so this question was not asked of it.",
        raw=observable,
    ).as_json()
    perimeter: Any = absence.absent(
        absence.OUT_OF_SCOPE,
        "Perimeter records answer for addresses. A domain is not an address "
        "the appliance logs, so this question was not asked of it.",
        raw=observable,
    ).as_json()

    if ask_dns:
        host_dns = ask(
            HOST_DNS_FIELD,
            "Sysmon event 22 — an endpoint asked DNS for this name. Endpoint "
            "telemetry across the hosts that report it.",
        )
        if not absence.is_absent(host_dns):
            host_dns["coverage"] = _coverage()

    if ask_perimeter:
        perimeter = ask(
            PERIMETER_FIELD,
            "Perimeter appliance records — traffic to this address as one "
            "network device saw it. NOT endpoint telemetry and not "
            "estate-wide: this field comes from a single agent.",
        )

    return {
        "observable": observable,
        "kind": kind,
        "tenant_id": tenant,
        "window": window,
        # Separate, always. There is deliberately no combined verdict: see the
        # module docstring on why a union would mean neither fact.
        "host_dns": host_dns,
        "perimeter": perimeter,
        "queried": queried,
    }


# --- the real client ------------------------------------------------------
#
# Everything above is tested against a fake. That is not evidence the lookup
# works: the fake implements an interface I wrote, and five times this week a
# check verified both halves of a join and not the join itself. So the adapter
# below is the seam, and it is verified against the live cluster with the
# figures from the recon rather than against my expectation of it.
#
# Nothing here is taken from a request. The nodes, index pattern, tenant field
# and credentials all come from the deployment's own per-tenant integration,
# because an estate query whose index or manager filter could be supplied by a
# caller is not pinned to a tenant at all.

#: Which agents reported. `agent.name` is the estate's own host identity and
#: the denominator the coverage figures are measured against.
AGENT_FIELD = "agent.name"

#: NOT a constant for the timestamp. The per-tenant integration carries
#: `opensearch_timestamp_field` (default `timestamp`), and the first version of
#: this adapter hard-coded `@timestamp`. On a tenant using the configured
#: default, that range filter matches nothing and the lookup returns a
#: confident zero — a silent negative in the one place this module exists to
#: prevent one. There is deliberately no fallback value below.

#: 180 agents in the estate, so a bucket count above that means the terms agg
#: truncated and `hosts` would be a lower bound rather than the set.
_HOST_BUCKETS = 400


class OpenSearchEstateClient:
    """`count_and_hosts` over one tenant's pinned cluster.

    Constructed from `opensearch_tenants.integration_for(tenant_id)`, so a
    tenant with no integration yields no client and the lookup reports
    `check_failed` rather than reaching for a default cluster.
    """

    def __init__(self, client: Any, integration: Any) -> None:
        self._client = client
        self._integration = integration

    def count_and_hosts(
        self, *, field: str, value: str, since: str, until: str, tenant_id: str
    ) -> tuple[int, list[str]]:
        integ = self._integration
        pattern = str(getattr(integ, "opensearch_index_pattern", "") or "")
        tenant_field = str(getattr(integ, "opensearch_tenant_field", "") or "")
        # The real attribute name. The first version read `tenant_values`,
        # which does not exist on TenantIntegration, and
        # `getattr(..., None) or []` turned the missing attribute into "no
        # tenant filter" — so the query ran across every tenant's documents.
        # It was caught by the live host count disagreeing with the recon
        # (109 hosts against 5), not by any test.
        tenant_values = [
            str(v) for v in (getattr(integ, "opensearch_tenant_value_list", None) or [])
            if str(v).strip()
        ]
        timestamp_field = str(getattr(integ, "opensearch_timestamp_field", "") or "")

        # Refusals, not defaults. Each of these would otherwise produce an
        # answer that looks clean: an unpinned query answers about somebody
        # else's estate, and a wrong timestamp field answers zero.
        if not pattern:
            raise RuntimeError("no index pattern configured for this tenant")
        if not timestamp_field:
            raise RuntimeError(
                "no timestamp field configured for this tenant; a guessed "
                "field would silently match nothing"
            )
        if not tenant_field or not tenant_values:
            raise RuntimeError(
                "this tenant has no log-store tenant pin "
                "(opensearch_tenant_field / opensearch_tenant_value_list), so "
                "the query is refused rather than run unpinned"
            )

        filters: list[dict[str, Any]] = [
            # `.keyword` is not appended: these Wazuh fields are mapped as
            # keyword already, and guessing a subfield that does not exist
            # returns zero hits — a silent negative of exactly the kind this
            # module exists to prevent.
            {"term": {field: value}},
            {"range": {timestamp_field: {
                "gte": since, "lte": until,
                "format": "strict_date_optional_time",
            }}},
            # A `filter`, not a `should`, for the same reason the log-context
            # query does it this way: a query that can return another tenant's
            # documents when the value clause happens to match is not pinned.
            # Unconditional, because the refusal above guarantees it is usable.
            {"terms": {tenant_field: tenant_values}},
        ]

        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"filter": filters}},
            "aggs": {"hosts": {"terms": {
                "field": AGENT_FIELD, "size": _HOST_BUCKETS,
            }}},
        }
        payload, _node, _failures = self._client._request(
            "POST", f"/{pattern}/_search", json_body=body,
        )
        total = (((payload or {}).get("hits") or {}).get("total") or {})
        docs = int(total.get("value") or 0)
        buckets = (((payload or {}).get("aggregations") or {})
                   .get("hosts") or {}).get("buckets") or []
        hosts = [str(b.get("key")) for b in buckets if b.get("key") is not None]
        return docs, hosts


def estate_client_for(tenant_id: str | None, *, settings: Any = None) -> Any:
    """The pinned client for this tenant, or None.

    None is the honest answer for a tenant with no log-store integration, and
    `lookup()` turns it into `check_failed` — never into a search against
    somebody else's cluster.
    """
    from app.services import opensearch_client as osc
    from app.services import opensearch_tenants

    integration = opensearch_tenants.integration_for(tenant_id, settings=settings)
    if integration is None:
        return None
    client = osc.safe_client(integration)
    if client is None:
        return None
    return OpenSearchEstateClient(client, integration)
