"""One OpenSearch integration per tenant, or none at all.

The cluster this platform reads today is C00's: `C00-Indexer`, pinned to
`manager.name: wm-c00.siembiot.int`. Running that query for another tenant
would not return an error — it would return C00's logs under someone else's
alert, which is the worst available outcome and an entirely silent one.

So enrichment is per tenant and fails closed:

* a tenant with no configured integration gets `None`, and the log context
  reports *unavailable — no integration configured for this tenant*;
* there is **no shared default** to fall back to. The global `OPENSEARCH_*`
  settings are the C00 integration, mapped to C00 by name, and are not reachable
  by any other tenant;
* nothing about the connection is ever taken from an alert request. Nodes,
  index pattern, manager filter and credentials come from deployment
  configuration keyed by the *verified* tenant on the run.

Per-tenant configuration is read from the environment rather than the database,
deliberately: these are credentials, and this codebase already declines to put
credentials in Postgres.

    OPENSEARCH_TENANT_<ID>_NODES            comma-separated
    OPENSEARCH_TENANT_<ID>_USERNAME
    OPENSEARCH_TENANT_<ID>_PASSWORD
    OPENSEARCH_TENANT_<ID>_INDEX_PATTERN
    OPENSEARCH_TENANT_<ID>_MANAGER          the tenant pin value(s)
    OPENSEARCH_TENANT_<ID>_TENANT_FIELD     default manager.name
    OPENSEARCH_TENANT_<ID>_CA_BUNDLE
    OPENSEARCH_TENANT_<ID>_VERIFY_TLS

`<ID>` is the tenant id upper-cased with non-alphanumerics as underscores, so
tenant `c00` reads `OPENSEARCH_TENANT_C00_*`.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_SAFE = re.compile(r"[^A-Z0-9]+")


#: How this integration appears on the integrations page.
#:
#: Declared **here**, beside the thing it describes, for the same reason a
#: collector declares `integration_category` on itself: the integrations
#: catalogue must be derived and not hand-listed in its consumer. A list of
#: tools inside `integration_status_service` is the position the eighth silent
#: registry occupied, and two separate tests refuse it.
#:
#: The log store needed this because it is not a collector and was therefore
#: **absent from the integrations page entirely** — the one integration
#: carrying 154M documents and feeding every alert's log context. When it
#: stopped on 2026-10-12 there was no row for any state to be red on.
INTEGRATION_SPEC: dict[str, object] = {
    "tool": "opensearch",
    "label": "OpenSearch / Wazuh log store",
    "category": "siem",
    "directions": ("enrichment",),
    # Read-only from the API: these values come from the deployment's
    # environment, not from a per-tenant credential row. "Test connection"
    # returned HTTP 400 "not configured" until this was declared, because the
    # verify path asked the credential store about an integration that is not
    # kept there.
    "managed": "deployment",
    # How often this should produce a result, so silence can be judged rather
    # than guessed. One alert_log_context row is written per analysed alert
    # and alerts do not arrive on a schedule; measured arrival over the last
    # five days is 1,601 runs, roughly 13/hour in working hours and sparse
    # overnight. 6h is comfortably longer than any observed quiet period and
    # far shorter than the 49h outage this is meant to catch.
    "expected_interval_hours": 6,
    "config_fields": {
        "nodes": "Cluster node URLs, from deployment configuration.",
        "index_pattern": "Which indices to search, e.g. wazuh-alerts-4.x-*",
        "tenant_field": "The field that pins a query to this customer.",
        "tenant_values": (
            "The value(s) identifying this customer's manager. EMPTY MEANS "
            "UNPINNED, and the platform refuses to query rather than reach "
            "across tenants — so an empty value reads as not configured."
        ),
    },
    "secret_fields": {},
}


async def verify(tenant_id: str) -> dict[str, Any]:
    """A real call to this tenant's cluster, from whichever process asks.

    Deployment-configured, so there is no stored credential to open — the
    verify path must come here rather than to `tenant_integrations`, which
    has no row for this tool and never will.

    **This result is about the process that ran it, and says so.** The HTTP
    route runs in the **api**; alert log context is collected in the
    **worker** (`alert_body_task` is dispatched with `.delay()`). On
    2026-10-14 the api was recreated with `OPENSEARCH_TENANT_VALUES` and the
    worker was not, so a green answer here would have been true of the api
    and false of the pipeline. A verifier that cannot tell those apart
    reports exactly the false comfort this platform keeps being bitten by, so
    the reason names the process and declines to generalise.
    """
    from app.services import opensearch_client as osc

    integration = integration_for(tenant_id)
    if integration is None:
        return {
            "ok": False,
            "reason": (
                f"No log-store configuration resolves for tenant "
                f"{tenant_id!r}. Checked the per-tenant environment "
                f"({_env_key(tenant_id, 'NODES')}) and the global "
                f"OPENSEARCH_* values."
            ),
        }

    if not integration.opensearch_tenant_value_list:
        return {
            "ok": False,
            "reason": (
                "Nodes and credentials are present but OPENSEARCH_TENANT_VALUES "
                "is empty, so no query can be pinned to this customer. The "
                "platform refuses to run an unpinned query rather than reach "
                "across tenants, which is why log enrichment is off. Set it "
                "and recreate the containers — `up -d --force-recreate`, not "
                "`restart`, because env_file is read at container creation."
            ),
        }

    client = osc.safe_client(integration)
    if client is None:
        return {"ok": False, "reason": "No usable client for this tenant."}

    try:
        info = client.ping()
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}

    return {
        "ok": True,
        "reason": (
            "A real query answered, from THIS process only. The HTTP route "
            "runs in the api; alert log context is collected in the worker, "
            "which reads its own copy of the environment — so this green does "
            "not establish that new alerts will get context. Check "
            "`scripts/liveness.sh` for env drift between the two."
        ),
        # `ping()` returns {cluster, node, version}. The first version read
        # `cluster_name` and rendered a null beside a claim that a cluster had
        # answered — a field asserted and not supplied.
        "cluster": str((info or {}).get("cluster") or "")[:64] or None,
        "node": str((info or {}).get("node") or "")[:120] or None,
        "version": str((info or {}).get("version") or "")[:32] or None,
        "index_pattern": integration.opensearch_index_pattern or None,
        "tenant_filter": {
            "field": integration.opensearch_tenant_field,
            "values": list(integration.opensearch_tenant_value_list),
        },
        "verified_in_process": "api",
    }


async def last_success(db: Any, tenant_id: str) -> Any:
    """When this log store last actually produced context for this tenant.

    Lives here rather than in `integration_status_service` because that module
    may not branch on a tool's name — a `if tool == "opensearch"` there is the
    same hand-listing its catalogue tests refuse, and its own guard caught the
    first version of this function sitting in it.

    The evidence is the `alert_log_context` rows. They ran until 2026-10-12
    12:26:32 and then stopped, which is the fact that tells "the configuration
    vanished" apart from "it was never configured" — and the fact nothing was
    reading while log enrichment was off for two days.

    `None` means no evidence of ever having worked, which the caller renders as
    a named absence and never as a date.
    """
    from sqlalchemy import text as _text

    result = await db.execute(_text("""
        select max(c.created_at)
        from alert_log_context c
        join alert_body_investigation_runs r on r.id = c.run_id
        where r.tenant_id = :tid and c.status in ('collected', 'partial')
    """), {"tid": tenant_id})
    return result.scalar()


def _env_key(tenant_id: str, suffix: str) -> str:
    return f"OPENSEARCH_TENANT_{_SAFE.sub('_', str(tenant_id).upper())}_{suffix}"


def _split(value: str | None) -> list[str]:
    return [v.strip() for v in str(value or "").split(",") if v.strip()]


@dataclass
class TenantIntegration:
    """The connection for one tenant.

    Shaped to be accepted by `OpenSearchClient(settings=...)` directly: the
    attribute names match what the client reads, so there is one client and no
    per-tenant branch inside it.
    """

    tenant_id: str
    opensearch_node1: str = ""
    opensearch_node2: str = ""
    opensearch_node3: str = ""
    opensearch_username: str = ""
    opensearch_password: Any = ""
    opensearch_verify_tls: bool = True
    opensearch_ca_bundle: str = ""
    opensearch_connect_timeout_seconds: int = 5
    opensearch_request_timeout_seconds: int = 20
    opensearch_index_pattern: str = ""
    opensearch_timestamp_field: str = "timestamp"
    opensearch_tenant_field: str = "manager.name"
    opensearch_tenant_value_list: list[str] = field(default_factory=list)
    opensearch_use_point_in_time: bool = True
    # Everything else a caller may read off the settings object.
    alert_log_window_minutes: int = 10
    alert_log_max_hits: int = 500
    alert_log_page_size: int = 100
    alert_log_case_max_hits: int = 2000
    alert_log_context_enabled: bool = True
    opensearch_enabled: bool = True
    opensearch_retention_days: int = 120

    @property
    def nodes(self) -> list[str]:
        return [n for n in (self.opensearch_node1, self.opensearch_node2, self.opensearch_node3) if n]

    @property
    def configured(self) -> bool:
        """Enough to connect *and* enough to stay inside this tenant.

        A pin is part of being configured, not an optional extra. An integration
        with nodes and credentials but no tenant filter would query the whole
        cluster, and on a shared cluster that is the boundary gone.
        """
        return bool(
            self.nodes
            and self.opensearch_username
            and self.opensearch_password
            and self.opensearch_index_pattern
            and self.opensearch_tenant_field
            and self.opensearch_tenant_value_list
        )

    def describe(self) -> dict[str, Any]:
        """Safe to put in an API response: no credentials, ever."""
        return {
            "tenant_id": self.tenant_id,
            "configured": self.configured,
            "node_count": len(self.nodes),
            "index_pattern": self.opensearch_index_pattern or None,
            "tenant_filter": (
                {"field": self.opensearch_tenant_field, "values": list(self.opensearch_tenant_value_list)}
                if self.opensearch_tenant_value_list else None
            ),
            "verify_tls": bool(self.opensearch_verify_tls),
        }


def _from_environment(tenant_id: str, base: Any) -> TenantIntegration | None:
    nodes = _split(os.environ.get(_env_key(tenant_id, "NODES")))
    if not nodes:
        return None
    pins = _split(os.environ.get(_env_key(tenant_id, "MANAGER")))
    return TenantIntegration(
        tenant_id=tenant_id,
        opensearch_node1=nodes[0] if len(nodes) > 0 else "",
        opensearch_node2=nodes[1] if len(nodes) > 1 else "",
        opensearch_node3=nodes[2] if len(nodes) > 2 else "",
        opensearch_username=os.environ.get(_env_key(tenant_id, "USERNAME"), ""),
        opensearch_password=os.environ.get(_env_key(tenant_id, "PASSWORD"), ""),
        opensearch_verify_tls=str(
            os.environ.get(_env_key(tenant_id, "VERIFY_TLS"), "true")
        ).strip().lower() not in ("false", "0", "no"),
        opensearch_ca_bundle=os.environ.get(_env_key(tenant_id, "CA_BUNDLE"), ""),
        opensearch_index_pattern=os.environ.get(_env_key(tenant_id, "INDEX_PATTERN"), ""),
        opensearch_timestamp_field=os.environ.get(
            _env_key(tenant_id, "TIMESTAMP_FIELD"), getattr(base, "opensearch_timestamp_field", "timestamp")
        ),
        opensearch_tenant_field=os.environ.get(
            _env_key(tenant_id, "TENANT_FIELD"), "manager.name"
        ),
        opensearch_tenant_value_list=pins,
        opensearch_connect_timeout_seconds=int(getattr(base, "opensearch_connect_timeout_seconds", 5)),
        opensearch_request_timeout_seconds=int(getattr(base, "opensearch_request_timeout_seconds", 20)),
        opensearch_use_point_in_time=bool(getattr(base, "opensearch_use_point_in_time", True)),
        alert_log_window_minutes=int(getattr(base, "alert_log_window_minutes", 10)),
        alert_log_max_hits=int(getattr(base, "alert_log_max_hits", 500)),
        alert_log_page_size=int(getattr(base, "alert_log_page_size", 100)),
        alert_log_case_max_hits=int(getattr(base, "alert_log_case_max_hits", 2000)),
        alert_log_context_enabled=bool(getattr(base, "alert_log_context_enabled", True)),
        opensearch_enabled=bool(getattr(base, "opensearch_enabled", True)),
        opensearch_retention_days=int(getattr(base, "opensearch_retention_days", 120)),
    )


def _legacy_c00(base: Any) -> TenantIntegration | None:
    """The global OPENSEARCH_* settings, which are C00's cluster.

    Named explicitly rather than treated as a default. Before this existed the
    same connection served every query; the risk was not that it was configured
    globally but that anything without a tenant could reach it.
    """
    nodes = [
        str(getattr(base, f"opensearch_node{i}", "") or "").strip() for i in (1, 2, 3)
    ]
    nodes = [n for n in nodes if n]
    if not nodes:
        return None
    return TenantIntegration(
        tenant_id=str(getattr(base, "alert_ingest_legacy_tenant", "c00") or "c00"),
        opensearch_node1=nodes[0] if len(nodes) > 0 else "",
        opensearch_node2=nodes[1] if len(nodes) > 1 else "",
        opensearch_node3=nodes[2] if len(nodes) > 2 else "",
        opensearch_username=str(getattr(base, "opensearch_username", "") or ""),
        opensearch_password=getattr(base, "opensearch_password", ""),
        opensearch_verify_tls=bool(getattr(base, "opensearch_verify_tls", True)),
        opensearch_ca_bundle=str(getattr(base, "opensearch_ca_bundle", "") or ""),
        opensearch_index_pattern=str(getattr(base, "opensearch_index_pattern", "") or ""),
        opensearch_timestamp_field=str(getattr(base, "opensearch_timestamp_field", "timestamp")),
        opensearch_tenant_field=str(getattr(base, "opensearch_tenant_field", "manager.name") or ""),
        opensearch_tenant_value_list=list(getattr(base, "opensearch_tenant_value_list", []) or []),
        opensearch_connect_timeout_seconds=int(getattr(base, "opensearch_connect_timeout_seconds", 5)),
        opensearch_request_timeout_seconds=int(getattr(base, "opensearch_request_timeout_seconds", 20)),
        opensearch_use_point_in_time=bool(getattr(base, "opensearch_use_point_in_time", True)),
        alert_log_window_minutes=int(getattr(base, "alert_log_window_minutes", 10)),
        alert_log_max_hits=int(getattr(base, "alert_log_max_hits", 500)),
        alert_log_page_size=int(getattr(base, "alert_log_page_size", 100)),
        alert_log_case_max_hits=int(getattr(base, "alert_log_case_max_hits", 2000)),
        alert_log_context_enabled=bool(getattr(base, "alert_log_context_enabled", True)),
        opensearch_enabled=bool(getattr(base, "opensearch_enabled", True)),
        opensearch_retention_days=int(getattr(base, "opensearch_retention_days", 120)),
    )


def integration_for(tenant_id: str | None, *, settings: Any = None) -> TenantIntegration | None:
    """The OpenSearch connection for this tenant, or None.

    `None` for an unassigned run. That is not an oversight to paper over with a
    default — a run whose tenant could not be verified has no cluster it is
    entitled to be enriched from, and guessing is how one client's logs get
    attached to another client's alert.
    """
    if not tenant_id:
        return None

    if settings is None:
        from app.config import get_settings

        settings = get_settings()

    tenant_id = str(tenant_id).strip()
    explicit = _from_environment(tenant_id, settings)
    if explicit is not None:
        return explicit

    legacy = _legacy_c00(settings)
    if legacy is not None and legacy.tenant_id == tenant_id:
        return legacy
    return None


def unavailable_reason(tenant_id: str | None) -> str:
    if not tenant_id:
        return (
            "This alert has no verified tenant, so there is no log cluster it can be "
            "enriched from. Assign it to a client to enable log retrieval."
        )
    return (
        f"No OpenSearch integration is configured for tenant {tenant_id!r}. "
        "Log enrichment is unavailable for this client until one is."
    )
