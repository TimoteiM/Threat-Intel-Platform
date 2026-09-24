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
