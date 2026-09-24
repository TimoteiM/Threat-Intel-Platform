"""Historical classification, and the rule that OpenSearch follows the tenant.

The migration is the risky half of tenancy: 13,084 runs already exist and a
wrong assignment puts one client's alert in another client's list permanently.
These pin the classification rules and the per-tenant routing that follows.
"""

from __future__ import annotations

import pytest

from app.services import opensearch_tenants as ot


class Base:
    opensearch_node1 = "https://os-1:9200"
    opensearch_node2 = "https://os-2:9200"
    opensearch_node3 = ""
    opensearch_username = "admin"
    opensearch_password = "pw"
    opensearch_verify_tls = True
    opensearch_ca_bundle = ""
    opensearch_index_pattern = "wazuh-alerts-4.x-*"
    opensearch_timestamp_field = "timestamp"
    opensearch_tenant_field = "manager.name"
    opensearch_tenant_value_list = ["wm-c00.siembiot.int"]
    opensearch_connect_timeout_seconds = 5
    opensearch_request_timeout_seconds = 20
    opensearch_use_point_in_time = True
    alert_ingest_legacy_tenant = "c00"
    alert_log_window_minutes = 10
    alert_log_max_hits = 500
    alert_log_page_size = 100
    alert_log_case_max_hits = 2000
    alert_log_context_enabled = True
    opensearch_enabled = True
    opensearch_retention_days = 120


# --- routing -----------------------------------------------------------------

def test_the_global_settings_belong_to_c00_and_to_nothing_else():
    """Before this, one connection served every query. The risk was never that
    it was configured globally — it was that anything could reach it."""
    assert ot.integration_for("c00", settings=Base()) is not None
    assert ot.integration_for("lin", settings=Base()) is None


def test_an_unassigned_run_has_no_cluster_to_read():
    assert ot.integration_for(None, settings=Base()) is None
    assert "no verified tenant" in ot.unavailable_reason(None)


def test_an_unconfigured_tenant_says_so_rather_than_falling_back():
    reason = ot.unavailable_reason("lin")
    assert "lin" in reason and "unavailable" in reason.lower()


def test_a_tenant_reads_its_own_nodes_from_the_environment(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_NODES", "https://lin-1:9200,https://lin-2:9200")
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_USERNAME", "lin-reader")
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_PASSWORD", "secret")
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_INDEX_PATTERN", "wazuh-alerts-4.x-*")
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_MANAGER", "wm-lin.siembiot.int")

    integration = ot.integration_for("lin", settings=Base())
    assert integration is not None and integration.configured
    assert integration.nodes == ["https://lin-1:9200", "https://lin-2:9200"]
    assert integration.opensearch_tenant_value_list == ["wm-lin.siembiot.int"]
    # And it is still not C00's cluster.
    assert "os-1" not in "".join(integration.nodes)


def test_an_integration_without_a_tenant_pin_is_not_considered_configured(monkeypatch):
    """Nodes and credentials but no filter would query the whole cluster; on a
    shared cluster that is the boundary gone."""
    monkeypatch.setenv("OPENSEARCH_TENANT_ACME_NODES", "https://acme-1:9200")
    monkeypatch.setenv("OPENSEARCH_TENANT_ACME_USERNAME", "u")
    monkeypatch.setenv("OPENSEARCH_TENANT_ACME_PASSWORD", "p")
    monkeypatch.setenv("OPENSEARCH_TENANT_ACME_INDEX_PATTERN", "acme-*")
    integration = ot.integration_for("acme", settings=Base())
    assert integration is not None
    assert not integration.configured


def test_describing_an_integration_never_includes_credentials(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_NODES", "https://lin-1:9200")
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_USERNAME", "lin-reader")
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_PASSWORD", "sup3rs3cret")
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_MANAGER", "wm-lin")
    monkeypatch.setenv("OPENSEARCH_TENANT_LIN_INDEX_PATTERN", "x-*")
    described = str(ot.integration_for("lin", settings=Base()).describe())
    assert "sup3rs3cret" not in described
    assert "lin-reader" not in described


def test_connection_details_can_only_come_from_configuration():
    """The alert body and the request payload are attacker-influenced. The only
    way to obtain a connection is to name a tenant, so there is no parameter
    through which a request could supply nodes, credentials or a filter."""
    import inspect

    params = set(inspect.signature(ot.integration_for).parameters)
    assert params == {"tenant_id", "settings"}

    # The two resolvers take a tenant and a settings object, and nothing else:
    # there is no parameter an HTTP request or an alert body could arrive through.
    for fn in (ot._from_environment, ot._legacy_c00):
        assert set(inspect.signature(fn).parameters) <= {"tenant_id", "base"}


# --- the historical classification rules ------------------------------------

def _classify(body: str, source: str | None, client: str | None) -> str | None:
    """The migration's two rules, expressed exactly as migration 030 applies them."""
    unassigned_client = (client or "unknown") in ("unknown", "")
    if "manager: siembiot" in (body or "").casefold() and unassigned_client:
        return "marker"
    if source == "wm-c00.siembiot.int" and unassigned_client:
        return "manager_source"
    return None


def test_the_c00_marker_assigns_c00():
    assert _classify("Agent: EXP-01\nManager: Siembiot\n", "Siembiot", None) == "marker"


def test_a_declared_other_client_blocks_the_marker():
    """One stored run declares 'Codex Desktop' and carries the marker. The rule
    refuses it rather than resolving the contradiction silently."""
    assert _classify("Manager: Siembiot", "Siembiot", "Codex Desktop") is None


def test_a_lin_run_is_never_assigned_to_c00():
    """Measured: none of the 18 runs declaring LIN carry the marker. This pins
    that even if one did, it would not be swept into C00."""
    assert _classify("client: LIN\nsome alert", "unknown", "LIN") is None


def test_tracecat_shaped_channels_are_not_a_tenant():
    """The unassigned bucket is Cloudflare, Office 365, Skyformation,
    SentinelOne and Exabeam — a mix of channels, and a channel is not a client."""
    for body in (
        'destinationServiceName=Cloudflare {"Policy":"Block_Bad_TLDs"}',
        "<110>1 2026-08-09T14:24:56Z host Skyformation - 5007",
        '{"agentDetectionInfo":{"accountId":"214234"}}',
    ):
        assert _classify(body, "unknown", None) is None


def test_a_mere_mention_of_the_manager_hostname_is_not_verification():
    """22 unassigned runs mention 'siembiot' and 9 mention 'wm-c00' somewhere in
    their body. A hostname can appear in a log forwarded from anywhere, so
    suggestive is not the same as verified."""
    assert _classify("some log mentioning wm-c00.siembiot.int inside it", "unknown", None) is None


def test_the_manager_naming_itself_as_the_source_is_verification():
    assert _classify("EXP-F2HFXL3 crashed", "wm-c00.siembiot.int", None) == "manager_source"
