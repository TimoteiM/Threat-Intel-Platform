"""The estate lookup: "did anything in this customer's estate touch this?"

This is the query that turns an intel hit into an incident, which is exactly
why the dangerous direction is written first. A reader who sees "no host
resolved this domain" **de-escalates**. So every way the lookup can fail to
answer must be distinguishable from an answer of no:

  * a URL — unanswerable at that grain in this estate at all, because there
    are no proxy logs (`data.proxy.url` and `data.http.url` are both 0 and
    `data.url` comes from one appliance)
  * a window older than the 120-day retention — unknown, never no contact
  * OpenSearch unreachable, or the tenant has no pinned integration
  * a tenant whose integration is absent — never a fallback to another
    tenant's cluster

And the structural rule from the recon: `queryName` (2.6M docs, 175 of 180
hosts) and `dstip` (2.07bn docs, ONE agent — a network appliance) answer
different questions and must never be merged. A perimeter hit with no
corresponding host query is a more suspicious shape than one with, and a
union would report a single yes meaning neither.
"""
from __future__ import annotations

import pytest

from app.services import absence
from app.services import estate_lookup_service as est


class _FakeClient:
    """Stands in for OpenSearchClient. Records what it was asked."""

    def __init__(self, hits=None, hosts=None, fail=False):
        self.calls: list[dict] = []
        self._hits = hits if hits is not None else 0
        self._hosts = hosts if hosts is not None else []
        self._fail = fail

    def count_and_hosts(self, *, field, value, since, until, tenant_id):
        self.calls.append({
            "field": field, "value": value, "since": since,
            "until": until, "tenant_id": tenant_id,
        })
        if self._fail:
            raise RuntimeError("cluster unreachable")
        return self._hits, list(self._hosts)


# --- the dangerous direction: an absence must never read as "not seen" ----


def test_a_url_is_out_of_scope_not_zero():
    """There are no proxy logs in this estate. Zero would be a lie."""
    result = est.lookup("https://evil.test/path", kind="url", tenant_id="c00",
                        client=_FakeClient())
    host = result["host_dns"]
    assert absence.is_absent(host)
    assert host["kind"] == absence.OUT_OF_SCOPE
    assert "proxy" in host["reason"].lower()
    # And it must not have queried anything: asking the wrong grain and
    # getting 0 is how this becomes a silent negative.
    assert result["queried"] == []


def test_a_window_older_than_retention_is_unknown_not_clean():
    result = est.lookup("evil.test", kind="domain", tenant_id="c00",
                        days=400, client=_FakeClient())
    host = result["host_dns"]
    assert absence.is_absent(host)
    assert host["kind"] == absence.TOO_LITTLE_HISTORY
    assert "retention" in host["reason"].lower()


def test_a_failed_query_is_check_failed_not_not_observed():
    result = est.lookup("evil.test", kind="domain", tenant_id="c00",
                        client=_FakeClient(fail=True))
    host = result["host_dns"]
    assert absence.is_absent(host)
    assert host["kind"] == absence.CHECK_FAILED


def test_no_tenant_integration_never_falls_back_to_another_cluster():
    result = est.lookup("evil.test", kind="domain", tenant_id="unknown-tenant",
                        client=None)
    host = result["host_dns"]
    assert absence.is_absent(host)
    assert host["kind"] == absence.CHECK_FAILED
    assert result["queried"] == []


def test_zero_hits_is_an_answer_and_says_so():
    """The one case that IS a negative, and it must be clearly distinct."""
    result = est.lookup("quiet.test", kind="domain", tenant_id="c00",
                        client=_FakeClient(hits=0, hosts=[]))
    host = result["host_dns"]
    assert not absence.is_absent(host)
    assert host["observed"] is False
    assert host["hosts"] == []
    assert host["documents"] == 0
    # The window is stated beside the answer, because "not seen" is only
    # meaningful with a population.
    assert host["window_days"] > 0


# --- the structural rule: never merge the two questions -------------------


def test_host_dns_and_perimeter_are_reported_separately():
    client = _FakeClient(hits=5, hosts=["ws1", "ws2"])
    result = est.lookup("evil.test", kind="domain", tenant_id="c00",
                        client=client)
    assert "host_dns" in result and "perimeter" in result
    assert "observed" in result["host_dns"]
    # No merged verdict anywhere in the payload.
    for banned in ("seen", "any", "observed_anywhere", "estate_hit"):
        assert banned not in result, (
            f"{banned!r} would be a union of two different questions"
        )


def test_the_two_questions_use_different_fields():
    client = _FakeClient(hits=1, hosts=["ws1"])
    est.lookup("1.2.3.4", kind="ip", tenant_id="c00", client=client)
    fields = [c["field"] for c in client.calls]
    assert est.HOST_DNS_FIELD not in fields or est.PERIMETER_FIELD not in fields \
        or est.HOST_DNS_FIELD != est.PERIMETER_FIELD
    assert est.HOST_DNS_FIELD == "data.win.eventdata.queryName"
    assert est.PERIMETER_FIELD == "data.dstip"


def test_a_domain_does_not_query_the_perimeter_address_field():
    """A domain is not an address; querying dstip for it would return 0 and
    that 0 would read as "the perimeter never saw it"."""
    client = _FakeClient()
    est.lookup("evil.test", kind="domain", tenant_id="c00", client=client)
    assert est.PERIMETER_FIELD not in [c["field"] for c in client.calls]
    assert absence.is_absent(
        est.lookup("evil.test", kind="domain", tenant_id="c00",
                   client=client)["perimeter"]
    )


def test_an_ip_does_not_query_the_dns_name_field():
    client = _FakeClient()
    result = est.lookup("1.2.3.4", kind="ip", tenant_id="c00", client=client)
    assert est.HOST_DNS_FIELD not in [c["field"] for c in client.calls]
    assert absence.is_absent(result["host_dns"])


def test_the_perimeter_answer_names_its_single_agent_limit():
    """2.07bn docs from ONE appliance. A reader must not read it as estate-wide."""
    client = _FakeClient(hits=900, hosts=["fw-01"])
    result = est.lookup("1.2.3.4", kind="ip", tenant_id="c00", client=client)
    per = result["perimeter"]
    assert not absence.is_absent(per)
    assert per["observed"] is True
    assert "appliance" in per["basis"].lower() or "perimeter" in per["basis"].lower()


def test_host_coverage_is_stated_with_the_dns_answer():
    """175 of 180 hosts run Sysmon DNS logging. "No host resolved it" is a
    claim about 97.2% of the estate, not 100%, and it must say so."""
    client = _FakeClient(hits=0, hosts=[])
    result = est.lookup("quiet.test", kind="domain", tenant_id="c00",
                        client=client)
    cov = result["host_dns"]["coverage"]
    assert cov["hosts_with_dns_logging"] == 175
    assert cov["hosts_total"] == 180
    assert 0.97 <= cov["fraction"] <= 0.98


# --- tenant pinning -------------------------------------------------------


def test_the_tenant_is_passed_to_every_query():
    client = _FakeClient(hits=1, hosts=["ws1"])
    est.lookup("evil.test", kind="domain", tenant_id="c00", client=client)
    assert client.calls
    for call in client.calls:
        assert call["tenant_id"] == "c00"


def test_a_blank_tenant_is_refused_not_defaulted():
    for blank in ("", "   ", None):
        result = est.lookup("evil.test", kind="domain", tenant_id=blank,
                            client=_FakeClient())
        assert absence.is_absent(result["host_dns"])
        assert result["queried"] == []


# --- the window is a measurement, so it is reported ----------------------


def test_the_window_and_the_retention_limit_are_both_reported():
    result = est.lookup("evil.test", kind="domain", tenant_id="c00",
                        days=30, client=_FakeClient(hits=2, hosts=["ws1"]))
    assert result["window"]["days"] == 30
    assert result["window"]["retention_days"] == est.RETENTION_DAYS
    assert result["window"]["within_retention"] is True


def test_an_unknown_kind_is_an_absence_with_its_own_reason():
    result = est.lookup("something", kind="mutex", tenant_id="c00",
                        client=_FakeClient())
    assert absence.is_absent(result["host_dns"])
    assert result["host_dns"]["kind"] in (
        absence.OUT_OF_SCOPE, absence.NO_FIELD_MAP,
    )


# --- the adapter: silent defaults are the whole danger -------------------
#
# Both of these were real defects in the first version of
# OpenSearchEstateClient, found by running it against the live cluster and
# noticing the host count disagreed with the recon (109 against 5).
#
#   * it read `tenant_values`, which does not exist — the field is
#     `opensearch_tenant_value_list` — and `getattr(..., None) or []` turned
#     the missing attribute into "no tenant filter", so the query ran
#     UNPINNED across every tenant's documents.
#   * it hard-coded `@timestamp`, while the integration carries
#     `opensearch_timestamp_field` (default `timestamp`). On a tenant using
#     the default, the range filter would match nothing and the lookup would
#     return a confident zero.
#
# Both are the same shape: a silent default where an absence should be loud,
# in the position where the consequence is an unpinned query or a false
# negative.


class _Integration:
    def __init__(self, **kw):
        self.opensearch_index_pattern = kw.get("pattern", "wazuh-alerts-4.x-*")
        self.opensearch_tenant_field = kw.get("tenant_field", "manager.name")
        self.opensearch_tenant_value_list = kw.get("values", ["wm-c00.siembiot.int"])
        self.opensearch_timestamp_field = kw.get("ts", "timestamp")


class _RecordingClient:
    def __init__(self):
        self.bodies: list[dict] = []

    def _request(self, method, path, *, json_body=None, params=None):
        self.bodies.append(json_body)
        return ({"hits": {"total": {"value": 3}},
                 "aggregations": {"hosts": {"buckets": [{"key": "ws1"}]}}},
                "node", [])


def _filters(body):
    return body["query"]["bool"]["filter"]


def test_the_adapter_pins_the_tenant_using_the_real_field_name():
    raw = _RecordingClient()
    est.OpenSearchEstateClient(raw, _Integration()).count_and_hosts(
        field=est.HOST_DNS_FIELD, value="x.test",
        since="2026-10-01T00:00:00+00:00", until="2026-10-08T00:00:00+00:00",
        tenant_id="c00",
    )
    pinned = [f for f in _filters(raw.bodies[0])
              if "terms" in f and "manager.name" in f["terms"]]
    assert pinned, (
        "no manager.name filter in the query: it would run across every "
        "tenant's documents"
    )
    assert pinned[0]["terms"]["manager.name"] == ["wm-c00.siembiot.int"]


def test_an_integration_with_no_tenant_values_refuses_rather_than_unpinning():
    """The dangerous direction. An unpinned estate query is worse than none."""
    raw = _RecordingClient()
    client = est.OpenSearchEstateClient(raw, _Integration(values=[]))
    with pytest.raises(Exception):
        client.count_and_hosts(
            field=est.HOST_DNS_FIELD, value="x.test",
            since="a", until="b", tenant_id="c00",
        )
    assert raw.bodies == [], "a query was sent despite having no tenant pin"


def test_an_integration_with_no_tenant_field_refuses_too():
    raw = _RecordingClient()
    client = est.OpenSearchEstateClient(raw, _Integration(tenant_field=""))
    with pytest.raises(Exception):
        client.count_and_hosts(
            field=est.HOST_DNS_FIELD, value="x.test",
            since="a", until="b", tenant_id="c00",
        )
    assert raw.bodies == []


def test_the_timestamp_field_comes_from_the_integration_not_a_constant():
    raw = _RecordingClient()
    est.OpenSearchEstateClient(raw, _Integration(ts="timestamp")).count_and_hosts(
        field=est.HOST_DNS_FIELD, value="x.test",
        since="s", until="u", tenant_id="c00",
    )
    ranges = [f["range"] for f in _filters(raw.bodies[0]) if "range" in f]
    assert ranges and "timestamp" in ranges[0], (
        f"range filter used {list(ranges[0]) if ranges else None}, not the "
        f"integration's configured timestamp field"
    )
    assert "@timestamp" not in ranges[0]


def test_a_refusal_surfaces_as_check_failed_not_as_zero():
    """End to end: the adapter raising must not become a clean answer."""
    class _Unpinnable:
        def count_and_hosts(self, **kw):
            raise RuntimeError("no tenant pin available")

    result = est.lookup("x.test", kind="domain", tenant_id="c00",
                        client=_Unpinnable())
    assert absence.is_absent(result["host_dns"])
    assert result["host_dns"]["kind"] == absence.CHECK_FAILED
