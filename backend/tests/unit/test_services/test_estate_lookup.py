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

from datetime import datetime, timedelta, timezone

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


# --- first-seen against the email's receipt time -------------------------
#
# The discriminator an analyst acts on. `aka.ms` is SEEN on 46 hosts and has
# nothing to do with the email it appeared in — it is Microsoft background
# traffic. Honest wording stops the panel over-claiming; it does not help
# anyone sort 46 background hosts from 2 meaningful ones.
#
# The separator is first-seen against receipt: a domain first resolved AFTER
# the email arrived is a finding; one resolved for months is infrastructure.
#
# And the trap: a 7-day window cannot produce "first resolved 4 months ago".
# `first_seen` inside a bounded window is a LOWER BOUND, and reporting it as
# an exact first-seen turns long-standing infrastructure into a brand-new
# finding — the clamp reads as the answer. `lower_bound` is already in the
# absence convention for exactly this.


class _TimedClient:
    """Counts, a first/last pair, and a per-host collection floor.

    `floor` defaults to well before any `first` these tests use, so a test
    that is not about the floor is not silently about the floor.
    """

    def __init__(self, hits=5, hosts=("ws1",), first=None, last=None,
                 floor=None, floors=None):
        self.calls = []
        self._hits, self._hosts = hits, list(hosts)
        self._first, self._last = first, last
        self._floor = floor or datetime(2026, 1, 1, tzinfo=timezone.utc)
        self._floors = floors

    def count_and_hosts(self, *, field, value, since, until, tenant_id):
        self.calls.append({"field": field, "since": since, "until": until})
        return self._hits, list(self._hosts)

    def first_last_seen(self, *, field, value, since, until, tenant_id):
        self.calls.append({"field": field, "window": "retention",
                           "since": since, "until": until})
        return self._first, self._last

    def observation_floor(self, *, field, since, until, tenant_id):
        self.calls.append({"field": field, "query": "floor", "since": since})
        if self._floors is not None:
            return dict(self._floors)
        return {h: self._floor for h in self._hosts}


#: Run 113's row time — which is its UPLOAD time, not when the mail arrived.
#: Named that way here because reporting it as the receipt time is the live
#: mistake this contract now prevents: see `test_a_bare_reference_time_...`.
UPLOADED = datetime(2026, 10, 15, 7, 45, tzinfo=timezone.utc)
REF = datetime(2026, 10, 15, 7, 45, tzinfo=timezone.utc)
ANCHOR = "the earliest Received header written by our own mail infrastructure"


def test_a_domain_resolved_long_before_the_email_reads_as_infrastructure():
    client = _TimedClient(
        hits=1868, hosts=("EXP-1", "EXP-2"),
        first=datetime(2026, 6, 20, 9, 0, tzinfo=timezone.utc),
        last=REF,
        floor=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    r = est.lookup("aka.ms", kind="domain", tenant_id="c00",
                   client=client, reference_time=REF,
                   reference_anchor=ANCHOR, now=REF)
    rel = r["host_dns"]["relative_to_reference"]
    assert rel["first_seen_before_reference"] is True
    assert rel["classification"] == est.PRE_EXISTING
    assert "before this email" in rel["sentence"]
    # The sentence must say which of the three timestamps it measured from.
    assert ANCHOR in rel["sentence"]
    assert rel["reference_anchor"] == ANCHOR


def test_a_domain_first_resolved_after_the_email_is_a_finding():
    client = _TimedClient(
        hits=3, hosts=("EXP-9",),
        first=REF + timedelta(minutes=11),
        last=REF + timedelta(minutes=14),
    )
    r = est.lookup("evil.test", kind="domain", tenant_id="c00",
                   client=client, reference_time=REF,
                   reference_anchor=ANCHOR,
                   now=REF + timedelta(minutes=20))
    rel = r["host_dns"]["relative_to_reference"]
    assert rel["first_seen_before_reference"] is False
    assert rel["classification"] == est.NEW_SINCE
    # Case-insensitive: the sentence emphasises AFTER deliberately, and a
    # test should not pin the emphasis.
    assert "after this email" in rel["sentence"].lower()
    assert "11 minutes" in rel["sentence"]


def test_a_first_seen_at_the_collection_floor_is_a_lower_bound():
    """The floor must not read as the answer.

    Without this, every long-standing domain whose telemetry happens to start
    after the email would be classified NEW_SINCE — turning infrastructure
    into a finding, which is the opposite of the discriminator's purpose.
    """
    floor = datetime(2026, 10, 2, 0, 5, tzinfo=timezone.utc)
    client = _TimedClient(
        hits=900, hosts=("EXP-1",),
        first=floor + timedelta(minutes=2),      # at the floor
        last=REF, floor=floor,
    )
    r = est.lookup("old.test", kind="domain", tenant_id="c00",
                   client=client, reference_time=REF,
                   reference_anchor=ANCHOR, now=REF)
    rel = r["host_dns"]["relative_to_reference"]
    assert rel["classification"] == est.AT_OBSERVATION_FLOOR
    assert rel["first_seen_is_lower_bound"] is True
    assert "at least" in rel["sentence"].lower()
    assert "not recorded either way" in rel["sentence"].lower()


def test_a_floor_inside_the_retention_window_still_bounds_the_first_seen():
    """The live failure, and the one the window-edge test could not catch.

    `aka.ms` — Microsoft infrastructure on 46 hosts, 1,871 documents —
    reported first_seen 2026-10-02 11:49 with a complete aggregation
    (360/360 shards, timed_out false) over a retention window reaching back
    to 2026-06-17. Nothing was near the window's edge, so the edge test was
    silent and the domain was classified `pre_existing` on 13 days of
    history. The real limit was collection: Sysmon event 22 began on
    2026-10-02, 107 days inside the window.

    The figures below are that measurement, re-read live after the fix: 47
    hosts, 1,858 documents, floor 11:27:31 and first-seen 11:49:42 — 22
    minutes, not the hours I first assumed when sizing the grace window. The
    threshold was never what was broken; what the floor was measured against
    was.
    """
    floor = datetime(2026, 10, 2, 11, 27, 31, tzinfo=timezone.utc)
    client = _TimedClient(
        hits=1858, hosts=tuple(f"EXP-{n}" for n in range(47)),
        first=datetime(2026, 10, 2, 11, 49, 42, tzinfo=timezone.utc),
        last=REF, floor=floor,
    )
    r = est.lookup("aka.ms", kind="domain", tenant_id="c00",
                   client=client, reference_time=REF,
                   reference_anchor=ANCHOR, now=REF)
    rel = r["host_dns"]["relative_to_reference"]
    assert rel["classification"] == est.AT_OBSERVATION_FLOOR, (
        "a first-seen on the first day of collection was reported as the "
        "domain's own history"
    )
    assert rel["first_seen_before_reference"] is False


def test_the_floor_is_the_earliest_among_the_hosts_that_hold_the_value():
    """Earliest, not latest.

    A host collecting since the start and still not resolving the name until
    later is the evidence that the name is new. Taking the latest floor would
    discard it and call every first-seen a collection artefact — a guard that
    swallows the finding it was meant to protect.
    """
    early = datetime(2026, 10, 2, tzinfo=timezone.utc)
    late = datetime(2026, 10, 12, tzinfo=timezone.utc)
    client = _TimedClient(
        hits=4, hosts=("EXP-A", "EXP-B"),
        first=datetime(2026, 10, 12, 6, 0, tzinfo=timezone.utc),
        last=REF,
        floors={"EXP-A": early, "EXP-B": late},
    )
    r = est.lookup("new.test", kind="domain", tenant_id="c00",
                   client=client, reference_time=REF,
                   reference_anchor=ANCHOR, now=REF)
    rel = r["host_dns"]["relative_to_reference"]
    assert rel["observation_floor"] == early.isoformat()
    # With the LATEST floor (Oct 12) this first-seen sits inside the grace
    # window and is swallowed as a collection artefact. With the earliest it
    # keeps its ten days of evidence and gets a real comparison.
    assert rel["classification"] == est.PRE_EXISTING
    assert rel["first_seen_is_lower_bound"] is False


def test_a_host_with_no_known_floor_makes_the_comparison_unknown():
    """Indexed, not `.get()`.

    A host missing from the floor map has an unknown collection start. If
    that read as "no floor" the comparison would quietly use another host's,
    which is the absence-as-value shape this convention exists to stop.
    """
    client = _TimedClient(
        hits=4, hosts=("EXP-A", "EXP-UNSEEN"),
        first=datetime(2026, 10, 12, tzinfo=timezone.utc), last=REF,
        floors={"EXP-A": datetime(2026, 10, 2, tzinfo=timezone.utc)},
    )
    r = est.lookup("x.test", kind="domain", tenant_id="c00",
                   client=client, reference_time=REF,
                   reference_anchor=ANCHOR, now=REF)
    rel = r["host_dns"]["relative_to_reference"]
    assert absence.is_absent(rel)
    assert rel["kind"] == absence.CHECK_FAILED
    assert "EXP-UNSEEN" in (rel.get("raw") or "")


def test_a_client_that_cannot_report_a_floor_gets_no_classification():
    """The dangerous direction: an older client silently keeps the old,
    floorless behaviour and goes on emitting confident sentences."""
    class _FloorlessClient:
        def count_and_hosts(self, **kw):
            return 9, ["ws1"]

        def first_last_seen(self, **kw):
            return datetime(2026, 10, 10, tzinfo=timezone.utc), REF

    r = est.lookup("x.test", kind="domain", tenant_id="c00",
                   client=_FloorlessClient(), reference_time=REF,
                   reference_anchor=ANCHOR, now=REF)
    rel = r["host_dns"]["relative_to_reference"]
    assert absence.is_absent(rel)
    assert rel["kind"] == absence.CHECK_FAILED


def test_a_bare_reference_time_with_no_named_anchor_is_refused():
    """What actually went wrong on 2026-10-15.

    `reference_time` took a bare datetime and the value handed to it was
    `email_investigation_runs.created_at` — the upload time — which was then
    reported as "this email". Nothing in the signature could tell. Requiring
    the anchor's name makes that call unwriteable rather than merely
    discouraged.
    """
    client = _TimedClient(hits=5, hosts=("ws1",),
                          first=REF - timedelta(days=90), last=REF)
    r = est.lookup("x.test", kind="domain", tenant_id="c00",
                   client=client, reference_time=UPLOADED, now=REF)
    assert absence.is_absent(r["host_dns"])
    assert r["host_dns"]["kind"] == absence.CHECK_FAILED
    assert "unnamed" in r["host_dns"]["reason"]
    assert client.calls == [], (
        "the store was queried for a comparison that cannot be made"
    )


def test_the_dns_question_is_pinned_to_the_resolution_event():
    """A timeout is not a resolution.

    1,966 of the documents carrying `queryName` over the full retention are
    Windows event 1014 — "DNS name resolution timed out" — and before
    2026-10-02 they are ALL of them. Counting those as contact answers the
    opposite of the question: a name nothing could reach would read as a name
    a host visited.
    """
    assert est.DNS_EVENT_QUERY == "22"
    clauses = est._SEMANTIC_FILTERS[est.HOST_DNS_FIELD]
    assert {"term": {est.DNS_EVENT_FIELD: "22"}} in clauses
    # And the perimeter question must NOT inherit it: `data.dstip` comes from
    # an appliance that writes no Windows event id, so the pin would zero it.
    assert est._SEMANTIC_FILTERS.get(est.PERIMETER_FIELD) is None


def test_the_true_first_seen_is_sought_over_retention_not_the_7_day_window():
    """A 7-day window cannot answer "months"; only a hit pays for the wider
    query, so the cost is per-hit rather than per-indicator."""
    client = _TimedClient(hits=5, hosts=("ws1",),
                          first=REF - timedelta(days=90), last=REF)
    est.lookup("x.test", kind="domain", tenant_id="c00", days=7,
               client=client, reference_time=REF,
               reference_anchor=ANCHOR, now=REF)
    wide = [c for c in client.calls if c.get("window") == "retention"]
    assert wide, "no retention-wide query was made for the first-seen"


def test_a_miss_costs_no_extra_query():
    client = _TimedClient(hits=0, hosts=())
    est.lookup("quiet.test", kind="domain", tenant_id="c00", days=7,
               client=client, reference_time=REF,
               reference_anchor=ANCHOR, now=REF)
    assert [c for c in client.calls if c.get("window") == "retention"] == [], (
        "a not-observed indicator paid for a first-seen query it cannot use"
    )
    assert [c for c in client.calls if c.get("query") == "floor"] == [], (
        "a miss paid for a collection-floor query it cannot use"
    )


def test_without_a_reference_time_no_comparison_is_claimed():
    client = _TimedClient(hits=5, hosts=("ws1",),
                          first=REF - timedelta(days=90), last=REF)
    r = est.lookup("x.test", kind="domain", tenant_id="c00", client=client)
    assert r["host_dns"].get("relative_to_reference") is None


def test_a_partial_first_seen_result_is_an_absence_not_an_answer():
    """A timed-out or shard-failed aggregation returns a LATER min than the
    truth, which would classify long-standing infrastructure as new.

    The condition is reachable on this cluster: a retention-wide min over
    `data.dstip` (2.07bn docs) timed out during the 2026-10-15 verification.
    So `timed_out` and `_shards.failed` must be read, and a partial result
    reported as unknown rather than used.
    """
    class _PartialClient:
        def count_and_hosts(self, **kw):
            return 5, ["ws1"]

        def first_last_seen(self, **kw):
            raise est.PartialResult(
                "aggregation timed out: 120 of 360 shards reported"
            )

    r = est.lookup("x.test", kind="domain", tenant_id="c00",
                   client=_PartialClient(), reference_time=REF,
                   reference_anchor=ANCHOR, now=REF)
    part = r["host_dns"]
    assert part["observed"] is True          # the hit itself is sound
    assert absence.is_absent(part["first_seen"])
    assert part["first_seen"]["kind"] == absence.CHECK_FAILED
    assert part.get("relative_to_reference") is None, (
        "a comparison was claimed against a first-seen that is not known"
    )
