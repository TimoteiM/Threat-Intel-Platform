"""Choosing who an alert is about, and reading ten minutes either side.

The entity decisions carry more weight here than anywhere else in the platform.
A wrong `entity_user` in correlation misfiles a case; a wrong one here returns
another person's activity and presents it as this alert's evidence. Both known
failure modes of the stored columns are pinned below.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services import alert_log_context_service as lc

EVENT = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


class Settings:
    alert_log_context_enabled = True
    opensearch_enabled = True
    alert_log_window_minutes = 10
    alert_log_max_hits = 500
    alert_log_page_size = 100
    alert_log_case_max_hits = 2000
    opensearch_index_pattern = "wazuh-alerts-4.x-*"
    opensearch_timestamp_field = "timestamp"


# --- who the alert is about --------------------------------------------------

def test_the_domain_half_is_not_queried_as_the_username():
    """The measured extractor bug: `CORP\\jdoe` is stored as `CORP`, in 318 of
    3,376 bodies. Querying `CORP` as an account returns nothing, or worse, some
    unrelated account that happens to be called that."""
    principal = lc.principal_of("CORP", alert_body="Logon failure for CORP\\jdoe on HOST01")
    assert principal.account == "jdoe"
    assert principal.domain == "CORP"
    assert "CORP\\jdoe" in principal.spellings()


def test_an_account_legitimately_called_corp_is_still_queried():
    """The override only fires when the body actually shows that value as the
    domain half. Otherwise a real account named CORP would become unqueryable."""
    principal = lc.principal_of("CORP", alert_body="Logon failure for CORP on HOST01")
    assert principal.account == "CORP"
    assert principal.domain is None


def test_non_principals_are_refused():
    """`system` and `anonymous` are stored as users on this deployment. Querying
    them returns every machine's activity, presented as one account's."""
    for value in ("SYSTEM", "system", "ANONYMOUS LOGON", "NT AUTHORITY\\SYSTEM", "-"):
        principal = lc.principal_of(value)
        assert not principal.usable, value
        assert principal.rejected_reason


def test_a_machine_account_is_refused():
    assert not lc.principal_of("HOST01$").usable


def test_one_principal_is_queried_in_every_spelling_it_wears():
    """`jdoe`, `CORP\\jdoe` and `jdoe@corp.tld` land in different fields of
    different documents; querying one finds a third of the activity."""
    spellings = lc.principal_of("CORP\\jdoe").spellings()
    assert "jdoe" in spellings
    assert "CORP\\jdoe" in spellings

    upn = lc.principal_of("jdoe@corp.tld")
    assert upn.upn == "jdoe@corp.tld"
    assert upn.account == "jdoe"


def test_a_manager_forwarded_alert_names_no_device():
    """agent.id 000 is the manager. Filtering logs on its name returns every
    forwarded log in the estate, which looks like a very busy host."""
    device = lc.device_of("wm-c00.siembiot.int", alert_fields={"agent_id": "000"})
    assert not device.usable
    assert "manager" in device.rejected_reason


def test_a_manager_forwarded_alert_still_uses_its_agent_ip():
    device = lc.device_of("wm-c00.siembiot.int", alert_fields={"agent_id": "000", "agent_ip": "10.10.30.14"})
    assert device.ip == "10.10.30.14"
    assert device.name is None


def test_a_device_category_is_not_a_device():
    """`dvchost=Personal computer` describes a machine rather than naming one."""
    device = lc.device_of("Personal computer", alert_fields={"agent_id": "007"})
    assert not device.usable


def test_a_named_host_is_used_as_written():
    device = lc.device_of("expsccm01", alert_fields={"agent_id": "1173", "agent_ip": "10.10.30.14"})
    assert device.name == "expsccm01"
    assert device.ip == "10.10.30.14"


# --- the window --------------------------------------------------------------

def test_a_historical_window_is_complete():
    window = lc.window_for(EVENT, minutes=10, now=EVENT + timedelta(hours=2))
    assert window.start == EVENT - timedelta(minutes=10)
    assert window.end == EVENT + timedelta(minutes=10)
    assert window.complete is True
    assert window.covered_until == window.end


def test_a_live_alert_window_ends_in_the_future():
    """The real-time flow. Only the part that has happened can be read."""
    now = EVENT + timedelta(minutes=3)
    window = lc.window_for(EVENT, minutes=10, now=now)
    assert window.complete is False
    assert window.covered_until == now
    assert window.pending_seconds == pytest.approx(7 * 60)


# --- the query ---------------------------------------------------------------

def test_the_query_filters_on_time_and_requires_an_entity_match():
    query = lc.build_query(
        device=lc.Device(name="expsccm01"), principal=lc.principal_of("jdoe"),
        start=EVENT - timedelta(minutes=10), end=EVENT + timedelta(minutes=10),
        timestamp_field="timestamp",
    )
    bool_q = query["bool"]
    assert bool_q["minimum_should_match"] == 1
    assert bool_q["filter"][0]["range"]["timestamp"]["gte"].startswith("2026-09-23T11:50")
    assert bool_q["filter"][0]["range"]["timestamp"]["lte"].startswith("2026-09-23T12:10")

    fields = {list(c.get("term", c.get("terms", {})).keys())[0] for c in bool_q["should"]}
    assert "agent.name" in fields
    assert "data.win.eventdata.subjectUserName" in fields


def test_every_entity_clause_is_an_exact_term_not_a_match():
    """The mapping makes these `keyword`, so a term filter is exact. A `match`
    would analyse the value and return near-misses as evidence."""
    query = lc.build_query(
        device=lc.Device(name="expsccm01"), principal=lc.principal_of("jdoe"),
        start=EVENT, end=EVENT, timestamp_field="timestamp",
    )
    for clause in query["bool"]["should"]:
        assert set(clause) <= {"term", "terms"}, clause


def test_no_entity_means_no_query():
    """An unfiltered window would return ten minutes of the whole estate."""
    assert lc.build_query(
        device=lc.Device(), principal=lc.Principal(),
        start=EVENT, end=EVENT, timestamp_field="timestamp",
    ) is None


# --- reading -----------------------------------------------------------------

class FakeResult:
    def __init__(self, hits, truncated=False):
        self.hits = hits
        self.truncated = truncated
        self.pages = 1
        self.indices_searched = ["wazuh-alerts-4.x-2026.09.23"]
        self.nodes_used = ["https://os-1:9200"]
        self.node_failures = []
        self.took_ms = 12
        self.total_available = None


class FakeClient:
    def __init__(self, result=None, raises=None):
        self._result = result
        self._raises = raises
        self.closed = False
        self.queries = []

    def concrete_indices(self, pattern):
        return ["wazuh-alerts-4.x-2026.09.23"]

    def search_all(self, **kwargs):
        if self._raises:
            raise self._raises
        self.queries.append(kwargs)
        return self._result

    def close(self):
        self.closed = True


def _hit(doc_id, *, agent="expsccm01", user=None, ts="2026-09-23T11:55:00+0000"):
    source = {"timestamp": ts, "agent": {"name": agent, "id": "1173"}, "rule": {"id": "1002", "level": 3}}
    if user:
        source["data"] = {"win": {"eventdata": {"subjectUserName": user}}}
    return {"_index": "wazuh-alerts-4.x-2026.09.23", "_id": doc_id, "_source": source}


def test_a_complete_window_is_collected():
    client = FakeClient(FakeResult([_hit("a"), _hit("b")]))
    ctx = lc.collect_for_alert(
        event_time=EVENT, entity_host="expsccm01", entity_user=None,
        alert_fields={"agent_id": "1173"}, now=EVENT + timedelta(hours=1),
        client=client, settings=Settings(),
    )
    assert ctx.status == "collected"
    assert len(ctx.logs) == 2
    assert ctx.window["complete"] is True
    assert ctx.sources["indices"] == ["wazuh-alerts-4.x-2026.09.23"]
    assert ctx.sources["queried_to"].startswith("2026-09-23T12:10")


def test_a_live_alert_is_partial_and_says_what_is_owed():
    """The real-time flow: what exists is returned now, the rest is owed."""
    client = FakeClient(FakeResult([_hit("a")]))
    ctx = lc.collect_for_alert(
        event_time=EVENT, entity_host="expsccm01", entity_user=None,
        alert_fields={"agent_id": "1173"}, now=EVENT + timedelta(minutes=2),
        client=client, settings=Settings(),
    )
    assert ctx.status == "partial"
    assert ctx.logs
    assert ctx.window["complete"] is False
    # Only as far as the present, never into the future.
    assert ctx.sources["queried_to"].startswith("2026-09-23T12:02")


def test_a_follow_up_reads_only_the_uncovered_slice():
    client = FakeClient(FakeResult([_hit("c")]))
    lc.collect_for_alert(
        event_time=EVENT, entity_host="expsccm01", entity_user=None,
        alert_fields={"agent_id": "1173"},
        start_override=EVENT + timedelta(minutes=2),
        now=EVENT + timedelta(minutes=30), client=client, settings=Settings(),
    )
    query = client.queries[0]["query"]
    assert query["bool"]["filter"][0]["range"]["timestamp"]["gte"].startswith("2026-09-23T12:02")


def test_a_cluster_that_is_down_does_not_fail_the_alert():
    """An outage in a search cluster must not stop security alerts being
    processed. It is missing evidence, stated as such."""
    from app.services.opensearch_client import OpenSearchUnavailable

    client = FakeClient(raises=OpenSearchUnavailable("no node answered"))
    ctx = lc.collect_for_alert(
        event_time=EVENT, entity_host="expsccm01", entity_user=None,
        alert_fields={"agent_id": "1173"}, now=EVENT + timedelta(hours=1),
        client=client, settings=Settings(),
    )
    assert ctx.status == "unavailable"
    assert "without its logs" in ctx.reason
    assert ctx.logs == []


def test_an_alert_with_no_queryable_entity_is_skipped_not_queried():
    client = FakeClient(FakeResult([]))
    ctx = lc.collect_for_alert(
        event_time=EVENT, entity_host="wm-c00.siembiot.int", entity_user="SYSTEM",
        alert_fields={"agent_id": "000"}, now=EVENT + timedelta(hours=1),
        client=client, settings=Settings(),
    )
    assert ctx.status == "skipped"
    assert client.queries == []
    assert "every log in the estate" in ctx.reason


def test_an_alert_without_an_event_time_has_no_window():
    ctx = lc.collect_for_alert(
        event_time=None, entity_host="expsccm01", entity_user=None,
        client=FakeClient(FakeResult([])), settings=Settings(),
    )
    assert ctx.status == "unavailable"
    assert ctx.logs == []


def test_hits_say_why_they_matched():
    """"Why is this log here" is answered by the record, not by inference."""
    device = lc.Device(name="expsccm01")
    principal = lc.principal_of("jdoe")
    by_device = lc.normalise_hit(_hit("a"), device=device, principal=principal)
    by_user = lc.normalise_hit(_hit("b", agent="other", user="jdoe"), device=device, principal=principal)
    assert by_device["matched_on"] == ["device"]
    assert "user" in by_user["matched_on"]


def test_a_hit_is_trimmed_to_something_storable():
    """The mapping has 1,644 leaf fields; whole documents would put megabytes of
    Windows event XML into every case."""
    hit = _hit("a")
    hit["_source"]["full_log"] = "x" * 5000
    record = lc.normalise_hit(hit, device=lc.Device(name="expsccm01"), principal=lc.Principal())
    assert len(record["full_log"]) <= 600
    assert record["key"] == "wazuh-alerts-4.x-2026.09.23:a"


# --- merging -----------------------------------------------------------------

def test_merging_is_a_union_on_the_documents_own_identity():
    """What makes the follow-up safe to retry any number of times."""
    first = [lc.normalise_hit(_hit("a"), device=lc.Device(), principal=lc.Principal())]
    second = [
        lc.normalise_hit(_hit("a"), device=lc.Device(), principal=lc.Principal()),
        lc.normalise_hit(_hit("b", ts="2026-09-23T12:05:00+0000"), device=lc.Device(), principal=lc.Principal()),
    ]
    merged = lc.merge_logs(first, second)
    assert [r["id"] for r in merged] == ["a", "b"]

    # And again, to be explicit that repetition changes nothing.
    assert lc.merge_logs(merged, second) == merged
