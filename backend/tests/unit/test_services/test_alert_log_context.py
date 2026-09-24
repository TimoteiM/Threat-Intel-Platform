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


# --- late-arriving documents -------------------------------------------------

def test_a_follow_up_starts_before_the_high_water_mark_not_at_it():
    """A document whose event time falls inside the covered slice can be indexed
    after that slice was read — measured lag on this cluster reaches 15.8s. A
    follow-up starting exactly at the mark steps over those documents for ever."""
    covered = EVENT + timedelta(minutes=2)
    start = lc.follow_up_start(
        window_start=EVENT - timedelta(minutes=10), covered_until=covered, overlap_seconds=300
    )
    assert start == covered - timedelta(seconds=300)


def test_the_overlap_never_reaches_before_the_window():
    """Re-reading before the window starts would pull in logs that are not this
    alert's context at all."""
    window_start = EVENT - timedelta(minutes=10)
    start = lc.follow_up_start(
        window_start=window_start,
        covered_until=EVENT - timedelta(minutes=8),
        overlap_seconds=3600,
    )
    assert start == window_start


def test_a_zero_overlap_is_honoured():
    covered = EVENT + timedelta(minutes=2)
    assert lc.follow_up_start(
        window_start=EVENT - timedelta(minutes=10), covered_until=covered, overlap_seconds=0
    ) == covered


def test_the_read_declares_whether_its_pages_were_consistent():
    """Paging a live index and paging a frozen one give different answers; which
    one happened is reported rather than assumed."""
    result = FakeResult([_hit("a")])
    result.consistent = True
    ctx = lc.collect_for_alert(
        event_time=EVENT, entity_host="expsccm01", entity_user=None,
        alert_fields={"agent_id": "1173"}, now=EVENT + timedelta(hours=1),
        client=FakeClient(result), settings=Settings(),
    )
    assert ctx.sources["consistent_pagination"] is True


# --- the tenant boundary -----------------------------------------------------

def test_the_tenant_pin_is_a_filter_not_a_should():
    """A clause that can be satisfied by the entity match instead is not a pin.
    It has to hold whatever else matched."""
    query = lc.build_query(
        device=lc.Device(name="expsccm01"), principal=lc.principal_of("jdoe"),
        start=EVENT, end=EVENT, timestamp_field="timestamp",
        tenant_field="manager.name", tenant_values=["wm-c00.siembiot.int"],
    )
    pins = [c for c in query["bool"]["filter"] if "terms" in c]
    assert pins == [{"terms": {"manager.name": ["wm-c00.siembiot.int"]}}]
    assert not any("terms" in c and "manager.name" in c.get("terms", {})
                   for c in query["bool"]["should"])


def test_an_unpinned_query_is_reported_as_unpinned():
    """Absence of a tenant filter is a fact a reader should see, not one they
    have to notice."""
    class Unpinned(Settings):
        opensearch_tenant_field = "manager.name"
        opensearch_tenant_value_list: list = []

    ctx = lc.collect_for_alert(
        event_time=EVENT, entity_host="expsccm01", entity_user=None,
        alert_fields={"agent_id": "1173"}, now=EVENT + timedelta(hours=1),
        client=FakeClient(FakeResult([_hit("a")])), settings=Unpinned(),
    )
    assert ctx.sources["tenant_filter"] is None


def test_a_pinned_query_says_what_it_is_pinned_to():
    class Pinned(Settings):
        opensearch_tenant_field = "manager.name"
        opensearch_tenant_value_list = ["wm-c00.siembiot.int"]

    client = FakeClient(FakeResult([_hit("a")]))
    ctx = lc.collect_for_alert(
        event_time=EVENT, entity_host="expsccm01", entity_user=None,
        alert_fields={"agent_id": "1173"}, now=EVENT + timedelta(hours=1),
        client=client, settings=Pinned(),
    )
    assert ctx.sources["tenant_filter"] == {
        "field": "manager.name", "values": ["wm-c00.siembiot.int"],
    }
    sent = client.queries[0]["query"]["bool"]["filter"]
    assert {"terms": {"manager.name": ["wm-c00.siembiot.int"]}} in sent


# --- the event's own fields --------------------------------------------------

def _fields(record):
    """The captured fields as a mapping, for assertions. The stored shape is an
    ordered list because JSONB does not preserve key order."""
    return {f["name"]: f["value"] for f in (record.get("fields") or [])}


def _win_hit(event_id, system=None, eventdata=None):
    return {
        "_index": "wazuh-alerts-4.x-2026.09.24", "_id": "abc",
        "_source": {
            "timestamp": "2026-09-24T11:12:48.000+0000",
            "agent": {"name": "EXP-47VD864", "ip": "10.10.126.169"},
            "rule": {"id": "67027", "level": 3, "description": "A process was created."},
            "data": {"win": {
                "system": {"eventID": event_id, "channel": "Security",
                           "computer": "EXP-47VD864.int.expertware.net", **(system or {})},
                "eventdata": eventdata or {},
            }},
        },
    }


def test_a_security_channel_process_event_is_not_empty():
    """The reported gap. The projection named Sysmon's `image`, `commandLine`
    and `parentImage`; Security 4688 calls the same three `newProcessName`,
    `commandLine` and `parentProcessName`, so every 4688 row was blank."""
    hit = _win_hit("4688", eventdata={
        "newProcessName": r"C:\Program Files\Docker\docker.exe",
        "parentProcessName": r"C:\Users\dnechita\AppData\Local\Code.exe",
        "subjectUserName": "dnechita",
        "subjectDomainName": "INT",
    })
    record = lc.normalise_hit(hit, device=lc.Device(name="EXP-47VD864"), principal=lc.Principal())

    assert record["process"]["image"].endswith("docker.exe")
    assert record["process"]["parent_image"].endswith("Code.exe")
    assert _fields(record)["data.win.eventdata.subjectUserName"] == "dnechita"
    assert _fields(record)["data.win.eventdata.subjectDomainName"] == "INT"


def test_an_event_type_nobody_listed_still_carries_its_fields():
    """The point of capturing subtrees: a type this code has never heard of
    arrives complete, instead of arriving blank until someone adds it."""
    hit = _win_hit("9999", eventdata={"somethingNeverSeenBefore": "a value", "andAnother": "42"})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())

    assert _fields(record)["data.win.eventdata.somethingNeverSeenBefore"] == "a value"
    assert _fields(record)["data.win.eventdata.andAnother"] == "42"


def test_sysmon_naming_still_works():
    hit = _win_hit("1", eventdata={"image": r"C:\powershell.exe", "commandLine": "-nop -w hidden",
                                   "parentImage": r"C:\explorer.exe"})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())
    assert record["process"]["image"].endswith("powershell.exe")
    assert record["process"]["command_line"] == "-nop -w hidden"


def test_the_columns_are_not_repeated_in_the_summary():
    hit = _win_hit("4688", eventdata={"subjectUserName": "dnechita"})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())
    assert record["event_id"] == "4688"
    assert record["channel"] == "Security"
    for repeated in ("data.win.system.eventID", "data.win.system.channel",
                     "data.win.system.computer"):
        assert repeated not in _fields(record)


def test_the_rendered_windows_message_is_not_kept_twice():
    """It restates every field below it and truncates mid-sentence."""
    hit = _win_hit("4688", system={"message": "A new process has been created." + "x" * 2000})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())
    assert "data.win.system.message" not in _fields(record)


def test_the_field_map_is_bounded():
    """One pathological document must not bloat a stored context."""
    hit = _win_hit("1", eventdata={f"f{i}": "v" * 5000 for i in range(200)})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())
    assert len(record["fields"]) <= 40
    assert all(len(v) <= 400 for v in _fields(record).values())


def test_empty_values_are_dropped():
    hit = _win_hit("1", eventdata={"real": "value", "blank": "", "nothing": None})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())
    assert "data.win.eventdata.real" in _fields(record)
    assert "data.win.eventdata.blank" not in _fields(record)
    assert "data.win.eventdata.nothing" not in _fields(record)


def test_a_machine_account_is_not_shown_ahead_of_a_person():
    """`EXP-47VD864$` in the user column says nothing the device column has not."""
    hit = _win_hit("4688", eventdata={"subjectUserName": "EXP-47VD864$", "targetUserName": "dnechita"})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())
    assert record["users"][0] == "dnechita"


def test_captured_fields_are_sanitised_before_they_can_reach_the_model():
    """These are whatever the event id happens to carry, so they are exactly
    where an unanticipated secret lives."""
    from app.services import log_secret_sanitizer as sec

    hit = _win_hit("4688", eventdata={"commandLine": "net user svc /add Password=Hunter2Hunter2"})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())
    cleaned, counts = sec.sanitize_records([record])

    blob = str(cleaned[0])
    assert "Hunter2Hunter2" not in blob
    assert "net user svc /add" in blob
    assert counts


def test_the_field_order_survives_a_jsonb_round_trip():
    """JSONB normalises object keys by length then bytewise, so a mapping came
    back with data.win.system.task above data.win.eventdata.newProcessName —
    the reverse of what a reader wants. A list keeps the server's ordering."""
    import json as _json

    hit = _win_hit("4688", system={"task": "13312", "threadID": "9104"},
                   eventdata={"newProcessName": "docker.exe", "subjectUserName": "dnechita"})
    record = lc.normalise_hit(hit, device=lc.Device(), principal=lc.Principal())

    names = [f["name"] for f in _json.loads(_json.dumps(record["fields"]))]
    assert names[0].startswith("data.win.eventdata.")
    assert names.index("data.win.eventdata.newProcessName") < names.index("data.win.system.task")

