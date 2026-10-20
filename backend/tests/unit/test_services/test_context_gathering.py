"""The gathering loop: playbook, one agent hop, budget, record, purge.

Against the mock source, which is the point — the loop, the budget, the stop
rule and the record are what is being built, and a real platform would make
every test cost somebody's quota and depend on their data.

The tests that matter most are the ones asserting a **refusal** or a
**distinction**: a source that could not be read is not a source that found
nothing; an agent cannot name a source; a real hostname never reaches the
record.
"""

from __future__ import annotations

import time

import pytest

from app.services import token_boundary as tb
from app.services.context_gathering import agent as ag
from app.services.context_gathering import loop as gl
from app.services.context_gathering import mock_source as ms
from app.services.context_gathering import playbook as pb
from app.services.context_gathering.mock_source import QUIET_HOST, SPREAD_HASH

HOST = "EXPDC001"
USER = "INT\\svc_report"
PROCESS = "C:\\Windows\\lsass.exe"


def _gather(event_id="10 | ThreatHunting", selectors=None, registry=None, **kw):
    return gl.gather(
        tenant_id="c00",
        investigation_id=kw.pop("investigation_id", "run-1"),
        alert_fields={"event_id": event_id},
        selectors=selectors if selectors is not None else {
            "host": HOST, "process": PROCESS, "hash": SPREAD_HASH},
        registry=registry if registry is not None else ms.default_registry(),
        **kw,
    )


# ── the playbook: the predictable part, with no model in it ──────────────


def test_the_key_is_the_event_class_not_the_rule_name():
    """Measured, not chosen: `event_id` + channel is 144 distinct values with
    the top ten covering 81%, where `rule_name` is 744 covering 41% and
    `detection_rule_name` is absent on 100% of runs — a playbook keyed on
    that last one would be keyed on nothing."""
    assert pb.event_class_of({"event_id": "10 | ThreatHunting"}) == "10"
    assert pb.event_class_of({"event_id": "18456"}) == "18456"
    assert pb.event_class_of({}) == ""
    assert pb.event_class_of({"detection_rule_name": "anything"}) == ""


def test_the_three_biggest_classes_have_rows():
    """Sysmon 10, 18 and 17 are 62% of the corpus between them."""
    for event_class in ("10", "18", "17"):
        assert event_class in pb.PLAYBOOK


def test_a_class_with_no_row_is_a_named_gap_not_an_empty_result():
    """19% of alerts fall outside the top ten. An empty tuple would read as
    "nothing to do here"; the raise makes the caller record it."""
    with pytest.raises(pb.NoPlaybookRow):
        pb.templates_for("99999", {"host": "[HOST_x_1]"})


def test_a_missing_selector_is_skipped_with_the_key_named():
    """75% of runs carry no principal. "No user on this alert" is a fact
    about the alert; reporting it as an empty result from the source would be
    the absence-as-value defect this codebase keeps finding."""
    chosen, skipped = pb.templates_for("4738", {"host": "[HOST_x_1]"})
    names = {s["template"] for s in skipped}
    assert "user_sessions" in names
    assert any("no user" in s["reason"] for s in skipped)
    assert all(t.name != "user_sessions" for t in chosen)


def test_a_rows_cost_is_known_before_it_runs():
    chosen, _ = pb.templates_for("10", {
        "host": "h", "process": "p", "hash": "x", "user": "u"})
    assert pb.declared_cost(chosen) == sum(t.declared_calls for t in chosen) > 0


def test_a_template_names_a_source_kind_never_a_source():
    """An agent that could name a source could name another tenant's. The
    tenant's map decides where a template goes."""
    for template in pb.TEMPLATES.values():
        assert template.source_kind in pb.SOURCE_KINDS


# ── the record is tokenised ──────────────────────────────────────────────


def test_no_real_hostname_reaches_the_record():
    """The record is what the analysis stage consumes, and it is stored. A
    real hostname in it defeats the boundary entirely."""
    record = _gather()
    blob = repr(record.as_json())
    assert HOST not in blob
    assert "[HOST_" in blob


def test_identifier_arguments_are_tokens_and_others_are_not():
    """Tokenised by class, not wholesale.

    `host` and `user` are identifiers of this customer's estate and are
    tokens. A SHA-256 is not — it identifies a binary the whole industry can
    look up — and tokenising it would be the over-tokenisation that buys no
    safety and costs the analysis.
    """
    record = _gather()
    seen = {}
    for outcome in record.outcomes:
        seen.update(outcome.arguments)
    assert seen["host"].startswith("[HOST_")
    assert seen.get("hash", SPREAD_HASH) == SPREAD_HASH
    assert HOST not in str(seen)


def test_an_identifier_inside_a_composite_row_id_does_not_leak():
    """A vendor builds `key` and `id` out of whatever it has, including the
    hostname, and no detector sees a hostname with no key beside it. Three
    real hostnames reached the record through that field while `agent.name`
    next to them was correctly tokenised.

    Digested rather than tokenised: these are the vendor's row numbers, not
    identifiers of anything, and the only thing done with them downstream is
    compare them.
    """
    record = _gather()
    for event in record.events:
        assert HOST not in event["key"]
        assert HOST not in event["id"]
        assert event["key"].startswith("ev-")


def test_the_digest_is_stable_so_dedup_still_works():
    """The control: a digest that changed per call would silently stop the
    record deduplicating and inflate every coverage number the stop rule
    reads."""
    first = _gather().events
    second = _gather().events
    assert [e["key"] for e in first] == [e["key"] for e in second]
    assert len({e["key"] for e in first}) == len(first), "duplicate events kept"


def test_the_source_sees_real_values_and_the_record_does_not():
    """The boundary is crossed at the last possible moment: tokens in, real
    values out, the call made, and the real values not retained."""
    registry = ms.default_registry()
    _gather(registry=registry)
    asked = [value for _, value in registry[pb.EDR].asked]
    assert HOST in asked, "the source was queried with a token, not a hostname"


# ── a source that could not be read ──────────────────────────────────────


def test_a_failed_source_is_check_failed_with_its_name():
    """Never "found nothing". The DNS collector reported an outage as "no DNS
    records" across 2,602 runs by merging those two answers."""
    registry = ms.default_registry()
    registry[pb.EDR].failing_templates = frozenset({"process_tree"})
    record = _gather(registry=registry)

    failed = [o for o in record.outcomes if o.template == "process_tree"]
    assert failed and failed[0].status == "check_failed"
    assert failed[0].absence["kind"] == "check_failed"
    assert "mock-edr" in failed[0].reason
    assert record.as_json()["coverage"]["sources_failed"] == ["mock-edr"]


def test_a_source_that_answered_nothing_is_empty_not_check_failed():
    """The control for the test above: without it, a check that reports
    everything as check_failed would pass."""
    record = _gather(selectors={"host": QUIET_HOST, "process": "x", "hash": "y"})
    statuses = {o.status for o in record.outcomes}
    assert "empty" in statuses
    assert "check_failed" not in statuses
    assert record.as_json()["coverage"]["sources_failed"] == []


def test_a_missing_source_kind_is_check_failed_not_silence():
    """A tenant whose map has no EDR platform. The query was never sent, and
    that is a different fact from a query that returned nothing."""
    registry = {pb.SIEM: ms.MockSource(name="mock-siem", kind=pb.SIEM)}
    record = _gather(registry=registry)
    edr = [o for o in record.outcomes if o.source_kind == pb.EDR]
    assert edr and all(o.status == "check_failed" for o in edr)
    assert all("source map" in o.reason for o in edr)


# ── the budget ───────────────────────────────────────────────────────────


def test_the_query_ceiling_is_on_distinct_queries():
    """Distinct, not total: a retry storm against a slow platform is also a
    runaway loop, and a count of calls would not see it."""
    budget = gl.Budget(max_queries=2)
    record = _gather(budget=budget)
    assert budget.queries_run <= 2
    assert "query ceiling" in budget.stop_reason


def test_the_same_query_twice_costs_one():
    budget = gl.Budget()
    signature = ("s", "t", "host=[HOST_x_1]")
    budget.charge(signature)
    assert budget.would_repeat(signature)
    budget.charge(signature)
    assert budget.queries_run == 1


def test_the_wall_clock_stops_the_loop():
    budget = gl.Budget(deadline_seconds=0.0)
    budget.started_at = time.monotonic() - 1.0
    record = _gather(budget=budget)
    assert record.outcomes == []
    assert "wall clock" in budget.stop_reason


def test_the_budget_is_recorded_not_just_enforced():
    """A budget nobody can see is a budget nobody can calibrate."""
    cost = _gather().as_json()["cost"]
    for field in ("queries_run", "max_queries", "elapsed_seconds",
                  "deadline_seconds", "stop_reason",
                  "playbook_queries", "agent_queries"):
        assert field in cost, field
    assert cost["stop_reason"]


def test_the_stop_rule_is_a_rule_not_a_judgement():
    budget = gl.Budget(enough_events=1, enough_sources=1)
    record = _gather(budget=budget)
    assert "enough gathered" in budget.stop_reason


# ── the agent ────────────────────────────────────────────────────────────


def test_the_agent_sees_the_playbook_results_before_it_decides():
    seen = {}

    def _spy(*, record, selectors, budget):
        seen["outcomes"] = len(record.outcomes)
        seen["events"] = len(record.events)
        return []

    _gather(agent=_spy)
    assert seen["outcomes"] > 0, "the agent ran before the playbook"
    assert seen["events"] > 0


def test_the_agent_cannot_name_a_source():
    """Its whole vocabulary is a template name and token arguments. A
    `Selection` has nowhere to put a source, which is the structural version
    of the rule."""
    import dataclasses

    fields = {f.name for f in dataclasses.fields(ag.Selection)}
    assert fields == {"template", "arguments", "because"}


def test_a_pivot_may_only_select_a_pivotable_template():
    """`process_tree` is two calls and fans out on its results; a pivot onto
    it is the runaway loop. Refused, and the refusal is recorded."""
    def _greedy(*, record, selectors, budget):
        return [ag.Selection(template="process_tree",
                             arguments={"host": selectors["host"],
                                        "process": selectors["process"]},
                             because="I would like to")]

    record = _gather(agent=_greedy)
    assert any("not a pivotable template" in n for n in record.notes)
    assert all(o.origin != "agent" for o in record.outcomes)


def test_an_unknown_template_is_refused():
    def _invent(*, record, selectors, budget):
        return [ag.Selection(template="drop_tables", arguments={}, because="")]

    record = _gather(agent=_invent)
    assert any("not a known template" in n for n in record.notes)


def test_the_hop_is_depth_one():
    """A pivot's own results are never pivoted on. Enforced by calling the
    agent once rather than by asking it to stop."""
    calls = []

    def _counting(*, record, selectors, budget):
        calls.append(len(record.outcomes))
        return []

    _gather(agent=_counting)
    assert len(calls) == 1


def test_the_fan_out_is_capped():
    def _many(*, record, selectors, budget):
        return [
            ag.Selection(template="hash_prevalence",
                         arguments={"hash": f"hash-{i}"}, because="x")
            for i in range(10)
        ]

    budget = gl.Budget(max_pivots=2, enough_events=999)
    record = _gather(agent=_many, budget=budget)
    assert sum(1 for o in record.outcomes if o.origin == "agent") <= 2


# ── what the agent pivots on, and what it must not ───────────────────────


def test_the_agent_does_not_pivot_on_the_reporting_hosts_own_address():
    """`agent.ip` is on every record by construction, so an indicator drawn
    from it is true of every row and cannot discriminate between them.

    The first policy walked the whole event, found that address on several
    records and pivoted on it — noise, and the fifth instance of this shape
    in this codebase.
    """
    events = [
        {"agent": {"name": "[HOST_a_1]", "ip": "[IP_a_9]"},
         "process": {"sha256": ""}, "network": {"src_ip": "", "dst_ip": ""},
         "users": []},
        {"agent": {"name": "[HOST_a_2]", "ip": "[IP_a_9]"},
         "process": {"sha256": ""}, "network": {"src_ip": "", "dst_ip": ""},
         "users": []},
    ]
    assert ag._indicators(events) == {}


def test_the_agent_pivots_on_a_hash_the_alert_did_not_carry():
    """The second hop's own case: the alert has a host and a pipe but no
    hash, so the playbook **skips** `hash_prevalence`; the pipe query returns
    events carrying one, and the pivot recovers the query that was skipped.
    """
    record = _gather(event_id="18 | ThreatHunting",
                     selectors={"host": HOST, "pipe": "\\\\.\\pipe\\atsvc"})
    agent_queries = [o for o in record.outcomes if o.origin == "agent"]
    assert [o.template for o in agent_queries] == ["hash_prevalence"]
    assert agent_queries[0].kept > 0, "the pivot returned nothing worth keeping"
    assert any(s["template"] == "hash_prevalence" for s in record.skipped)


def test_the_agent_does_not_re_ask_what_the_alert_already_named():
    """When the alert carries the hash, the playbook has already asked. A
    pivot onto it would be a duplicate query with a model call in front."""
    record = _gather()  # the alert carries host, process AND hash
    assert all(o.template != "hash_prevalence" or o.origin == "playbook"
               for o in record.outcomes)


def test_the_tail_gets_a_cold_start_rather_than_nothing():
    """§3.3: for the 19% in no top-ten row, the agent picks templates **from
    the same fixed set**. The first policy only pivoted on gathered evidence,
    so an alert with no row got no queries at all — the tail was the case the
    agent exists for and the one it did nothing about."""
    record = _gather(event_id="4662 | Security",
                     selectors={"host": HOST, "hash": SPREAD_HASH})
    assert any("no_playbook" in n for n in record.notes)
    assert [o for o in record.outcomes if o.origin == "agent"]
    assert record.events, "the tail gathered nothing"


def test_a_cold_start_still_selects_only_known_templates():
    record = _gather(event_id="4662 | Security",
                     selectors={"host": HOST, "hash": SPREAD_HASH})
    for outcome in record.outcomes:
        assert outcome.template in pb.TEMPLATES


# ── the loop owns the lifecycle, so it purges ────────────────────────────


def test_the_loop_purges_the_token_map_on_completion():
    purged = {}

    class _Db:
        pass

    def _fake_purge(db, *, tenant_id, investigation_id, reason=tb.PURGE_COMPLETED):
        purged["args"] = (tenant_id, investigation_id, reason)
        return tb.PurgeResult(reason=reason, deleted=1,
                              scopes=(f"{tenant_id}/{investigation_id}",))

    import app.services.token_boundary as boundary_module

    original = boundary_module.purge_investigation
    boundary_module.purge_investigation = _fake_purge
    try:
        record = _gather(db=_Db(), investigation_id="run-purge")
    finally:
        boundary_module.purge_investigation = original

    assert purged["args"][0] == "c00"
    assert purged["args"][1] == "run-purge"
    assert purged["args"][2] == tb.PURGE_COMPLETED
    assert any("purged on completion" in n for n in record.notes)


def test_a_purge_failure_does_not_fail_the_investigation():
    """The 24-hour ceiling is the backstop and it warns when it fires. Losing
    an investigation because its bookkeeping failed would be worse than the
    map living a few hours longer."""
    class _Db:
        pass

    def _boom(db, **kw):
        raise RuntimeError("database gone")

    import app.services.token_boundary as boundary_module

    original = boundary_module.purge_investigation
    boundary_module.purge_investigation = _boom
    try:
        record = _gather(db=_Db())
    finally:
        boundary_module.purge_investigation = original

    assert record.events or record.outcomes
    assert any("purge failed" in n for n in record.notes)


def test_without_a_database_there_is_nothing_to_purge():
    record = _gather()
    assert not any("purge" in n for n in record.notes)


# ── the record into the analysis stage ───────────────────────────────────


def test_the_record_projects_into_the_shape_the_pipeline_consumes():
    """Not a path of its own. A second way into the analysis stage is a
    second thing to keep in step, and this codebase has eight registries that
    show how that ends."""
    from app.services.context_gathering import projection

    context = projection.to_log_context(_gather())
    for key in ("status", "tenant_id", "reason", "log_count", "truncated",
                "window", "selectors", "sources", "logs"):
        assert key in context, key
    # What the digest builder reads. Without these it answers `no_alert_time`
    # and declines to use a context it has already accepted.
    for key in ("alert_time", "entity_host", "entity_user"):
        assert key in context, key


def test_the_analysis_stage_accepts_the_projection():
    """The real digest builder, not a stand-in — the claim is that the
    existing pipeline reasons over this, so the existing pipeline has to be
    the thing that reads it."""
    from datetime import datetime, timezone

    from app.services.alert_body_investigation_service import _build_log_digest
    from app.services.context_gathering import projection

    record = _gather(event_time=datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc))
    digest, selection = _build_log_digest(
        projection.to_log_context(record), "alert body", {"event_id": "10"},
        indicators=[],
    )
    assert selection.get("status") != "no_alert_time"
    assert HOST not in (digest or ""), "a real hostname reached the model"


@pytest.mark.parametrize("status,selectors,failing", [
    # events and no failure
    ("collected", {"host": HOST, "process": "p", "hash": SPREAD_HASH}, frozenset()),
    # events AND a failure: usable, and incomplete in a known way
    ("partial", {"host": HOST, "process": "p", "hash": SPREAD_HASH},
     frozenset({"host_threat_state"})),
    # read, held nothing — a real negative
    ("empty", {"host": QUIET_HOST, "process": "p", "hash": "0" * 64}, frozenset()),
    # nothing gathered AND something unreadable — NOT empty
    ("unavailable", {"host": QUIET_HOST, "process": "p", "hash": "0" * 64},
     frozenset({"host_threat_state"})),
])
def test_the_status_distinguishes_nothing_found_from_could_not_look(
    status, selectors, failing
):
    """`empty` and `unavailable` are different answers. Merging them is what
    had the DNS collector reporting an outage as "no DNS records" across
    2,602 runs."""
    from app.services.context_gathering import projection

    registry = ms.default_registry()
    registry[pb.EDR].failing_templates = failing
    context = projection.to_log_context(_gather(selectors=selectors, registry=registry))
    assert context["status"] == status


def test_every_event_carries_where_it_came_from():
    """"The alert said this" and "we went and found this" are different kinds
    of claim, and a flat list of events erases the difference."""
    from app.services.context_gathering.projection import (
        PROVENANCE_FIELD, to_log_context,
    )

    context = to_log_context(_gather(
        event_id="18 | ThreatHunting",
        selectors={"host": HOST, "pipe": "\\\\.\\pipe\\atsvc"}))
    origins = {e[PROVENANCE_FIELD]["origin"] for e in context["logs"]}
    assert origins == {"playbook", "agent"}
    for event in context["logs"]:
        found = event[PROVENANCE_FIELD]
        assert found["template"] in pb.TEMPLATES
        assert found["source"] and found["purpose"]


def test_an_unreadable_source_is_in_the_projection_by_name():
    """A source that could not be read contributes no events and is therefore
    invisible in a list of events. It has to be stated, or its absence reads
    as a source with nothing to say."""
    from app.services.context_gathering.projection import sources_block

    registry = ms.default_registry()
    registry[pb.EDR].failing_templates = frozenset({"host_threat_state"})
    block = sources_block(_gather(registry=registry))
    assert [u["source"] for u in block["unreadable"]] == ["mock-edr"]
    assert block["unreadable"][0]["absence"]["kind"] == "check_failed"
    assert block["unreadable"][0]["asked"]


# ── the report: composed in tokens, detokenised once ─────────────────────


def test_what_the_model_reads_contains_no_real_name():
    from app.services.context_gathering import report

    composed = report.compose(record=_gather())
    assert HOST not in composed
    assert "[HOST_" in composed


def test_what_the_analyst_reads_contains_real_names():
    from app.services.context_gathering import report

    boundary = tb.in_memory(tenant_id="c00", investigation_id="render")
    record = _gather(boundary=boundary)
    rendered = report.render(record=record, boundary=boundary)
    assert HOST in rendered
    assert "[HOST_" not in rendered


def test_the_alert_section_prints_tokens_not_the_alerts_own_values():
    """The alert's own values are no less sensitive for having arrived with
    the alert. The first version printed `alert_fields` straight through and
    put a real hostname into the text the model reads — in the one section
    whose job is to say what the alert carried."""
    from app.services.context_gathering import report

    composed = report.compose(record=_gather())
    section = composed.split("WHAT THE ALERT CARRIED")[1].split("WHAT GATHERING")[0]
    assert "[HOST_" in section
    assert HOST not in section


def test_the_report_separates_what_the_alert_carried_from_what_was_added():
    from app.services.context_gathering import report

    composed = report.compose(record=_gather())
    assert "WHAT THE ALERT CARRIED" in composed
    assert "WHAT GATHERING ADDED" in composed


def test_the_report_names_an_unreadable_source_and_says_what_that_means():
    """The case this matters most for: a reader must not read silence as a
    clean result."""
    from app.services.context_gathering import report

    registry = ms.default_registry()
    registry[pb.EDR].failing_templates = frozenset({"host_threat_state"})
    composed = report.compose(record=_gather(registry=registry))
    assert "mock-edr" in composed
    assert "unknown, not absent" in composed
    assert "this host's current threat state" in composed


def test_a_report_with_no_events_says_why_not():
    from app.services.context_gathering import report

    registry = ms.default_registry()
    registry[pb.EDR].failing_templates = frozenset({"host_threat_state"})
    composed = report.compose(record=_gather(
        selectors={"host": QUIET_HOST, "process": "p", "hash": "0" * 64},
        registry=registry))
    assert "No events" in composed
    assert "could not be read" in composed


def test_the_report_separates_playbook_queries_from_the_agents():
    from app.services.context_gathering import report

    composed = report.compose(record=_gather(
        event_id="18 | ThreatHunting",
        selectors={"host": HOST, "pipe": "\\\\.\\pipe\\atsvc"}))
    assert "From the playbook" in composed
    assert "Chosen by the agent" in composed
    assert "chose it because:" in composed, "the agent's reason is not shown"


def test_a_report_with_no_agent_query_says_so_rather_than_omitting_it():
    """An absent section reads as a section nobody filled in."""
    from app.services.context_gathering import report

    composed = report.compose(record=_gather())
    assert "Chosen by the agent: none" in composed


# ── the sweep: no raw value on ANY surface the stage produces ────────────


#: Values that exist nowhere in the mock corpus, so finding one in an output
#: means it travelled there from the input rather than being a coincidence.
SENTINEL_HOST = "ZZSENTINELHOST01"
SENTINEL_USER = "ZZDOM\\zz_sentinel_user"
SENTINEL_IP = "203.0.113.77"


def test_no_raw_identifier_reaches_any_surface_the_stage_produces():
    """**Mechanical, not visual.**

    The report section that printed the alert's own fields was found by
    reading the output. That does not scale and it does not survive the next
    surface somebody adds, so this enumerates every output the stage has and
    asserts the sentinels are in none of them.

    A new surface added without a line here is the gap this is meant to
    close — so the list is asserted to be the complete set of public
    producers, below.
    """
    from app.services.alert_body_investigation_service import _build_log_digest
    from app.services.context_gathering import projection, report

    from datetime import datetime, timezone

    boundary = tb.in_memory(tenant_id="c00", investigation_id="sweep")
    record = _gather(
        boundary=boundary,
        # Without this the digest builder answers `no_alert_time` and returns
        # an empty string, and the sweep would pass over it by having nothing
        # to look at. The length control below caught exactly that.
        event_time=datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc),
        selectors={"host": SENTINEL_HOST, "user": SENTINEL_USER,
                   "ip": SENTINEL_IP, "hash": SPREAD_HASH},
    )
    context = projection.to_log_context(record)

    # **With autosend ON**, which is not this deployment's setting.
    #
    # `_build_log_digest` selects events and then returns an empty digest
    # unless `alert_log_ai_autosend` is set, so with the default the model
    # receives nothing and this surface would be swept by having nothing on
    # it. The configuration worth checking is the one where the text is
    # actually sent, and a sweep that only passes in the safe configuration
    # is not a sweep.
    import app.services.alert_body_investigation_service as svc

    original = svc.get_settings

    class _Autosend:
        alert_log_ai_autosend = True

        def __getattr__(self, name):
            return getattr(original(), name)

    svc.get_settings = lambda: _Autosend()
    try:
        digest, _ = _build_log_digest(context, "alert body", {"event_id": "10"},
                                      indicators=[])
    finally:
        svc.get_settings = original

    surfaces = {
        "record.as_json()": record.as_json(),
        "projection.to_log_context()": context,
        "projection.sources_block()": projection.sources_block(record),
        "report.compose()": report.compose(record=record),
        "analysis digest": digest or "",
    }
    for name, surface in surfaces.items():
        blob = repr(surface)
        for sentinel in (SENTINEL_HOST, SENTINEL_USER, SENTINEL_IP):
            assert sentinel not in blob, f"{sentinel!r} reached {name}"
        # And the control: the surface is not empty, or it would pass by
        # containing nothing at all.
        assert len(blob) > 50, f"{name} produced nothing to check"


def test_render_is_the_only_surface_that_shows_real_names():
    """The counterpart of the sweep: exactly one producer detokenises, and a
    test that only asserted absence everywhere would also pass if the stage
    produced nothing anybody could read."""
    from app.services.context_gathering import report

    boundary = tb.in_memory(tenant_id="c00", investigation_id="sweep2")
    record = _gather(boundary=boundary,
                     selectors={"host": SENTINEL_HOST, "process": "x", "hash": SPREAD_HASH})
    assert SENTINEL_HOST not in report.compose(record=record)
    assert SENTINEL_HOST in report.render(record=record, boundary=boundary)


def test_the_sweep_covers_every_public_producer_of_the_stage():
    """A new output surface added without a line in the sweep would pass by
    not being looked at — the shape this codebase has found eight times in
    hand-maintained lists.

    So the set of public functions that build something a caller reads is
    derived here and compared against what the sweep enumerates.
    """
    import inspect

    from app.services.context_gathering import projection, report

    producers = set()
    for module in (projection, report):
        for name, obj in vars(module).items():
            if name.startswith("_") or not inspect.isfunction(obj):
                continue
            if obj.__module__ != module.__name__:
                continue
            producers.add(f"{module.__name__.rsplit('.', 1)[1]}.{name}")

    swept = {"projection.to_log_context", "projection.sources_block",
             "report.compose"}
    detokenising = {"report.render"}
    assert producers == swept | detokenising, (
        f"a producer is neither swept nor declared as the detokenising one: "
        f"{producers - (swept | detokenising)}"
    )
