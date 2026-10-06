"""The alert, anchored, with the events either side of it.

No database: the store lookup and the run are stubbed, because what is worth
pinning is which row becomes the anchor and how the two sides are cut — not
SQLAlchemy.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import app.api.alert_investigations as api

RUN_ID = uuid.uuid4()
ALERT_TIME = datetime(2026, 9, 24, 13, 46, 30, tzinfo=timezone.utc)
ALERT_DOC_ID = "ZFMF06AB2rdPVBlxiErt"


def _event(n: int, doc_id: str | None = None):
    stamp = ALERT_TIME + timedelta(seconds=n)
    ident = doc_id or f"doc{n:+d}"
    return {
        "key": f"wazuh-alerts-4.x-2026.09.24:{ident}",
        "id": ident,
        "timestamp": stamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "agent": {"name": "EXP-47VD864", "ip": "10.10.126.169"},
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "rule": {"id": "92213", "level": 3, "description": f"event {n:+d}"},
    }


def _call(*, events, external_ref, before=5, after=5, monkeypatch):
    run = SimpleNamespace(
        id=RUN_ID, tenant_id="c00", external_ref=external_ref, event_time=ALERT_TIME,
        entity_host="EXP-47VD864", entity_user=None, title="PowerShell with bypass flags",
        detection_rule_id="92213", detection_rule_name=None, result_json={},
    )

    class _DB:
        async def get(self, _model, _id):
            return run

    monkeypatch.setattr(api, "run_in_threadpool", lambda fn: _done(fn()))
    monkeypatch.setattr(api.tenant_scope, "assert_can_read", lambda *_a: None)

    import app.services.alert_log_context_store as store

    monkeypatch.setattr(store, "for_run", lambda _db, _rid: SimpleNamespace(
        logs=list(events), status="collected", reason=None, truncated=False,
        window_start=ALERT_TIME, window_end=ALERT_TIME, covered_until=ALERT_TIME,
        selectors={}, sources={}, attempts=0, logs_at_analysis=len(events),
        analysed_at=ALERT_TIME, run_id=RUN_ID,
    ))
    monkeypatch.setattr(store, "as_payload", lambda _row, include_logs=True: {"status": "collected"})

    return asyncio.get_event_loop().run_until_complete(
        api.get_run_log_context(run_id=RUN_ID, db=_DB(), before=before, after=after,
                                request=SimpleNamespace(state=SimpleNamespace(identity=None)))
    )


async def _await(value):
    return value


def _done(value):
    async def _inner():
        return value
    return _inner()


@pytest.fixture(autouse=True)
def _loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield
    loop.close()


def test_the_anchor_is_the_alerts_own_document(monkeypatch):
    """Not the nearest event to its timestamp — the alert itself, matched on the
    OpenSearch _id the sender gave us."""
    events = [_event(n) for n in (-3, -2, -1)] + [_event(0, ALERT_DOC_ID)] + [_event(n) for n in (1, 2, 3)]
    page = _call(events=events, external_ref=ALERT_DOC_ID, monkeypatch=monkeypatch)

    assert page["anchor"]["id"] == ALERT_DOC_ID
    assert page["anchor"]["is_alert"] is True
    assert not page["anchor"].get("synthetic")
    # And it appears exactly once — not in a side as well.
    assert ALERT_DOC_ID not in [e["id"] for e in page["before"] + page["after"]]


def test_five_either_side_by_default(monkeypatch):
    events = [_event(n) for n in range(-20, 0)] + [_event(0, ALERT_DOC_ID)] + [_event(n) for n in range(1, 21)]
    page = _call(events=events, external_ref=ALERT_DOC_ID, monkeypatch=monkeypatch)

    assert len(page["before"]) == 5
    assert len(page["after"]) == 5
    assert page["available_before"] == 20
    assert page["available_after"] == 20


def test_the_sides_are_the_events_nearest_the_alert(monkeypatch):
    """Loading five older must give the five immediately before it, not the five
    oldest in the window."""
    events = [_event(n) for n in range(-20, 0)] + [_event(0, ALERT_DOC_ID)] + [_event(n) for n in range(1, 21)]
    page = _call(events=events, external_ref=ALERT_DOC_ID, monkeypatch=monkeypatch)

    assert [e["id"] for e in page["before"]] == [f"doc{n:+d}" for n in (-5, -4, -3, -2, -1)]
    assert [e["id"] for e in page["after"]] == [f"doc{n:+d}" for n in (1, 2, 3, 4, 5)]


def test_expanding_pulls_in_more_from_that_end(monkeypatch):
    events = [_event(n) for n in range(-20, 0)] + [_event(0, ALERT_DOC_ID)] + [_event(n) for n in range(1, 21)]
    page = _call(events=events, external_ref=ALERT_DOC_ID, before=10, after=5, monkeypatch=monkeypatch)

    assert len(page["before"]) == 10
    assert len(page["after"]) == 5
    assert page["before"][-1]["id"] == "doc-1"


def test_an_alert_whose_document_is_not_in_the_window_still_anchors(monkeypatch):
    """The entity filter can exclude the alert's own document. The view is never
    anchorless, and never pretends a neighbour is the alert."""
    events = [_event(n) for n in (-3, -2, -1, 1, 2, 3)]
    page = _call(events=events, external_ref="an-id-not-in-the-window", monkeypatch=monkeypatch)

    assert page["anchor"]["synthetic"] is True
    assert page["anchor"]["is_alert"] is True
    assert len(page["before"]) == 3
    assert len(page["after"]) == 3


def test_a_run_with_no_recorded_alert_id_still_anchors_by_time(monkeypatch):
    events = [_event(n) for n in (-2, -1, 1, 2)]
    page = _call(events=events, external_ref=None, monkeypatch=monkeypatch)

    assert page["anchor"]["synthetic"] is True
    assert [e["id"] for e in page["before"]] == ["doc-2", "doc-1"]
    assert [e["id"] for e in page["after"]] == ["doc+1", "doc+2"]


def test_nothing_after_the_alert_is_reported_as_nothing_available(monkeypatch):
    events = [_event(n) for n in (-3, -2, -1)] + [_event(0, ALERT_DOC_ID)]
    page = _call(events=events, external_ref=ALERT_DOC_ID, monkeypatch=monkeypatch)

    assert page["after"] == []
    assert page["available_after"] == 0
    assert page["available_before"] == 3


# --- a re-analysis must be a new answer, not the old one shown again --------

def test_requesting_a_reanalysis_clears_the_completion_it_supersedes():
    """A poll landing between the request and the worker picking it up saw the
    previous completed state and presented that verdict as the new one —
    instant, identical, and wrong."""
    import inspect

    source = inspect.getsource(api.reanalyse_with_log_context)
    assert "run.completed_at = None" in source
    assert "previous_completed_at" in source


def test_the_status_reports_what_was_sent_not_what_the_ranking_costed():
    """`used_tokens` is the budget the selection would have spent. Reporting it
    when nothing was sent told an analyst 3,689 tokens had gone on an empty
    block."""
    import inspect

    source = inspect.getsource(api.get_analysis_status)
    assert '"sent_tokens"' in source
    assert '"ranking_tokens"' in source
    # Zero unless something actually went.
    assert 'if selection.get("sent_refs") else 0' in source


def test_the_context_view_hands_over_every_relevant_ref():
    """"Re-analyse with the relevant events" has to mean all of them. The view
    holds a window of ten; the flagged set spans the whole retrieval — measured
    on a real alert, 24 flagged out of 691 retrieved."""
    import inspect

    source = inspect.getsource(api.get_run_log_context)
    assert 'payload["relevant_refs"]' in source


def test_the_superseded_report_is_actually_kept():
    """The endpoint promised to keep the previous verdict and preserved a null:
    it read `assistant_report` while the pipeline writes `ai_report`. So an
    analyst asking "did my events change anything?" had nothing to compare."""
    import inspect

    source = inspect.getsource(api.reanalyse_with_log_context)
    assert 'existing.get("ai_report")' in source
    assert '"report_markdown": superseded.get("report_markdown")' in source
    assert '"verdict"' in source


def test_the_status_says_whether_the_answer_changed():
    """A model that read the added events and kept its conclusion has answered
    the question. Silence makes that look like a failed request."""
    now = {
        "ai_report": {"report_markdown": "new wording"},
        "overall_verdict": "benign",
        "previous_analyses": [
            {"superseded_at": "2026-09-24T15:00:00+00:00", "by": "tim",
             "verdict": "suspicious", "report_markdown": "old wording"}
        ],
    }
    previous = api._previous_analysis(now)
    assert previous["verdict"] == "suspicious"
    assert previous["interpretation_changed"] is True

    same = dict(now)
    same["previous_analyses"] = [{"report_markdown": "new wording", "verdict": "benign"}]
    assert api._previous_analysis(same)["interpretation_changed"] is False


def test_an_unrecorded_earlier_report_is_not_claimed_to_be_unchanged():
    """Runs written before the key was fixed have no earlier text. Saying "the
    wording is the same" about a blank is worse than saying nothing."""
    result = {
        "ai_report": {"report_markdown": "new"},
        "previous_analyses": [{"report_markdown": None, "verdict": "benign"}],
    }
    assert api._previous_analysis(result)["interpretation_changed"] is None


def test_no_history_means_no_comparison():
    assert api._previous_analysis({"ai_report": {"report_markdown": "x"}}) is None


def test_each_reanalysis_is_identified_so_its_own_result_can_be_recognised():
    """Comparing completion timestamps left a hole: a run with no completion to
    compare against accepted any finished status, so a poll landing before the
    worker started reported the previous answer as this one — zero events, zero
    tokens, zero history, and an interpretation that had not moved."""
    import inspect

    request = inspect.getsource(api.reanalyse_with_log_context)
    assert '"request_id": request_id' in request
    assert "uuid.uuid4().hex" in request

    status = inspect.getsource(api.get_analysis_status)
    assert '"request_id": requested.get("request_id")' in status


# --- the fields and filters an analyst had on screen -------------------------


def test_requested_field_names_are_bounded_and_strict():
    """These names project fields out of records already retrieved. They are
    never interpolated into an OpenSearch request — but a name is still caller
    input, so the shape is checked rather than trusted."""
    assert api._requested_log_fields(
        ["data.win.eventdata.logonId", "channel", "agent.ip"]
    ) == ["data.win.eventdata.logonId", "channel", "agent.ip"]
    # Nothing that is not a field name.
    assert api._requested_log_fields(
        ["../../etc/passwd", "a b", '{"match_all":{}}', "", None, 0, ["x"], "a" * 200]
    ) == []
    # Bounded, because every field is charged to the token budget on every
    # selected event: an unbounded list pushes out the events it was meant to
    # enrich.
    assert len(api._requested_log_fields([f"f{i}" for i in range(50)])) == 12
    assert api._requested_log_fields(["dup", "dup"]) == ["dup"]
    assert api._requested_log_fields("channel") == []


def test_requested_filters_keep_the_analysts_words_bounded():
    assert api._requested_log_filters(
        [{"field": "channel", "value": "Security"}]
    ) == [{"field": "channel", "value": "Security"}]
    # A filter with no value narrows nothing and says nothing.
    assert api._requested_log_filters([{"field": "channel", "value": ""}]) == []
    assert api._requested_log_filters([{"field": "bad name", "value": "x"}]) == []
    assert api._requested_log_filters([{"field": None, "value": "x"}]) == []
    assert len(api._requested_log_filters([{"field": "c", "value": "y" * 500}])[0]["value"]) == 120


def test_the_reanalysis_records_the_view_not_just_the_picks():
    """The pins were once accepted, stored, and then ignored by the run they
    were meant to steer. The fields and filters travel the same three hops, so
    each one is asserted rather than assumed."""
    import inspect

    source = inspect.getsource(api.reanalyse_with_log_context)
    assert "_requested_log_fields(body.get(\"extra_fields\"))" in source
    assert "_requested_log_filters(body.get(\"filters\"))" in source
    assert '"extra_fields": extra_fields' in source
    assert '"log_filters": log_filters' in source

    from app.tasks import alert_body_task

    carried = inspect.getsource(alert_body_task._collect_log_context)
    assert 'payload["extra_fields"]' in carried
    assert 'payload["log_filters"]' in carried

    from app.services import alert_body_investigation_service as svc

    used = inspect.getsource(svc)
    assert "extra_fields=extra_fields" in used
    assert "analyst_filters=log_filters" in used


def test_the_status_separates_fields_asked_for_from_fields_sent():
    """A field no selected event carries is dropped from the projection to save
    tokens. An analyst checking "did the model see the logon id" needs the sent
    list, not the asked list."""
    import inspect

    source = inspect.getsource(api.get_analysis_status)
    assert '"extra_fields_requested"' in source
    assert '"extra_fields_sent"' in source
