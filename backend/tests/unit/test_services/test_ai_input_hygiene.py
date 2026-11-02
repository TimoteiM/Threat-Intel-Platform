"""Nothing hands a model the key to its own redaction.

A finished report is de-anonymised for the analyst and carries a table mapping
every token back to its value. The correlated-case narrative reads finished
reports to build its evidence, so both went back out to the provider.

Measured against the real sanitiser before these were written: hostname and IP
are re-tokenised on the way back through, leaving a `[HOST_1] | Hostname |
[HOST_1]` row that costs tokens and says nothing — but a bare account name in a
table cell matches none of the keyed account patterns and reached the provider
in the clear.
"""

from __future__ import annotations

import pytest

from app.services.assistant_service import strip_resolved_identifiers

REPORT = """## Event Interpretation

On [HOST_1], `agentexecutor.exe` ran under [ACCOUNT_1].

---

## Resolved Identifiers

Sensitive values were redacted before AI analysis. The table below maps every redacted token to its original value:

| Token | Category | Value |
|-------|----------|-------|
| `[HOST_1]` | Hostname | `EXP-4LWK334.int.expertware.net` |
| `[IP_1]` | IP Address | `10.10.126.64` |
| `[ACCOUNT_1]` | Account | `dnechita` |
"""


def test_the_resolution_table_is_removed():
    out = strip_resolved_identifiers(REPORT)
    assert "Resolved Identifiers" not in out
    for value in ("EXP-4LWK334.int.expertware.net", "10.10.126.64", "dnechita"):
        assert value not in out


def test_the_analysis_itself_survives():
    """Stripping must cost the reasoning nothing — only the key."""
    out = strip_resolved_identifiers(REPORT)
    assert "## Event Interpretation" in out
    assert "agentexecutor.exe" in out
    assert "[HOST_1]" in out


def test_a_report_without_a_table_is_untouched():
    plain = "## Event Interpretation\n\nNothing was redacted here."
    assert strip_resolved_identifiers(plain) == plain


def test_empty_and_none_are_safe():
    assert strip_resolved_identifiers("") == ""
    assert strip_resolved_identifiers(None) == ""


def test_the_account_leak_this_was_written_for():
    """The one the sanitiser does not catch on its own: a bare name in a table
    cell is not a keyed account pattern."""
    from app.services.assistant_sanitizer_service import sanitize_entries

    through_sanitiser = sanitize_entries([REPORT], existing_token_map={}).entries[0].sanitized_text
    assert "dnechita" in through_sanitiser, "if this ever fails, the sanitiser improved"

    # Stripping first is what closes it.
    stripped = sanitize_entries(
        [strip_resolved_identifiers(REPORT)], existing_token_map={}
    ).entries[0].sanitized_text
    assert "dnechita" not in stripped


def test_every_model_input_passes_through_the_strip():
    """The backstop. Entries are the only way text reaches a model, so a caller
    that assembles evidence from finished reports cannot reintroduce the table
    by forgetting."""
    import inspect

    from app.services.assistant_service import AssistantService

    source = inspect.getsource(AssistantService.add_entry)
    assert "strip_resolved_identifiers(text)" in source


def test_the_case_narrative_prefers_the_model_safe_report():
    import inspect

    from app.tasks import case_narrative_task

    source = inspect.getsource(case_narrative_task)
    assert "report_markdown_model_safe" in source
    # And falls back to stripping, for analyses written before it was stored.
    assert "strip_resolved_identifiers" in source


def test_the_model_safe_report_is_stored_alongside_the_analyst_one():
    import inspect

    from app.services.assistant_service import AssistantService

    source = inspect.getsource(AssistantService.run_session)
    assert "report_markdown_model_safe = cleaned" in source
    # `cleaned` is pre-restoration: the model's own output before tokens became
    # real values. Anything after _restore_tokens would defeat the point.
    assert source.index("report_markdown_model_safe = cleaned") > source.index("cleaned = self._scrub_token_leakage")


# --- correlation acts on a schedule, not on a page load ----------------------

def test_a_read_does_not_commission_ai_work():
    """Opening an alert ran correlation and could queue a narrative per changed
    case. That made reading the queue the thing that drove the AI bill."""
    import inspect

    from app.services import alert_correlation_service as svc

    signature = inspect.signature(svc.correlate_alerts)
    assert signature.parameters["emit"].default is False

    source = inspect.getsource(svc.correlate_alerts)
    assert "if emit:" in source
    # Both side effects are behind it, not only the expensive one.
    emit_block = source[source.index("if emit:"):]
    assert "dispatch(emissions)" in emit_block
    assert "dispatch_narratives(narrative_jobs)" in emit_block


def test_every_read_path_leaves_emit_alone():
    import inspect

    from app.api import detections
    from app.services import alert_correlation_service as svc

    for fn in (detections.get_correlated_cases, svc.case_for_run, svc.case_by_key):
        assert "emit=True" not in inspect.getsource(fn)


def test_the_scheduled_job_is_the_one_that_acts():
    import inspect

    from app.tasks import case_correlation_task

    assert "emit=True" in inspect.getsource(case_correlation_task.correlate_and_notify)


def test_the_job_is_registered_and_hourly():
    from app.tasks.celery_app import celery_app
    import app.tasks.case_correlation_task  # noqa: F401

    assert "app.tasks.case_correlation_task.correlate_and_notify" in celery_app.tasks
    entry = celery_app.conf.beat_schedule["case-correlation-hourly"]
    assert entry["task"] == "app.tasks.case_correlation_task.correlate_and_notify"
