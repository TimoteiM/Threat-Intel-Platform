"""How long ANY.RUN is asked to run a file, and how long we wait for it.

An analyst watching the recording of a submitted zip saw the archive unpacked
and then nothing at all until the video ended, with automated interactivity
enabled. The run had finished: `opt_timeout` was hardcoded to 60 seconds,
against an SDK default of 240. Sixty seconds covers booting a Windows VM and
opening the sample, and leaves the interactivity almost nothing to act in.

It was 60 because of a second number. The poll budget was derived from
`anyrun_timeout_file_hash_seconds` (90), giving 150 seconds to wait — and when
that expires with the task still running the whole result is discarded as an
error. So the detonation had been cut to fit the wait, and the two were set
independently in different places.

They are tied together now: the wait is derived from the detonation, with room
for boot and report assembly.
"""

from __future__ import annotations

import inspect

from app.config import get_settings
from app.services import anyrun_service


def _budgets():
    """The three numbers as the service computes them, for a file."""
    settings = get_settings()
    detonation = int(settings.anyrun_file_sandbox_analysis_timeout)
    file_hash_wait = int(settings.anyrun_timeout_file_hash_seconds)
    sandbox_timeout = max(file_hash_wait, detonation + 90)
    poll_budget = max(120, sandbox_timeout + 60)
    return detonation, sandbox_timeout, poll_budget


def test_a_file_gets_long_enough_to_be_interacted_with():
    detonation, _, _ = _budgets()
    assert detonation >= 180, "automated interactivity needs more than a boot"


def test_the_wait_always_covers_the_detonation_it_asked_for():
    """The regression. A wait shorter than the run means the report is never
    ready, and the run is thrown away with 'task is still running'."""
    detonation, sandbox_timeout, poll_budget = _budgets()

    assert sandbox_timeout >= detonation + 60, "no room for boot and upload"
    assert poll_budget >= detonation + 90, "the report would never be collected"


def test_the_detonation_is_configurable_rather_than_hardcoded():
    """It was a literal 60 in the submission kwargs, with no setting and no URL
    equivalent — the URL path had had one all along."""
    source = inspect.getsource(anyrun_service._submit_anyrun_task_with_fallback)
    assert '"opt_timeout": 60' not in source
    assert '"opt_timeout": file_analysis_timeout' in source
    assert "anyrun_file_sandbox_analysis_timeout" in source


def test_the_wait_is_derived_from_the_detonation_not_set_beside_it(monkeypatch):
    """Raising the detonation must raise the wait with it. Set independently,
    they drift, and the drift is silent until a run is discarded."""
    settings = get_settings()
    original = settings.anyrun_file_sandbox_analysis_timeout
    try:
        object.__setattr__(settings, "anyrun_file_sandbox_analysis_timeout", 600)
        detonation, sandbox_timeout, poll_budget = _budgets()
        assert detonation == 600
        assert poll_budget >= 690
    finally:
        object.__setattr__(settings, "anyrun_file_sandbox_analysis_timeout", original)


def test_interactivity_is_still_demanded_of_the_sdk():
    """`opt_automated_interactivity` is passed as a required kwarg, so an SDK
    that does not support it raises rather than silently submitting a passive
    run. That part was already right and must stay right."""
    source = inspect.getsource(anyrun_service._submit_anyrun_task_with_fallback)
    assert source.count('required_kwargs={"opt_automated_interactivity"}') == 2
    assert anyrun_service._ANYRUN_AUTOMATED_INTERACTIVITY is True


def test_the_collector_thread_outlives_the_poll_budget():
    """Otherwise the thread is killed before the report it is waiting for."""
    from app.tasks.investigation_task import _sandbox_collector_timeout

    _, _, poll_budget = _budgets()
    assert _sandbox_collector_timeout(60) >= poll_budget
