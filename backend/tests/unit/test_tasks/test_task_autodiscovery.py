"""Every Celery task module is actually registered with the worker.

This list has now been the bug three times. The failure is quiet and total:
the API queues the task happily, the worker answers "Received unregistered
task", the message is discarded, and the work sits in its initial state for
ever. Nothing raises, and the only evidence is one line in the worker log.

It cost a CAPE submission stuck in `queued` with no explanation, and before
that the case-event and escalation-webhook tasks. So rather than trusting the
next person to remember, this compares the modules on disk against the list.
"""

from __future__ import annotations

from pathlib import Path

import pytest

TASKS_DIR = Path(__file__).resolve().parents[3] / "app" / "tasks"

# Modules that legitimately define no Celery task, or are infrastructure.
NOT_TASK_MODULES = {"celery_app", "cancellation", "__init__"}


def _module_names() -> set[str]:
    return {
        path.stem
        for path in TASKS_DIR.glob("*.py")
        if path.stem not in NOT_TASK_MODULES
    }


def _declares_a_task(name: str) -> bool:
    source = (TASKS_DIR / f"{name}.py").read_text(encoding="utf-8")
    return "@celery_app.task" in source or "@shared_task" in source


def _autodiscovered() -> set[str]:
    """The literal list in celery_app.py, read as text.

    Read rather than imported: importing the module would pull in the whole
    application, and what is being asserted is the contents of that list.
    """
    source = (TASKS_DIR / "celery_app.py").read_text(encoding="utf-8")
    start = source.index("autodiscover_tasks([")
    end = source.index("])", start)
    return {
        line.strip().strip(",").strip('"').rsplit(".", 1)[-1]
        for line in source[start:end].splitlines()
        if line.strip().startswith('"app.tasks.')
    }


def test_every_task_module_is_autodiscovered():
    missing = sorted(
        name for name in _module_names()
        if _declares_a_task(name) and name not in _autodiscovered()
    )
    assert not missing, (
        "These modules define Celery tasks but are not in the autodiscover_tasks "
        f"list in app/tasks/celery_app.py: {missing}. The worker will reject "
        "anything they queue with 'Received unregistered task', silently."
    )


def test_the_autodiscover_list_names_only_real_modules():
    """A typo here fails the same way round: the module is never imported."""
    unknown = sorted(name for name in _autodiscovered() if not (TASKS_DIR / f"{name}.py").exists())
    assert not unknown, f"autodiscover_tasks names modules that do not exist: {unknown}"


def test_the_cape_workflow_in_particular_is_registered():
    """Named explicitly because its absence is what sent a submission into a
    permanent `queued` state with no error anywhere the operator would look."""
    assert "cape_task" in _autodiscovered()


@pytest.mark.parametrize("name", sorted(_module_names()))
def test_each_task_module_is_importable(name):
    """A module in the list that cannot import is registered as nothing."""
    import importlib

    importlib.import_module(f"app.tasks.{name}")
