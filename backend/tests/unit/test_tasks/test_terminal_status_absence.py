"""A terminal write must not manufacture a verdict it was not given.

Six times in six weeks a skip has read as a result in this codebase, so the
property under test is the general one: **when a stage produced nothing, the
terminal record must not say it produced something.**

The audit behind this file is `docs/design/did-not-run-is-not-a-verdict.md`.
It found two conflations. This covers the one whose before/after is provably
empty — `alert_body_task` defaulting an absent verdict to `inconclusive`,
which had never fired across 17,640 runs. The other (`Classification` having
no value for "did not run") needs an enum decision and is deliberately not
touched here.
"""

from __future__ import annotations

import app.tasks.alert_body_task as task


def _captured_update(monkeypatch):
    """Capture what the task would write, without a database."""
    seen: dict = {}

    def fake_update(run_id, **fields):
        seen.update(fields)

    monkeypatch.setattr(task, "_update_run", fake_update)
    return seen


def test_an_absent_verdict_is_written_as_null_not_as_inconclusive(monkeypatch):
    """The dangerous direction: a summary with no verdict.

    `inconclusive` is defined in `app/models/enums.py` as "Evidence
    insufficient to decide" — a claim about the evidence. A missing verdict
    is a claim about us, and conflating them is how an analyst comes to read
    "we looked and could not tell" where the truth was "nothing told us".
    """
    seen = _captured_update(monkeypatch)
    summary = {"indicators_total": 3, "highest_risk_score": 0}   # no verdict
    verdict = (
        str(summary["overall_verdict"]) if summary.get("overall_verdict") else None
    )
    task._update_run("run-1", status="completed", overall_verdict=verdict)
    assert seen["overall_verdict"] is None
    assert seen["overall_verdict"] != "inconclusive"


def test_a_real_verdict_still_survives(monkeypatch):
    """The positive control.

    Without this, the assertion above is satisfied by a change that writes
    NULL unconditionally — which would destroy every verdict the platform
    produces while passing the dangerous-direction test. That is the exact
    trap the RLS work fell into: six refusal tests green while the feature
    denied everything.
    """
    seen = _captured_update(monkeypatch)
    summary = {"overall_verdict": "malicious", "indicators_total": 3,
               "highest_risk_score": 90}
    verdict = (
        str(summary["overall_verdict"]) if summary.get("overall_verdict") else None
    )
    task._update_run("run-1", status="completed", overall_verdict=verdict)
    assert seen["overall_verdict"] == "malicious"


def test_the_source_line_carries_no_default(monkeypatch):
    """Read the shipped expression, not a copy of it.

    The two tests above exercise the expression as this file restates it,
    which proves the logic and not the code. This one asserts the code: no
    `or "inconclusive"` anywhere in the task.
    """
    import inspect

    # Comment lines are stripped first. The comment explaining the removal
    # quotes the removed expression, so searching the raw source made this
    # test fail on the documentation of its own fix — a test matching prose
    # rather than code.
    code = "\n".join(
        line for line in inspect.getsource(task).splitlines()
        if not line.lstrip().startswith("#")
    )
    assert 'or "inconclusive"' not in code, (
        "the verdict default is back; see docs/design/did-not-run-is-not-a-verdict.md"
    )
    # And the nullable form is what is there instead.
    assert 'if summary.get("overall_verdict") else None' in code
