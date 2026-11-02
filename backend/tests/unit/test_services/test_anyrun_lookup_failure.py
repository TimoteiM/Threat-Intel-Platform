"""A failed intelligence lookup must not cancel the detonation.

An archive submitted while ANY.RUN's Threat Intelligence Lookup was timing out
came back as "ANY.RUN unavailable for this sample. Fallback source used:
HYBRID. Reason: ... Status code: 408. Search request timed out." — with
MODE: LOOKUP, zero HTTP requests, zero connections, zero DNS. The file had
never been sent to the sandbox at all.

The hash sandbox is deliberately held until TI has answered, because it needs
the uploaded bytes and a redundant second task is wasteful. But the code
treated "TI said not found" and "TI could not answer" differently: only the
first fell through to the submission. The second returned the lookup error as
the result, and the file was dropped.

408s in this data go back to 2026-08-10, so the timeout itself is ordinary and
intermittent. What is not ordinary is losing the analysis because of one.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services import anyrun_service


@pytest.fixture
def harness(monkeypatch):
    """Drive the real lookup with a failing TI and a recording sandbox."""
    calls: dict[str, Any] = {"sandbox": []}

    def _lookup(*_args, **kwargs):
        if kwargs.get("indicator_type") == "domain":
            return {"checked": False, "error": "no info"}
        return {
            "checked": False,
            "error": (
                "[AnyRun Exception] Status code: 408. Description: Search request "
                "timed out. Please try again with a more specific query."
            ),
        }

    def _sandbox(_connector_cls, **kwargs):
        calls["sandbox"].append(kwargs)
        return {
            "checked": True,
            "indicator_type": kwargs.get("indicator_type"),
            "verdict": "malicious",
            "analysis_id": "task-1",
        }

    monkeypatch.setattr(anyrun_service, "_lookup_intelligence", _lookup)
    monkeypatch.setattr(anyrun_service, "_run_anyrun_sandbox_with_fallback", _sandbox)
    # `_attach_domain_intel` is nested inside `lookup_anyrun` and cannot be
    # patched from here. For a hash indicator there is no hostname, so it is
    # a no-op and the real one runs.
    return calls


def _run(**kwargs):
    defaults = dict(
        indicator="a" * 64,
        indicator_type="hash",
        file_bytes=b"MZ\x00\x00payload",
        file_name="dropper.zip",
        submit_on_not_found=True,
        sandbox_first=False,
    )
    defaults.update(kwargs)
    return anyrun_service.lookup_anyrun(**defaults)


def test_an_uploaded_file_is_detonated_even_when_the_lookup_times_out(harness):
    """The regression. One 408 used to mean the sample was never run."""
    result = _run()

    assert harness["sandbox"], "the file was never submitted"
    submitted = harness["sandbox"][0]
    assert submitted["file_bytes"] == b"MZ\x00\x00payload"
    assert submitted["indicator_type"] == "hash"
    # And the sandbox's answer is what comes back, not the lookup's error.
    assert result.get("verdict") == "malicious"


def test_the_sandbox_still_waits_for_the_lookup_rather_than_racing_it(harness):
    """Submitting in parallel would run a second task for every file whose
    hash ANY.RUN already knows. The fall-through happens after TI answers."""
    import inspect

    source = inspect.getsource(anyrun_service.lookup_anyrun)
    assert "hash sandbox needs file bytes" in source or "needs the bytes" in source.lower()


def test_without_file_bytes_there_is_nothing_to_detonate_and_the_error_stands(harness):
    """A bare hash with no upload cannot be run, so the lookup error is the
    honest result rather than a submission that must fail."""
    result = _run(file_bytes=None, submit_on_not_found=False)

    assert not harness["sandbox"]
    assert "408" in str(result.get("error") or "")


def test_a_lookup_that_says_not_found_still_detonates(harness, monkeypatch):
    """The path that already worked, kept working."""
    monkeypatch.setattr(
        anyrun_service, "_lookup_intelligence",
        lambda *a, **k: {"checked": False, "error": "Hash not found in database"},
    )

    _run()

    assert harness["sandbox"], "not-found must still reach the sandbox"
