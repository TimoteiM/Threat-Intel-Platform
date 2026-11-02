"""Automated Interactivity: that we ask for it, and that we check we got it.

Reported as "the sandbox appears not to perform automated interactions to
advance execution". Traced against this account's own task history, read-only:
nine tasks submitted through this integration all report
`data.analysis.options.automatization.interactivity = true`, and sixteen
submitted elsewhere all report false. So the option is reaching the API; what
was missing was any check that it had, and any consequence when a run did not
complete.

These pin the four things that were actually wrong, plus the two contracts
that were already right and must stay that way.
"""

from __future__ import annotations

import inspect

from app.services import anyrun_service as svc


# --- the option, and its serialisation ---------------------------------------

def test_the_submission_asks_for_automated_interactivity():
    """Explicitly, rather than relying on the SDK default.

    The SDK's default is True today, and the vendor documents that the feature
    is "activated by default for all sandbox sessions launched via API" — but
    a default is the vendor's decision to change, and this is the one option
    the whole integration depends on.
    """
    source = inspect.getsource(svc._submit_anyrun_task_with_fallback)
    # Both submission modes, not just one.
    assert source.count('"opt_automated_interactivity": _ANYRUN_AUTOMATED_INTERACTIVITY') == 2
    assert svc._ANYRUN_AUTOMATED_INTERACTIVITY is True


def test_a_real_bool_is_sent_not_a_string():
    """`opt_automated_interactivity` must stay a bool.

    The SDK serialises a JSON submission straight from the Python value, so a
    string "true" would arrive as a string. It also drops falsy values from
    the body entirely (`if value:` in both of its body builders), which is why
    the flag being True is what makes it transmissible at all.
    """
    assert isinstance(svc._ANYRUN_AUTOMATED_INTERACTIVITY, bool)


def test_an_sdk_without_the_option_fails_loudly():
    """Never silently downgraded.

    `_call_with_supported_kwargs` drops kwargs the installed SDK does not
    accept, which is right for optional extras and catastrophic for this one:
    the submission would succeed with no interactivity and look identical to
    one that worked.
    """
    def old_sdk_method(url, *, opt_timeout=None):
        return {"ok": True}

    try:
        svc._call_with_supported_kwargs(
            old_sdk_method, "https://example.com",
            required_kwargs={"opt_automated_interactivity"},
            opt_timeout=120, opt_automated_interactivity=True,
        )
    except RuntimeError as exc:
        assert "opt_automated_interactivity" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("a missing required option must raise, not be dropped")


def test_a_method_taking_kwargs_receives_the_option_untouched():
    """The installed SDK declares every option explicitly, but a build that
    takes `**kwargs` must not have the option filtered out of it."""
    seen = {}

    def sdk_with_kwargs(url, **kwargs):
        seen.update(kwargs)
        return {"ok": True}

    svc._call_with_supported_kwargs(
        sdk_with_kwargs, "https://example.com",
        required_kwargs={"opt_automated_interactivity"},
        opt_automated_interactivity=True, opt_timeout=120,
    )
    assert seen["opt_automated_interactivity"] is True


# --- the analysis duration ---------------------------------------------------

def test_the_duration_is_clamped_to_the_documented_range():
    """ANY.RUN documents 10-660s on `opt_timeout`. Outside it the API answers
    400, so a mistyped setting would fail every submission rather than being
    corrected."""
    assert svc._clamp_anyrun_timeout(5, 120) == svc._ANYRUN_TIMEOUT_MIN
    assert svc._clamp_anyrun_timeout(99999, 120) == svc._ANYRUN_TIMEOUT_MAX
    assert svc._clamp_anyrun_timeout(300, 120) == 300
    # A non-numeric setting falls back rather than raising at submission time.
    assert svc._clamp_anyrun_timeout("not a number", 120) == 120
    assert svc._clamp_anyrun_timeout(None, 240) == 240


# --- what the task actually applied ------------------------------------------

def _report(interactivity, *, status="done", timeout=120):
    return {
        "status": status,
        "analysis": {
            "options": {
                "automatization": {"uac": True, "interactivity": interactivity},
                "timeout": timeout, "additionalTime": 0, "network": True,
                "fakeNet": False, "mitm": True, "tor": {"used": False},
                "privacy": "owner",
            }
        },
    }


def test_the_applied_option_is_read_from_the_report():
    """Taken from `data.analysis.options`, which is the task's applied
    settings. The diagnostic used to record `_ANYRUN_AUTOMATED_INTERACTIVITY`
    — a module constant that is always True — so it agreed with itself however
    the task ran and could never have shown a downgrade."""
    out = svc._anyrun_execution_report(
        _report(True), requested_interactivity=True, final_status="COMPLETED",
    )
    assert out["applied"]["automated_interactivity"] is True
    assert out["automated_interactivity_downgraded"] is False
    assert out["execution_completeness"] == "complete"


def test_asking_for_interactivity_and_not_getting_it_is_reported():
    """Measured shape of a task submitted without it — the sixteen in this
    account's history that did not come from here."""
    out = svc._anyrun_execution_report(
        _report(False, timeout=60), requested_interactivity=True, final_status="COMPLETED",
    )
    assert out["applied"]["automated_interactivity"] is False
    assert out["automated_interactivity_downgraded"] is True


def test_an_absent_field_is_unknown_and_not_false():
    """A report that does not mention the option has not said it was off. The
    difference matters: one is a downgrade to investigate, the other is an
    older report shape."""
    out = svc._anyrun_execution_report(
        {"status": "done", "analysis": {"options": {}}},
        requested_interactivity=True, final_status="COMPLETED",
    )
    assert out["applied"]["automated_interactivity"] is None
    assert out["automated_interactivity_downgraded"] is None


# --- completeness, and the verdict ------------------------------------------

def test_completeness_is_unknown_unless_the_telemetry_settles_it():
    """Never "complete" by omission. The status stream ends for reasons that
    are not completion — a dropped connection, our own deadline — and "we
    stopped looking" is not "it finished"."""
    for status in (None, "", "RUNNING", "QUEUED", "PREPARING"):
        out = svc._anyrun_execution_report(
            {"status": "running", "analysis": {"options": {}}},
            requested_interactivity=True, final_status=status,
        )
        assert out["execution_completeness"] == "unknown", status


def test_a_failed_task_is_reported_as_failed():
    out = svc._anyrun_execution_report(
        _report(True, status="failed"), requested_interactivity=True, final_status="FAILED",
    )
    assert out["execution_completeness"] == "failed"


def test_a_failed_run_never_becomes_a_benign_verdict():
    """The defect this guards.

    `final_status` was computed and never read — assigned on one line and
    referenced nowhere — so a FAILED detonation fell through to
    `get_analysis_verdict`, which answers "No threats detected" for a run that
    never executed, and that normalises to `clean`. A crashed sandbox became
    evidence of safety.
    """
    source = inspect.getsource(svc)
    assert 'if str(final_status or "").strip().upper() == "FAILED":' in source
    # And "No threats detected" really does normalise to clean, which is why
    # the guard above has to come first.
    assert svc._normalize_anyrun_verdict("No threats detected") == "clean"


def test_a_refusal_carries_the_task_so_an_analyst_can_take_over():
    """Requirement when automation cannot answer: the vendor's own session is
    still there, and the fallback is to look at it."""
    out = svc._error(
        "url", "task reported FAILED", mode="sandbox", analysis_id="task-uuid-1",
        execution={"execution_completeness": "failed"},
    )
    assert out["verdict"] == "unknown", "a failed run must never be clean"
    assert out["analysis_link"].endswith("task-uuid-1")
    assert out["raw_summary"]["analyst_fallback"]
    assert out["raw_summary"]["sandbox_execution"]["execution_completeness"] == "failed"


def test_an_error_without_a_task_claims_no_link():
    """Most submission failures have no task at all, and inventing a link to
    one would send an analyst to a 404."""
    out = svc._error("url", "submission refused")
    assert "analysis_link" not in out
    assert "permanentUrl" not in out["raw_summary"]


# --- the URL that gets detonated --------------------------------------------

def test_the_whole_url_survives_submission():
    """A phishing URL's query and fragment are usually the payload selector —
    the victim id, the redirect target, the stage. Submitting the bare path
    detonates a different page from the one in the alert, and the sandbox then
    has nothing to interact with, which looks exactly like automation
    failing."""
    for value in (
        "https://example.com/login?id=42&next=/pay#step2",
        "http://example.com/a/b/c.php?x=1",
        "https://1.2.3.4:8080/p?q=1",
        "https://example.com/%20space?a=%2F",
    ):
        assert svc._normalize_submission_url(value) == value


def test_a_bare_domain_becomes_a_url_without_losing_anything():
    assert svc._normalize_submission_url("example.com") == "https://example.com"
    assert (
        svc._normalize_submission_url("example.com/path?q=1#frag")
        == "https://example.com/path?q=1#frag"
    )


def test_a_defanged_indicator_is_refanged_before_submission():
    """`hxxps://` is not a scheme anything can fetch, so the task could only
    fail — and a failed task used to read as clean."""
    assert svc._normalize_submission_url("hxxps://example.com/p?q=1") == "https://example.com/p?q=1"
    assert svc._normalize_submission_url("hxxp://evil[.]com/a?b=c") == "http://evil.com/a?b=c"
    assert svc._normalize_submission_url("example[.]com") == "https://example.com"


def test_the_single_slash_form_keeps_its_query():
    """`https:/host/p?q=1` was rebuilt from the scheme and the path alone,
    producing `https:///host/p` — not resolvable, and missing the query."""
    assert svc._normalize_submission_url("https:/example.com/p?q=1") == "https://example.com/p?q=1"
