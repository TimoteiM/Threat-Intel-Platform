"""Per-request providers stay off the automatic alert path.

An alert fans out over many indicators. A provider that is worth a few cents
once, for an analyst investigating a domain by hand, is not worth it dozens of
times a ticket — and Brave Search bills per request.

Three mechanisms already existed and each covered a different path, which is
how this gap survived: ANY.RUN is held back by `sandbox_suppressed`, the alert
service's `OPT_IN_COLLECTORS` covers inline indicator triage, and neither
touched full investigations *spawned* from an alert. Those pass
`requested_collectors=None` and take the platform defaults, Brave included.
"""

from __future__ import annotations

import pytest

from app.config import Settings


def _selected(defaults: str, excluded: str, *, origin: str | None, supported: set[str]) -> list[str]:
    """The selection the task performs, in the same order."""
    settings = Settings(default_collectors=defaults, alert_excluded_collectors=excluded)
    chosen = [c for c in settings.default_collectors_list if c in supported]
    if origin == "alert":
        chosen = [c for c in chosen if c not in settings.alert_excluded_collector_set]
    return chosen


DEFAULTS = "dns,whois,vt,brave_osint,urlscan"
SUPPORTED = {"dns", "whois", "vt", "brave_osint", "urlscan"}


def test_an_alert_spawned_investigation_does_not_call_brave():
    chosen = _selected(DEFAULTS, "brave_osint", origin="alert", supported=SUPPORTED)
    assert "brave_osint" not in chosen
    # Everything else still runs — this holds one provider back, not the path.
    assert chosen == ["dns", "whois", "vt", "urlscan"]


def test_a_manual_investigation_still_calls_brave():
    """The whole point: an analyst submitting a domain by hand gets the OSINT."""
    assert "brave_osint" in _selected(DEFAULTS, "brave_osint", origin=None, supported=SUPPORTED)


def test_an_empty_exclusion_list_changes_nothing():
    before = _selected(DEFAULTS, "", origin=None, supported=SUPPORTED)
    after = _selected(DEFAULTS, "", origin="alert", supported=SUPPORTED)
    assert before == after


def test_more_than_one_provider_can_be_held_back():
    """The next per-request provider is a setting change, not a code change."""
    chosen = _selected(DEFAULTS, "brave_osint,urlscan", origin="alert", supported=SUPPORTED)
    assert chosen == ["dns", "whois", "vt"]


def test_the_setting_tolerates_spacing():
    settings = Settings(alert_excluded_collectors=" brave_osint , urlscan ")
    assert settings.alert_excluded_collector_set == frozenset({"brave_osint", "urlscan"})


def test_brave_is_excluded_by_default():
    """Stated as a default rather than left to the deployment to remember."""
    assert Settings.model_fields["alert_excluded_collectors"].default == "brave_osint"


def test_the_spawn_path_marks_its_origin():
    """Without the marker the task cannot tell an alert run from a manual one."""
    import inspect

    from app.services import alert_investigation_spawn_service as spawn

    source = inspect.getsource(spawn)
    assert '"origin": "alert"' in source
    assert '"sandbox_suppressed": True' in source, "the ANY.RUN suppression must survive"


def test_the_task_only_trims_the_automatic_path():
    """An explicitly requested collector list is never trimmed — an analyst who
    asks for Brave on an alert indicator still gets it."""
    import inspect

    from app.tasks import investigation_task

    source = inspect.getsource(investigation_task.run_investigation)
    trim = source.split("alert_excluded_collector_set")[0]
    # The trim sits in the branch that had no requested_collectors.
    assert trim.rindex("collectors_to_run = [") > trim.rindex("if requested_collectors:")
