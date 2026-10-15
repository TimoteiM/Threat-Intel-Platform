"""A guard on the event that expires backlog 18's reasoning.

The log store's `verified_ok` is promoted on **collector output**, and that
is defended by collection evidence being a *superset* of what an api ping
proves. That holds only because there is currently **no api-side user-facing
OpenSearch query**: the sole `search_all` caller is
`alert_log_context_service`, reached only from `alert_body_task` and
`alert_log_followup_task`, and the api's only contact with the cluster is
`ping()` in `GET /admin/opensearch-health`.

`estate_lookup_service` already calls `_request` and has **no consumer**. The
day it gets an API route the superset dies: the ping becomes the sole witness
for the api path, neither warrant subsumes the other, and a card showing only
`collector_output` makes a narrower claim than it appears to — the worker can
be answering while an analyst's on-demand lookup fails.

Whoever wires that route will not be reading backlog 18. So this fails on
that event and sends them there, which is the difference between a control
and a note — the lesson from the seam list the same morning.
"""
from __future__ import annotations

import pathlib

API_DIR = pathlib.Path(__file__).resolve().parents[3] / "app" / "api"
BACKLOG_ITEM = "backlog 18"


def _api_files() -> list[pathlib.Path]:
    return sorted(API_DIR.rglob("*.py"))


def test_the_api_dir_exists_so_this_guard_is_looking_somewhere():
    """Without this, an empty glob passes the guard for the wrong reason."""
    files = _api_files()
    assert files, f"no api modules found under {API_DIR}"
    assert len(files) > 5


def test_estate_lookup_has_no_api_side_consumer_yet():
    """When this fails, it is because the thing it guards has happened.

    Do not delete it and do not add the new route to an allowlist. Read
    backlog 18: the log store needs TWO direction states once an api-side
    consumer exists, because the collection path and the on-demand path are
    separate consumers with separate failure modes — the same argument that
    already keeps `enrichment` and `ingest` apart. Update the promotion
    reasoning, then retire this guard deliberately.
    """
    importers = [
        f.name for f in _api_files()
        if "estate_lookup_service" in f.read_text()
        or "estate_client_for" in f.read_text()
    ]
    assert importers == [], (
        f"{importers} now reach the estate lookup from the api side. The "
        f"superset argument behind the log store's promoted verified_ok has "
        f"expired — see {BACKLOG_ITEM}. The ping is now the sole witness for "
        f"the api path and needs its own direction state; one warrant must "
        f"not stand in for both."
    )


def test_the_worker_is_still_the_only_route_to_the_log_search():
    """The other half of the superset claim, asserted rather than recalled."""
    root = pathlib.Path(__file__).resolve().parents[3] / "app"
    callers = sorted(
        str(f.relative_to(root)) for f in root.rglob("*.py")
        if "search_all" in f.read_text() and f.name != "opensearch_client.py"
    )
    assert callers == ["services/alert_log_context_service.py"], (
        f"search_all now has callers beyond the log-context service: "
        f"{callers}. Check whether any of them runs in the api process; if "
        f"so the superset argument in {BACKLOG_ITEM} has expired."
    )
