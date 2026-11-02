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


#: FIRED AND RETIRED, 2026-10-15.
#:
#: `app/api/email_investigations.py` gained
#: `GET /{run_id}/estate-dns`, the guard below failed naming that file, and
#: the obligation was met rather than allowlisted: the log store now declares
#: `enrichment` and `on_demand` as separate directions, with separate
#: expectations (6h and *none*) and separate admissible warrants
#: (`collector_output` and `api_ping`).
#:
#: What replaces it is the inverse assertion. The original guard watched for
#: an event; once the event has happened, watching for it again is watching
#: for nothing, and a guard that can never fire is worse than no guard because
#: it reads as coverage. So the test below now asserts the *obligation* holds —
#: it fails if someone collapses the directions back to one, or lets
#: collection output promote the api path.
def test_an_api_side_consumer_obliges_two_direction_states():
    """The event happened, so this asserts what it obliged.

    An api-side consumer of the estate lookup exists. From that moment the
    api ping is the sole witness for the api path, neither warrant subsumes
    the other, and a single direction would make a narrower claim than it
    appears to: the worker can be answering while an analyst's on-demand
    lookup fails.
    """
    from app.services import integration_status_service as iss

    consumers = [
        f.name for f in _api_files()
        if "estate_lookup_service" in f.read_text()
        or "estate_client_for" in f.read_text()
    ]
    assert consumers, (
        "no api module reaches the estate lookup any more. If the route was "
        f"removed, the superset argument in {BACKLOG_ITEM} is live again and "
        "the two direction states could be collapsed — but do that "
        "deliberately, not by deleting this test."
    )

    spec = iss.catalogue()["opensearch"]
    assert iss.ENRICHMENT in spec.directions
    assert iss.ON_DEMAND in spec.directions, (
        f"{consumers} query the cluster from the api process, but the log "
        f"store reports only {spec.directions}. One direction cannot describe "
        f"two consumers with different failure modes — see {BACKLOG_ITEM}."
    )
    assert spec.warrant_for_direction(iss.ON_DEMAND) == iss.WARRANT_API_PING, (
        "the on-demand direction accepts collector output as its warrant, "
        "which promotes an api consumer on evidence from the worker"
    )
    assert spec.expectation_for(iss.ON_DEMAND) is None, (
        "the on-demand direction declares a silence interval. An analyst "
        "triggers it or nobody does, so a number manufactures an outage on "
        "every quiet day."
    )


def test_the_worker_is_still_the_only_route_to_the_log_search():
    """Still useful after the superset expired, for a narrower reason.

    The superset argument is gone — the estate route killed it. What this
    now guards is the *scope* of the enrichment direction's warrant: the
    6h expectation and `collector_output` warrant are sized against one
    producer, `alert_log_context_service` writing a row per analysed alert.
    A second `search_all` caller with a different rhythm would make that
    interval a measurement of something else.
    """
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
