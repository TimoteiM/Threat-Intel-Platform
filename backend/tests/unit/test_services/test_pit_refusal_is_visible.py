"""A refused point-in-time must not be a silent downgrade.

`open_pit` returns `None` when the cluster refuses, by design — a frozen view
is an improvement to consistency, not a precondition for reading logs. The
defect was that the degradation then went nowhere a reader would see it: an
INFO log line and a boolean in `sources`, while the page said "related
activity".

That is the same class as a detection search on a field that does not exist.
The analyst sees a narrower answer than the one the screen claims, and on a SOC
platform "no related activity" is a conclusion people act on.

A PIT can be refused by cluster pressure, a PIT limit or a timeout, not only by
a missing permission, so this is not conditional on any configuration decision.
Measured 2026-10-15: 0 of 3,524 recorded log-context reads had a PIT refused —
latent, not live, and nothing would have reported it if it were.
"""

from __future__ import annotations

from app.services import absence
from app.services.opensearch_client import OpenSearchError, SearchResult


class _Client:
    """Just enough of the client to exercise `search_all`'s PIT handling."""

    def __init__(self, *, pit: str | None, refuse_reason: str | None = None):
        self._pit, self._refuse = pit, refuse_reason
        self._last_pit_refusal: str | None = None
        self.searched = 0

    # --- the two methods under test, borrowed from the real class ---------
    open_pit = None  # replaced per instance below
    search_all = None

    def _scrub(self, exc):  # noqa: D401
        return str(exc)


def _real(instance):
    """Bind the real methods onto the stub, so the test exercises shipped code
    rather than a reimplementation of it."""
    from app.services.opensearch_client import OpenSearchClient

    instance.open_pit = OpenSearchClient.open_pit.__get__(instance)
    instance.search_all = OpenSearchClient.search_all.__get__(instance)
    instance.close_pit = lambda pit_id: None
    instance._page = lambda **kw: None
    return instance


def _request_ok(pit):
    def _inner(method, path, **kwargs):
        return {"pit_id": pit}, "node", []
    return _inner


def _request_refuses(reason):
    def _inner(method, path, **kwargs):
        raise OpenSearchError(reason)
    return _inner


def test_a_granted_pit_records_no_absence():
    """The control: without this, a test asserting an absence appears could
    pass because the absence is always set."""
    c = _real(_Client(pit="pit-123"))
    c._request = _request_ok("pit-123")
    result = c.search_all(indices=["i-1"], query={}, sort=[], max_hits=10)

    assert result.consistent is True
    assert result.consistency_requested is True
    assert result.consistency_absence is None


def test_a_refused_pit_puts_a_named_absence_on_the_result():
    c = _real(_Client(pit=None))
    c._request = _request_refuses("too many point-in-time contexts")
    result = c.search_all(indices=["i-1"], query={}, sort=[], max_hits=10)

    assert result.consistent is False
    assert result.consistency_requested is True
    assert absence.is_absent(result.consistency_absence)
    assert result.consistency_absence["kind"] == absence.CHECK_FAILED
    # The reason has to say what it costs the reader, not just that it failed.
    reason = result.consistency_absence["reason"]
    assert "skipped or duplicated" in reason
    assert "not a complete window" in reason
    assert "too many point-in-time contexts" in reason, (
        "the cluster's own reason was dropped, so nobody can tell cluster "
        "pressure from a missing permission"
    )


def test_not_requesting_a_pit_is_distinct_from_being_refused():
    """`consistent: False` alone conflated the two.

    "Nobody asked for a frozen view" is a configuration choice. "The cluster
    refused one" means the pages may be wrong. Reporting them as one boolean
    is why the second was invisible.
    """
    c = _real(_Client(pit=None))
    c._request = _request_ok("unused")
    result = c.search_all(indices=["i-1"], query={}, sort=[], max_hits=10,
                          use_pit=False)

    assert result.consistent is False
    assert result.consistency_requested is False
    assert result.consistency_absence is None, (
        "a window nobody asked to freeze was reported as a degraded one"
    )


def test_a_refusal_is_logged_at_warning_not_info(caplog):
    """INFO is where it went unseen. The log is not the fix, but it must not
    contradict the fix."""
    import logging

    c = _real(_Client(pit=None))
    c._request = _request_refuses("circuit_breaking_exception")
    with caplog.at_level(logging.WARNING, logger="app.services.opensearch_client"):
        c.search_all(indices=["i-1"], query={}, sort=[], max_hits=10)

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings, "a refused PIT produced no record at WARNING or above"
    assert "LIVE index" in warnings[0].getMessage()


def test_a_real_client_has_the_refusal_field_before_any_paging():
    """So a reader never has to guess whether a refusal simply was not
    recorded. `getattr(..., None)` would make absence and silence the same
    value again.

    Asserted on a REAL client, because the stub above sets the attribute
    itself and would therefore prove nothing about the shipped class.
    """
    from app.services.opensearch_client import OpenSearchClient

    class _Settings:
        # The real attribute names: the client reads node1/2/3, not `nodes`.
        opensearch_node1 = "https://localhost:9200"
        opensearch_node2 = ""
        opensearch_node3 = ""
        opensearch_username = "u"
        opensearch_password = "p"
        opensearch_verify_certs = False
        opensearch_ca_cert_path = ""
        opensearch_timeout_seconds = 5
        opensearch_index_pattern = "x-*"
        opensearch_timestamp_field = "timestamp"

    client = OpenSearchClient(settings=_Settings())
    assert client._last_pit_refusal is None


def test_the_context_consumes_the_absence_rather_than_storing_it():
    """An absence computed and not consumed is the defect being fixed.

    This is a SOURCE-LEVEL wiring assertion and is labelled as one: the
    context assembly is a long async function over a live cluster, so the
    behavioural coverage belongs in the view test. What this holds is the one
    thing that regressed before — the absence reaching `context.status` and
    `context.reason` rather than only `sources`, where no reader sees it.
    """
    from pathlib import Path

    import app.services.alert_log_context_service as ctx

    text = Path(ctx.__file__).read_text()
    assert '"consistency_absence": getattr(result, "consistency_absence", None)' in text, (
        "the absence is not carried into sources"
    )
    reached = text.split("pit_absence = getattr(result,", 1)
    assert len(reached) == 2, "the absence is never read back out"
    after = reached[1][:400]
    assert "context.status" in after and "context.reason" in after, (
        "the absence is read but reaches neither the status nor the reason, "
        "so it is stored and not reported — the original defect"
    )
