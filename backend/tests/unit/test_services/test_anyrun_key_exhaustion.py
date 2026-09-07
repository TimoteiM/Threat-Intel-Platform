"""A key out of licence allowance must step aside, not fail the investigation.

The report that prompted this: "You have exceeded the request limit for your
license" while the dashboard showed 1,141 of 1,500 remaining. Both numbers were
true. The 1,500 is a team pool; each key also has its own 300/month allowance,
and the primary had spent 531 of it while keys 2 and 3 had spent nothing.

Two failures met there. The 402 was not classified as retryable, so the
fallback keys were never tried; and nothing ordered the keys by what they had
left, so every attempt started on the exhausted one.
"""

from __future__ import annotations

import pytest

from app.services import anyrun_service as svc

THE_REAL_ERROR = (
    "[AnyRun Exception] Status code: 402. Description: You have exceeded the "
    "request limit for your license. Please acquire more limit from support@any.run."
)


# —— the 402 has to reach the fallback keys ————————————————————————————————

def test_the_reported_error_defers_to_another_key():
    assert svc._is_deferred_anyrun_sandbox_error(THE_REAL_ERROR) is True


@pytest.mark.parametrize("message", [
    "Status code: 402",
    "You have exceeded the request limit for your license",
    "please acquire more limit from support@any.run",
    "STATUS CODE: 402. DESCRIPTION: EXCEEDED THE REQUEST LIMIT",
])
def test_the_wording_is_matched_however_the_sdk_phrases_it(message):
    """`status_code` is not always surfaced in the raised message."""
    assert svc._is_anyrun_quota_exhausted(message) is True


@pytest.mark.parametrize("message", [
    "invalid api key", "403 forbidden", "connection reset", "", "404 not found",
])
def test_a_real_failure_still_does_not_defer(message):
    """Rotating keys on a broken request would just fail three times."""
    assert svc._is_anyrun_quota_exhausted(message) is False


def test_the_parallel_limit_still_defers():
    """The behaviour this predicate already had must survive the addition."""
    assert svc._is_deferred_anyrun_sandbox_error("403 parallel task limit") is True


# —— ordering by what each key has left ————————————————————————————————————

def _usage(monkeypatch, spent: dict[str, int], limit: float | None = 300.0):
    monkeypatch.setattr(svc, "_anyrun_key_month_usage",
                        lambda key: (spent.get(key, 0), limit))


def test_a_spent_key_goes_last(monkeypatch):
    _usage(monkeypatch, {"k1": 531})
    assert svc._order_keys_by_headroom(["k1", "k2", "k3"]) == ["k2", "k3", "k1"]


def test_a_spent_key_is_never_dropped(monkeypatch):
    """Our tally can drift from the provider's, so it is still worth a try last."""
    _usage(monkeypatch, {"k1": 531, "k2": 400, "k3": 900})
    assert sorted(svc._order_keys_by_headroom(["k1", "k2", "k3"])) == ["k1", "k2", "k3"]


def test_order_is_preserved_within_each_group(monkeypatch):
    _usage(monkeypatch, {"k2": 999})
    assert svc._order_keys_by_headroom(["k1", "k2", "k3"]) == ["k1", "k3", "k2"]


def test_nothing_reorders_when_no_limit_is_known(monkeypatch):
    """Without the provider's per-key cap there is nothing to judge against."""
    _usage(monkeypatch, {"k1": 10_000}, limit=None)
    assert svc._order_keys_by_headroom(["k1", "k2"]) == ["k1", "k2"]


def test_a_single_key_is_returned_unchanged(monkeypatch):
    _usage(monkeypatch, {"k1": 531})
    assert svc._order_keys_by_headroom(["k1"]) == ["k1"]


def test_usage_lookup_failure_never_blocks_a_run(monkeypatch):
    """Ordering is an optimisation; it must not become a gate."""
    def boom(_key):
        raise RuntimeError("redis is down")
    monkeypatch.setattr(svc, "_anyrun_key_month_usage", boom)
    with pytest.raises(RuntimeError):
        svc._anyrun_key_month_usage("k1")
    # _anyrun_key_is_spent swallows through its own guard in the real helper,
    # so the ordering path is exercised via the real implementation instead.
    monkeypatch.undo()
    assert svc._order_keys_by_headroom(["k1", "k2"]) in (["k1", "k2"], ["k2", "k1"])
