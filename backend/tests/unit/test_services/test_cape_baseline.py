"""The sandbox's own traffic, told apart from the sample's."""

import asyncio
from types import SimpleNamespace

import pytest

from app.services import cape_baseline_service as bl


def _analysis(*domains):
    return {"network": {"domains": list(domains), "dns_queries": list(domains)}}


class _Scalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _Result:
    def __init__(self, rows, count):
        self._rows = rows
        self._count = count

    def scalar(self):
        return self._count

    def scalars(self):
        return _Scalars(self._rows)


class _DB:
    """Answers the count first, then the rows — the order the service asks."""

    def __init__(self, rows):
        self.rows = rows
        self.calls = 0

    async def execute(self, _stmt):
        self.calls += 1
        return _Result(self.rows, len(self.rows))


@pytest.fixture(autouse=True)
def _clear_cache():
    bl._CACHE.update({"generation": None, "prevalence": {}, "analyses": 0})
    yield
    bl._CACHE.update({"generation": None, "prevalence": {}, "analyses": 0})


def test_the_vm_telemetry_is_background_and_the_target_is_not():
    """The measured split on real data: seven domains in 100% of detonations,
    and the one an analyst opened the page for in exactly one."""
    rows = [_analysis("cdn.onenote.net", "outlook.office.com", f"target{i}.example")
            for i in range(10)]
    db = _DB(rows)

    share = asyncio.run(bl.prevalence(db))

    assert share["cdn.onenote.net"] == 1.0
    assert share["outlook.office.com"] == 1.0
    assert share["target0.example"] == pytest.approx(0.1)


def test_one_detonation_does_not_make_its_own_target_background():
    """Prevalence over three analyses is not prevalence.

    Without the floor, a first detonation would report 100% for the very domain
    it was asked to investigate and file it as noise.
    """
    db = _DB([_analysis("evil.example")] * 3)

    share = asyncio.run(bl.prevalence(db))

    assert share == {}, "too little history to measure"

    out = asyncio.run(bl.annotate(db, _analysis("evil.example", "cdn.onenote.net")))
    rows = {r["value"]: r for r in out["network"]["annotated"]["domains"]}
    # Falls back to the seed: the Office telemetry is known background, the
    # target is not.
    assert rows["cdn.onenote.net"]["baseline"] is True
    assert rows["evil.example"]["baseline"] is False


def test_nothing_is_hidden():
    """The guarantee that makes labelling safe instead of dangerous.

    A sample really can talk to login.microsoftonline.com. Dropping it from the
    report would be a worse bug than the one this fixes.
    """
    rows = [_analysis("cdn.onenote.net", "login.microsoftonline.com") for _ in range(10)]
    db = _DB(rows)

    original = _analysis("cdn.onenote.net", "login.microsoftonline.com", "evil.example")
    out = asyncio.run(bl.annotate(db, original))

    annotated = {r["value"] for r in out["network"]["annotated"]["domains"]}
    assert annotated == {"cdn.onenote.net", "login.microsoftonline.com", "evil.example"}


def test_the_stored_lists_are_left_alone():
    """The collector looks these up by JSONB containment, and the evidence it
    builds reads the same keys. Annotation is additive or it is a breakage."""
    db = _DB([_analysis("cdn.onenote.net") for _ in range(10)])

    out = asyncio.run(bl.annotate(db, _analysis("cdn.onenote.net", "evil.example")))

    assert out["network"]["domains"] == ["cdn.onenote.net", "evil.example"]
    assert out["network"]["dns_queries"] == ["cdn.onenote.net", "evil.example"]


def test_an_analysis_with_no_network_does_not_count_as_evidence_of_anything():
    """Seven of the 26 stored analyses have no network at all. Counting them
    would halve every domain's measured prevalence and silently disable the
    split."""
    rows = [_analysis("cdn.onenote.net") for _ in range(10)] + [{"network": {}}] * 20
    db = _DB(rows)

    share = asyncio.run(bl.prevalence(db))

    assert share["cdn.onenote.net"] == 1.0
    assert bl._CACHE["analyses"] == 10


def test_a_failure_to_measure_returns_the_result_unchanged():
    """A label is never worth a 500 on the report it is labelling."""

    class _Broken:
        async def execute(self, _stmt):
            raise RuntimeError("database is away")

    original = _analysis("evil.example")
    out = asyncio.run(bl.annotate(_Broken(), original))

    assert out == original
