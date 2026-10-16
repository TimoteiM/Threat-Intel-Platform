"""The standing control on Falcon's alert field names.

The Alerts API returns HTTP 200 with zero resources for a field name that does
not exist. That is a permanent property of the provider, not a bug awaiting a
fix, so a one-off probe is not enough — every `never_observed` this platform
reports from Falcon alerts depends on the control having passed.

Measured 2026-10-15 against tenant c00: the same hash returns 17 rows as
`sha256` and 0 as `behaviors.sha256`. The map shipped on 2026-10-14 used the
latter for every indicator kind.

Every test is written in the dangerous direction: the failure mode is a clean
negative, not an error.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.integrations import falcon_client as fc

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
BASE = "https://api.eu-1.crowdstrike.example"
HEADERS = {"Authorization": "Bearer x"}


class _Resp:
    def __init__(self, code, payload):
        self.status_code = code
        self._payload = payload

    def json(self):
        return self._payload


def _page(ids):
    return {"resources": list(ids),
            "meta": {"pagination": {"total": len(ids)}}}


class _Http:
    """A Falcon that behaves the way the real one was measured to behave.

    **This fake honoured the field NAME and ignored the VALUE until
    2026-10-16**, which meant it returned rows for a value that cannot exist —
    so it modelled an API that ignores its own filters, and the control's
    nonsense probe failed against it. The real API returns `total: 0` for a
    value no record holds. A fake that is more permissive than the provider
    certifies behaviour the provider does not have, which is the same error as
    the control it was testing.

    `records` is the population; a filter matches a record when the record's
    value at that field equals the filtered value.
    """

    def __init__(self, *, record, filterable, unfiltered=("id-1",),
                 records=None, ignores_filters=False):
        self.record = record
        self.records = list(records) if records is not None else [record]
        self.filterable = set(filterable)
        self.unfiltered = list(unfiltered)
        self.filters = []
        # For the dangerous-direction test: an API that accepts a filter and
        # applies nothing, which axis 2 exists to catch.
        self.ignores_filters = ignores_filters

    def get(self, url, headers=None, params=None, timeout=None):
        f = (params or {}).get("filter")
        if not f:
            return _Resp(200, _page(self.unfiltered))
        self.filters.append(f)
        field, _, raw = f.partition(":")
        wanted = raw.strip().strip("'")
        # The measured behaviour: an unknown field is a 200 with no rows, NOT
        # an error. This is the whole hazard.
        if field not in self.filterable:
            return _Resp(200, _page([]))
        if self.ignores_filters:
            return _Resp(200, _page([f"id-{i}" for i in range(len(self.records))]))
        hits = [f"id-{i}" for i, r in enumerate(self.records)
                if str(fc._dotted(r, field)) == wanted]
        return _Resp(200, _page(hits))

    def post(self, url, headers=None, json=None, timeout=None):
        return _Resp(200, {"resources": list(self.records)})


@pytest.fixture(autouse=True)
def _clear_cache():
    fc._FIELD_CONTROL_CACHE.clear()
    yield
    fc._FIELD_CONTROL_CACHE.clear()


# --- the corrected map -----------------------------------------------------


def test_the_broken_behaviors_prefix_is_gone_from_every_mapping():
    """`behaviors` does not exist on an alert record — 0 of 200 carried one.

    Asserted on the module's own constants rather than recalled, because this
    is the shape that returned "the EDR has nothing" for every hash.
    """
    source = fc.ALERT_HASH_FIELDS
    # The durable claim is the one in this test's name: no mapping carries the
    # `behaviors.` prefix. The exact SET of mapped fields is a decision that
    # has since changed on a measurement — `sha1` was removed 2026-10-16
    # because its only value in this tenant is forty zeros — so pinning the
    # set here would have made this test an authority on a field's contents.
    assert not any("behaviors" in v for v in source.values())
    assert not any("behaviors" in str(v) for v in fc.ALERT_UNMAPPABLE_KINDS.values())
    assert not any("behaviors" in str(v)
                   for v in fc.ALERT_SENTINEL_HASH_FIELDS.values())
    # And every mapped field is a bare alert field, not a dotted path into a
    # structure the record does not have.
    assert all("." not in v for v in source.values())


def test_hash_dispatch_is_by_digest_length():
    """One field name cannot serve all three digests.

    Filtering a 32-character MD5 against `sha256` is the same silent zero one
    level down — a valid field, a valid value, and no possible match.

    SHA-1 now routes to NOTHING, and that is a measurement rather than an
    omission: `sha1` is present on 1,953 of this tenant's 2,047 alerts and
    carries exactly one distinct value, forty zeros. See
    `test_a_sha1_does_not_route_to_a_falcon_field` in test_falcon_paging.py.
    """
    assert fc.alert_filter_field("hash", "a" * 64) == "sha256"
    assert fc.alert_filter_field("hash", "a" * 32) == "md5"
    assert fc.alert_filter_field("hash", "a" * 16) is None
    assert fc.alert_filter_field("hash", "a" * 40) is None
    # ...and the refusal carries its reason, so the absence is not a silence.
    assert fc.alert_hash_sentinel_reason("a" * 40)


@pytest.mark.parametrize("kind", ["domain", "url", "ip"])
def test_the_unaskable_kinds_return_no_field_rather_than_a_guess(kind):
    """Measured: every domain-shaped filter returned 200/0, and `source_ips`
    holds internal addresses a remote IP can never match. None means no field
    exists — not "unimplemented"."""
    assert fc.alert_filter_field(kind, "example.com") is None
    assert kind in fc.ALERT_UNMAPPABLE_KINDS
    assert len(fc.ALERT_UNMAPPABLE_KINDS[kind]) > 30


def test_data_domains_is_not_offered_as_a_domain_field():
    """The plausible name that answers a different question.

    `data_domains` is populated on 193 of 200 alerts and holds `['Endpoint']`
    — a data classification. Exactly the `queryName` defect: a field name that
    reads like the question being asked.
    """
    assert "data_domains" not in fc.ALERT_HASH_FIELDS.values()
    assert "data_domains" in fc.ALERT_UNMAPPABLE_KINDS["domain"]


# --- the control -----------------------------------------------------------


def test_the_control_passes_when_a_read_back_value_filters():
    http = _Http(record={"sha256": "abc123"}, filterable={"sha256"})
    out = fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS,
                                  http=http, now=NOW)
    assert out["passed"] is True
    assert any("abc123" in f for f in http.filters)


def test_the_control_fails_on_a_field_the_api_silently_ignores():
    """The shipped bug, as a test.

    The record carries a value at `behaviors.sha256`? No — it cannot. So the
    control fails for the right reason even before the filter is tried.
    """
    http = _Http(record={"sha256": "abc123"}, filterable={"sha256"})
    out = fc.alerts_field_control("behaviors.sha256", base_url=BASE,
                                  headers=HEADERS, http=http, now=NOW)
    assert out["passed"] is False
    assert "nothing to filter for" in out["reason"]


def test_a_value_that_exists_but_does_not_filter_fails_the_control():
    """The exact signature of a renamed field: the API hands us a value at
    that path and then ignores it in a filter."""
    http = _Http(record={"ghost_field": "abc123"}, filterable=set())
    out = fc.alerts_field_control("ghost_field", base_url=BASE,
                                  headers=HEADERS, http=http, now=NOW)
    assert out["passed"] is False
    assert "ignoring this field name" in out["reason"]
    assert "every negative from it would be false" in out["reason"]


def test_a_dotted_path_is_read_out_of_the_nested_record():
    http = _Http(record={"device": {"hostname": "EXP-22MY264"}},
                 filterable={"device.hostname"})
    out = fc.alerts_field_control("device.hostname", base_url=BASE,
                                  headers=HEADERS, http=http, now=NOW)
    assert out["passed"] is True
    assert any("EXP-22MY264" in f for f in http.filters)


def test_an_estate_with_no_alerts_is_not_a_pass():
    """A control that cannot run has not run.

    This is the tempting one to treat as success — nothing is broken, there is
    simply nothing to sample. But then the first tenant with a quiet estate
    gets unverified negatives, which is the condition the control exists for.
    """
    http = _Http(record={}, filterable={"sha256"}, unfiltered=())
    out = fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS,
                                  http=http, now=NOW)
    assert out["passed"] is False
    assert out["absence"] == "too_little_history"


def test_the_control_never_raises_and_never_fails_open():
    class _Broken:
        def get(self, *a, **k):
            raise ConnectionError("boom")

        def post(self, *a, **k):
            raise ConnectionError("boom")

    out = fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS,
                                  http=_Broken(), now=NOW)
    assert out["passed"] is False
    assert "did not complete" in out["reason"]


def test_a_pass_is_cached_and_a_failure_is_not():
    """A failure must be retried: the usual cause is a provider-side change
    that may be transient, and caching it turns one bad minute into an hour
    of refusals."""
    ok = _Http(record={"sha256": "abc"}, filterable={"sha256"})
    fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS, http=ok, now=NOW)
    assert "sha256" in fc._FIELD_CONTROL_CACHE

    bad = _Http(record={"x": "abc"}, filterable=set())
    fc.alerts_field_control("x", base_url=BASE, headers=HEADERS, http=bad, now=NOW)
    assert "x" not in fc._FIELD_CONTROL_CACHE


def test_a_cached_pass_expires():
    """Standing, not one-off. A field can be renamed by the provider at any
    release, and the control is the only thing that would notice."""
    http = _Http(record={"sha256": "abc"}, filterable={"sha256"})
    fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS, http=http, now=NOW)
    calls = len(http.filters)

    later = NOW + timedelta(seconds=fc.FIELD_CONTROL_TTL_SECONDS + 1)
    fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS, http=http, now=later)
    assert len(http.filters) > calls, "an expired control was served from cache"


def test_the_cache_is_per_field():
    http = _Http(record={"sha256": "a", "md5": "b"}, filterable={"sha256", "md5"})
    fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS, http=http, now=NOW)
    fc.alerts_field_control("md5", base_url=BASE, headers=HEADERS, http=http, now=NOW)
    assert sorted(fc._FIELD_CONTROL_CACHE) == ["md5", "sha256"]


# --- axes 2 and 4: the two the control did not have until 2026-10-16 -------


def _population(n, field, value, *, vary=False):
    """n records carrying `field`, constant unless `vary`."""
    return [{"composite_id": f"c{i}",
             field: (f"{value}{i}" if vary else value)} for i in range(n)]


def test_a_constant_valued_field_is_refused_however_well_it_filters():
    """THE sha1 case. Forty zeros on 1,953 of 1,953 records: the control
    samples the zeros, filters on them, gets every row back, and certifies a
    field that can never match a real digest. It verified a round trip, not a
    capability.
    """
    recs = _population(25, "sha1", "0" * 40)
    http = _Http(record=recs[0], filterable={"sha1"}, records=recs)
    out = fc.alerts_field_control("sha1", base_url=BASE, headers=HEADERS,
                                  http=http, now=NOW)
    assert out["passed"] is False, (
        "a field whose only value is a sentinel passed the control, which is "
        "how every SHA-1 lookup returned a false negative"
    )
    assert out["distinct_sampled"] == 1
    assert "ONE distinct value" in out["reason"]
    assert out["absence"] == "unrecognised_absence"


def test_a_varied_field_still_passes():
    """The control on the test above: variance must distinguish two states,
    not refuse every field."""
    recs = _population(25, "sha256", "abc", vary=True)
    http = _Http(record=recs[0], filterable={"sha256"}, records=recs)
    out = fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS,
                                  http=http, now=NOW)
    assert out["passed"] is True
    assert out["distinct_sampled"] == 25
    assert out["axes"]["has_variance"] is True


def test_one_distinct_value_in_a_SMALL_sample_is_not_a_constant_field():
    """A small sample agreeing is a small sample, not a sentinel. Refusing
    here would fail a correct field on a quiet estate."""
    recs = _population(3, "sha256", "abc")
    http = _Http(record=recs[0], filterable={"sha256"}, records=recs)
    out = fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS,
                                  http=http, now=NOW)
    assert out["passed"] is True
    assert out["axes"]["has_variance"] is False, (
        "it passed, and it must still report that variance was not established"
    )


def test_a_field_that_is_accepted_and_ignored_is_refused_by_the_nonsense_probe():
    """Axis 2, and the failure it catches is the dangerous one: rows come back
    for anything, so every answer looks like a hit and none of them is about
    the question asked."""
    # A flat field name: `_dotted` WALKS a dotted path, so a literal
    # "device.hostname" key is not what it reads — a fixture detail that made
    # this test fail for the wrong reason on first run.
    recs = _population(25, "filename", "run", vary=True)
    http = _Http(record=recs[0], filterable={"filename"}, records=recs,
                 ignores_filters=True)
    out = fc.alerts_field_control("filename", base_url=BASE,
                                  headers=HEADERS, http=http, now=NOW)
    assert out["passed"] is False
    assert out["nonsense_total"] == 25
    assert "cannot exist returned" in out["reason"]
    assert "looks like a hit" in out["reason"]


def test_the_nonsense_probe_is_actually_sent():
    recs = _population(25, "sha256", "abc", vary=True)
    http = _Http(record=recs[0], filterable={"sha256"}, records=recs)
    fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS,
                            http=http, now=NOW)
    assert any(fc._NONSENSE_VALUE in f for f in http.filters), (
        "axis 2 was not exercised, so a field accepted-and-ignored would pass"
    )


def test_a_pass_without_an_external_reference_says_so():
    """Axis 4b rests on provenance, and the control must not imply it checked
    a namespace it had no outside value for."""
    recs = _population(25, "sha256", "abc", vary=True)
    http = _Http(record=recs[0], filterable={"sha256"}, records=recs)
    out = fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS,
                                  http=http, now=NOW)
    assert out["axes"]["external_reference_checked"] is False
    assert "No external reference value was supplied" in out["reason"]


def test_an_external_reference_is_sent_when_supplied():
    recs = _population(25, "sha256", "abc", vary=True)
    http = _Http(record=recs[0], filterable={"sha256"}, records=recs)
    out = fc.alerts_field_control("sha256", base_url=BASE, headers=HEADERS,
                                  http=http, now=NOW, reference="d" * 64)
    assert out["passed"] is True
    assert any("d" * 64 in f for f in http.filters)
    assert out["axes"]["external_reference_checked"] is True
