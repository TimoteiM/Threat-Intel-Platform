"""The paging helper, which exists because README rule 21 was not holdable as a rule.

Three instances in two days, the third inside the fix for the second:

* `limit: 20` on a hash with 29 alerts — both confirmed records outside the
  page, so `any(resolution == 'true_positive')` evaluated **False** on a hash
  an analyst had twice confirmed;
* `limit: 5` on a sampled field value, concluding a working field was ignored
  because the sampled row was sixth of six;
* the same method, in the same run, condemning `sha256` — `total: 771`.

A rule that is broken by the fix for its own first instance is not going to be
held by documentation, so the enforcement is the return type: `Page` carries
`total` and `complete`, and a caller that wants a list has to go through a
field that says whether it is the population.

**Every test here is written in the dangerous direction.** The failure mode is
never an error — it is a short list that looks like an answer.
"""

from __future__ import annotations

import pytest

from app.integrations import falcon_client as fc

BASE = "https://api.eu-1.crowdstrike.example"
HEADERS = {"Authorization": "Bearer x"}


class _Resp:
    def __init__(self, code, payload):
        self.status_code = code
        self._payload = payload

    def json(self):
        return self._payload


class _Falcon:
    """Enough of the Alerts API to reproduce the two shapes that bit.

    `population` is the full ordered id list; `records` maps id -> entity. The
    query endpoint honours `limit`/`offset` and always reports the true total,
    which is what the real API does and what nobody read.
    """

    def __init__(self, population, records=None, *, report_total=True,
                 hydrate_fails=()):
        self.population = list(population)
        self.records = dict(records or {})
        self.report_total = report_total
        self.hydrate_fails = set(hydrate_fails)
        self.gets = []
        self.posts = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.gets.append(dict(params or {}))
        limit = int((params or {}).get("limit") or 100)
        offset = int((params or {}).get("offset") or 0)
        rows = self.population[offset:offset + limit]
        meta = {"pagination": {"offset": offset, "limit": limit}}
        if self.report_total:
            meta["pagination"]["total"] = len(self.population)
        return _Resp(200, {"resources": rows, "meta": meta})

    def post(self, url, headers=None, json=None, timeout=None):
        ids = list((json or {}).get("composite_ids") or [])
        self.posts.append(ids)
        out = [self.records[i] for i in ids
               if i in self.records and i not in self.hydrate_fails]
        return _Resp(200, {"resources": out})


def _population(n, **per_record):
    ids = [f"id-{i:04d}" for i in range(n)]
    records = {i: {"composite_id": i, **per_record} for i in ids}
    return ids, records


def test_paging_to_the_end_reports_complete():
    ids, recs = _population(450)
    http = _Falcon(ids, recs)
    page = fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                           headers=HEADERS, http=http)
    assert page.fetched == 450
    assert page.total == 450
    assert page.complete is True
    assert page.reason is None


def test_a_bounded_read_is_not_complete_and_says_how_short_it_is():
    """THE defect. 29 in the population, 20 asked for, and the answer must not
    look like an answer."""
    ids, recs = _population(29)
    http = _Falcon(ids, recs)
    page = fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                           headers=HEADERS, http=http, want=20)
    assert page.fetched == 20
    assert page.total == 29
    assert page.complete is False, (
        "a 20-of-29 read reported itself as the population, which is how a "
        "hash with two confirmed detections came back with none"
    )
    assert "20 of 29" in page.reason
    assert "may be in the 9 not read" in page.reason


def test_the_confirmed_record_outside_the_page_is_why_complete_exists():
    """The original failure, reproduced end to end: the only interesting
    record is last, the caller asks for a page, and `complete` is the single
    thing standing between that and a false negative."""
    ids, recs = _population(29, resolution="false_positive")
    recs[ids[-1]]["resolution"] = "true_positive"
    http = _Falcon(ids, recs)

    short = fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                            headers=HEADERS, http=http, want=20)
    found_in_page = any(r.get("resolution") == "true_positive" for r in short.rows)
    assert found_in_page is False
    # The predicate is False and the page knows it cannot say so.
    assert short.complete is False

    whole = fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                            headers=HEADERS, http=http, want="all")
    assert whole.complete is True
    assert any(r.get("resolution") == "true_positive" for r in whole.rows)


def test_no_total_means_not_complete_even_after_paging_to_an_empty_page():
    """Covering everything the API chose to hand over is not covering the
    population. When nobody said how many there were, we do not know."""
    ids, recs = _population(37)
    http = _Falcon(ids, recs, report_total=False)
    page = fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                           headers=HEADERS, http=http, want="all")
    assert page.fetched == 37
    assert page.total is None
    assert page.complete is False
    assert "did not report a total" in page.reason


def test_every_query_carries_a_sort():
    ids, recs = _population(10)
    http = _Falcon(ids, recs)
    fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE, headers=HEADERS,
                    http=http, want="all")
    assert http.gets, "no query was made"
    assert all(g.get("sort") for g in http.gets), (
        "a page was requested in an unspecified order, so the same read twice "
        "can return different rows"
    )


def test_the_sort_has_no_default_at_the_generic_helper():
    """`sort` is required, because the one read where order IS the measurement
    — the oldest alert, for the retention floor — would silently become
    'some alert' under a default."""
    with pytest.raises(TypeError):
        fc.paged("/alerts/queries/alerts/v2", {}, base_url=BASE,
                 headers=HEADERS, http=_Falcon([]))  # type: ignore[call-arg]


def test_hydration_returns_records_not_ids():
    """Backlog 31: the queries endpoint returns composite ids, and every field
    a predicate needs lives on the entity."""
    ids, recs = _population(5, status="new", resolution=None)
    http = _Falcon(ids, recs)
    page = fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                           headers=HEADERS, http=http)
    assert page.fetched == 5
    assert all(isinstance(r, dict) for r in page.rows)
    assert all("status" in r for r in page.rows), (
        "the rows are ids rather than records, which is the shape that made "
        "every predicate over this output unimplementable"
    )


def test_a_partial_hydration_is_incomplete_rather_than_a_shorter_list():
    """Ids that do not come back as records are a hole, not an answer."""
    ids, recs = _population(10)
    http = _Falcon(ids, recs, hydrate_fails={ids[3], ids[7]})
    page = fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                           headers=HEADERS, http=http, want="all")
    assert page.fetched == 8
    assert page.complete is False
    assert "did not come back as records" in page.reason


def test_the_page_cap_is_reported_rather_than_silently_applied():
    ids, recs = _population(fc.PAGE_SIZE * (fc.MAX_PAGES + 3))
    http = _Falcon(ids, recs)
    page = fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                           headers=HEADERS, http=http, want="all")
    assert page.complete is False
    assert "stopped after" in page.reason
    assert page.fetched == fc.PAGE_SIZE * fc.MAX_PAGES


def test_an_empty_filter_is_omitted_rather_than_sent_empty():
    """The retention floor asks the unfiltered population, and `filter=` is a
    different request from no filter."""
    ids, recs = _population(3)
    http = _Falcon(ids, recs)
    fc.paged_alerts(filter_expr="", base_url=BASE, headers=HEADERS,
                    http=http, want=1, sort="created_timestamp|asc")
    assert "filter" not in http.gets[0]
    assert http.gets[0]["sort"] == "created_timestamp|asc"


def test_a_refusal_is_raised_rather_than_returned_as_an_empty_page():
    """401/403 must never arrive as "no rows" — that is a missing scope
    reading as a clean estate."""
    class _Refusing(_Falcon):
        def get(self, url, headers=None, params=None, timeout=None):
            return _Resp(403, {})

    with pytest.raises(fc.FalconAuthError):
        fc.paged_alerts(filter_expr="sha256:'x'", base_url=BASE,
                        headers=HEADERS, http=_Refusing([]))


def test_want_n_means_n_records_not_one_page():
    """A regression introduced BY this helper and caught by comparing against
    a measurement taken before it: `want=500` clamped the per-request limit to
    the page size and then stopped, cutting the host panel from 500
    detections to 200. A coverage reduction inside the fix for a coverage bug.
    """
    ids, recs = _population(1432)
    http = _Falcon(ids, recs)
    page = fc.paged_alerts(filter_expr="device.hostname:'h'", base_url=BASE,
                           headers=HEADERS, http=http, want=500)
    assert page.fetched == 500, "want=N returned one page instead of N records"
    assert page.total == 1432
    assert page.complete is False
    assert len(http.gets) == 3, "500 records should take ceil(500/200) queries"
    assert [g["limit"] for g in http.gets] == [200, 200, 100], (
        "the last request must ask for the remainder, not a full page"
    )


def test_want_n_larger_than_the_population_is_complete():
    ids, recs = _population(7)
    http = _Falcon(ids, recs)
    page = fc.paged_alerts(filter_expr="x:'y'", base_url=BASE,
                           headers=HEADERS, http=http, want=500)
    assert page.fetched == 7
    assert page.complete is True
    assert page.reason is None
