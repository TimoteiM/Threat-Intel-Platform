# The tolerated test failures

> **Resolved 2026-10-19. The set is 1, and that one is a live product defect
> rather than a tolerated failure.** See `tolerated-failures.txt` for the
> current list and the diagnosis of each. This page is kept because how the
> set was cleared is the useful part, and because the sentence further down
> that says *"12 of the 14 pass in isolation and fail only in the full
> suite"* had the answer in it for seven days and was labelled a hypothesis
> nobody had tested.
>
> * **14 → 13**: `test_dns.py::test_empty_evidence_on_failure` was a **live
>   defect**. The DNS collector reported `completed` for runs that produced
>   no evidence, so an outage was indistinguishable from "no DNS records".
>   The test had been right since it was written.
> * **13 → 1**: 12 shared one cause, in the tests rather than the product —
>   `monkeypatch.setattr("app.x.y", v)` with a dotted string target, which
>   pytest resolves by walking `getattr(app, "x")` and which therefore
>   depends on import order. Fixed by passing the module object. The rule is
>   rule 2 in `writing-tests.md`.
> * **The last one** fails in isolation too, and is a configured lexical
>   model that is never loaded because the flag that would load it is off,
>   with nothing recording that it was skipped. Backlog 41.
>
> **Every entry anybody actually asked about turned out to be either a
> one-line harness fault or a real defect. None was a test that deserved to
> fail.** The set was never a defect count; it was a question nobody had put.

`backend/tests/unit` had **14 failing tests** that predated the week of
2026-10-12. Every suite run that week was reported as "the same 14 as
baseline", compared against a list captured on 2026-10-12 — a real control,
because it proves no change added a failure, and a quiet hazard, because it
turned 14 into a constant of the project rather than a defect count.

**A tolerated failure set that nobody has enumerated only ever grows.** Each
new failure arrives inside a number already agreed to be acceptable, and the
diff that guards against regressions accepts the new total the moment someone
re-captures the baseline. So the list lives here now, in the repository,
rather than in a scratch file in a session directory.

## Reproducing the baseline

    cd backend && .venv/bin/python -m pytest tests/unit -q

Run from the **host venv**, never inside the container — the container cannot
import `app.*`. Expected (2026-10-19): `1 failed, 7 skipped, 3 xfailed` and a
passing count that rises as tests are added. It was `14 failed` until the
note at the top of this page.

## The 14

Captured 2026-10-12, before this week's changes. The second column is from
running each id on its own: **12 of the 14 pass in isolation and fail only in
the full suite**, which makes most of this set test pollution — shared state,
import order, a fixture leaking — rather than broken production code. That is
a hypothesis from the isolation result, not a diagnosis; none of these has
been investigated.

| test | in isolation | status |
|---|---|---|
| `tests/unit/test_collectors/test_brave_osint_collector.py::test_collector_keeps_observed_results_when_no_hits_match_security_filter` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_collectors/test_brave_osint_collector.py::test_collector_run_builds_brave_osint_evidence` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_collectors/test_dns.py::TestDNSCollector::test_empty_evidence_on_failure` | fails alone too | not diagnosed |
| `tests/unit/test_collectors/test_intel_collector_timeouts.py::test_check_urlhaus_uses_explicit_timeout` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_collectors/test_intel_collector_timeouts.py::test_query_crtsh_uses_explicit_timeout` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_collectors/test_intel_collector_timeouts.py::test_spamhaus_public_resolver_response_is_not_blocklist_hit` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_collectors/test_intel_collector_timeouts.py::test_spamhaus_reputation_response_is_blocklist_hit` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_collectors/test_intel_collector_timeouts.py::test_spamhaus_sia_domain_query_uses_bearer_token` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_collectors/test_intel_collector_timeouts.py::test_spamhaus_sia_refresh_token_uses_login_endpoint` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_collectors/test_urlscan_collector.py::test_accepted_scan_is_not_resubmitted_when_result_is_still_processing` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_services/test_url_lexical_ml_service.py::test_assess_url_lexical_risk_fallbacks_to_built_in_when_model_missing` | fails alone too | not diagnosed |
| `tests/unit/test_tasks/test_analysis_compact_evidence.py::test_run_analyst_with_compaction_does_not_retry_non_size_errors` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_tasks/test_analysis_compact_evidence.py::test_run_analyst_with_compaction_retries_prompt_too_long` | passes alone, fails in the suite | not diagnosed |
| `tests/unit/test_tasks/test_analysis_persistence.py::test_persist_results_updates_existing_evidence_row` | passes alone, fails in the suite | not diagnosed |

## Diffing against it

`tolerated-failures.txt` beside this file is the same list, one test id a
line, sorted — so the check is a diff rather than a count:

    cd backend && .venv/bin/python -m pytest tests/unit -q 2>&1 \
      | grep '^FAILED' | sed 's/FAILED //' | sort \
      | diff ../docs/testing/tolerated-failures.txt -

Empty output means no regression. Any line means something changed, in
either direction — a new failure *or* one of these starting to pass, which
is equally worth knowing and would otherwise be invisible.

## What to do with it

1. **Keep this list current.** If a run shows 15, the fifteenth is a
   regression and belongs in a fix, not in this table.
2. **Diagnose the 12 together, not separately.** They share a cause by
   hypothesis — one polluting test, not twelve — so the cheap first step is
   bisecting the suite order, rather than reading twelve tests.
3. **The 2 that fail alone are different** and are the only two that might be
   real defects in the code under test.
4. **Report the comparison, not the count.** "Identical to the baseline" is a
   claim about regressions. "14 failures" sounds like a tolerance.
