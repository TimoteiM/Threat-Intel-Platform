# The silent registries, enumerated

Eight hand-maintained lists in this repo swallow a new feature with **no
error** — no exception, no log line — so the code imports cleanly, the feature
looks shipped, and it does nothing. Five of them each caused a separate "it's
not working" round trip during one integration.

This file exists because the eighth was found at **19.1% of account nodes**
while nobody was looking for it. An unenumerated set only grows, the same way
the tolerated test failures did before
[`docs/testing/tolerated-failures.txt`](../testing/tolerated-failures.txt)
pinned them to names. The discipline below therefore applies wherever a
registry exists, not only where one has already bitten.

## The rule

**Derive the list from what it is a list of, or guard it with a test that
fails when it is incomplete.** A hand-kept registry is acceptable only where
omission fails *loudly* — `APP_NAV_SECTIONS` stays hand-kept because a missing
nav entry is immediately visible, and not every hand-kept list is worth the
machinery.

Two things are needed when a derivation is impossible: a test that enumerates
the expected set from somewhere independent, and a line in this table.

## The eight

| # | Registry | Where | Symptom if missed | Status |
|---|---|---|---|---|
| 1 | `autodiscover_tasks([...])` | `app/tasks/celery_app.py` | API queues it, worker logs `Received unregistered task`, row sits in its initial state for ever | **guarded by a test** |
| 2 | `sectionDefs` | `frontend/.../report/TechnicalEvidenceTab.tsx` | `<Section>` returns `null` unless its title is listed *and* selected — the panel can never be shown | hand-kept |
| 3 | `DEFAULT_COLLECTORS` | **`.env`**, which overrides `app/config.py` | Collector supported for the type but never selected, so it never runs. Editing `config.py` alone does nothing | hand-kept |
| 4 | `COLLECTORS_PER_TYPE` / `DEFAULT_COLLECTORS_PER_TYPE` | `frontend/.../investigation/InvestigationInput.tsx` | Not offered in the picker. `OPT_IN_COLLECTORS` additionally holds a collector back from alert bodies | hand-kept |
| 5 | `CollectedEvidence` field | `app/models/schemas.py` | Collector output never reaches the analyst prompt. Evidence models must be defined *above* `CollectedEvidence` | hand-kept |
| 6 | Ingest allowlist — **two gates** | `INGEST_CIDRS` (compose/firewall) **and** `INGEST_TRUSTED_CIDRS` (`.env`) | Missing from the firewall: packet dropped, connect timeout, nothing in the app log. Missing from auth: 401 | hand-kept |
| 7 | `_for_prompt` projection | `app/services/alert_log_selection.py` | The AI sees a fixed key list, so an unnamed log field is dropped however prominently the UI shows it. Three of the log table's own **default** columns had never been in it | hand-kept |
| 8 | `_ALIASES` | `app/services/alert_graph_extraction_service.py` | Maps `"User"` and no other identity label, so `Account Name`, `SAM Account Name`, `Display Name`, `User Principal Name` and `Security ID` are never read by the attack graph however well they parse. **4,805 account nodes (19.1%)** sit on a body carrying one | hand-kept — see [backlog 11](../BACKLOG.md) |

## Where derivation has already replaced a hand-kept list

- **The answer-rate source set** is now derived from `COLLECTOR_REGISTRY`
  rather than listed. `otx` had been missing from the check built to find dead
  sources *while being 70% dead* — the check could not report the gap it
  existed for.
- **The integration catalogue** (`integration_status_service.catalogue()`) is
  derived from the collectors that declare `integration = True`, and a test
  tokenises the API source to assert no tool name is hard-coded in a branch.

Both replaced a list that had already failed. The point of this file is to
stop waiting for that.

## The sibling failure: accepted, stored, then ignored

A value can be accepted by the API, written to the row, and dropped at the
next hop. Analyst-pinned events were stored on the run and never reached the
prompt. Anything riding on a re-analysis request has to be walked end to end:
API → `alert_body_task` payload → `alert_body_investigation_service` →
`alert_log_prompt`.

## Before reporting a feature done

Trace the path in the running system: queue a real task, select the section in
the UI, confirm the collector appears in `collector_results`. For the firewall
specifically, `grep TIP8000DROP /var/log/kern.log` distinguishes "blocked"
from "application broken" — a dropped packet leaves no other trace.
