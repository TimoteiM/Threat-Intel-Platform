# Terminal statuses and verdicts: can each one say "did not run"?

Audited 2026-10-21. Six instances in six weeks of a skip reading as a result
is a property of the codebase, not a run of bad luck, so this enumerates
every writer of a terminal status or verdict and asks one question of each:
**can a consumer tell "did not run" from "ran and found nothing"?**

Where the answer is no, this file says so. It does **not** widen an enum to
make the answer yes — that is a change with consumers, and inventing a new
status value inside an audit is how the next conflation gets added.

## The scope of the search, so the completeness claim is checkable

A completeness claim is a search result. These are the searches:

```
grep -rn '\.status = |"status": |status="' app --include=*.py
    | grep -iE '"(completed|failed|done|finished|error|success|ok|skipped
                 |absent|unavailable|empty|partial|collected|withheld
                 |check_failed)"'
grep -rn 'overall_verdict|"verdict"|verdict =|classification=' app --include=*.py
grep -rn 'run.status\s*=|\.status = ' app --include=*.py
```

What they do **not** cover, stated rather than left implicit: statuses
written from the frontend, statuses in Alembic migrations, and any writer
that builds the key name dynamically. The first two are not consumer-facing
verdicts; the third would defeat any grep and is the residual risk in this
audit.

## The platform already has the vocabulary

`app/services/absence.py` defines the distinctions this audit is about:

| value | means |
|---|---|
| `CHECK_FAILED` | the check could not run at all |
| `NEVER_OBSERVED` | the check ran and has never once matched |
| `UNPARSED` | a value was present and failed its shape check |
| `UNCLASSIFIED` | nobody has made this judgement yet |
| `NO_FIELD_MAP` | this platform cannot read this source |
| `UNRATED` | the source states no value |

So this is not "adopt a convention". It is "apply the one that exists", and
the audit below is mostly a map of where it was and was not applied.

## A. Writers that already distinguish

| writer | states | how it distinguishes |
|---|---|---|
| `alert_log_context_service` / `_store` | `collected`, `empty`, `partial`, `unavailable`, `skipped` | `empty` is a real negative, `unavailable` is could-not-look, `skipped` is never-asked. Three different words for three different facts. This is the DNS-collector lesson already applied — it is the model the rest should follow |
| `context_gathering/projection.to_log_context` | same five | built on the above deliberately |
| `collectors/base.py` `CollectorStatus` | `COMPLETED`, `FAILED`, `SKIPPED` | failed ≠ skipped ≠ completed-with-nothing |
| `collectors/falcon_collector.py` | `absent(...)` values | uses the convention directly, per field |
| `alert_body_ai_service.run_alert_body_ai_analysis` | `completed` / `failed` **+ `withheld`** | `withheld=True` means nothing was sent. Added 2026-10-21 with b-2 precisely so "failed" would stop meaning two things |
| `api/detections.py` closure classification | includes `NOT_A_JUDGEMENT` | a closure that is not an analyst verdict is named as such rather than counted as one |
| `context_gathering` outcomes | `check_failed` with the **source named** | never "found nothing" for a source that could not be read |

## B. Cannot express it, and that is structural

**`AlertBodyInvestigationRun.status`** — writers: `alert_body_task.py:84`
(`processing`), `:155` (`completed`), `:168` (`failed`);
`api/alert_investigations.py:936` (`failed`), `:1837` (`queued`), `:2066`
(`cancelled`); `tasks/alert_recovery_task.py:116`, `:147`.

This column is about **the task**, not about the stages inside it. A run
whose AI step failed while its collectors succeeded is, as a task,
completed — and that is the honest answer for this column. Measured: all
17,640 rows are `completed`, and the 7 runs whose AI step failed are among
them.

**So the fix is not a new status value here.** Asking this column to carry
per-stage outcomes would make it mean two things, which is the defect being
audited. The per-stage records already hold the truth
(`result_json.ai_report.status`, `.withheld`, `alert_log_context.status`).
What is missing is that **nothing reads them together**: an analyst looking
at a run sees `completed` and has to open the JSON to learn a stage produced
nothing.

The additive change that does not widen anything: a derived, run-level
`stages_that_did_not_produce` list, computed from the stage records at read
time. See "What to do" below. Not built.

## C. Conflations — defects, both latent

### C1. `alert_body_task.py:157` defaults an absent verdict into a verdict

```python
overall_verdict=str(summary.get("overall_verdict") or "inconclusive"),
```

`or "inconclusive"` turns "the summary recorded no verdict" into a published
verdict. Same shape as a Pydantic `= []` making "found nothing" and "nobody
looked" the same bytes.

**Measured: it has never fired.** 0 rows have a row-level verdict where
`result_json` recorded none, and `overall_verdict` is non-NULL on all 17,640
rows. So this is a **latent trap**, not a realised defect — worth saying
precisely, because "an absence became a verdict 3,465 times" would have been
the wrong claim. The 3,465 `inconclusive` rows were computed, including the
one belonging to the 11M-char run, which this audit checked specifically.

Fix: drop the default, let the column be NULL, and have the API render that
as a distinct state. The column is already nullable.

### C2. `analyst/response_parser.py:258` encodes a parse failure as a verdict

```python
def _fallback_report(raw_response: str) -> AnalystReport:
    """When parsing fails, return a minimal report preserving raw text."""
    return AnalystReport(
        classification=Classification.INCONCLUSIVE,
```

`Classification.INCONCLUSIVE`'s own definition in `app/models/enums.py:26`
is **"Evidence insufficient to decide"** — a claim about the evidence. A
response that could not be parsed is a claim about *us*. The information
survives in `primary_reasoning` ("Analyst response could not be parsed into
structured format"), so a reader who opens the report can tell; a reader who
reads the classification cannot, and the classification is what aggregates,
ranks and filters.

This is the `Classification` enum having no value for "did not run", and it
is the one place in this audit where the honest answer requires a new enum
value. **Not added here.** It would change a published enum consumed by the
API, the frontend filters and `api/detections.py:185-187`'s risk weighting,
and that needs its own decision and before/after.

Whether it has ever fired is **not established**: the analyst reports are not
stored in a `result_json` column on `investigations`, so the query I tried
failed and I did not chase the right column. That is an open question, not a
zero.

## What to do, in the order the evidence supports

1. **C1 now**: remove `or "inconclusive"`. It is two characters of behaviour,
   it has never fired, so the before/after is provably empty, and leaving a
   trap armed because it has not sprung is how the other five happened.
2. **B, additive**: derive `stages_that_did_not_produce` at read time from
   the stage records and surface it on the run. No enum changes, no writes,
   and it makes the thing an analyst actually needs visible without opening
   JSON.
3. **C2, with its own decision**: `Classification` needs a value meaning
   "not determined by this pipeline", or `_fallback_report` needs to refuse
   to produce a report at all. Both change consumers. Settle whether it has
   ever fired first.

## The rule, for the next writer

Before writing a terminal status or a verdict, answer in the code: **what
does this value say when the thing never ran?** If the answer is "the same
as when it ran and found nothing", the value is wrong and
`app/services/absence.py` already has the word for it.
