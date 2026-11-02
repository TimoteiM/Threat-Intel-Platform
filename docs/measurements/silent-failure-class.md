# The silent-failure class: AI steps that failed, against what the run said

> **Population: Expertware's own estate.** Confirmed 2026-10-21 by asking
> CrowdStrike directly: one CID (`eed7e41845d04c26b4198f4c85f6216e`) across
> **176 of 176** devices, every `machine_domain` an `expertware.net` domain
> (`int` 141, `ext` 24, `dev` 10, one blank), every OU path ending in
> `ExpertWare`. **`c00` is not a customer.** The figures below are correctly
> measured; the label was wrong. See
> [POPULATION.md](POPULATION.md) and backlog 45.

Measured 2026-10-21 over all 17,640 alert-body runs. The one item here about
the past rather than the future.

## Answer first

| | |
|---|---|
| runs where the AI step **failed** | **7** (0.04%) |
| runs with **no `ai_report` key at all** | 2 |
| runs with `ai_report: null` — **AI not requested** | 26 |
| runs `completed` with an AI report but **no narrative** | **0** |
| runs that **timed out** | **0** |
| period | **2026-08-05 to 2026-08-31**, and none in the 51 days since |
| **runs that published a verdict with nothing examined** | **0** |
| runs that reached an analyst as `inconclusive` after a failed AI step | **1** (verdict computed, not defaulted — see below) |

**`run.status` is `completed` on all 17,640 rows.** There is no other value
in that column, ever. So none of the above is visible from the run status —
it is visible only inside `result_json->'ai_report'`. That is the systemic
point, and it is item 2.

## What the seven were

| date | verdict | indicators examined | body | cause |
|---|---|---|---|---|
| 2026-08-05 | benign | 3 | 2,021 | `RuntimeError` on an asyncio task |
| 2026-08-24 | malicious | 21 | 14,194 | `error: bad escape \d at position 6` |
| 2026-08-24 | malicious | 15 | 3,924 | `error: bad escape \m at position 6` |
| 2026-08-24 | suspicious | 9 | 1,643 | `error: bad escape \m at position 6` |
| 2026-08-25 | suspicious | 9 | 5,296 | `error: bad escape \i at position 6` |
| 2026-08-25 | malicious | 14 | 13,330 | `error: bad escape \d at position 6` |
| 2026-08-31 | **inconclusive** | 2 | 10,999,999 | `BadRequestError: prompt is too long: 5,284,191 tokens > 200,000` |

**Every one still had indicator reports** — 2 to 21 of them — so in no case
was a verdict published with nothing examined. What was lost in each case is
the **AI narrative**, which for an analyst is the reading of the alert rather
than the collector results.

## Client impact, stated plainly

* **7 alerts over 27 days reached an analyst without a model narrative**, out
  of 17,640. Four were called `malicious` and two `suspicious` — so the
  deterministic side still flagged them, and an analyst looking at those runs
  saw collector findings with no assistant report where one is normally
  present.
* **1 alert reached an analyst as `inconclusive`** having had 1,792 seconds
  of worker time spent on it and no narrative produced: the 10,999,999-char
  body of 2026-08-31.

  **Checked, and the verdict itself was honest.** `result_json.summary`
  records `overall_verdict='inconclusive'`, so it was *computed* by
  `summarize_indicator_reports` from the 2 indicator reports — not defaulted.
  An earlier draft of this file implied the word was manufactured; it was
  not. What the analyst did not get was the narrative, and what the record
  did not say was that a narrative had been attempted and lost. The verdict
  field was right and the absence was silent.
* **26 runs recorded `ai_report: null`**, which the code produces when
  `run_ai` is false. Those are not failures. But the stored record cannot
  distinguish them from "AI was requested and never ran", which is the same
  defect class one level up — see item 2.

## Causes, and whether they can recur

**Five of seven were one bug, and it is fixed.** `assistant_service.py:483`
now carries both the fix and its post-mortem: `re.sub` treats a **string**
replacement as a *template* and parses backslash escapes in it, so restoring
a token whose real value contained `\d`, `\m` or `\i` raised `bad escape` and
lost the whole narrative. The replacement is now a callable
(`lambda _match, value=original: value`), which is not parsed. A
content-triggered crash on the analysis path, closed.

**One is the realised instance of backlog 43** — the 1,792s spent sanitising
a body the provider then rejected unread. Open.

**One `RuntimeError` on an asyncio task**, 2026-08-05, single occurrence,
nothing since; not investigated further on this evidence.

**No timeouts at all.** Worth stating because the 1,792s run looks like one
and is not: it ran to a provider rejection, inside the 1,800s limit.

## What this does not cover

* The **manual assistant path** has no run record, so a failure there is not
  in this count at all. Backlog 44a.
* A narrative that was produced but **wrong** is outside this measurement; it
  counts production, not quality.
* `withheld=True` — the new fail-closed state from b-2 — is **0** since the
  restart, as expected, and would appear here in future.
