# ThreatFox is switched off

2026-10-13. `Settings.threatfox_enabled`, default `False`.

> **The feed's data was right. The query semantics made it produce the
> opposite conclusion.** `nlahtc.theluxehomeoffice.com` is correctly listed
> in ThreatFox — a real malicious host, accurately reported. Matching that
> indicator against `office.com`, because `search_ioc` is a substring search,
> is what condemned a Microsoft apex as malicious/high/`block`. A substring
> query turned a true positive into a false positive. **Data quality and
> query semantics are separate problems, and only one of them was ever being
> discussed.**

Not a judgement call. **Measured benefit over seven months: zero verdicts
changed** — 25 of 25 knowable positives were already reached as
malicious/high by other sources, and the single non-redundant listing
postdates its own verdict. **Measured cost within two hours of the credential
being restored: two malicious/high/risk-90/`block` verdicts on Microsoft
apexes.** An expected cost above zero against a benefit measured at zero is
not a trade-off.

## The root cause is the query, not the filter

Both callers send:

```python
{"query": "search_ioc", "search_term": domain}
```

`search_ioc` is a **substring** search. Asked about `live.com` the API
returns every indicator containing that string. No amount of downstream
scoping turns a substring query into an exact lookup, which is why the feed
is off rather than merely filtered.

## Three relations, and only one was tested

| relation | example | hit? | tested before today |
|---|---|---|---|
| exact match | `nlahtc.theluxehomeoffice.com` = `nlahtc.theluxehomeoffice.com` | **yes** | yes |
| IOC is a path on the observable's host | `discord.com` vs `https://discord.com/api/webhooks/...` | no | **yes** |
| observable is a substring of the IOC's host | `office.com` vs `nlahtc.theluxehomeoffice.com` | no | **no** |

The third is what reached production. `sdoffice.com.br` and `www82live.com`
are the same shape. All three now have explicit tests in
`test_threatfox_relation_shapes.py`, along with a real subdomain
(`mail.example.com` vs `example.com`, also not a hit) and a control that
fails if the scoping becomes too aggressive.

`scope_of` was in fact already correct for all three — it compares hosts for
equality, so the reverse direction returned `elsewhere` too. The logic was
never the defect.

## The defect was scope, for the fourth time in one day

**2 of 30 consumers scoped.** `about_observable` went into `decision_engine`
and nowhere else, and this was reported as "scoped at the call site" — a
completeness claim whose search covered one file.

The unscoped consumers that decide things:

| site | what it does |
|---|---|
| `analysis_task.py:1414` | `tf_matches` → the malicious clause. **This produced the verdicts.** |
| `analysis_task.py:1366` | the IP path's `tf_matches` |
| `analysis_task.py:2458` | `worth_escalating` |
| `signals.py:737` | `sig_threatfox`, `severity="critical"` |
| `anyrun_gate.py:123` | gating |
| `alert_finding_builder.py:271` | a finding |
| `investigation_intelligence.py:576` | `tf_count` |

Patching 28 sites is not a fix; the next consumer would be written unscoped.
**You cannot make 28 consumers remember to scope. You can remove the thing
they would have to remember.** So **the scoped list takes the name every
consumer reads**:

* `threatfox_matches` — scoped to the observable. Every one of the 28
  unscoped readers is now correct without being edited.
* `threatfox_matches_all_hosts` — the unfiltered answer, kept because
  "malware is hosted on this platform" is real context, under a name no
  decision reads.

Both assignment sites go through one `_record_threatfox` helper, and a test
asserts neither bypasses it — because two API callers were fixed separately
with one missed, and then two consumers were scoped with 28 missed.

## What it cost

| observable | verdict | matches | about the observable |
|---|---|---|---|
| `live.com` | malicious / high / 90 / **block** | 25 | **0** |
| `office.com` | malicious / high / 90 / **block** | 2 | **0** |
| `nlahtc.theluxehomeoffice.com` | malicious / high / 90 / block | 1 | 1 — **true positive** |

Nothing was pushed outward: no `client_domain`, no `batch_id`,
`client_alerts = 0` on all three, and no callback mechanism exists in the
analysis path. The 11 IOCs recorded against `live.com` are all
`confidence = low` and correctly described as Microsoft infrastructure, so
nothing propagated.

### `office.com` is recorded here because the database no longer holds it

It was deleted through the UI at 13:55 today —
`DELETE /api/investigations/a31bf41b-e95a-45dd-a3f5-832025cd96b5 → 204`, from
the frontend container, and `evidence` cascaded to zero rows. Two cases,
handled two ways, and one of them left no trace; without this section the
record implies a single occurrence. So the first instance, transcribed from
the measurement taken while it still existed:

| | |
|---|---|
| investigation | `a31bf41b-e95a-45dd-a3f5-832025cd96b5` |
| observable | `office.com` (observable_type `domain`) |
| created | 2026-10-13 12:39 UTC |
| verdict | **malicious / high / risk 90 / action `block`**, state `concluded` |
| client_domain | none |
| batch_id | none |
| `client_alerts` | 0 |
| ThreatFox matches | 2 |
| matches about the observable | **0** |

The two matches, both `observable is a substring of the IOC host`:

```
http://sdoffice.com.br/wp-content/plugins/verify/proxy.php   (ioc_type url,  confidence 100)
nlahtc.theluxehomeoffice.com                                 (ioc_type domain, confidence 100)
```

Note the second: the indicator that falsely condemned `office.com` is the one
host in this whole episode that *is* genuinely listed. A substring search made
one true positive into a false positive on a Microsoft apex.

Deleting it was a defensible call in the moment and it is the reason this
section exists. On a SOC platform the audit trail of a wrong verdict is itself
evidence, which is why `live.com` is being **corrected** rather than removed.

`http://ecs.office.com/`, investigated at 12:39:21 the same minute, is a
different observable and was correctly judged benign/high/monitor. It is easy
to mistake for the deleted row when reading the table by timestamp.

`nlahtc.theluxehomeoffice.com` stays malicious with `threatfox_matches`
emptied entirely, so it is not ThreatFox's verdict and must not be unwound.

## The authority question, settled

Before correcting `live.com`, the test that could have invalidated the whole
thing: **does `analysis_task` delegate the verdict, or classify on its own?**
If it has its own path, recomputing with `decision_engine` substitutes one
function's opinion for another's and proves only that the two disagree.

It delegates. Three pieces of evidence:

1. **The ladder at `analysis_task.py:1414` is not the authority.** It sits
   inside `_generate_automated_report`, the rule-based fallback.
   `apply_decision_to_report` then overlays the engine's
   `classification`/`confidence`/`risk_score`/`recommended_action` over
   whatever the report said — unconditionally, except when the collectors
   reached `inconclusive` with no risk score, in which case the analyst's
   reading is adopted and *labelled* `analyst_fallback`.
2. **The stored report says which happened.** Its `decision_engine` block
   reads `{"source": "deterministic", "version": 1, "canonical_fields":
   [classification, confidence, risk_score, recommended_action]}` — the
   engine decided, not the model, even though `ai_model` is
   `gpt-5.6-luna` and the narrative is the model's.
3. **The stored artefact proves the running code was unscoped.**
   `decision_engine` builds that line as
   `key_evidence.append(f"ThreatFox matches: {len(tf_matches)}")` from the
   **scoped** variable. The stored report says `ThreatFox matches: 25`. With
   scoping, `tf_matches` is 0 for `live.com` and the line would not appear at
   all. So the function that ran had all 25.

The recomputation is therefore a **replay of the producing function with the
fix loaded**, not a second opinion. The correction stands.

## Why a fix committed at 10:53 produced a false verdict at 12:05

Because `analysis_task` runs in the **worker**, and the worker does not
reload.

| | |
|---|---|
| scoping committed | 2026-10-13 **10:53** |
| worker process started | 2026-10-13 **09:21:06** |
| `live.com` analysed | 2026-10-13 **12:03–12:05** |
| worker next restarted | 2026-10-13 **13:53:43** |

The worker was 1h12m stale when it produced the verdict, and stayed stale for
three hours after the fix existed. `uvicorn --reload` covers the api; Celery
has no equivalent, so between 10:53 and 13:53 the api was running today's
code and the worker was running this morning's — the api-new/worker-old skew
this platform already has a `code_version` task for.

**15 investigations ran in that window.** 2 malicious (`live.com`, false;
`nlahtc.theluxehomeoffice.com`, a true positive that is malicious with or
without ThreatFox), 9 suspicious, 4 benign. None of the 13 non-malicious rows
carries a ThreatFox match — only 3 rows in the entire corpus ever did — so
the material impact is the one false verdict.

The honest version of this morning's claim is narrower than it was made:
"scoped at the call site" was true of the source and false of the running
system, which is the distinction the `code_version` task was built for
earlier the same day and then not used after the commit that needed it.
Restarting `worker` and `beat` after a change to worker-executed code is the
missing step, and `docs/deploy/schema-changes.md` already says so for
migrations.

### `live.com` still needs correcting

Recomputed from its own stored evidence through `build_decision_report`,
which scopes:

```
stored (from analysis_task)      malicious/high  risk=90  block
engine, same evidence            suspicious/low  risk=40  monitor
engine, threatfox emptied        suspicious/low  risk=40  monitor
```

The correction was written and **refused by the permission layer** as a
shared-resource write, so investigation
`ba1666cb-3148-4766-a3af-8db897f365b4` still reads malicious/block. The
script is at `scratchpad/unwind.py`; it refuses to downgrade if the
recomputation is still malicious, leaves the report row in place as the
record of the error, and appends its reason to `context`.

## The rule

**A feed's value is measurable, and once measured it is not a matter of
taste.** Seven months of silence changed zero verdicts; two hours of answers
produced two false blocks on Microsoft apexes. The argument for keeping a
source is its measured marginal contribution, and the argument against is
its measured cost — both numbers exist here and they point the same way.

**And an absence bug hides inside its own fix.** The switched-off branch
first assigned `threatfox_status` to a bare local instead of
`result["threatfox_status"]`, so a disabled feed recorded nothing and would
have read downstream as "asked, nothing listed" — the exact defect being
fixed, for the sixth time today, caught only because the test for the
dangerous direction was written before the branch.
