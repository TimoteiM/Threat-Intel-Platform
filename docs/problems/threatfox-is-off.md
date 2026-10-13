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

### `office.com`: its investigation was deleted, but the record survives

**Correction to an earlier claim of mine.** I wrote that the database no
longer held the first instance. It does. The *investigation* was deleted
through the UI at 13:55 today —
`DELETE /api/investigations/a31bf41b-e95a-45dd-a3f5-832025cd96b5 → 204` from
the frontend container, with `evidence` cascading to zero rows — but the
**alert run** that spawned it was untouched:

| | |
|---|---|
| alert run | `154323c9-70f1-48ad-bbf3-030360547346` |
| created | 2026-10-13 12:39:21 UTC |
| `overall_verdict` | **malicious** |
| `indicator_risk_score` | **90** |
| `summary.malicious_indicators` | `["office.com"]` |
| reasons | carry `ThreatFox matches: 2` |

`alert_body_investigation_runs` has no cascade from `investigations`, so the
wrong verdict outlived the row it was derived from — and that is the only
reason the first instance is still inspectable. The transcription below was
taken from the investigation while it existed, and it now has a surviving
source to check against.

**Two alert runs still read malicious/90 and have not been corrected:**

| run | indicator | ThreatFox count | verdict |
|---|---|---|---|
| `0703a5f1-0dd1-4ac1-8d6e-d93cae6f8984` | `live.com` | 25 | malicious / 90 |
| `154323c9-70f1-48ad-bbf3-030360547346` | `office.com` | 2 | malicious / 90 |

So correcting the investigation alone would have satisfied the condition in
one direction and broken it in the other: the investigation would read
corrected while the alert run still said malicious.

The search behind that table, stated because the claim quantifies: every row
of `alert_body_investigation_runs` whose `result_json` matches
`ThreatFox matches: [1-9]` — two rows, both today. A looser first search on
the literal `ThreatFox matches` returned twelve, including a
malicious/85 run on the IP `136.243.220.212` from 2026-09-10 that I nearly
reported as a third case. Its text reads *"no ThreatFox matches, and no
OpenCTI record"* — the negative phrasing. My own completeness search had a
false positive, found by reading the matched text instead of trusting the
match.

### The first instance, as measured while the investigation existed

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

Deleting it was a defensible call in the moment. On a SOC platform the audit
trail of a wrong verdict is itself evidence, which is why `live.com` was
**corrected** rather than removed — and the office.com case shows the trail
surviving by accident rather than by design, in a table that happens not to
cascade.

### The IP side is clean, measured

The IP relation is the worse one in principle — `1.2.3.4` is a substring of
`11.2.3.40` with no label structure to anchor equality on — but nothing was
hit by it:

| | |
|---|---|
| `ip_lookups` rows | 6,616 |
| ...that ever recorded a ThreatFox IOC | **0** |
| `ip`-type investigations | **0** (1,680 url, 800 domain, 65 hash) |

So `analysis_task.py:1366`, the unscoped IP consumer, never fired, and the
seven-month 401 is why `ip_lookups` holds no matches to be wrong about. The
parsed-address rule is **preventive**, not remedial.

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

### The proof I first offered was tautological

I presented this as the evidence:

```
engine, evidence as stored      suspicious/low  risk=40  monitor
engine, threatfox emptied       suspicious/low  risk=40  monitor
```

"Both runs agree, therefore the malicious verdict came from ThreatFox and
nothing else." That does not follow. The two runs agree **because the engine
already scopes** — `decision_engine.py:274` and `:569` call
`about_observable`, all 25 matches scope to `elsewhere`, so *both* runs read
an empty list. The invariance cannot distinguish "no other signal justifies
malicious" from "ThreatFox is being ignored". It is a check that could not
have returned the other answer, which is the defect this codebase has a
README rule about, committed inside the argument for a correction.

The control that does discriminate replaces `about_observable` with the
identity function — exactly the pre-`b83772e` line
`tf_matches = threat_feeds.get("threatfox_matches") or []`:

```
pre-fix engine, unscoped tf     malicious/high  risk=90  block   <- reproduces the stored verdict
pre-fix engine, tf emptied      suspicious/low  risk=40  monitor
```

That pair isolates causation. It would have printed malicious in both rows
had another signal been responsible. And the full production chain was
replayed step by step — `apply_decision_to_report`,
`_inject_lexical_contribution`, `_apply_phishing_redirect_risk_floor`,
`_ensure_report_completeness` — all returning suspicious/low/40/monitor,
with `_trusted_external_risk_floor` returning `(0, [])`, which kills the one
path that could have forced malicious independently of ThreatFox.

### And the corrected verdict is not a correct verdict

`suspicious/low/40/monitor` is what production returns and it is
non-actionable, but it is not positively right for `live.com`. Its
`risk_rationale` rests on an **unverified PhishTank row from 2010** and a
"third-party brand reference: 'microsoft' on non-microsoft domain" signal
that is itself a false positive — `live.com` *is* Microsoft.
`benign/high/15/monitor` was blocked only because the weak-signal-cluster
branch fires first. The correction removes a false block; it does not make
the row right.

The evidence it rests on also has `intel.meta.status = "failed"`
(Spamhaus 401, empty `blocklist_hits`) — an absence, not a clean result.

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

**The write is on hold, and the reason is stronger than the permission
refusal.** It would produce an *inconsistent* record, which is worse than
the current wrong one.

`investigations.classification` is not where the investigation page gets its
verdict. The detail page reads `reports.report_json` and the read-time
`confidence_engine`; measured against the real stored row, that pipeline
returns `verdict=malicious score=90` **byte-identically before and after**
the proposed write. The instrument is not dead — perturbing the inputs it
actually reads moves it (report corrected → malicious/74; threatfox emptied
→ malicious/90; both plus `final_risk` → suspicious/40) — so the identical
pre/post result is a finding.

What *would* flip to suspicious: the investigations **list** page, the
dashboard's `classification_breakdown` and `recent_malicious` panels
(`dashboard.py:31-42`, `:105-118`), and similar-investigations
(`investigations.py:505,543`). What would **not**: the detail page, the
case-story tab, and the PDF/Markdown/JSON exports — all three export
`detail_dict`s omit `context` entirely and `export_service` takes its verdict
from `confidence_engine`. A client-facing PDF exported after the write would
still read MALICIOUS / BLOCK.

And the note itself would be invisible. `investigations.context` is
**input-only**: present on `InvestigationCreate`, absent from
`InvestigationResponse`, `InvestigationListItem` and
`InvestigationCreatedResponse`, and read by no frontend component.
`get_investigation` returns neither `context` nor `updated_at`, so even the
*when* of a correction is absent from the payload.

### There is already a home for this record

`analyst_feedback` — built, API-backed, and rendered by a component that
already exists:

| | |
|---|---|
| columns | `subject_type`, `subject_id`, `verdict`, `platform_classification`, `platform_risk_score`, `note`, `analyst`, `created_at` |
| constraint | `UNIQUE (subject_type, subject_id)` |
| foreign keys | **none** — so the row survives a UI delete, which is exactly what `office.com` lacked |
| contents today | 5 rows, all `subject_type = 'alert_run'`; zero for `investigation` |
| API | `POST`/`GET /api/detections/feedback` |
| renderer | `AnalystFeedbackControl.tsx:173-181` — "Recorded <when> · the platform said <classification> · "<note>"" |

Two traps in using it, both measured:

1. **Ordering.** `_subject_snapshot` (`detections.py:767-784`) copies
   `investigation.classification` and `.risk_score` onto the feedback row
   **at insert time** — its docstring says so deliberately: "the feedback is
   about the answer as it was given, not as it now stands." A row inserted
   *after* the UPDATE records `suspicious`/`40` and destroys the only
   surviving copy of the prior verdict. `create_feedback` updates only
   `verdict`/`note`/`analyst` on an existing row and never re-snapshots, so
   it cannot be repaired through the API. **Snapshot first, guard on
   `platform_classification == "malicious"`, then update.**
2. **The control is mounted in dead code.**
   `page.tsx:1041-1043` mounts `<AnalystFeedbackControl
   subjectType="investigation" .../>` — inside a block opened
   `{false && <div ...>` at `:934` and closed at `:1052`. That block holds
   the *entire* lower page, tabs and content included, so it is a stale
   second copy of the body rather than a hidden feature. Un-deadening it
   would duplicate the page; the control has to be mounted in the live
   render instead.

### The decision that is not mine

The corrected value and the audit path are settled. What the **verdict
surface** should say is not:

* **(a)** correct `investigations.*` and accept that the detail page and the
  PDF keep showing malicious, with the correction notice beside it; or
* **(b)** also set `report_json.classification/confidence/risk_score/
  recommended_action` and add `report_json.superseded = {prior verdict,
  reason, when}`, keeping the narratives untouched as the withdrawn account.

(b) makes the surfaces agree; (a) is the smaller change. Either way this
historical row keeps feeding `final_risk = 90/high` and 25 unscoped matches
to every read-time consumer — the collector rename only affects new runs — so
a note on the page is required in both cases, not optional.

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
