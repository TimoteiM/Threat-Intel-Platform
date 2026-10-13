# ThreatFox is switched off

2026-10-13. `Settings.threatfox_enabled`, default `False`.

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
So **the scoped list takes the name every consumer reads**:

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

`office.com` was deleted through the UI at 13:55
(`DELETE /api/investigations/a31bf41b-... 204`), evidence cascaded.

`nlahtc.theluxehomeoffice.com` stays malicious with `threatfox_matches`
emptied entirely, so it is not ThreatFox's verdict and must not be unwound.

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
