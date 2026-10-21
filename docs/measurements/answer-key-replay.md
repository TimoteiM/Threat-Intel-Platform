# Replaying the five answer-key cases through the loop

Run 2026-10-21, read-only, against live CrowdStrike Falcon.
`scripts/replay_answer_key_cases.py`. Nothing written, nothing delivered.

> **Population: Expertware's own estate.** `c00`, CID
> `eed7e41845d04c26b4198f4c85f6216e`, 176 of 176 devices on an
> `expertware.net` domain. See [POPULATION.md](POPULATION.md). This is why
> it is the right first connector, not a client pilot.

## The answer key, and exactly how thin it is

Five of 2,526 closed cases were closed by an analyst.

| | |
|---|---|
| `false_positive` | **4** |
| `inconclusive` | **1** |
| **`true_positive`** | **0** |
| attributable to a named analyst (`closed_by`) | **3 of 5** — all `timotei.moscaliuc` |
| span | 2026-10-07 to 10-08, two days |

**There are no true positives.** So this measures whether the loop agrees
that nothing happened. It cannot measure whether the loop finds something
that did, and no amount of replaying will change that — the population has
no positive in it. That is the single most important sentence about this
answer key and it is why the next section exists.

## What the loop did

| case | resolution | peak score | classes | queries | gathered | EDR said |
|---|---|---|---|---|---|---|
| #61 | inconclusive | **100** | 18, 17, 10, 29, 7, 11 | 1 | 1 | device record only |
| #892 | false_positive | 45 | 18, 17, 10 | 1 | 1 | device record only |
| #1050 | false_positive | 35 | **15** | 3 | 1 | **no detections, hash unknown** |
| #1087 | false_positive | 5 | 10 | 1 | 1 | device record only |
| #1184 | false_positive | 35 | **1102** | 2 | 1 | **no detections in the window** |

Three results worth separating:

**1. On the four false positives, the EDR corroborates "nothing here."**
`host_detections_window` returned **empty** on #1050 and #1184 — a real
negative, not a failure: Falcon was asked and had no detections on that host
in a ±6h window. `hash_prevalence` on #1050 came back empty too, so that
file stream's hash is unknown to Falcon across the estate. Both consistent
with the analyst's `false_positive`.

**2. Case #61 scored 100 and the EDR has nothing on it.** 564 reconstructed
alerts across six Sysmon classes, peak correlation score 100, and the only
thing gathered was the device record. The analyst closed it `inconclusive`.
So the correlation score and the EDR disagree, and the analyst sided with
neither. That is one case, with no analyst recorded, and it is the most
interesting row here — not evidence of anything yet.

**3. The missing SIEM source is named, not silent.** `user_risk_timeline`
returned `check_failed` with *"this tenant's source map has no siem
platform"* on every case that had a user. That is the correct behaviour — an
absent source appears by name — and it means roughly half the playbook
cannot run on `c00` until a SIEM source exists there. Four of five cases ran
only 1–3 queries for that reason.

## Two defects this found in my own work

**`hash_prevalence` could never fire, and the reason was my selector
extraction.** The first version read `sha256`/`hash`/`file_hash` from
`alert_fields` and found nothing, so every hash template skipped with "no
hash on this alert" — an absence manufactured by looking in the wrong place,
and one that would have been reported as a property of the alerts.

Measured: `alert_fields` carries `agent`, `event_id`, `rule_id`, `rule_name`,
`manager`, `agent_ip`, `user` and severities, and **no indicator at all**.
The extracted indicators live in `indicator_reports[].indicator`, typed
`ip`/`domain`/`hash` — 168 hash indicators across 300 sampled runs on these
hosts. Corrected, and `hash_prevalence` then ran on #1050.

**Two of the five cases had no playbook row at all.** #1050 is entirely class
`15` (Sysmon FileCreateStreamHash) and #1184 entirely class `1102` ("The
audit log was cleared"). Both were invisible to the playbook. Rows added for
`15`, `1102`, `7` and `11` — the classes these five cases actually involve —
with one new template, `host_detections_window`, keyed on `host` because
that is what those classes carry: class 15 has a host on 202 of 202 runs and
a user on 39; **class 1102 has a host on 20 of 20 and a user on none.**

## Still approximate: membership is reconstructed

A case is not a row. `alert_case_spine` holds the overlay and membership is
recomputed by `correlate_alerts` on every read
(`docs/problems/derived-case-membership.md`), and `case_read_set` has **no
row for any of these five**. So the replay reconstructs membership as
host + session window, which is the pair the case key is built from.

It visibly disagrees with the stored count: #61 says 100 alerts at close and
reconstructs 564; #1087 says 2 and reconstructs 14. Both numbers are printed
side by side rather than reconciled, because reconciling them silently would
be inventing a membership rule. **Any per-case claim from this replay is
bounded by that approximation.**

---

# What it would take to author new ground truth

Five cases, no positives, one analyst, two days. The estate is ours, so this
is the one population where we can make more — and making it is cheaper than
waiting for analysts to close more cases.

## The shape

Run something **detectable and benign** on a test machine in this estate, at
a recorded time, and compare what the loop gathered against what we know we
did. The comparison is the point: we hold the answer key before the alert
exists, which is the opposite of the historical cases.

## What it needs, in order

1. **A machine we own that is in this Falcon tenant and in the SIEM.** The
   coverage measurement already says those two sets differ: 19 hosts send
   SIEM events with no Falcon sensor, and 15 Falcon hosts send no SIEM
   alerts (`docs/outbound/falcon-edr-coverage-gap.md` — now correctly
   labelled as our own estate). A ground-truth host must be in **both** or
   the exercise measures a coverage gap instead of the loop. Confirm with
   one query per side before anything is run.

2. **A written protocol per exercise, authored before execution.** Host,
   UTC start and stop, the exact command, the expected event classes, the
   expected selectors, and what we assert the loop should gather. Written
   first and stored, because a protocol reconstructed afterwards records
   what happened rather than what was intended — the
   "ground truth must record what was seen" problem, one level up.

3. **Benign, reversible techniques only, and a named owner.** The obvious
   candidates map onto classes this playbook now covers:
   - `1102` — clear a local Security event log on the test host. Detectable,
     trivially reversible, and it is the class case #1184 was made of.
   - `15` — write an alternate data stream (`echo x > f.txt:s`). Class 15.
   - `11`/`7` — drop a benign exe in a watched folder; load a signed DLL.
   - `10` — a non-credential process access against a benign target.
   Nothing that touches credentials, nothing that needs elevation beyond the
   test host, nothing on a domain controller, and no technique that would
   trip containment. This is an authorisation question before a technical
   one: it needs an owner who can say yes to running detections on our own
   estate, and a window agreed with whoever watches the console.

4. **A quiet host, so attribution is possible.** On a busy host the gathered
   events cannot be attributed to the exercise. Pick a host with low alert
   volume in the last 7 days — measurable now from the runs table — and
   record its baseline rate in the protocol so the exercise's events can be
   separated from background.

5. **The comparison, as a measurement rather than a read-through.** For each
   exercise: did the alert fire at all; did it carry the expected class; did
   the selectors extract; which templates ran; what did Falcon return; and
   what did the loop *fail* to gather that we know was true. **The last one
   is the valuable column** — it is the only way to measure a false negative,
   which five historical false positives cannot do.

6. **A SIEM source for `c00`, or accept half a playbook.** Half the templates
   are SIEM-keyed and currently `check_failed`. An exercise designed around
   logons or user sessions would measure the absence of a source, not the
   loop.

## What it will not fix

Authored ground truth is still **our estate, our machines, our techniques**.
It can measure whether the loop gathers what we know is there. It cannot
tell us whether the playbook is right for a client's estate, whose event
mix, naming and noise floor are unmeasured. That needs a client tenant with
a working source — and today neither Exabeam credential can even be
attributed to anyone (backlog 47).
