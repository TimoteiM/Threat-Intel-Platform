# Retiring the lexical probability

**Decided and implemented 2026-10-19.** Three decisions, taken from
`docs/measurements/url-lexical-three-arms.md`. Backlog 41.

| | decision |
|---|---|
| 1 | **The foreign calibration curve is removed**, not gated. |
| 2 | **The LightGBM artefact is retired.** The model path and the flag are gone from configuration, not set to false. |
| 3 | **The lexical score is demoted.** The rule observations stay as named, checkable findings; the probability and its low/medium/high label no longer reach the report. |

---

## 1. The calibration curve

Removed, with the functions that loaded it (`_load_calibration_metadata`,
`_calibrate_score`). Gating it would have left the loading in place for the
next person to re-enable.

It was loaded **by model path** and applied to whatever produced the score, so
with the model switched off a curve fitted to LightGBM's output distribution
was being applied to the built-in heuristic's output. Its domain is
0.0224–0.3174 — the model's own output range — so:

* a heuristic score above 0.3174 fell outside it and was returned untouched
  (1,318 of 1,535 corpus URLs);
* a heuristic score inside it was, by definition, a low one, and the curve
  mapped it **upward**, because its top bin maps 0.317 to an observed rate of
  0.601.

Measured effect: **217 scores moved, all 217 upward**, median +0.265, and
**171 URLs promoted from `low` to `medium`** — among them `aka.ms` and
`avatars.githubusercontent.com`.

## 2. The artefact

`url_lexical_model_path` and `url_lexical_use_lightgbm` are **deleted from
`Settings`**, along with every function that could have loaded or run a model.
There is no flag to flip.

The reasoning, recorded here because the model file still exists on disk and
somebody will find it:

| from the artefact's own `.metadata.json` | |
|---|---|
| `accuracy@0.5` | **0.9692** |
| always-predict-benign baseline (`train_neg_count / train_size`) | **0.9698** |
| difference | **−0.0006** |
| `valid_pred_q10 … q90` | 0.022438 … 0.022904 — a band **0.0005** wide |
| `valid_pred_q99` | 0.310672 |
| `best_iteration` | **10** |
| `scale_pos_weight` | 1.0, on a 32:1 class imbalance |
| samples | 365,728 benign / 11,429 phishing |

Its reported accuracy is **worse than predicting "benign" for everything**,
and it has to be: 99% of its validation predictions are below 0.31, so nothing
reaches the 0.5 decision point and it classifies the entire validation set as
benign. The headline number measures the base rate.

On our own corpus of 1,535 URLs:

* **0 could reach `high`** (nothing above 0.65) — not "did not", *could not*;
* **90.4% landed in a band 0.04 wide**, with 75 distinct values at 3 d.p. and
  **633 URLs sharing exactly 0.311**;
* its median output sat **0.009 above** the `low`/`medium` threshold, so the
  threshold decided the label rather than the model;
* **all 376 of its `high` labels came from the rule floor**, none from the
  model.

The two files its metadata names as training sources are Windows paths on a
developer's machine and are not on this host, so the artefact cannot be
retrained or re-validated from anything we hold.

**The model file itself was left in place** — deleting an ops artefact was not
part of the decision. It is now referenced by nothing. If you find it, this
section is why it is not wired up. `extra="ignore"` on `Settings` means a
leftover `URL_LEXICAL_*` in an environment is inert rather than an error.

## 3. The demotion

### What is gone

| | |
|---|---|
| `label` (`low`/`medium`/`high`) | removed from the payload, the schema, the report text, the AI payload and the frontend |
| `thresholds` | removed — they only existed to make the label |
| `calibration_applied` | removed with the calibration |
| `raw_score` | removed; there is one score and no transform to compare it against |
| the score ring and band scale in `LexicalRiskExplainer` | removed, along with the traffic-light `scoreTone` that coloured them |
| `ml_url_score.phishing_probability`, `.risk_level`, `.model_version` | removed from the facade and its schema |
| the decision engine's lexical **aggregate** | removed — it contributed 1–2 points from the band and appended "Lexical model high risk (0.99)" as a reason |

### What stayed, and why

**The rule observations.** They are where every genuine `high` came from — all
376 in the model arm — and each one is a fact a person can check against the
URL in front of them, which a probability is not. They are now `observations`:
a list of `{code, statement}`.

`RULE_OBSERVATIONS` is one entry per **fact**, not per combination, and the
reported set is a **superset of the set the decision engine scores**. The
first version of this change reported only the floor's combinations, so a URL
with a sensitive keyword and nothing else scored a point in the weak-signal
cluster and produced no observation to explain it — the probability's own
defect, rebuilt. `test_the_reported_observations_cover_everything_that_scores`
pins the relationship.

**`score`, for exactly one consumer.** The risk-score blend in
`_inject_lexical_contribution` still reads it. That blend is disclosed rather
than hidden — see below — and is the open question in backlog 41.

### The gate that needed a new predicate

Two places asked `lexical.label == "high"`: `_url_is_risky` in the email
pipeline, and the narrative's suspicious-URL list (which asked for `high` *or*
`medium`). With the band gone they needed a predicate, and it is
`strong_observations()` — the facts taking part in a satisfied
`ESCALATING_COMBINATIONS` entry, which are the floor's own tiers: a raw-IP
host or an `@` alone, punycode **with** a keyword, a disposable TLD **with** a
keyword or with a machine-generated look.

A single weak fact is deliberately not enough: `sensitive_keyword` alone fires
on an enormous amount of legitimate mail and `shortener` alone is how half of
marketing email is written.

**Measured consequence, and it is a narrowing:**

| | URLs of 1,535 |
|---|---|
| old gate, `label == "high"` | **1,008 (65.7%)** |
| new gate, an escalating observation | **376 (24.5%)** |
| newly flagged by the new gate | **0** |
| no longer flagged | **632** |

The new set is a strict subset. Most of what loses the flag is infrastructure
that was being marked suspicious on URL shape — `ctldl.windowsupdate.com`,
`1d.tlu.dl.delivery.mp.microsoft.com`, `f.c2r.ts.cdn.office.net`,
`ocsp.globalsign.com`, `ts-ocsp.ws.symantec.com`, `edgedl.me.gvt1.com`,
`pov-my.sharepoint.com`.

**The real cost, stated plainly:** long machine-generated hostnames on
ordinary TLDs also lose the flag — e.g.
`1bf5d9p.1bf5d9c8d3dbb6665bfabbbd0a2b0f866f777ca9.com`. They trip
`digit_heavy_and_high_entropy`, but that is not an escalating combination on
its own, and `.com` is not a disposable TLD. Adding
`digit_heavy_and_high_entropy` + `deep_subdomains_and_many_params` as a
combination would recover them. **That was not done**, because it is a rule
the floor never had and inventing one would be exactly the shape-based
reasoning the measurement argues against. It is a decision, not an oversight.

### The flag's meaning narrowed

`URL_SHAPE_AFFECTS_SCORE` used to re-enable the aggregate's points in the
weak-signal cluster. With the aggregate gone there is nothing there for it to
re-enable, so a shape-only URL now scores 0 in that cluster whether the flag
is on or off.

It is **not dead**: it still decides whether a shape-only URL's score blends
into the final risk score. Its meaning went from "shape can score anywhere" to
"shape can move the risk blend". Both halves are pinned —
`test_decision_engine.py` for the part that no longer happens,
`test_the_flag_still_governs_the_risk_blend` for the part that does.

### The blend, which is not presentational

The decision was taken on the understanding that demoting the score is
presentational, because the weak-signal gate already stops shape-only
verdicts moving the risk score. **That is true only for shape-only verdicts.**
When any semantic feature is present the gate opens and the lexical score
contributes 25% of the blended risk.

Measured over the stored reports:

| | |
|---|---|
| investigations where the blend is active | **584 of 2,667** |
| their median lexical score | **0.9999** |
| their median stored risk score | **62.0** |
| implied median pre-blend risk | **49.3** |
| **median points the blend adds** | **+12.7** |
| investigations where it adds ≥10 points | **521** |

So the score is not decoration on 22% of URL investigations; it is adding a
median 12.7 risk points, across a band boundary in many cases.

**It was therefore not removed here.** Removing it is a score change of that
size and belongs with a decision, not inside a presentational one. What
changed instead is that it is now **disclosed**: where the blend moves the
number, the finding says so — "The URL-structure signal moved the risk score
by +18 points (weight 0.25)" — and where it moves nothing, no number is
printed at all. A risk score partly driven by a figure the report no longer
shows would have been worse than showing the figure.

**This is the open item.** Backlog 41.

### Absence is not a low score

`enabled: False` is the exception path. It used to arrive with `score: 0.0`,
and 0.0 is a legitimate value meaning "nothing unusual about this URL's
shape", so a crash rendered as a green "0% lexical risk / Low" ring and
produced a normal finding. Now it produces a finding titled "URL structure not
assessed" saying *"This is an absence of evidence, not an absence of risk"*,
and the frontend renders a "Not assessed" panel. If no reason was recorded,
the finding says that too, because a silent absence is the defect one level
down.

---

## On quoting the AUC

The measurement reports that all three arms scored **below 0.5 AUC** against a
VirusTotal proxy — 0.242, 0.228, 0.318. **That number must not travel without
its cause.**

The VT-flagged URLs in that corpus are measurably **shorter and tidier** than
the clean ones: median length 42 characters against 153, entropy 4.30 against
4.86, and `url_length` *alone* scores AUC 0.257. Every shape feature therefore
points the wrong way on this corpus, and the label correlates with the domain
— known-bad domains have short URLs, enterprise domains have long ones — so
part of the inversion is domain reputation wearing a length disguise.

A sub-0.5 AUC against a proxy whose flagged URLs are shorter and tidier is a
statement about **the proxy's fit to this corpus**, not a verdict that the
scorers are inverted. The honest reading is narrower and still sufficient:
these scorers carry no usable signal *here*, which is why the probability
stopped being reported — not that they are reliably wrong, which would make
them useful upside down.
