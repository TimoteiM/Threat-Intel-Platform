# Three arms over the URL corpus

> **Decided 2026-10-19.** The calibration curve was removed, the LightGBM
> artefact retired outright, and the probability and its label dropped from
> the report. See `docs/design/lexical-scoring-retirement.md` for what was
> done and what it cost. **The one thing still open is the risk-score blend**,
> which turned out not to be presentational: it adds a median +12.7 risk
> points on 584 of 2,667 investigations.
>
> **If you quote the AUC figures below, quote their cause in the same breath**
> — see "On quoting the AUC" in the design note. A number below 0.5 against a
> proxy whose flagged URLs are shorter and tidier is a statement about the
> proxy's fit to this corpus, not a verdict on the scorers.

**Backlog 41 part 2.** Measured 2026-10-19 against 1,535 distinct URL
observables — every `investigations.domain` with `observable_type='url'`
matching `^https?://`.

| arm | what it is |
|---|---|
| **1 — current** | built-in heuristic, then the LightGBM model's calibration curve. This is production today. |
| **2 — raw** | built-in heuristic, no calibration. |
| **3 — model** | LightGBM, then its own calibration curve. This is what turning `url_lexical_use_lightgbm` on gives you. |

The rule-based floor (`_rule_based_floor`) is applied in **all three** arms,
where production applies it — after calibration. It is also recorded per row,
because a floor-determined score is identical in every arm and would otherwise
read as the three arms agreeing.

Per-URL detail, with full URLs, is at
`~/evidence/url-lexical-three-arms-2026-10-19.jsonl`. This page shows hosts
only: a URL from a phishing lure can carry a victim's address or a session
token in its query string.

---

## Ground truth: neither of the two is available

**The model's `.metadata.json` does not carry its validation set.** It carries
summary metrics only — `valid_size`, prediction quantiles, calibration bins
with counts and observed rates. The two files it names as training sources are
Windows paths on a developer's machine
(`C:\Users\…\backend\data\ml\phishing_urls.txt`) and are not on this host.

**Analyst verdicts are not a label set.** `analyst_feedback` has **6 rows** in
total — 3 `false_positive`, 1 `true_positive`, 2 `unclear` — and all 6 have
`subject_type = alert_run`, none on a URL or an investigation.

So, as you said to treat it: **the arm comparison below shows change, not
improvement.**

**A third source exists that nobody asked for, and it is worth having.**
VirusTotal verdicts stored in the evidence are external and independent of our
lexical scorer. Restricted to rows where VT's own `scope` is `url` *and* its
`scope_value` is byte-identical to the URL being scored — so the label applies
to this string rather than to its domain or a normalised variant — that is
**646 URLs: 118 flagged by at least one vendor, 528 flagged by none.** It is
reported separately at the end, labelled as a proxy, with its weaknesses
stated. It is not analyst truth and it does not turn change into improvement.

---

## Arm 1 vs arm 2 — what the foreign curve is doing today

**It only ever inflates, and it inflates exactly the most benign-looking
URLs.**

| | |
|---|---|
| rows where the curve returned a value | **217 / 1,535** (14.1%) |
| rows where arm 1 > arm 2 (inflated) | **217** |
| rows where arm 1 < arm 2 (deflated) | **0** |
| size of the move, when it moves | +0.067 min, **+0.265 median**, +0.410 max |
| label flips | **171**, every one of them `medium` (arm 1) → `low` (arm 2) |

The curve's domain is **0.0224 – 0.3174** — the range of the *model's* outputs
on its own validation set. The built-in heuristic scores across the full 0–1
range, so:

* a heuristic score **above 0.3174** falls outside the curve and is returned
  unchanged — that is the other 1,318 rows;
* a heuristic score **inside** the domain is, by definition, a low one — the
  affected rows' raw scores run **0.0569 to 0.1886** — and the curve maps it
  upward, because its top bin maps 0.317 to an observed phishing rate of
  **0.601**.

So the entire effect of the misapplied curve is to take the URLs the heuristic
thought were safest and promote 171 of them from `low` to `medium`. Two of
them:

```
medium -> low   arm1=0.3401  arm2=0.1168   http://aka.ms
medium -> low   arm1=0.4645  arm2=0.1514   http://avatars.githubusercontent.com
```

Microsoft's own link shortener and GitHub's avatar CDN are being raised into
`medium` by a calibration curve fitted to a different scorer's output
distribution.

**I predicted the wrong direction before measuring.** I expected the curve to
compress scores toward zero and make everything `low`. It does the opposite,
and only to the bottom of the range. The prediction was worth writing down
precisely because it was wrong.

**Robustness.** 66% of the corpus sits on three registrable domains
(`delicitate.ro` 564, `workers.dev` 348, `bizinfo.ro` 101), so the per-URL
counts are partly a statement about how often one domain was investigated.
Deduplicated to one representative URL per registrable domain (135 domains),
the direction is unchanged: **46 of 135 domains flip, all `medium` → `low`.**

---

## Arm 2 vs arm 3 — the real question

**The model cannot produce a high verdict. Not "does not" — cannot.**

Arm 3's scores before the rule floor:

| | |
|---|---|
| range | 0.0100 – **0.5864** |
| median | **0.3090** |
| within [0.28, 0.32] | **1,387 / 1,535 (90.4%)** |
| distinct values at 3 d.p. | **75** (633 URLs share exactly 0.311; 353 share 0.281) |
| able to reach `high` (> 0.65) | **0 / 1,535** |

The model is very nearly a constant. Its median output sits **0.009 above the
`low`/`medium` threshold of 0.30**, which means the threshold decides the
label, not the model — and is why arm 3 produces 901 `medium`.

**Every one of arm 3's 376 `high` labels comes from the rule floor, not the
model:**

| arm | `high` | of which the rule floor set the score |
|---|---|---|
| 1 | 1,008 | 34 (3.4%) |
| 2 | 1,008 | 34 (3.4%) |
| 3 | 376 | **376 (100%)** |

The floor is always 0.90 and always the same clause — `has_ip_host` or
`has_at_symbol`. No other tier fires on this corpus. So under arm 3 the
"high-risk URL" verdict is produced entirely by two boolean checks that exist
independently of any model.

### Labels and flips

| | low | medium | high |
|---|---|---|---|
| arm 1 (current) | 191 | 336 | 1,008 |
| arm 2 (raw) | 362 | 165 | 1,008 |
| arm 3 (model) | 258 | 901 | 376 |

**arm 2 → arm 3: 892 of 1,535 rows flip (58%).**

| from | to | count |
|---|---|---|
| high | medium | 524 |
| low | medium | 236 |
| high | low | 108 |
| medium | low | 24 |

Score delta (arm 3 − arm 2): nonzero on 1,501/1,535; min −0.7188, median
−0.1000, max +0.4990.

**arm 1 → arm 3: 811 flip.** high→medium 524, low→medium 110, high→low 108,
medium→low 69.

Examples, host only:

```
high -> low      arm2=0.7206 arm3=0.1897   https://stm-keyid-….microsoftaik.azure.net
high -> low      arm2=0.8421 arm3=0.2463   https://app.controlup.com
high -> medium   arm2=0.9904 arm3=0.3107   http://1d.tlu.dl.delivery.mp.microsoft.com
low  -> medium   arm2=0.2408 arm3=0.3107   http://17.siembiot.eu
low  -> medium   arm2=0.1914 arm3=0.3107   http://adcont.expertware.ro
```

Deduplicated by domain (135): **77 of 135 flip** — low→medium 51, high→medium
15, medium→low 7, high→low 4. Same shape: everything converges on `medium`.

### The model's own metadata already said this

| metric | value |
|---|---|
| `accuracy@0.5` | **0.9692** |
| always-predict-benign baseline (`train_neg/train_size`) | **0.9698** |
| difference | **−0.0006** |
| `valid_pred_q10 … q90` | 0.022438 … 0.022904 |
| `valid_pred_q99` | 0.310672 |
| `best_iteration` | **10** |
| `scale_pos_weight` | 1.0, on a 32:1 class imbalance |
| samples | 365,728 benign / 11,429 phishing |

The reported accuracy is **worse than predicting "benign" for everything**,
and it has to be: 99% of validation predictions are below 0.31, so nothing
ever crosses the 0.5 decision point and the model classifies the entire
validation set as benign. The headline number measures the base rate.

90% of its validation predictions lie in a band **0.0005 wide**. That is the
same near-constancy seen on our corpus, in the artefact's own file, before
anyone ran it.

---

## Against the VT proxy — imperfect, external, and uncomfortable

646 URLs, 118 flagged / 528 clean. **AUC is the probability that a random
flagged URL scores above a random clean one.** It is threshold-free, so it
cannot be an artefact of where `low`/`medium`/`high` sit.

| scorer | AUC against this proxy, whose flagged URLs are measurably shorter and tidier |
|---|---|
| arm 1 — current | **0.242** |
| arm 2 — raw heuristic | **0.228** |
| arm 3 — LightGBM | **0.318** |

**All three are far below 0.5 against this proxy — and the proxy's flagged
URLs are measurably shorter and tidier than its clean ones, which is why.**
Those two halves belong in the same sentence every time the number is quoted.
The table's own header carries the caveat because a row lifted out of a table
loses its surrounding prose; the column heading travels with it.

A sub-0.5 AUC here is a statement about **the proxy's fit to this corpus**,
not a finding that the scorers are reliably inverted — a reliably inverted
scorer would be useful upside down, and these are not. The defensible reading
is narrower and still enough for the decision: **these scorers carry no usable
signal on this estate.**

The metric was controlled before this was believed:

| control | result | expected |
|---|---|---|
| score = the label | 1.0000 | 1.0 |
| score = 1 − label | 0.0000 | 0.0 |
| constant score | 0.5000 | 0.5 |
| random score, 5 draws | 0.447, 0.489, 0.549, 0.492, 0.551 | ~0.5 |

**The cause is measured, and it is not a bug in any arm.** On this corpus the
features themselves point the wrong way — so the sub-0.5 figures above are the
corpus and the proxy disagreeing with the premise of lexical scoring, not
three scorers each being wrong in the same direction by coincidence:

| feature | flagged median | clean median | feature AUC |
|---|---|---|---|
| `url_length` | **42** | **153** | 0.257 |
| `entropy` | 4.30 | 4.86 | 0.269 |
| `digit_ratio` | 0.118 | 0.251 | 0.327 |
| `subdomain_depth` | 1 | 2 | 0.301 |
| `has_sensitive_keyword` | — | — | 0.308 |
| `has_at_symbol` | — | — | 0.312 |
| `is_shortener` | — | — | 0.500 |

The VT-flagged URLs are **short and tidy**; the VT-clean ones are long,
high-entropy, digit-heavy enterprise URLs — Microsoft delivery endpoints,
SharePoint links, Cloudflare Workers with tokens. Every scorer built on "does
this URL look messy" is therefore anti-predictive here, and `url_length`
alone, at AUC 0.257, is nearly as inverted as the full scorers.

At the production thresholds, flagging `medium`-or-above under arm 1 flags
**492 of 646 URLs (76%)** to catch **57%** of the flagged ones — less than
flagging at random would catch. The rule floor alone fires on 215 URLs and
catches **3** of the 118: precision 0.014.

**What this proxy is not.** VT "flagged by ≥1 vendor" includes single-vendor
false positives; "flagged by none" includes URLs VT never meaningfully
analysed. The corpus is our own investigation history, so it is selection-
biased — these URLs were investigated *because* something already flagged
them. And the label correlates with the domain (known-bad domains have short
URLs; enterprise domains have long ones), so part of the inversion is domain
reputation wearing a length disguise. None of that rescues a 0.24.

---

## What I would conclude, and what is yours to decide

**On (a), turning the flag on.** It is a choice between two scorers that are
both anti-predictive on the only external labels available (0.228 → 0.318,
both far below 0.5). It would move 58% of labels, almost all of them toward
`medium`, and it would reduce `high` verdicts from 1,008 to 376 — all 376 of
which come from two boolean checks that already run without the model. The
case for *on* is that it stops the heuristic calling 1,008 of 1,535 URLs
high. The case against is that it replaces it with a near-constant 0.31 that
is `medium` only because the threshold is 0.30. **Neither is a risk signal.**

**On (b), the foreign calibration.** This one I would stop regardless of (a),
and it is the narrower change: a curve fitted to one scorer's output
distribution, applied to another's, whose entire measured effect is to promote
171 benign-looking URLs — `aka.ms`, GitHub's CDN — from `low` to `medium`. It
is not a tuning parameter anyone chose; it is a side effect of loading
calibration by model path while the model is switched off. If the flag goes
on, it becomes correct by construction and the question disappears.

**What I think the measurement actually argues for**, and it is outside what
you asked so it is yours entirely: the lexical score's problem is not which
scorer computes it. 1,008 of 1,535 URLs at `high` from arm 2, and an AUC of
0.24 against external labels, say the signal is not carrying information on
this estate in either form. The existing weak-signal gate already stops
shape-only verdicts from moving the risk score, which is the platform
protecting itself from this. The decision worth having may be whether this
score should reach a report at all, rather than which arm computes it.

## Reproducing

The harness is three throwaway scripts; it writes nothing to the database. The
corpus query, the arm definitions and the controls are in this page's commit
message and in `~/evidence/url-lexical-three-arms-2026-10-19.jsonl`. Re-run
against a fresh corpus by re-executing the arm computation over
`SELECT DISTINCT domain FROM investigations WHERE observable_type='url'`.
