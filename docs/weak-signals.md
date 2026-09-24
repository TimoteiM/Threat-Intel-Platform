# URL shape does not decide a verdict

Two things changed about how the lexical URL model and the weak-signal cluster
affect a classification:

* The **shape** of a URL — its length, entropy, dot count, subdomain depth,
  path depth, and the lexical model's aggregate score, which those features
  dominate — is reported to the analyst and contributes nothing to the risk
  score.
* What a URL **says about itself** still scores: a sensitive keyword, punycode,
  a raw-IP host, an `@`, a shortener, a throwaway TLD.

Nothing was deleted. Shape observations still appear on the investigation, with
`severity: informational` and text saying they were not counted.

## Why

Measured, not assumed. This is a real SharePoint deep link:

```
https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/Forms/AllItems.aspx
  ?id=%2Fsites%2FFinance%2FShared%20Documents%2FFY26%20Budget%20Review%2Epptx
  &parent=%2Fsites%2FFinance
```

The lexical model scores it **HIGH, 0.71**, on nothing but its size and
structure. An `outlook.office365.com` mail deeplink scores MEDIUM, 0.53. Three
points makes a domain `suspicious`, and three points was reachable from
observations true of most of the corporate web:

| Observation | Points | Now |
|---|---|---|
| Lexical model HIGH (≥ 0.65) | 2 | shape — not counted |
| Lexical model MEDIUM (≥ 0.45) | 1 | shape — not counted |
| One semantic feature found | 1 | counted |
| Two or more semantic features | 2 | counted |
| Registered 31–365 days ago | 1 | counted |
| Registrant/registrar pivot to another investigated domain | 1 | counted |
| Static HTTP brand/input observation | 1 | counted |
| High email spoofability *(only if something else already scored)* | 1 | counted |
| Shared hosting *(only if something else already scored)* | 1 | counted |

The semantic contribution is capped at 2 so the lexical block can never
contribute more than its old aggregate did — one long URL tripping several
features cannot escalate itself.

## What counts as semantic

`SEMANTIC_FEATURES` in `app/services/url_lexical_ml_service.py` is the one place
this is defined:

`has_ip_host`, `has_at_symbol`, `has_punycode`, `has_sensitive_keyword`,
`has_suspicious_tld`, `is_shortener`.

Two features that look semantic are deliberately **excluded**, because both
fire on this estate's own legitimate traffic:

* **`brand_keyword_count`** — its search area includes the subdomain, so
  `outlook.office.com` counts "outlook"; and a registrable label counts as a
  lookalike whenever it merely *contains* a brand without equalling it, so
  `office365` counts as a lookalike of `office`.
* **`has_abnormal_port`** — any internal service not on 80/443 trips it, and
  there are plenty here.

Both remain in the model and still shape the reported score. They just cannot
escalate a verdict.

`semantic_features_present()` reads the raw `features` vector, not
`top_features`, because `top_features` is capped at five — a URL long enough to
fill that list with shape features would otherwise hide its own punycode
hostname.

## Where the model was actually moving the number

Gating the weak-signal cluster was not enough, and the first attempt at this
change missed it. `_inject_lexical_contribution` in `app/tasks/analysis_task.py`
blends the lexical score into the final risk at a fixed 25% weight, on every
investigation, independent of the cluster:

```
final = 0.75 × reputation + 0.25 × lexical
```

A long legitimate URL scoring 0.56 lifted a 20/100 reputation result to 29/100
on shape alone. That blend is now skipped when the model found nothing
semantic, and the finding is retitled "URL lexical ML observation" with
`informational` severity. Two details worth keeping:

* When there is no upstream risk score at all, the blend used to fall back to a
  0.5 midpoint and write **50/100** — a number sourced entirely from a signal
  we had just declined to count. It now leaves the field alone.
* The trusted-external-intelligence floor still applies regardless. Declining
  to count URL shape does not decline to count a feed hit.

## One scorer, not two

`analysis_task` carried its own copy of `_domain_weak_signal_score`, and the
copy had drifted: no domain-age rule, no self-pivot check, and shared hosting
and spoofability still scoring on their own rather than only as corroboration.
Identical evidence produced different scores depending on which path ran. The
fork is deleted; both paths import the one in `decision_engine`. A test asserts
they are the same object, which is the only version of that claim that cannot
rot.

## Restoring the old behaviour

```
URL_SHAPE_AFFECTS_SCORE=true
```

in `.env`, then `docker compose up -d --force-recreate api worker beat`.
`docker compose restart` does **not** re-read `env_file`.

With it on, the aggregate lexical verdict scores 2/1 again and the blend always
runs. The flag is read through `url_shape_affects_score()` in
`app/services/decision_engine.py`, which takes an optional settings object so a
test can inject one — the suite reloads `app` through importlib in places, and
monkeypatching `"app.config.get_settings"` by dotted path stops resolving when
it does.

## Known, unchanged

A registrant pivot to another investigated domain (1) plus high email
spoofability (1) plus shared hosting (1) still reaches three points and returns
`suspicious` with no URL signal involved at all. That path was not part of the
reported problem and was left alone, but it is the next thing to look at if
benign investigations keep escalating.
