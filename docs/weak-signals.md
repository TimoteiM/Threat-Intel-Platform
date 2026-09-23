# Weak signals: reported, not scored

Two findings are shown to the analyst but **do not move the risk score**:

* **Weak-signal cluster** (`weak_signal_cluster`)
* **URL lexical ML observation** (`url_lexical_ml`)

They still appear on the investigation, with `severity: informational` and the
text *"reported for review only; these signals key on URL shape and did not
affect the risk score."* Nothing was deleted — what changed is that neither can
escalate a verdict on its own.

## Why

The cluster's largest contributors key on the **shape of a URL** rather than on
anything observed about it. Length, entropy, dot count, subdomain depth,
percent-encoding: a legitimate deep link into SharePoint or a tenant's Office
portal scores MEDIUM on all of them, because that is what such URLs look like.

The threshold is low enough that this matters. Three points made a domain
`suspicious`, and three points is reachable from observations that describe
most of the web:

| Observation | Points |
|---|---|
| Lexical model HIGH (≥ 0.65) | 2 |
| Lexical model MEDIUM (≥ 0.45) | 1 |
| Hostname contains `secure` / `login` / `account` | 1 |
| Registered 31–365 days ago | 1 |
| Registrant or registrar pivot to another investigated domain | 1 |
| Static HTTP brand/input observation | 1 |
| High email spoofability *(only if something else already scored)* | 1 |
| Shared hosting *(only if something else already scored)* | 1 |

A long corporate URL on a year-old domain, hosted somewhere crowded, reaches
the threshold without anything suspicious having been found. That was the
reported problem: benign investigations were being pushed to `suspicious` by
URL length.

## The cost, stated plainly

This is a categorical change and it blunts a real detection. A domain with all
of:

* lexical model HIGH at 0.82, top feature `has_sensitive_keyword`
* high email spoofability
* registrant pivots to other investigated domains

now returns **benign** where it previously returned **suspicious**. That
cluster was a genuine signal. The test asserting it (`weak_but_real`) was kept
and now pins *both* modes rather than being deleted.

The trade is deliberate: the cluster was wrong far more often than it was
right, and it was wrong on exactly the traffic this platform sees most. But a
narrower rule is available if the trade turns out to be a bad one — excluding
only the URL-*shape* features (entropy, length, subdomain depth, dot count)
while letting semantic ones like `has_sensitive_keyword` keep scoring.

## Restoring the old behaviour

```
WEAK_SIGNALS_AFFECT_SCORE=true
```

in `.env`, then `docker compose up -d --force-recreate api worker beat`.
`docker compose restart` does **not** re-read `env_file`.

With it on, the findings return to `low`/`medium` severity and escalate as
before. The flag is read through `weak_signals_affect_score()` in
`app/services/decision_engine.py`, which takes an optional settings object so a
test can inject one — the suite reloads `app` through importlib in places, and
monkeypatching `"app.config.get_settings"` by dotted path stops resolving when
it does.

## Both paths are gated

There are **two** places that escalate on `weak_score`, with duplicated logic:

| Path | File |
|---|---|
| Decision engine | `app/services/decision_engine.py` |
| Deterministic analysis fallback | `app/tasks/analysis_task.py` |

Gating one and not the other produces two different verdicts for the same
evidence depending on which path ran. Any future change to this rule has to
touch both.

## What still scores

Everything that observes rather than infers: reputation hits, DNS and WHOIS
facts, TLS findings, sandbox detonation results, and the signals that come from
a control actually seeing something. Clean controls also still override — a
cluster present alongside clean observable evidence records
`weak_signals_overridden_by_clean_controls`, which is a separate finding from
the cluster itself and is emitted independently of it.
