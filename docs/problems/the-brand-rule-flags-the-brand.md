# The brand-impersonation rule flags the brand's own estate, and exempts lookalikes

Measured 2026-10-13, after `live.com` — Microsoft's own domain — was flagged
with *"Third-party brand reference: 'microsoft' on non-microsoft domain"*.

## The rule

`app/collectors/http_collector.py:353-359`:

```python
for brand in KNOWN_BRANDS:
    if brand in body_lower:
        brand_slug = brand.split()[0]        # "microsoft", "google", "paypal"
        if brand_slug not in own_host_lower:
            evidence.phishing_indicators.append(
                f"Third-party brand reference: '{brand}' on non-{brand_slug} domain")
            break
```

Ownership is decided by `brand_slug not in own_host_lower` — a **substring
test of the brand word against the hostname**. The same defect as ThreatFox's
`search_ioc`, in a different place: containment used where ownership is
needed.

It is wrong in both directions.

| | |
|---|---|
| **false positive** | `live.com` does not contain the string `microsoft`, so Microsoft's own domain is flagged as referencing Microsoft on a non-Microsoft domain |
| **false negative** | `paypal-secure-login-update-account.xyz` *does* contain `paypal`, so the rule **exempts it** — and brand-in-the-hostname is the commonest real impersonation shape |

## Scale

Grain: one row per evidence record, one per investigation.

| | |
|---|---|
| rows with an `http.phishing_indicators` array | 2,413 |
| carrying the brand-reference signal | **1,637 (67.8%)** |

For comparison, the ThreatFox defect that occupied most of today touched
**3** investigations. This one is on two-thirds of the corpus and is running
now.

## It does not discriminate — it points the wrong way

| verdict | rows | with signal | prevalence | lift vs base |
|---|---|---|---|---|
| suspicious | 1,566 | 1,308 | 83.5% | 1.23× |
| benign | 674 | 246 | 36.5% | 0.54× |
| **malicious** | **164** | **78** | **47.6%** | **0.70×** |
| inconclusive | 9 | 5 | 55.6% | 0.82× |

Read the malicious row. A signal whose only effect is to push a verdict
toward *suspicious* is **less** common among independently-judged malicious
domains than across the corpus as a whole.

The `suspicious` figure is partly endogenous — the signal contributes to
`http_score`, and `http_score >= 1` reaches suspicious — so it cannot be read
as evidence of anything. The malicious row can: `malicious` is reached
through `vt_malicious >= 5`, `tf_matches`, `urlscan_malicious` and the
OpenPhish/PhishTank clauses, none of which consult this signal. Among domains
those clauses condemned, the brand signal is below base rate.

Fifth instance of a fact true of most rows being used to rank them — and the
first that is actively inverted.

## What the signal mostly is

| brand named | rows |
|---|---|
| google | 1,083 |
| microsoft | 221 |
| meta | 217 |
| apple | 50 |
| aws | 38 |

**Of the 1,085 rows flagged for a Google brand mention, 984 (90.7%) also load
a Google or gstatic external resource.** So two-thirds of the signal is "this
page uses Google Fonts, Analytics or reCAPTCHA" — the rule matches the brand
word anywhere in the response body, including inside a `<script src>`.

## The false positives, named

Verdicts on the brand's own domains, flagged for referencing that brand:

| domain | brand | verdict |
|---|---|---|
| `office.net` | microsoft | suspicious / medium, risk 62, **investigate** |
| `office.com` | microsoft | suspicious / medium, risk 49, **investigate** |
| `youtube.com` | google | suspicious / low, risk 48, monitor |
| `live.com` | microsoft | benign / medium, risk 15, monitor |
| `bing.com` | microsoft | benign / medium, risk 15, monitor |
| `windows.com` | microsoft | benign / high, risk 15, monitor |
| `gstatic.com` | google | benign / high, risk 15, monitor |

**42 rows across 7 distinct apexes — and that count is a floor, not a
measurement.** It was produced by comparing against a hand-written list of
brand-owned domains, which is the eighth hand-maintained list in this
codebase and has the same failure mode as the other seven: any brand estate
not in my list is a false positive that did not get counted.

## The exempted, named

Domains the rule skipped because the brand word is in the hostname:

```
paypal-secure-login-update-account.xyz      contains 'paypal'
nlahtc.theluxehomeoffice.com                contains 'office'   (genuinely malicious)
stm-keyid-fb17d70d734870e919c4e8e603975e6   contains 'microsoft'
copilot.teams.cloud.microsoft               contains 'microsoft' (legitimate)
onmicrosoft.com                             contains 'microsoft' (legitimate)
sharepointonline.com                        contains 'sharepoint' (legitimate)
```

The first is a textbook phishing hostname. The rule's one job is to notice
that shape, and the shape is precisely what it exempts.

## The exemption is the whole defect, in one line

My three alternatives below all improve the *method* of the ownership test.
That misses it. **The ownership test is inverted in its use, not just its
method.**

> `paypal-secure-login-update-account.xyz` contains "paypal", so the rule
> concludes PayPal owns it and skips.

The detection worth having is **"contains the brand word and isn't the
brand's"** — and that is the exact condition the code uses to *exclude*.
Containment of the brand word is being read as evidence of ownership when it
is evidence of the opposite. No improvement to how ownership is determined
fixes a predicate that is pointed the wrong way.

## Blast radius, measured before flipping anything

A bulk silent downgrade on a SOC platform is its own event, so this was
measured first. Each stored evidence row was run through the production
`build_decision_report` twice — as stored, and with every brand-reference
entry stripped.

The control: rows **not** carrying the signal must come out identical.
**0 of 779 moved**, so the table is measuring the signal and not the harness.

| change | rows |
|---|---|
| suspicious → benign | **828** |
| suspicious, same class, medium/50 → low/40 | 350 |
| suspicious, same class, medium/65 → low/40 | 11 |
| suspicious, same class, low/40 → medium/50 | 6 |
| **malicious → suspicious** | **5** |
| unchanged entirely | 451 |

**833 of 1,651 carriers change class — 50.5% of carriers, 34.3% of every row
in the corpus.**

Among them: `https://attack.mitre.org/techniques/T1569/002/` and nine other
ATT&CK technique pages, which are suspicious because MITRE's own technique
descriptions say "microsoft"; `tarom.ro`, the Romanian national airline;
`pragma-core.com`; `bizinfo.ro`; `dataforseo.com`.

### The detection cost of disabling is zero

The five rows that lose severity, named rather than counted:

| observable | before | after |
|---|---|---|
| `googlebot.com` | malicious / medium / 82 | suspicious / 65 |
| `http://www.google.com/bot.html` | malicious / medium / 82 | suspicious / 65 |
| `http://www.apple.com/go/applebot` | malicious / medium / 82 | suspicious / 65 |
| `https://attack.mitre.org/techniques/T1036/008/` | malicious / medium / 82 | suspicious / 65 |
| `otar.nl` | malicious / medium / 82 | suspicious / 65 |

Google's own crawler domain, Google's own bot documentation, Apple's own bot
documentation, and a MITRE page — all currently rated **malicious at risk
82**. Every row that loses severity is itself a false positive. Disabling
loses no true positive and fixes five more.

## Switched off

`Settings.brand_reference_signal_enabled`, default `False`, gating the emit
in `http_collector`. The rule is kept rather than deleted so the switch
carries its measurements and re-enabling is one setting if a replacement is
not ready.

**Not retroactive.** New analyses use the corrected logic; historical
verdicts keep their stored classification and will carry a `superseded`
record as they are naturally re-analysed — which is how `live.com` corrected
itself. A sweep that silently re-graded a third of the corpus would be the
event, not the fix.

## What a fix has to avoid

The obvious repair — add the missing domains to a brand-ownership list — is
the eighth hand-maintained list, and `live.com` is only the one that happened
to be investigated. The alternatives worth weighing:

* decide ownership from **evidence already collected** rather than a list:
  the hosting ASN org (`evidence_json->'hosting'->>'asn_org'` reads
  `Microsoft Corporation` for `live.com`), the TLS certificate's issuer and
  SANs, the WHOIS registrant. All three are already in the payload;
* require the mention to be in **rendered text or a form action**, not
  anywhere in the body — which removes the `<script src>` case that is 90.7%
  of the Google flags;
* and separate the two claims the rule currently conflates: *"this page
  mentions a brand"* (true of most of the web, worth no score) from *"this
  hostname imitates a brand"* (the lookalike shape, currently exempted).

Of the three, **rendered text or form action first**: it is the only one that
needs no list at all, and it kills two-thirds of the signal outright — the
Google Fonts/Analytics/reCAPTCHA matches are `<script src>` hits that vanish
the moment the match stops running against the raw body.

**Ownership-by-evidence needs a third state.** Anything behind a CDN reads
`Cloudflare` in `asn_org`, so "no evidence of ownership" must mean
**unknown**, not *not-owned* — otherwise the same inversion returns wearing
better evidence.

**Splitting "mentions" from "imitates" should happen regardless.** They are
one field carrying two claims, and only one of them is a detection.

And whatever is built must not be list number nine.

## The rule

**Containment is not ownership, and it is not identity.** Three times in one
day the same substitution: ThreatFox's `search_ioc` matching
`nlahtc.theluxehomeoffice.com` against `office.com`; an IP comparison that
would match `11.2.3.40` against `1.2.3.4`; and a brand check asking whether
the brand's name appears inside the hostname. Each time the test was a
substring where the question was "is this the same thing, or does this belong
to that thing" — and each time it failed in both directions at once.
