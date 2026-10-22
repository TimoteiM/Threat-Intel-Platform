# Defender for Office 365: what the credential reaches, and what email content would leak

> Measured 2026-10-22, read-only. GETs only — no write, no action endpoint,
> and in particular **no isolate call** was made, despite the credential being
> able to make one (see §1b).
>
> All identifier probes in §3 use **invented** values. No real email was read;
> the credential cannot reach any email surface.

Answers steps 1 and 2 of the MDO integration request. **Step 1 is blocked on
a console action, and the app registration is the wrong one.** Step 2 is half
answerable without the credential and that half is done.

---

## 1. The credential: valid, and not for this job

### 1a. Identity of the app

| claim | value |
|---|---|
| token request | **HTTP 200** on all four audiences tried — the secret is correct and unexpired |
| `tid` | `ed83fd36-beab-445f-b653-60fe5d3b63c4` |
| region | **EU**, commercial cloud (`microsoftonline.com`) |
| `idtyp` | `app` (client-credentials, app-only) |
| **`app_displayname`** | **`Windows Defender - Device Isolation`** |

The display name is the finding. This registration was created for a
**Defender for Endpoint response action**, not for reading Office 365 email.

### 1b. The `roles` claim, per audience — the whole answer in one table

| audience | roles granted |
|---|---|
| `graph.microsoft.com` | **0 — empty** |
| `manage.office.com` (Management Activity API) | **0 — empty** |
| `api.security.microsoft.com` (XDR) | **0 — empty** |
| `outlook.office365.com` (Exchange) | **0 — empty** |
| **`api.securitycenter.microsoft.com`** (Defender for **Endpoint**) | **5**: `Machine.Isolate`, `Machine.Read.All`, `Ip.Read.All`, `Ti.Read.All`, `Ti.ReadWrite` |

So the credential is a **device-containment and threat-indicator-write
credential for Defender for Endpoint**. It has no permission on any
Office 365 or Graph surface at all.

**Two of those five are not read-only.** `Machine.Isolate` cuts a machine off
the network; `Ti.ReadWrite` writes threat indicators. That is a containment
capability sitting in plaintext `.env` on this box — a finding independent of
this integration, and worth establishing who issued it and whether this
platform should hold it.

### 1c. Every candidate surface, probed

| surface | HTTP | error |
|---|---|---|
| `v1.0 /security/alerts_v2` | **403** | `Missing application roles. API required roles: SecurityAlert.Read.All, …` |
| `v1.0 /security/incidents` | **403** | `Missing application roles. API required roles: SecurityIncident.Read.All, …` |
| `v1.0 /security/alerts` (legacy) | **403** | `Auth token does not contain valid permissions` |
| `beta /security/collaboration/analyzedEmails` | **401** | `Auth failed.` |
| `v1.0 /security/collaboration/analyzedEmails` | **401** | `Auth failed.` |
| `v1.0 /security/threatSubmission/emailThreats` | **400** | `Resource not found for the segment 'threatSubmission'` (not on v1.0) |
| `beta /security/threatSubmission/emailThreats` | **401** | — |
| `v1.0 /organization` | **403** | `Authorization_RequestDenied` |
| `v1.0 /subscribedSkus` | **403** | `Authorization_RequestDenied` |
| `manage.office.com …/subscriptions/list` | **401** | `AF10001 — The permission set () sent in the request does not include the expected permission` |

Note the Management Activity API error prints the permission set as `()` —
empty. It agrees with the roles claim.

### 1d. What to ask the console for, by name

**Stopping here, as instructed — this is a console action, not code.**

For *"flagged emails analysed the way alerts are"* the surface is **Threat
Explorer data via Graph**:

| # | permission | gets you | note |
|---|---|---|---|
| 1 | **`SecurityAnalyzedMessage.Read.All`** | `/security/collaboration/analyzedEmails` — the analysed-email records with verdicts, sender, recipients, URLs, attachments | **the one that matters.** Requires **MDO Plan 2** on the tenant — unverified, because `subscribedSkus` is 403 |
| 2 | `SecurityAlert.Read.All` | the *alerts about* email ("malware removed after delivery") | alert-level only, no message detail |
| 3 | `SecurityIncident.Read.All` | incident grouping | optional |
| 4 | `ThreatSubmission.Read.All` | user- and admin-submitted phish only | a narrow subset, not all flagged mail |
| 5 | **`Organization.Read.All`** | verified domains + licensing | **needed to settle §2**, and to confirm MDO P2 before asking for #1 |

**Quarantine has no Graph API.** `Get-QuarantineMessage` is Exchange Online
PowerShell, needing `Exchange.ManageAsApp` plus a directory role
(Security Reader or Quarantine Administrator). That is a different auth model
and a different client; it should be a separate decision, not bundled in.

### 1e. Ask for a NEW app registration, not these scopes on this one

Adding email-read scopes to `Windows Defender - Device Isolation` would put
mail-reading and machine-isolation behind **one secret in one `.env`**. A
separate, read-only registration for MDO ingest costs the console five
minutes and keeps the blast radius of this file from including containment.

---

## 2. What the vendor says this tenant is: **UNRESOLVED**, and the estate is mixed

The Falcon check ended in a confirmed answer (c00 = CID `eed7e418…`). **This
one does not, and the honest status is unresolved.**

Both vendor-side identity routes are refused:

* `v1.0 /organization` → 403
* `v1.0 /tenantRelationships/findTenantInformationByTenantId(…)` → 403
  (`CrossTenantInformation.ReadBasic.All` not granted)

So the only name we have for this tenant is the GUID in our own `.env`, which
is not independent evidence.

### What the one permission we do hold shows

`Machine.Read.All` enumerates the device inventory. **519 devices, read to
completion** (no `@odata.nextLink` remaining — this is a count, not a floor),
14 distinct DNS suffixes:

| devices | DNS suffix |
|---|---|
| **272** | **(no domain suffix)** |
| 183 | `int.expertware.net` |
| 20 | `dkv.ergo-service.belgium.io.ergo` |
| 14 | `oned.net.intra` |
| 14 | `hamburg-mannheimer.ergo-service.belgium.io.ergo` |
| 3 | `getronics.int-it.net` |
| 2 | `finance.expertware.net` · `pwcglb.com` · `expertware.ro` · `lab.expertware.net` · `ecolux.lan` |
| 1 | `dkcore.local` · `tek-experts.com` · `workgroup` |

Rolled up: **189 Expertware** (`expertware.net` 187 + `expertware.ro` 2),
**34 ERGO-affiliated** (`io.ergo`), and 23 across five other suffixes. Of the
**247** devices whose domain is identifiable, **189 (76.5%) are Expertware and
58 are not**. The remaining **272 (52.4%) have no suffix and are unresolved**.

### Three caveats, because this evidence is weaker than it looks

1. **A domain join is not ownership.** A consultant's laptop joined to a
   client domain during an engagement is indistinguishable from a
   client-owned device here. For a consultancy that is the *more* likely
   reading.
2. **Device AD domains say little about M365 mailboxes.** MDO's email scope is
   mailboxes in this Microsoft tenant, a different population that
   `Machine.Read.All` cannot enumerate. So this does **not** establish that
   the email data would be mixed.
3. **52.4% is unresolved**, so even 76.5% is a figure about the identifiable
   subset, not about the tenant.

### The consequence for the integration

**Labelling this source `c00` is not yet justified.** `c00` is
`internal_estate` — Expertware's own machines — and this tenant is
demonstrably not purely Expertware at the device layer, with the mailbox
layer unmeasured. Under the standing rule (*never run a c00 query for another
tenant; do not infer a tenant from a self-declared value*), the source label
needs either `Organization.Read.All` → verified domain list, or a human
answer, before any row is written as `c00`.

---

## 3. Step 2: the identifier profile of email content

### 3a. What is blocked and stated as blocked

**The per-email identifier count cannot be measured.** It needs a real
sample, and no email surface is reachable (§1c). So there is **no figure to
set against the 4.09 identifiers per alert** measured for logs. That number
stays open and must not be guessed at from the structure of the API.

### 3b. What is answerable now, and is measured: our own boundary

This needs no vendor access — it is a property of our detectors, probed with
invented email-shaped content. **7 of 22 probes tokenised; 15 reached the
model in the clear.**

| class | caught | detail |
|---|---|---|
| **A — DISPLAY NAMES** | **0 / 5** | quoted `"Jane Doe"`, unquoted, comma form `"Mueller, Hans"`, alone, and inside a subject line — **none** |
| B — email addresses | **3 / 3** | `local@domain` is caught reliably, keyed or bare |
| **C — email-keyed accounts** | **1 / 4** | `recipient:`, `sender:`, `smtp.mailfrom=` all missed; only `user:` works |
| D — sending hosts | 1 / 2 | 3-label FQDN caught; **single-label host missed** |
| E — source addresses | 2 / 2 | IPv4 and IPv6 both caught |
| F — sender / auth domain | 0 / 2 | 2-label registrable domains not tokenised — **see 3d, this may be correct** |
| G — URLs, attachment names | 0 / 2 | `https://phishprobe.com/…`, `Invoice_AnaMaria_Q3.xlsm` |
| H — mailbox / group display | 0 / 2 | `Finance Team Romania`, `Ionescu Ana (Finance RO)` |

### 3c. Display names are the dominant class and nothing sees them

As predicted. Every `From`, `To`, `Cc` and `Reply-To` in every email carries
a person's name as free text, and **no detector we have will see one**. The
reason is structural, not a bug: every detector that works is either
context-free with a hard shape (an email address, an IP) or **keyed** by a
field name it recognises. A human name has neither — `Jane Doe` is two
capitalised words, indistinguishable from `Invoice Overdue`.

Class C is the same fault one level down: `_ACCOUNT_KEY` is
`username|user|accountname|samaccountname|account`. **It contains no email
vocabulary** — no `recipient`, `sender`, `mailfrom`, `from`, `to`. So the
keyed detector that works on log lines is blind to the keys email actually
uses.

### 3d. The sender domain should probably NOT be tokenised

Worth separating from the gaps. Tokenising `contosoprobe.com` in
`smtp.mailfrom=` would remove **the evidence the model needs to judge a
phish**. Sender reputation, lookalike domains and SPF alignment are the
analysis. So F being 0/2 is plausibly the right behaviour — but it should be a
**recorded decision**, not an accident of the 2-label rule, and the recipient's
own domain is a different matter from the sender's.

### 3e. The design consequence: tokenise by field, not by pattern

**The fix for display names is not a better detector.** `analyzedEmails`
returns **structured JSON with named fields** — sender display name, recipient
list, subject, attachment names are each their own key. A detector exists
because log text is unstructured and we must *guess* where an identifier is.
Here we do not have to guess.

So for this source: map each MDO field to a boundary `kind` and call
`tokenize_value(value, kind)` per field at ingest. Display names become a
solved problem by construction, and no pattern has to recognise a human name.
The pattern detectors stay for the free-text residue — the subject line and
the message body preview, which is where a name genuinely is unstructured and
where the 0/5 above still applies.

This is the thing to settle before step 4, and it changes the shape of the
ingest path: **field-mapped tokenisation, not `protect_outbound` over a
flattened blob.**

### 3f. One probe artefact, recorded

My first run reported sending hosts as 0/2, including the 3-label FQDN. That
was wrong: I used `.example`, which is not in the public-suffix list the host
detector relies on, so the zero was about my probe. With `.com`/`.net`/`.ro`
the 3-label FQDN tokenises. The real rule is **3+ labels tokenise, 2-label
registrable domains do not** — which is also what produced F.

The control that caught it was running the same value with a real TLD. A zero
is about the comparison until a known-present value returns non-zero.

---

## 4. Not done — steps 3 and 4

Untouched, as instructed. Step 3 (the source taxonomy and the retrofit
mapping) and step 4 (ingest path and UI label) wait on the scope grant and on
the tenancy answer in §2, because the label a row carries is exactly what §2
cannot currently justify.
