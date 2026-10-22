# Three asks before we build the Defender for Office 365 integration

**From:** Threat Intel Platform engineering
**Date:** 2026-10-22
**Needs an answer from:** whoever administers the Microsoft tenant
`ed83fd36-beab-445f-b653-60fe5d3b63c4`, plus whoever issued the app
registration in ask 1.

We were asked to ingest Defender for Office 365 flagged emails into the
platform's alert list. Before writing any code we verified what the supplied
credentials actually reach. **Three things need a human answer, and we would
rather have them than build around them.** Each ask below has its evidence
attached; all of it is read-only and reproducible.

**Ask 3 grew while we were checking.** It began as "a read-only registration
for email". The coverage cross-check in ask 2 showed the estate runs two EDRs
and this platform reads only one, leaving **seven machines with no endpoint
source at all** in our investigations. Since a new registration is being
requested regardless, ask 3 now covers endpoint alerts as well — as a
**separately grantable group**, so email and endpoint can be approved
independently.

One of the three is a security finding we did not go looking for. It is
**ask 1**, and it is the one we would like answered first.

---

## Ask 1 — Who issued the device-isolation credential, and should we hold it?

### The ask

1. Who created the app registration **`Windows Defender - Device Isolation`**
   in tenant `ed83fd36-…`, when, and for what?
2. Was it a deliberate decision that the threat-intel platform holds a
   credential that can **isolate machines from the network** and **write
   threat indicators**?
3. If not — and we do not believe it was — please **revoke the client secret**
   (not merely remove it from our configuration; see below).

### Why we are asking

The credentials we were given for the email work belong to that registration.
Its permissions are not email permissions. Decoding the `roles` claim of
tokens it issues, per API audience:

| audience | application roles granted |
|---|---|
| `graph.microsoft.com` | **none** |
| `manage.office.com` | **none** |
| `api.security.microsoft.com` | **none** |
| `outlook.office365.com` | **none** |
| **`api.securitycenter.microsoft.com`** (Defender for **Endpoint**) | **`Machine.Isolate`**, `Machine.Read.All`, `Ip.Read.All`, `Ti.Read.All`, **`Ti.ReadWrite`** |

`Machine.Isolate` cuts a host off the network. `Ti.ReadWrite` writes threat
indicators that other systems act on. Those are **response capabilities**, not
read access, and they were sitting in a plaintext configuration file on the
platform host.

### What we have established about the exposure

We checked rather than assumed, and the news is mostly good:

| check | result |
|---|---|
| Does any platform code reference these credentials? | **No.** No match anywhere in the repository for the key names, nor for `securitycenter.microsoft`, `Machine.Isolate`, MSAL or the Azure identity SDKs. |
| Do they reach the running containers? | **No.** Zero matching environment variables in the `api`, `worker` and `beat` containers. |
| Were they ever committed to git? | **No.** The file is gitignored, has never been tracked, and the client ID appears in no commit in any branch. |
| File permissions | `600`, owned by the service account. |

So the platform has **never used this credential**, and it has not leaked
through our source control.

**One caveat, and it is an uncomfortable one.** The reason the credentials
never reached the running services is an accident: the three keys in the
configuration file carry **trailing whitespace in their names**, which makes
them invalid environment-variable names, so the container runtime silently
dropped them. Had they been written correctly they would have been present in
three containers. We are not relying on that as a control.

**And the credential is live.** We obtained valid tokens with it during this
check — the secret works and has not expired. Deleting our copy does not
revoke it, and we do not know where else it is stored or who else was given
it. Hence the request to revoke rather than just remove.

### What we are doing on our side

Removing the three keys from the platform configuration today. That is
unilateral and safe, because nothing reads them. We are **not** revoking
anything ourselves — if another system depends on that registration, revoking
it would break that system, and we cannot see what does.

---

## Ask 2 — What is this Microsoft tenant, in terms of whose data it holds?

### The ask

Grant **`Organization.Read.All`** (read-only) so we can enumerate the
tenant's verified domains — or simply tell us: **are the mailboxes in tenant
`ed83fd36-…` Expertware's own, or does it also hold other organisations'?**

### Why this blocks the integration

The platform labels data by tenant. `c00` is defined in our data model as
`internal_estate` — Expertware's own machines — and that label is enforced by
a database constraint precisely so a document cannot quietly relabel a
customer as internal. **We cannot currently justify writing email rows as
`c00`**, and we will not guess.

Both vendor-side routes to the tenant's identity are refused:

```
GET /v1.0/organization
  -> HTTP 403  Authorization_RequestDenied
               "Insufficient privileges to complete the operation."

GET /v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='ed83fd36-…')
  -> HTTP 403  Authorization_RequestDenied

GET /v1.0/subscribedSkus
  -> HTTP 403  Authorization_RequestDenied
```

So the only name we have for the tenant is the GUID we were handed, which is
not independent evidence. For comparison, the equivalent CrowdStrike check
ended in a confirmed answer; this one cannot.

### What the one permission we do have suggests

Using `Machine.Read.All`, the Defender for Endpoint device inventory reads to
completion — **519 devices**, no pagination remaining — across **14 DNS
suffixes**:

| devices | DNS suffix |
|---|---|
| **272** | **(no domain suffix recorded)** |
| 183 | `int.expertware.net` |
| 20 | `dkv.ergo-service.belgium.io.ergo` |
| 14 | `oned.net.intra` |
| 14 | `hamburg-mannheimer.ergo-service.belgium.io.ergo` |
| 3 | `getronics.int-it.net` |
| 2 each | `finance.expertware.net`, `pwcglb.com`, `expertware.ro`, `lab.expertware.net`, `ecolux.lan` |
| 1 each | `dkcore.local`, `tek-experts.com`, `workgroup` |

Of the **247** devices whose domain is identifiable, **189 (76.5%) are
Expertware** and **58 are not**, spanning at least five other organisations.

**Three caveats, because this evidence is weaker than the table looks**, and
we would rather state them than let the table be quoted on its own:

1. **A domain join is not ownership.** A consultant's laptop joined to a
   client domain during an engagement is indistinguishable from a
   client-owned device in this data. For a consultancy that is arguably the
   more likely reading.
2. **Device domains say little about mailboxes.** Office 365 email scope is
   mailboxes in the Microsoft tenant, a different population that
   `Machine.Read.All` cannot see. This does **not** establish that the email
   data would be mixed — only that we cannot establish it is not.
3. **52.4% of the inventory has no domain recorded**, so even 76.5% describes
   the identifiable subset, not the tenant.

That is exactly why we are asking rather than concluding.

---

## Ask 3 — One separate, read-only app registration, covering email **and** endpoint

### The ask

A **new** app registration with admin consent, read-only throughout. The
permissions are deliberately split into **three independently grantable
groups**, so you can approve one without the others:

#### Group A — email (the original request)

| permission | resource | why |
|---|---|---|
| **`SecurityAnalyzedMessage.Read.All`** | Microsoft Graph | `/security/collaboration/analyzedEmails` — analysed-email records with verdicts, sender, recipients, URLs and attachments. The surface that answers "flagged emails, analysed like alerts". |

#### Group B — endpoint (added after the coverage cross-check below)

| permission | resource | why |
|---|---|---|
| **`SecurityAlert.Read.All`** | Microsoft Graph | `/security/alerts_v2` — the unified alert stream. One scope covers **both** Defender for Endpoint and Defender for Office 365 alerts, which is why it sits here rather than in group A. |
| **`Machine.Read.All`** | WindowsDefenderATP | the device inventory. This is what produced the coverage finding below, and see the dependency note — we lose it when ask 1 is actioned. |
| `SecurityIncident.Read.All` *(optional)* | Microsoft Graph | incident grouping, so related alerts arrive pre-correlated |

#### Group C — tenant identity (needed for either of the above)

| permission | resource | why |
|---|---|---|
| **`Organization.Read.All`** | Microsoft Graph | answers ask 2 — the verified-domain list — and confirms the licence question below |

**If you grant only one group, grant C plus A or C plus B.** Group C is small,
read-only, and without it we cannot label incoming data correctly for either
product.

### Why group B is worth adding to the same conversation

This started as an email integration. The coverage cross-check we ran for
ask 2 changed the picture:

* **The estate runs two EDRs and the platform reads one.** We read CrowdStrike
  Falcon. We do not read Defender for Endpoint at all.
* **Seven machines have no EDR source in the platform today.**
  `exp-044036414857`, `exp-3brrpb4`, `exp-ops-46807`, `exp-ops-58255`,
  `exp-ops-81958`, `exp-ops-66927` and `cpc-alexa-gtfxm` are all Onboarded and
  Active in Defender, and invisible to us. When the platform investigates an
  alert on one of them it asks Falcon, gets nothing, and correctly reports
  "no EDR data" — which is true of our sources and false of the machine.
* **Our coverage reporting is systematically wrong in one direction.** Any
  figure computed from Falcon alone overstates the gap by however many hosts
  Defender covers. In the note we were about to send you, that was **7 of 19
  hosts — 37%** — and we corrected it before sending rather than after.

So group B is not scope creep onto a separate system; it closes a blind spot
in the thing the platform already does, using a registration you are being
asked to create anyway.

### A dependency between ask 1 and ask 3, worth stating plainly

**The coverage cross-check above was run with the credential we are asking you
to revoke.** `Machine.Read.All` on the isolation app is what let us enumerate
the 519 devices. Once that app is revoked we lose the ability to check EDR
coverage at all — so `Machine.Read.All` in group B is not a new capability,
it is the read-only half of what we already demonstrably use, moved onto a
credential that cannot also isolate a machine.

If asks 1 and 3 are actioned in that order with a gap between them, we simply
have no coverage visibility in the gap. That is acceptable; it is worth
knowing rather than discovering.

### One thing we could not determine and would like to know

**Is Defender antivirus in active or passive mode on those seven machines?**

`Machine.Read.All` reports `onboardingStatus: Onboarded` and
`healthStatus: Active`, which together mean the sensor is installed and
reporting in. **Neither field says whether Defender is actually blocking.**
A machine running Defender in passive mode alongside another product is
onboarded, active, and not preventing anything — it observes and reports.

That distinction decides whether those seven are genuinely protected or
merely visible, and it changes the answer to the licence conversation in the
coverage note. We cannot see it from the API with the permission we have;
it is readable in the Defender portal per device, or via
`AdvancedQuery.Read.All` (not requested here — see below).

### Please confirm one licensing fact

`analyzedEmails` requires **Defender for Office 365 Plan 2**. We could not
verify the tenant has it, because `subscribedSkus` is also 403 (see ask 2).
If the tenant is P1 only that surface does not exist and the email
integration needs a different design — worth knowing before group A is
granted.

### Why a new registration rather than adding scopes to the existing one

Adding these permissions to `Windows Defender - Device Isolation` would put
**reading company email** and **isolating machines** behind one secret in one
configuration file. A separate read-only registration keeps the blast radius
of that file away from response actions, and costs a few minutes in the
console.

### What we are not asking for, deliberately

* **Quarantine access.** There is no Microsoft Graph API for quarantined
  messages — `Get-QuarantineMessage` is Exchange Online PowerShell and needs
  `Exchange.ManageAsApp` plus a directory role. Different authentication
  model, larger grant, separate decision.
* **`AdvancedQuery.Read.All` / `ThreatHunting.Read.All`** (advanced hunting).
  This would answer estate-wide prevalence questions and the AV-mode question
  above, and we expect to want it later. We are **not** asking now, because
  it is effectively arbitrary-query access over the whole estate and deserves
  its own conversation rather than riding along with a read-only alert feed.
* **Anything that writes.** No `ReadWrite`, no action or response scope, in
  any group.

---

## Appendix — every surface we probed

All read-only `GET`s. No write and no action endpoint was called; in
particular **we did not call the isolate endpoint**, despite the credential
being able to.

| surface | result |
|---|---|
| token request, 4 audiences | **HTTP 200** — the secret is valid and unexpired |
| `v1.0 /security/alerts_v2` | 403 — `Missing application roles. API required roles: SecurityAlert.Read.All, …` |
| `v1.0 /security/incidents` | 403 — `Missing application roles. API required roles: SecurityIncident.Read.All, …` |
| `v1.0 /security/alerts` (legacy) | 403 — `Auth token does not contain valid permissions` |
| `beta /security/collaboration/analyzedEmails` | 401 — `Auth failed.` |
| `v1.0 /security/collaboration/analyzedEmails` | 401 — `Auth failed.` |
| `beta /security/threatSubmission/emailThreats` | 401 |
| `v1.0 /security/threatSubmission/emailThreats` | 400 — not present on `v1.0` |
| `v1.0 /organization` | 403 — `Authorization_RequestDenied` |
| `v1.0 /subscribedSkus` | 403 — `Authorization_RequestDenied` |
| `v1.0 /tenantRelationships/findTenantInformationByTenantId` | 403 — `Authorization_RequestDenied` |
| `manage.office.com …/activity/feed/subscriptions/list` | 401 — `AF10001: The permission set () sent in the request does not include the expected permission` |
| `api.securitycenter.microsoft.com /api/machines` | **200** — 519 devices |

Note the Management Activity API prints the permission set as `()` — empty.
It agrees with the roles claim.

Full technical write-up, including the identifier measurements that informed
the integration design:
`docs/measurements/defender-o365-credential-and-email-identifiers.md`
