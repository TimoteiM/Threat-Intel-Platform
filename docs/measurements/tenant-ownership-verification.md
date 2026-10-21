# Who do our configured credentials actually belong to?

Verified 2026-10-21 by asking each vendor, read-only. Re-run with
`scripts/verify_tenant_ownership.py`.

## First: the source map is empty

`config/client-sources.yaml` is `version: 1` / `clients: []`. It was built as
structure with nothing populated, which is what was asked for at the time. So
"for each client in the source map" has **no entries to iterate**, and the
question has to be answered from `tenant_integrations` — the Settings path —
which is where the three live credentials are.

Stating that rather than quietly substituting one source for the other,
because "the map says" and "the database says" are different claims and the
map currently says nothing.

## The table

| our `tenant_id` | mapped client | platform | what the vendor says this credential belongs to |
|---|---|---|---|
| `c00` | none in the map | CrowdStrike (falcon) | **CID `eed7e41845d04c26b4198f4c85f6216e`**, `machine_domain = int.expertware.net`, OU `Hybrid Joined Devices,Computers,ExpertWare`, `site_name = EXPERTWARE` — on **20 of 20** devices sampled |
| `lin` | none in the map | Exabeam | authenticates (HTTP 200); the token response carries **only** `expires_in` and `token_type`. **No identity of any kind.** |
| `pov` | none in the map | Exabeam | identical: 200, `expires_in`, `token_type`. No identity. |

Credentials were compared by a truncated SHA-256 of the key id, never by
value: `c00` `ae2cb716b111`, `lin` `48cb24fe3e2d`, `pov` `8ff55032e8e4`.

## Flag 1 — the vendor's answer is our own estate: **1**

**`c00` / CrowdStrike is Expertware's own estate**, and CrowdStrike says so
four different ways: the CID, the AD domain, the OU path containing
`ExpertWare`, and a site literally named `EXPERTWARE`. All 20 sampled devices
agree, so this is not a mixed estate with a few of our machines in it.

This was first suspected on 2026-10-16 (README rule 24). It is now confirmed
against the vendor's own identifiers rather than inferred, and **it is still
mapped to `c00`** — the tenant carrying **16,552 of 17,640 alert runs,
93.8%** of everything this platform has analysed.

What that means concretely: every finding, verdict, score distribution and
"client" statistic derived from `c00` is a statement about our own machines.
Nothing is wrong with the data; the label is wrong, and the label is what
makes it a customer report.

## Flag 2 — one credential answering for more than one tenant: **0**

`lin` and `pov` have different key fingerprints, so neither Exabeam
credential is shared. There is no key-scoping violation among the three
configured integrations.

This is the flag that no lower control can fix, so it is worth saying what
the check actually was: a hash of the key id, compared across tenants. It
would **not** catch two different keys issued against the same Exabeam
instance — which, given flag 3, cannot currently be detected at all.

## Flag 3 — no vendor identity to check: **2**

Both Exabeam tenants. Verification is **not possible**, which is a different
answer from "passed".

Exabeam's search API is the only contract this platform has evidence for, and
the token exchange is its only authenticated call. Its response is
`{expires_in, token_type}`: no scope, no tenant, no instance, no customer.

**And the data cannot answer either**, which is the fallback that would have
caught the Falcon mistake. A read-only search over 7 days:

| tenant | rows | fields actually returned |
|---|---|---|
| `lin` | 25 | **none** — the row objects are empty |
| `pov` | 25 | `time` only; `host`, `user`, `dest_host` absent |

So there is no estate-revealing field to inspect, with the field names this
platform knows. Both routes are closed. **Neither Exabeam credential can
currently be attributed to anyone.**

Reporting zero DNS suffixes as "not our estate" would have been an absence
read as a value — the empty result is about the fields, not the estate.

## Found while verifying: Exabeam's `total` is the page size

`SearchResult(rows, total, complete)` exists so a bounded read cannot be
mistaken for a complete one. Measured against the live API:

| requested limit | rows | `total` | `complete` |
|---|---|---|---|
| 1 | 1 | 1 | True |
| 5 | 5 | 5 | True |
| 25 | 25 | 25 | True |
| 100 | 100 | 100 | True |

`total` tracks `limit` exactly and `complete` is always `True`. The signature
is right and the value feeding it is wrong, so the guard built to prevent
exactly this failure currently certifies every truncated read as complete.
Filed as backlog 45.

`pov`'s config also still carries `data_lake_url` and `site_id` — invented
fields from the first, wrong version of the Exabeam spec. They are inert but
they are debris an operator filled in once.

## Closed incidents available to replay, per tenant

| tenant | closed cases | with `entity_host` | **analyst-closed** | runs | playbook coverage |
|---|---|---|---|---|---|
| `c00` | **2,118** | 2,118 | **5** | 16,552 | **54.4%** (9,012) |
| (unassigned) | 394 | 394 | 0 | 1,045 | 0.5% |
| `pov` | **9** | 9 | **0** | 23 | 0% |
| `lin` | **5** | 5 | **0** | 20 | 0% |

Closed-case range: `c00` 2026-10-07 to 10-21, avg 4.1 alerts per case; `lin`
and `pov` from 2026-10-19, avg 0.6 and 0.7 alerts per case.

Two columns matter more than the count:

* **`closure_kind`.** Of 2,526 closed cases, **5 were closed by an analyst**.
  The rest are `auto` (10-minute quiet period, 2,147), `expired` (176),
  `unreadable` (89), `merged` (59), `inherited` (50). A harness can *replay*
  an auto-closed case; it has nothing to *check its answer against*. The
  platform's own closure classifier already calls most of these
  `NOT_A_JUDGEMENT`.
* **playbook coverage.** The loop's predictable half is keyed on event class.
  `c00` has a class on 13,595 runs and a playbook row on 9,012. `lin` has a
  class on 3 runs and a playbook row on **none**; `pov` on none at all. So
  for `lin` and `pov` the harness would run the agent on every case, which
  measures the agent and not the loop.

## What this means for picking the first connector

The uncomfortable answer: **`c00` is the only tenant with enough material,
and `c00` is us.**

* `lin` (5 closed cases, 0% playbook coverage, unattributable credential) and
  `pov` (9, 0%, unattributable) cannot support a retrospective measurement.
  Five cases with no analyst verdicts and no playbook rows will not tell
  anyone whether the loop earns its queries.
* `c00` has 2,118 closed cases, 54.4% playbook coverage and a working,
  attributable CrowdStrike credential.

So the recommendation is to build the first connector against
**`c00` / CrowdStrike**, *because* it is our own estate: a read-only replay
against our own machines carries no customer-data risk, and it is the only
corpus large enough to measure the loop. That is a deliberate use of the
mislabelling, not an acceptance of it.

Two conditions on that:

1. **Relabel `c00` before any result is shown to anyone.** Any output from
   this replay is a statement about Expertware's estate. Presenting it as a
   client pilot is the 2026-10-16 mistake repeated with more evidence behind
   it.
2. **The 5 analyst-closed cases are the only ground truth that exists.** The
   harness's first output should be read against those five and nothing
   else — see "ground truth must record what was seen". Everything else is a
   replay with no answer key.
