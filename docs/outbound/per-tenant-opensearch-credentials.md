# OpenSearch access for Threat Analyzer: two changes, one of which needs nothing from you

**For:** whoever owns the Wazuh and OpenSearch deployment.
**From:** the Threat Analyzer platform team.
**Measured against the live cluster 2026-10-15. Nothing was changed.**

## The sentence this document is about

**Today a flaw in our application can delete a customer's security logs.**

Everything else here is about who can read what. That sentence is about whether
the evidence survives at all.

The platform connects to `C00-Indexer` (OpenSearch 2.19.4) as the user
`admin`, holding `all_access` and `own_index`, backend role `admin` — verified
via `/_plugins/_security/api/account`. That is the cluster superuser. It can
read every index, **write to them, delete them**, and modify the security
configuration that would otherwise constrain it.

The platform does not need any of that. It **only reads**. We have enumerated
every call it makes (below) and there is no write, no delete, no index
creation, no template change, no snapshot and no security API call anywhere in
it.

So the deletion capability is not a trade-off we accepted. It is a default
nobody chose.

## Two changes, and they have different prerequisites

This was previously written as one proposal with two options. That was wrong in
a way worth correcting, because it hid a dependency:

| | needs from you | can start |
|---|---|---|
| **Change 1 — a read-only credential** | nothing — no renaming, no new manager, one customer, one role | **now** |
| **Change 2 — per-customer separation** | the index-naming decision, and a Wazuh manager per customer | after you decide |

**Change 1 is step zero of Change 2, not an alternative to it.** And
specifically: **document-level security cannot work until Change 1 is done.**
In OpenSearch a user's effective access is the **union** of its roles, so a
role carrying a DLS filter on `manager.name` added alongside `all_access`
restricts nothing at all — the unrestricted role wins. A DLS role on a
superuser is decoration. As the earlier draft read, the two options looked like
alternatives and one of them was silently conditional on a step neither of them
named.

---

# Change 1 — a read-only credential (no prerequisites)

## Every call the platform makes to the cluster

Enumerated from the client code, not assumed. There are six, and they are all
reads:

| call | made by | why |
|---|---|---|
| `GET /` | `ping()` | health check and connection verification |
| `GET /_cat/indices/{pattern}?format=json&h=index` | `concrete_indices()` | so a 20-minute window names the two daily indices it needs instead of putting all 120 into the query |
| `POST /{indices}/_search/point_in_time` | `open_pit()` | a consistent view while paging |
| `DELETE /_search/point_in_time` | `close_pit()` | releasing it, so segments are not pinned |
| `POST /_search` (PIT in body) | log context paging | the alert's surrounding events |
| `POST /{pattern}/_search` | log context, and the estate DNS lookup's three aggregations | search and aggregate |

## The role we are asking for

Index permissions on the alert indices (today `wazuh-alerts-4.x-*`):

- the **`read`** action group — search, get, mget, msearch
- the **`search`** action group
- the **`indices_monitor`** action group — for `_cat/indices`
- point-in-time **create** and **delete** on those indices

Cluster permissions:

- `cluster:monitor/main` — the only thing `GET /` needs

And nothing else. No `indices:data/write/*`, no `indices:admin/delete`, no
`indices:admin/create`, no `cluster:admin/*`, no access to
`/_plugins/_security`.

**We are naming action groups rather than individual permission strings on
purpose.** The exact strings OpenSearch 2.19 requires for PIT and `_cat` are
the part most likely to be slightly wrong in a document, so the role should be
validated by *exercising all six calls above* with the new credential before
the old one is retired — not by us asserting the list is complete. We can run
that check and report the result.

## What breaks if the role is wrong — and the two failures that are silent

This matters more than the permission list, because two of the six fail
quietly by design.

| if this is missing | what happens | visible? |
|---|---|---|
| `cluster:monitor/main` | health check and integration verification report failure | **loud** — the card goes red |
| search on the indices | alert log context and the estate lookup stop returning anything | **loud** — everything stops |
| `indices_monitor` (`_cat/indices`) | the error propagates and the log-context read reports a failure reason | **loud** |
| **PIT create** | `open_pit` catches the refusal, returns `None`, logs at INFO, and **paging continues without a consistent view** — pages can skip or duplicate documents across a shifting index | **silent** |
| **PIT delete** | `close_pit` swallows the error at INFO and the PIT **leaks**, pinning segments and costing the cluster disk until it expires | **silent** |

**We have fixed the visibility on our side already, and not conditionally on
your answer.** A PIT can be refused by cluster pressure, a point-in-time limit
or a timeout — not only by a missing permission — so this was a live defect
regardless of what is decided here: log context could silently return a
narrower answer than the page claimed, while "no related activity" is a
conclusion analysts act on. A refused PIT now carries a named absence on the
result, downgrades the window's status to partial, states that pages may have
skipped or duplicated documents, and logs at WARNING rather than INFO. Logging
at INFO is not reporting.

**We measured it before telling you, and the news is good:** of **5,948**
searches that recorded the result, between 2026-09-24 and 2026-10-15, **zero**
had a point-in-time refused. **Ten** further follow-up reads did not record it
either way and are unclassified — about 0.2%, and we are not claiming them as
successes. So this was latent rather than an incident, on 5,948 known-good
observations and 10 unknown ones.

We are giving you the remainder rather than the round number because you are
making a permissions decision on it. Nothing would have reported a refusal if
there had been one, which is the defect; the figure is what the fix makes
visible from now on.

Grant the PIT permissions if you can, since consistent paging is worth having.
If you would rather not, say so and we will stop requesting one, which is a
different and now-distinguishable state from being refused.

## The blast radius is the argument for planning it, not for deferring it

The `admin` credential is used by **every** path the platform has to the
cluster. Replacing it touches alert log retrieval, the estate DNS lookup and
the health check at once, and anything we have not found fails closed rather
than silently.

That is a reason to do it as a planned change with the old credential held for
rollback, not a reason to leave a superuser in an application. Concretely:

1. You create the role and user; we configure it alongside the existing
   credential.
2. We exercise all six calls with the new credential and report each result.
3. We switch, with the `admin` credential retained and reversible for a stated
   window.
4. The `admin` credential is then rotated, because it has been in our
   environment file.

Point 4 is worth saying plainly: that credential has sat in our deployment
configuration, so it should be considered exposed to everyone who has had
access to this host, and rotated regardless of what else is decided here.

---

# Change 2 — per-customer separation (needs your decision first)

The goal: one OpenSearch user per customer, restricted to that customer's data,
so that **a query our code builds wrongly returns one customer's data instead
of everyone's.**

Why this is needed on top of Change 1: Change 1 stops us destroying data. It
does not stop one customer's analyst seeing another customer's logs, because
that boundary is still a `terms` filter our application adds. **That filter has
been omitted twice** — once because a configuration attribute did not exist and
the code turned "missing" into "no filter" (noticed only because a host count
came back as 109 where we expected 5, not by any test), and once in a path
that still builds the filter conditionally today. Both were our defects. Both
were harmless only because there is one customer.

## The decision that gates it

**All 120 indices are named `wazuh-alerts-4.x-YYYY.MM.DD` — date only, with no
customer, manager or tenant in any index name.** A second manager writing into
this cluster under the default template would land in **the same daily
indices**, and no index-scoped role could separate them.

So: **will customer two get its own Wazuh manager, and can its indices carry a
distinct prefix?** The two answers lead to different work:

| | how separation is enforced | cost |
|---|---|---|
| **Separate prefixes** (preferred) | a role per customer granting read on `wazuh-alerts-{customer}-*` | an indexing/template change at the manager; per-prefix templates and retention policies; index count multiplies by customer, and at 360 shards across 120 indices today, small-shard proliferation becomes a real consideration at ten customers |
| **Shared indices** | a role per customer with a DLS filter on `manager.name` | no indexing change, but per-document evaluation on every query — including retention-wide aggregations, one of which already timed out this week against 2.07 billion documents. Measure on a copy before committing |

Either way the `manager.name` filter in our code **stays**, as defence in depth
rather than as the sole control. We would rather have both and rely on neither.

## What it changes on our side

The per-customer integration record becomes the **single source of truth** for
both credential and filter. Today there are two sources for the same fact: one
query path reads global deployment settings, the others read the per-customer
record. They agree only because there is one customer, and the global-settings
path **cannot express "this customer" at all** — so it is removed rather than
kept in step. A second source kept in agreement by discipline is the same bug
waiting on a distraction.

## The per-customer artefacts are a script, not a checklist

Whichever model you choose, onboarding a customer creates several things: an
index prefix or template, a retention policy, an OpenSearch role, an internal
user, a role mapping, and a credential delivered to the platform.

**We will not implement that as a documented sequence of manual steps.** Five
or six manual steps per onboarding is a failure mode we have hit repeatedly at
the application layer: customer six gets four of five, and nothing reports
which one is missing — the gap is discovered later, by its consequence. At this
layer the consequence is a customer whose data is not isolated.

So onboarding emits the artefacts from **one definition**: a single declaration
per customer, applied by a script that is idempotent and that **verifies what
it created** — the role exists, the mapping resolves, and a query with that
credential returns that customer's data **and is refused another customer's**.

That last step is the only one that actually proves isolation, and **its
failure is fatal to the onboarding, not a warning.** A script that reports
"could not confirm isolation" and exits zero has onboarded a customer whose
data may not be separated, which is worse than not onboarding them — the same
reason a guard has to be seen refusing before it is trusted to permit. It is
also re-runnable afterwards, so isolation is something that can be
demonstrated on any given day rather than asserted once at setup.

We will build that against whichever model you ratify, and we would like your
review of the declaration's contents, since the Wazuh side of it is yours.

## The deliberate inversion, which is the point

Cross-customer queries stop being the default and become a separate, explicitly
authorised operation. Today a query that forgets its filter searches every
customer; afterwards it searches one, and searching all of them needs a
different credential, a different code path, and a stated reason.

For an MSSP that is not a limitation — it is the correct shape. *"Have we seen
this indicator at any of our customers?"* is a real and valuable question and
it should be **opt-in**: a separate role with a deliberately broader scope,
used only by a path built for it, with each use recorded against the person who
asked. What exists today is the same capability **opt-out** — available by
accident to anything that forgets a filter, with no record of who used it.

---

---

# Change 3 — split Sysmon's `Hashes` field at the decoder (same owner)

Travelling with the index-naming decision because it is the same owner and the
same kind of change: a Wazuh-side decoder edit.

## What the field looks like now

`data.win.eventdata.hashes` is well collected — **2,626,536 documents across
190 hosts**, spanning the full 120-day retention from 2026-06-17, so unlike
some of our telemetry it has no gap. Three Sysmon events produce it: 1 (Process
Create) 2,614,044, 7 (Image Loaded) 10,364, 29 (File Executable Detected)
2,128.

The problem is the value's shape. It is a single composite string:

    MD5=F63068E6…,SHA256=90D12088…,IMPHASH=D60B7706…

and there is **no parsed sibling field** — `data.win.eventdata.sha256`,
`.md5` and `data.hash.sha256` are all empty. So a search for a bare digest
cannot use a `term` on a keyword; we measured `term` and `match_phrase` at
**0 hits** against **18,571** for a leading wildcard on the same value.

## What we are asking for

Split `Hashes` at the Wazuh decoder into separate keyword fields — `sha256`,
`md5`, `imphash` — so a digest can be matched exactly.

What that buys: an exact `term` lookup instead of a leading wildcard. Our
measured costs for the wildcard, timed on a quiet cluster, median of three,
all complete (360/360 shards, 0 failed):

| window | median | hits |
|---|---|---|
| 24 hours | 83 ms | 455 |
| 7 days | 161 ms | 3,024 |
| 30 days | 422 ms | 13,442 |
| 120 days (full retention) | 1,682 ms (4,335 ms cold) | 27,363 |

We have shipped the hash question with a **7-day default and a 30-day
ceiling** on those figures, and the window is stated on the result rather than
assumed — beyond 30 days the platform says the cost is unmeasured rather than
guessing. A parsed field would remove the bound entirely.

## The part that needs your decision, not just your agreement

**A decoder change affects only new documents.** The existing 120 days keep the
composite form. So there are two outcomes and they are not equivalent:

- **Reindex the existing 120 days** so one query shape answers the whole
  retention window. This costs cluster time and needs planning, and it is the
  only option that leaves a single question with a single answer.
- **Leave the old documents as they are**, in which case the two paths answer
  **different questions**: an exact `term` covers everything after the change,
  and anything before it needs the wildcard. A query written against one will
  silently under-report on the other, and the boundary is a date nobody will
  remember in six months.

We would rather you chose than have us pick a default. If reindexing is not
practical, say so and we will carry both query shapes explicitly with the
changeover date in the code, which is uglier but at least cannot quietly
answer half the window.

One further note for whoever makes the decoder change: we pin to **event 1
only**. Not because the three producing events disagree about meaning — they
all mean "hashes of an image" — but because event 1 is the *execution* claim
and 7 and 29 are not. A question about what **ran** must not silently include
what was loaded into another process or what was merely seen on disk. Please
keep the event id available on the split fields.

## What we need from you

**For Change 1, which needs no decisions about the future:**

1. Create a read-only role and user as specified, so we can validate it
   alongside the existing credential.
2. Confirm whether the PIT permissions are granted. Not so we can decide
   whether to report a refusal — that is fixed either way — but so we know
   whether to keep requesting one.
3. Agree a window for the switch, and for rotating the `admin` credential
   afterwards.

**For Change 3 (the decoder split):**

8. Can `Hashes` be split into `sha256` / `md5` / `imphash` keyword fields at
   the decoder?
9. **Reindex the existing 120 days, or accept two query shapes with a
   changeover date?** This is the decision, not the split itself.

**For Change 2:**

4. Will customer two get its own Wazuh manager, and can its indices carry a
   distinct prefix? *(This is the gate on everything else in Change 2.)*
5. Separate prefixes or shared indices with DLS, given the costs above.
6. Prefix and shard granularity, if separate prefixes.
7. Who issues and rotates per-customer credentials — you, or us through a
   delegated mechanism.

## What we will not do until Change 2 is ratified

We will not build the application-side enforcement, because the two models
produce different boundaries: separate prefixes mean our code must own the
index set *and* the filter; shared indices mean the filter only. Enforcement
written against the wrong model reads as protection without being it.

Change 1 we would like to start as soon as you can create the role, because it
is independent of all of the above and it is the half that protects the logs
themselves.

Internal references: `docs/design/opensearch-tenant-pin.md` — the full
inventory of every path that queries the cluster and where each gets its
filter; backlog item 17.
