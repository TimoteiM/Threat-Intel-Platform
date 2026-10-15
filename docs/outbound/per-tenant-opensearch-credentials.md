# Proposal: per-customer OpenSearch credentials, scoped in the cluster

**For:** whoever owns the Wazuh and OpenSearch deployment. This needs your
ratification before we build the application side.
**From:** the Threat Analyzer platform team.
**Measured against the live cluster 2026-10-15. Nothing was changed.**

## What we are asking for

Today, which customer's logs a user can read is decided entirely by **our
application code** adding a filter to each query. We would like it decided by
**the cluster** instead: one OpenSearch user per customer, restricted by an
OpenSearch role to that customer's indices, with the platform holding a
separate credential per customer.

Then a query our code builds wrongly returns *that customer's data only*,
instead of everyone's.

## Why we are asking — the current state, measured

**The platform connects to `C00-Indexer` (OpenSearch 2.19.4) as the user
`admin`, holding the roles `all_access` and `own_index`, backend role
`admin`.** That is the cluster superuser. With that credential the platform
can read every index, write to them, delete them, and modify the security
configuration that would otherwise constrain it.

So the boundary between one customer's analyst and another customer's logs is
a `terms` filter that our own code chooses to add. **That filter has been
omitted twice:**

1. One query path read a configuration attribute that did not exist, and the
   surrounding code turned "attribute missing" into "no filter". The query ran
   across every document in the cluster. It was noticed only because a host
   count came back as 109 where we expected 5 — not by any test.
2. A second path still builds the filter conditionally: if the configured
   tenant field or its values are empty, the query is produced **without** the
   filter and succeeds. Verified this week. It is not currently exposed,
   because the values happen to be configured — but nothing structural
   prevents it.

Both were our defects, in our code, and both would have been harmless if the
credential could not see other customers' data in the first place.

There is one customer today, so neither incident disclosed anything. That is
the only reason.

## Two ways to implement it

Both move enforcement into the cluster. The first is index topology; the
second is cluster configuration. Either removes our application from the
trust path.

### Option A — separate indices per customer (preferred)

Each customer's Wazuh manager writes to its own index prefix, e.g.
`wazuh-alerts-c00-*`, `wazuh-alerts-c01-*`. An OpenSearch role per customer
grants read on that pattern only; an internal user per customer is mapped to
that role; the platform stores that user's credential against that customer.

**Relevant measurement:** all 120 indices behind the current pattern are named
`wazuh-alerts-4.x-YYYY.MM.DD` — **date only, with no customer, manager or
tenant in any index name.** So today a second manager writing into this
cluster under the default template would land in **the same daily indices** as
the first, and no index-scoped role could separate them. Option A therefore
requires an index-naming change at the manager or template level before it can
work at all. That is the part only you can decide.

Why we prefer it: a role restricted to an index pattern is simple to audit,
costs nothing at query time, and the separation is visible in `_cat/indices`
rather than buried in security configuration.

### Option B — document-level security on the shared indices

If customers are to keep sharing indices, the equivalent is an OpenSearch role
per customer carrying a document-level security filter on `manager.name` — the
same field our application currently filters on, but applied by the cluster to
every query from that credential, regardless of what the query says.

This is weaker than Option A in two ways: DLS is evaluated per document at
query time, so it has a cost on the large queries we already run; and the
separation lives in security configuration rather than in the index layout, so
it is less obvious to an auditor. But it still means **our code cannot bypass
it**, which is the whole point, and it requires no change to how Wazuh indexes.

## What changes on our side

- The **per-customer integration record becomes the single source of truth**
  for both the credential and the pin. Today we have two sources for the same
  fact: one query path reads global deployment settings, the others read the
  per-customer record. They agree only because there is one customer — and the
  global-settings path **cannot express "this customer" at all**, so it is
  removed rather than kept in step. A second source kept in agreement by
  discipline is the same bug waiting on a distraction.
- The `manager.name` filter **stays**, as defence in depth rather than as the
  sole control. We would rather have both and rely on neither.
- We would ask to **stop using the `admin` credential** for day-to-day
  querying. Note this has its own blast radius worth planning: that credential
  is currently used by every path the platform has to the cluster, so replacing
  it touches alert log retrieval, the estate DNS lookup and the health check at
  once, and anything we have not found yet fails closed rather than silently.
  We would rather discover that during a planned change than later.

## Costs, stated plainly

**Per customer, at onboarding:** a Wazuh manager, an index prefix or template,
an OpenSearch role, an internal user, and a credential handed to the platform.
That is five artefacts where today there are zero, and onboarding currently
takes none of your time.

**Operational, if Option A:** index templates and ISM/retention policies per
prefix rather than one set shared. The cluster currently runs 360 shards
across 120 indices — about 3 per index — and per-customer daily indices
multiply index count by the number of customers, which makes small-shard
proliferation a real consideration at ten customers in a way it is not at one.
Shard sizing is your call and we would follow your guidance on prefix
granularity (daily, weekly or monthly per customer).

**Operational, if Option B:** no indexing change, but DLS adds per-document
evaluation to every query, including the retention-wide aggregations we run.
One of those already timed out this week against 2.07 billion documents, so
this cost is not hypothetical and should be measured on a copy before it is
committed to.

**For us:** credential storage and rotation per customer instead of one
deployment-wide secret, and the work to remove the global-settings path.

## The deliberate inversion, which is the point

**Cross-customer queries stop being the default and become a separate,
explicitly authorised operation.**

Today, a query that forgets its filter searches every customer. After this, a
query that forgets its filter searches one customer, and searching all of them
requires a different credential, used by a different code path, for a stated
reason.

For an MSSP that is not a limitation — it is the correct shape. The question
*"have we seen this indicator at any of our customers?"* is a real and
valuable one, and it should be **opt-in**: a separate role with a deliberately
broader scope, used only by a path built for it, with each use recorded
against the person who asked. What we have now is the same capability
**opt-out** — available by accident to anything that forgets a filter, with no
record of who used it.

We would build the cross-customer path as its own feature, with its own
credential and its own audit, rather than inherit it as a side effect.

## What we need from you

1. **Will customer two get its own Wazuh manager, and can its indices carry a
   distinct prefix?** This decides Option A versus Option B, and it is the
   gate on everything else.
2. **Which option do you want**, given the costs above.
3. **Prefix and shard granularity**, if Option A.
4. **Is replacing the platform's `admin`/`all_access` credential with a scoped
   one acceptable**, and when would you want that change made.
5. **Who issues and rotates the per-customer credentials** — you, or us
   through a delegated mechanism.

## What we will not do until this is ratified

We will not build the application-side enforcement, because the two options
produce different boundaries: Option A means our code must own the index set
*and* the field filter; Option B means the field filter only. Designing for
the wrong one would be work thrown away, and worse, enforcement written against
the wrong model reads as protection without being it.

The two defects described above are recorded in our own tracker as the reason
for this proposal, and the second one is still open.

Internal references: `docs/design/opensearch-tenant-pin.md` (the full
inventory of every path that queries the cluster, and where each gets its
filter), backlog item 17.
