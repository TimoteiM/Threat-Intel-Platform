# Backlog 17, parts 1 and 4: the current state of the OpenSearch tenant pin

**Measured 2026-10-15. Nothing changed.** Parts 2 (make the pin
unforgettable) and 3 (the test against a synthetic restricted principal) are
not started, pending the answer to part 4's open question.

## Part 1 — every path that sends a body to the cluster

### How completeness was established

Not by listing what I remembered. The cluster is reachable in exactly two
ways, and both were enumerated:

1. **Through `OpenSearchClient`**, whose only HTTP primitive is `_request`.
   Every call site of it was listed.
2. **By a direct HTTP call aimed at the cluster**, which requires reading the
   cluster's address. So: `grep` for every setting that carries it
   (`opensearch_nodes`, `opensearch_url`, `opensearch_host`,
   `OPENSEARCH_NODE`) across `app/`, excluding `opensearch_client.py` and
   `config.py`.

   **Result: no matches.** Nothing outside the client module reads the
   cluster's address, so there is no bypass path. That is the completeness
   argument — not "I looked at the three I knew about".

**Correction to the assumed set.** `alert_log_selection.py` was named as a
third path. It does **not** reach the cluster: it ranks records already
retrieved, and the `_request` matches in it are a local helper called
`_requested_value`. The set is two owners, not three.

### The paths

| # | path | who builds the body | where the pin comes from | can a caller influence the pin? |
|---|---|---|---|---|
| 1 | `OpenSearchClient.search_all` → `_page` | the client builds the envelope; **`body["query"] = query` comes wholesale from the caller** | **nowhere in the client** | **Yes — entirely. The client enforces nothing.** |
| 2 | `OpenSearchEstateClient.count_and_hosts` | the estate client | the per-tenant integration; `filters` list, unconditional | No — and it **raises** if the pin is missing |
| 3 | `OpenSearchEstateClient.first_last_seen` | same | same | No — same refusal |
| 4 | `OpenSearchEstateClient.observation_floor` | same | same | No — same refusal |
| — | `open_pit` / `close_pit` | the client | n/a — not a search; takes no query | n/a, but see the PIT note |
| — | `ping` | the client | n/a — `GET /` | n/a |

Only one caller uses path 1 today: `alert_log_context_service`, at two sites
(`_search_around` and the main context read).

### The defect in path 1, which is live

`search_all` accepts the whole `query` and adds no tenant clause. The pin
exists only because its single caller builds one in. And that caller's
builder makes it **conditional**:

```python
# alert_log_context_service.build_query
if tenant_field and tenant_values:
    filters.append({"terms": {tenant_field: list(tenant_values)}})
```

Both parameters default to `None`. The comment immediately above reads *"A
`filter`, not a `should`: this one is not negotiable against the entity
match"* — and the `if` makes it precisely negotiable. The caller supplies the
values as:

```python
tenant_field = str(getattr(settings, "opensearch_tenant_field", "") or "")
tenant_values = list(getattr(settings, "opensearch_tenant_value_list", []) or [])
```

So an unset `OPENSEARCH_TENANT_FIELD`, an empty value list, or a future call
site that simply omits the arguments produces a query across **every
tenant's documents**, successfully and silently. This is the same shape as the
pin that was already dropped once in `count_and_hosts` — `getattr(..., None)
or []` turning a missing attribute into *no filter*, caught by a host count
disagreeing with the recon and by no test.

**Verified, 2026-10-15:** calling `build_query` with no tenant arguments
returns a body with **one** filter clause (the time range) and no tenant
terms. It does not raise and does not return `None`.

**Latent, not active.** Live settings carry `manager.name` and one non-empty
pin value, so queries issued today *are* pinned. The exposure is that nothing
makes that structural.

### The contrast worth copying

The estate client already does the right thing:

```python
if not tenant_field or not tenant_values:
    raise RuntimeError(
        "this tenant has no log-store tenant pin "
        "(opensearch_tenant_field / opensearch_tenant_value_list), so "
        "the query is refused rather than run unpinned")
```

Two paths to the same cluster, one refusing and one silently proceeding. Part
2's job is to move that refusal **below** both of them, into the client, so a
fourth call site written next year cannot be written wrong.

### Two further observations for part 2

- **The index selection is also caller-supplied.** `search_all(indices=...)`
  and `open_pit(indices)` take whatever they are given, and with a PIT the
  indices come from the PIT rather than the request path. A pin on the query
  does not constrain *which indices* are searched, so the client boundary
  needs to own both.
- **Path 1 pins from global settings; paths 2–4 pin from the per-tenant
  integration.** Those are different sources of truth for the same fact. With
  one customer they agree. They will not necessarily agree with two, and the
  global-settings source cannot express "this tenant".

## Part 4 — are all 28 accounts ours?

| | |
|---|---|
| accounts | **28** |
| `all_tenants = true` | **28 of 28** |
| `tenant_ids` | `[]` on all 28 |
| roles | analyst 25, owner 2, admin 1 |
| `auth_provider` | **local on all 28** |
| identity domains | `expertware.net` 27, no e-mail 1 |
| non-`expertware.net` e-mail domains | **none** |

**27 of 28 carry an `expertware.net` identity.** No account carries a customer
e-mail domain. On that evidence `all_tenants = true` is plausibly correct for
every current user, and the gap is that the enforcement mechanism has never
executed — preparation, not an incident.

**One account cannot be classified from the data, and it is the one that
matters:**

| | |
|---|---|
| role | **owner** |
| auth_provider | local |
| e-mail | none |
| username | does **not** match `BOOTSTRAP_ADMIN_USERNAME` |
| created | 2026-09-23 06:32:45 UTC |
| last login | 2026-09-23 06:33:23 UTC — **38 seconds later, and never since** |
| must_change_password | false |
| active | **true** |

It is not the bootstrap account, it holds the highest role, it has no e-mail to
attribute it to anyone, it was used once at creation, and it is still enabled.

### What the host establishes, and what it cannot

Asked of the host rather than of anyone's recall, because the shape — created,
used once within a minute, never again, still enabled, highest privilege — is
the shape that resolved `svc-tools` three weeks earlier.

**Established:**

| | |
|---|---|
| interactive sessions that day | **exactly one** `Accepted`: `expert` from **10.10.126.103**, 05:35:22 → 15:23:55 |
| was a human on the box during the window? | **yes** — that session spans both 06:32:45 and 06:33:23 |
| sudo or any second principal in the window | none |
| what happened next | the **api container was restarted** at 06:34:15–06:34:18 — same container id stopped and started, so a `restart` and not a recreate — **52 seconds after the login** |
| does the platform record a creator? | **no.** `users` has no creator column: id, username, password_hash, role, active, created_at, last_login_at, must_change_password, auth_provider, external_id, email, display_name, all_tenants, tenant_ids |

**And the timeline turns out to be ordinary, which corrects my own framing.**
The API's create-user endpoint sets `must_change_password = generated is not
None`, and the change-password endpoint sets it to `False`. So:

> created 06:32:45 with a generated password → `must_change_password = True`
> → first login 06:33:23 → password set in that session → `False`

is **exactly** the row we observe. The 38-second gap between creation and the
only login is the signature of ordinary provisioning — someone creating an
account and the recipient logging straight in to set their password — not of
anything anomalous. The `svc-tools` resemblance does not survive contact with
the creation path. I raised it as alarming and the evidence says routine.

**Not established, and not establishable from this host:**

| question | why not |
|---|---|
| API call, bootstrap, or direct `INSERT`? | Postgres has `log_statement = none` and `log_min_duration_statement = -1`, so no statement was recorded and a direct insert would leave no trace. The api container from that day (`a635a3e0…`) **no longer exists** — the current one was created 2026-10-15 10:40:55 — so its json-file log is gone with it, and no access log was preserved from 2026-09-23. |
| who the account is for | no e-mail, no creator record, no SSO identity |
| whether the password change actually happened | nothing audits it; `must_change_password = False` is consistent with both an explicitly supplied password and a changed generated one |

It was **not** the bootstrap path: `_ensure_admin` only runs when `users` is
empty and creates `role="admin"`, and this row is `role="owner"`.

So the honest position on identity: a human with host access was present, the
row is shaped exactly as the normal API flow produces, and nothing recorded who
did it or for whom.

### Close it on its own merits, regardless of the answer

This does not depend on identifying the holder. An `owner` account with no
e-mail address, no SSO binding and `must_change_password = False` has:

- **no reset path** — nowhere to send a reset, so recovery means an
  administrator setting a password out of band;
- **no notification path** — nothing can tell the holder their account was
  used, changed or granted anything;
- **nothing to attribute an action to** — the highest privilege in the system,
  held by an identity that resolves to no person.

That is worth closing or attributing now rather than pending the
identification, and it is also the strongest argument for the submitter
attribution work: an audit trail whose actor column can hold this account
answers nothing.

**The original question still stands for the tenancy conclusion:** If that account belongs to an
Expertware person, the conclusion above holds. If it was created for anyone
outside Expertware, a customer-facing principal already holds `owner` with
`all_tenants = true` against an enforcement path that has never run, and this
stops being preparatory work.

Separately and regardless of the answer: an active `owner` account with no
e-mail, no SSO, a password that need not be changed, and one login two weeks
ago is worth closing or attributing on its own merits.

Also noted: **all 28 accounts are `auth_provider = local`.** The Entra SSO
work is built and gated off awaiting the Azure registration, so every
principal here is a local password today.

## Two things to resolve before part 2 is designed

### 1. How will tenants actually be separated? — and a factual precondition

Enforcement has to cover whichever control is primary, and both if the answer
is both. But one half of the question is already settled by measurement:

**Index scope cannot separate tenants today.** All **120** concrete indices
behind `wazuh-alerts-4.x-*` are named `wazuh-alerts-4.x-YYYY.MM.DD` — **date
only, with no tenant, manager or customer in any name.** So a second customer
writing into this cluster under the default Wazuh template lands in **the same
daily indices** as the first.

Consequences, stated precisely because they change over time:

- **Today**, `manager.name` is not merely the primary control — it is the
  *only* control that exists. Index selection chooses a date range, so a
  caller choosing indices or opening a PIT over them is making a
  data-volume-and-time-window choice, **not** a cross-tenant one.
- **The moment index separation is introduced** — a second Wazuh manager with
  its own index prefix or alias — index choice silently becomes a cross-tenant
  control, and the caller-supplied `indices=` argument and PIT indices become
  an isolation hole that does not exist yet.
- So index separation is a **deployment decision nobody has made**, and it has
  to be made before enforcement is designed, because the two answers produce
  different enforcement boundaries:

| if customer two… | primary control | what enforcement must own |
|---|---|---|
| shares this cluster and these indices | `manager.name` field filter | the query body only |
| gets its own manager with its own index prefix | index scope | **both** — the index set *and* the field filter as defence in depth |

**Both rows assume our code enforces the boundary, and that is what failed
twice.** The recommendation put to the Wazuh owner goes past both:
**per-customer OpenSearch credentials, role-scoped in the cluster**, so an
unpinned query returns one customer's data whatever our query builder does.
`manager.name` then becomes defence in depth rather than the sole control, and
the two sources of truth collapse — the per-customer integration becomes the
single source and the global-settings path is removed, since it cannot express
"this customer" at all.

The fact that makes this urgent rather than tidy: **the platform authenticates
to the cluster as `admin` with `all_access` and `own_index`** (verified
2026-10-15 via `/_plugins/_security/api/account`). It is the cluster
superuser — it can read every index, write, delete, and modify the security
configuration that would otherwise constrain it. Both of our filter defects
were therefore bounded only by there being one customer.

Written up for ratification in
`docs/outbound/per-tenant-opensearch-credentials.md`, with two
implementations (index-scoped roles, or document-level security on shared
indices if the indexing is not to change), the onboarding and operational
costs of each, and the inversion stated as the point: cross-customer search
becomes opt-in with its own credential and audit, instead of the opt-out it is
today.

**Parts 2 and 3 stay unstarted pending that ratification**, because the two
implementations produce different enforcement boundaries and enforcement
written against the wrong model reads as protection without being it.

### 2. One source of truth for the pin, with the other removed

Path 1 pins from **global settings** (`settings.opensearch_tenant_field`,
`settings.opensearch_tenant_value_list`); paths 2–4 pin from the **per-tenant
integration**. Two sources for one fact.

They agree only while there is one customer, which means **the disagreement
first appears on the day it matters** — and the global-settings source cannot
express "this tenant" at all, so it is the one that cannot survive customer
two. The resolution is one source, derived from the tenant, with the other
**removed rather than kept in sync**: a second source kept in agreement by
discipline is the same bug waiting on a distraction.

## What parts 2 and 3 will be

- **Part 2.** The refusal moves into the client: no body reaches `_request`
  without a tenant `terms` clause the caller cannot supply or suppress, and the
  index set is resolved from the tenant rather than passed in. Same reasoning
  as `NOT NULL` with no default — make the mistake unwriteable rather than
  remembered.
- **Part 3.** A synthetically restricted principal, because no real one exists
  and an untested enforcement path first executes on the day a customer account
  is created. Every path from part 1, asserting on **the outgoing body**, not
  on the call site.
