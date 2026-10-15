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

**This is the question that decides whether backlog 17 is preparation or an
incident, and the data cannot answer it.** If that account belongs to an
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

## What parts 2 and 3 will be, once part 4 is answered

- **Part 2.** The refusal moves into the client: no body reaches `_request`
  without a tenant `terms` clause the caller cannot supply or suppress, and the
  index set is resolved from the tenant rather than passed in. Same reasoning
  as `NOT NULL` with no default — make the mistake unwriteable rather than
  remembered.
- **Part 3.** A synthetically restricted principal, because no real one exists
  and an untested enforcement path first executes on the day a customer account
  is created. Every path from part 1, asserting on **the outgoing body**, not
  on the call site.
