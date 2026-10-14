# Per-client Integrations page — Phase 0 reconnaissance

2026-10-14. No implementation. Six questions answered from the running system,
then the design consequences that follow from the answers rather than from the
brief.

---

## 1. What reads `CROWDSTRIKE_*`? Is there a Falcon client?

**Nothing reads it, and there is no Falcon client — not even half-built.**

| | |
|---|---|
| `CROWDSTRIKE_CLIENT_ID` / `_CLIENT_SECRET` / `_BASE_URL` in `.env` | all three present and non-empty |
| `Settings` fields for them | **none** — `config.py` has no `crowdstrike_*` |
| references anywhere in `backend/app` | **one**, and it is unrelated |
| `docker-compose.yml` mentions | none; they reach containers only via `env_file: .env` |

The single hit is `hybrid_analysis_service.py:159`, a
`"User-Agent": "Falcon Sandbox"` header against
`https://hybrid-analysis.com/api/v2`. That is the public Hybrid Analysis
service — CrowdStrike-owned, but a different product, a different API host
and a different credential from the Falcon platform
(`api.crowdstrike.com`). **There is nothing to reuse.** No OAuth client, no
token cache, no detection model, no field map.

So the credentials have been sitting in `.env` unread. Worth noting as the
same shape as the abuse.ch key before it was wired: a credential present
with nowhere to put it is not a configured integration. And the drift the
liveness check found (`worker` and `beat` missing all three) was therefore
harmless — but only by accident.

**Consequence for the build:** this is greenfield. That is good news for the
status model, because there is no half-state to reverse-engineer, and it
means the first state in the status model — *not implemented* — is the one
CrowdStrike is in today for every client.

---

## 2. Is there a `clients` table? Is C00 in it?

**There is a `clients` table. C00 is not in it. C00 is a `tenant`.**

This is the most important finding in the recon, because the brief says
"per-client" and names C00, and those are two different axes in this
schema.

### `clients` — one row

```
id uuid | name | domain | aliases jsonb | brand_keywords jsonb
contact_email | notes | status | created_at | alert_count
last_alert_at | default_collectors jsonb
```

| | |
|---|---|
| rows | **1** — `Expertware SRL`, domain `expertware.net` |
| keyed by | `domain` (indexed); no client *code* column |
| referenced by | `client_alerts.client_id`, `email_investigations.client_id` |

### `tenants` — one row

```
id uuid | tenant_id varchar(64) UNIQUE | name | status | notes | created_at
```

| | |
|---|---|
| rows | **1** — `tenant_id = "c00"`, `name = "Expertware (C00)"` |
| notes | *"The estate behind wm-c00.siembiot.int. Created by migration 030."* |

Both currently point at Expertware, which is why the two can be confused.
They are not the same thing:

* a **client** is a brand to be protected — `aliases` and `brand_keywords`
  feed impersonation detection, and `default_collectors` configures
  investigations;
* a **tenant** is an *estate* — the hosts behind one Wazuh manager.

### How each travels

| column | table | kind |
|---|---|---|
| `tenant_id` | `alert_body_investigation_runs`, `alert_case_spine` | trusted, set from the URL path |
| `tenant_assignment` | `alert_body_investigation_runs` | how the tenant was decided |
| `tenant_ids`, `all_tenants` | `users` | **authorisation** |
| `tenant_ids` | `api_keys` | **authorisation** |
| `client_id` | `client_alerts`, `email_investigations` | FK to `clients` |
| `client_domain` | `investigations` | free string, no FK |
| `alert_client` | `alert_body_investigation_runs`, `alert_case_spine` | **self-declared, untrusted** |
| `client` | `sandbox_analyses` | free string |

**Tenant is already the authorisation axis.** Nothing authorises on
`client`. And `alert_client` is the self-declared value the platform
already decided not to trust —
`docs/problems/` records that a tenant must not be inferred from it.

### Consequence for the build

**An EDR integration belongs to a tenant, not a client.** CrowdStrike Falcon
covers an estate of hosts; that is the thing `tenants` models and the thing
`users.tenant_ids` already restricts. Anchoring integration credentials on
`clients.id` would put them on the axis that carries no authorisation, and
would need a second isolation mechanism built from nothing.

Microsoft Defender — the stated follow-up, for emails Defender flags — is
the awkward case, because email investigation is `client`-scoped
(`email_investigations.client_id`) while Defender is an estate tool. That
tension should be settled now rather than after the first table exists.

**This needs a decision before anything is built.** The options are: anchor
on tenant and map clients to tenants where a client view is wanted; anchor on
client and build tenant-style isolation for it; or model the join explicitly.
Either way the page's title word and the schema's key should agree, because
"per-client" and `tenant_id` diverging in the same feature is how
`alert_client` happened.

---

## 3. Does auth have roles? Is there an admin concept?

**Yes, three roles, already enforced. No new concept needed.**

| | |
|---|---|
| column | `users.role varchar(20)`, not null |
| roles in use | `owner` (2), `admin` (1), `analyst` (25) |
| the check | `app/api/auth.py:259` `has_admin_rights(role)` against `ADMIN_ROLES` |
| enforced today on | user administration — role changes, activation, `_refuse_if_last_admin` |
| also | `auth_oidc.py` assigns `admin` from `oidc_admin_email_set`; bootstrap creates `admin` and `ingest` |

Owner carries every administrator right plus some of its own.

### The caveat that matters

**All 28 users have `all_tenants = true` and `tenant_ids = []`.** So tenant
scoping exists in the schema, has a service (`app/services/tenant_scope.py`),
and **is currently exercised by nobody**. Every user sees every tenant.

That makes the brief's requirement — *"test that a query without a client
filter fails"* — unusually valuable here, because no existing test or user
would notice a missing filter. There is no production traffic that would
reveal it. The test is the only thing that would.

---

## 4. How do alerts enter the pipeline?

**Five HTTP endpoints, all funnelling into one function.**

```
POST /api/alert-investigations                      body carries the tenant
POST /api/alert-investigations/raw
POST /api/alert-investigations/tenants/{tenant_id}  the path carries it
POST /api/alert-investigations/tenants/{tenant_id}/raw
POST /api/alert-investigations/extract
        ↓
_create_alert_run(request, db, identity, declared_via)   alert_investigations.py:532
```

The tenant-scoped path exists because of who sends alerts: NiFi cannot attach
an `Authorization` header — it is admitted by source address — but it can
template a path per flow, so the URL is the only channel through which it can
state the tenant. **The path overrides any `tenant_id` in the body**, and an
unconfigured or inactive tenant is refused with 400 rather than filed.

`_create_alert_run` already handles the two things a poller needs:

* **deduplication by `external_ref`**, taken from `_id` / `id` / `alert_id`
  in the alert — a Falcon detection id maps onto this directly, at any age;
* **body-level dedupe** within a window, and only failed or cancelled runs
  re-run.

### Consequence for the build

The named insertion point is `_create_alert_run`. Two notes:

1. **The existing endpoints are a *push* model; Falcon ingest is a *pull*.**
   Nothing would POST to us — a scheduled task would poll Falcon's detections
   API and call the insertion point directly. So the integration does not use
   the HTTP surface at all.
2. **`_create_alert_run` is a private function in an API module.** A Celery
   task importing from `app.api.alert_investigations` is the wrong direction
   of dependency. Extracting it into a service, unchanged, is a prerequisite
   — and it is the kind of move that should be its own commit with the five
   callers' behaviour pinned first, because this platform has been bitten by
   a second implementation of a shared path nine times.

---

## 5. Is there a config/settings table?

**No. Configuration is entirely `.env`.**

Searched `pg_tables` for `%setting%`, `%config%`, `%integration%`,
`%credential%` — **zero matches** across all 35 public tables.

| what exists | where |
|---|---|
| every provider credential | `.env` → `Settings` (pydantic), process-global |
| per-client collector choice | `clients.default_collectors` jsonb — the one per-client config that exists |
| per-tenant anything | `tenants` has `status` and `notes` only |

So there is no row-level configuration store, no encryption-at-rest
machinery, no secret-write-only surface, and no audit table. All of that is
new.

Two existing facts worth carrying into the design:

* `clients.default_collectors` is the precedent for per-customer
  configuration, and it is a bare jsonb with no validation against the
  collector registry. Whatever the integrations table looks like, its tool
  identifiers should be validated against the implemented connectors — which
  is the brief's "derived, not hand-kept" requirement, applied one level
  down.
* `.env` is read at **container creation**, not restart. The liveness check
  now reports env drift for exactly this reason, and three variables have
  already been in `.env` and in no container. A credential store in the
  database sidesteps that class of problem entirely, which is an argument for
  the table beyond multi-tenancy.

---

## 6. How are frontend pages added?

Next.js **App Router**. A page is `src/app/<route>/page.tsx`; a dynamic one is
`src/app/<route>/[id]/page.tsx`. 21 pages exist.

| | |
|---|---|
| nav registry | `src/lib/constants.ts` — `APP_NAV_SECTIONS` (4 sections) and a links array of `{ href, label, group, icon }` |
| sidebar | `src/components/layout/Sidebar.tsx` filters links by `group` and resolves `isActive` by prefix |
| closest analogue | `src/app/clients/page.tsx` (415 lines) and `src/app/clients/[id]/page.tsx` (490) |
| a settings page already exists | `src/app/settings/page.tsx`, linked from `SessionControl` as `/settings#account` |

The data pattern is the one in `investigations/[id]/page.tsx`: a
`fetchData` callback calling several `api.*` helpers in sequence and holding
each in its own state.

### Consequence for the build

* **`APP_NAV_SECTIONS` / the links array is a hand-maintained registry** —
  the frontend counterpart of the seven that have swallowed a feature
  silently in the backend. A new page that is not added to it simply has no
  route anyone can reach. Worth listing in the silent-registry note.
* There are two plausible homes and they are not equivalent: a tab under
  `clients/[id]` (or `tenants/[id]`, which does not exist yet) for the
  per-customer card grid, and a top-level page for the cross-customer
  matrix. The brief asks for both views, so both are needed — and the
  matrix is the one that answers "who has no EDR", so it should not be
  buried inside a per-customer route.
* **There is no `tenants` page at all.** If integrations anchor on tenant per
  §2, the per-customer view has no existing route to live in, and a
  `tenants/[id]` page becomes part of this work rather than a follow-on.

---

## What the answers change about the brief

Everything below follows from the recon, not from a preference.

1. **"Per-client" is probably "per-tenant."** C00 is a tenant; `clients` has
   no C00 and carries no authorisation. §2 needs deciding first — it
   determines the primary key of the main table, so it cannot be deferred.
2. **The status model's first state is already true of everything.** No
   connector exists for CrowdStrike, so *not implemented* is not a
   theoretical state — it is today's state for every tool, and the catalogue
   derived from implemented connectors would currently be empty of EDRs. The
   page has to read sensibly in that condition on day one.
3. **The dual status (enrichment / ingest) has a concrete asymmetry here.**
   Enrichment would be a collector in `COLLECTOR_REGISTRY`, which
   `source_coverage_service` already derives its expected set from, so it
   joins the answer-rate and per-verdict coverage machinery for free. Ingest
   has no registry — `_create_alert_run` has no notion of a source that
   should be delivering. That half needs the registration the brief asks
   for, built, not inherited.
4. **Client isolation cannot be tested against current users.** All 28 have
   `all_tenants = true`, so an unfiltered query returns the same rows as a
   filtered one and no existing test would fail. The isolation test must
   construct a restricted principal rather than rely on a real one.
5. **The OAuth-expiry requirement already has a home.** `docs/BACKLOG.md`
   item 7 — no credential in this system has an expiry check — was written
   from the Spamhaus JWT whose `exp` sat readable in the database while
   nothing read it. Falcon's token expiry should register with that
   mechanism rather than growing a private refresh timer, so there is one
   place that knows which credentials are near expiry.
6. **No table, no encryption, no audit exists.** §5. The secret-handling
   requirements are all new build, and the rotation path should be written
   before the first row is encrypted rather than after, because a rotation
   added later has to handle rows written by two schemes.
7. **`_create_alert_run` should be extracted before ingest, not during.**
   §4. Five callers, a private API function, and a new sixth caller from a
   Celery task.

## Not investigated, deliberately

* Falcon's API shape — detections schema, token lifetime, rate limits. That
  is vendor documentation and it only matters once §2 is decided.
* Microsoft Defender beyond noting the client/tenant tension in §2.
* What the field map for Falcon detections would contain. The brief already
  fixes the rule — unmapped fields quarantined as `no_field_map`, never
  inferred — and the mapping itself is ingest-pass work.
* Whether Falcon's MITRE attributions can be distinguished from rule-derived
  ones in its payload. It must not join `rule_only`, per the brief; whether
  the payload supports the distinction is a question for the ingest pass.
