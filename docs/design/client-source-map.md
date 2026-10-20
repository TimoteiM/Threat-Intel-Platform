# The per-client source map

**Built 2026-10-19. Structure, enforcement and tests only — no connectors, no
credentials populated.** What is still needed to fill it in is at the end,
along with what onboarding a new client looks like.

## The three pieces, and why they are separate

| | where | holds | reviewed by |
|---|---|---|---|
| **authoring** | `config/client-sources.yaml` | which client runs which platform, and the connection details for each | a pull request diff |
| **enforcement** | `tenant_integrations` (Postgres) | the same connection details, plus the encrypted credential | the database |
| **credentials** | `tenant_integrations.secret_ciphertext` | one secret per (client, platform), Fernet-encrypted | set through the API, never a file |

The file is a **control over** the database, not a second thing that claims to
know: `scripts/apply_client_sources.py --apply` writes it in, `--check`
reports any difference. This codebase has had eight registries where two
places both knew something, and they have been the bug every time — so the
file is reviewed, the database is enforced, and a difference between them is a
reportable fact rather than a question about which one is right.

A client gaining or losing a platform is a change worth reviewing, which is
the whole argument for the file existing at all.

## The control: a run carrying tenant X can only reach X's sources

**Enforced by Postgres, not by this platform's code.** Migration 072 puts a
row-level policy on `tenant_integrations`:

```sql
CREATE POLICY tenant_integrations_tenant_isolation ON tenant_integrations
    USING (tenant_id = current_setting('app.tenant_id', true));
```

**It binds because of the role separation built the same day.** Row-level
security does not apply to a table's owner, nor to a role with `BYPASSRLS`.
While the application connected as `threatintel` — superuser, owner of every
table — a policy here would have been decoration. It now connects as
`tip_app`, which owns nothing and has neither attribute. That ordering was not
incidental: the role split had to come first for this to be possible at all.

Measured as `tip_app`:

| query | rows |
|---|---|
| `SET app.tenant_id='c00'` then `SELECT count(*) FROM tenant_integrations` | c00's only |
| …then `SELECT count(*) … WHERE tenant_id='c01'` | **0** |
| …then `SELECT count(*) … WHERE tenant_id <> 'c00'` | **0** |
| no binding at all, `SELECT count(*) FROM tenant_integrations` | **0** |

The second and third rows are the control: **a query written to cross cannot**,
whatever the code intended. The fourth matters more — with nothing bound, the
table is empty, so a path that forgets to scope reads nothing instead of
everything. **It fails closed.**

A `WHERE tenant_id = :tid` convention holds on the queries somebody wrote.
This holds on the ones they have not written yet.

### What is enforced where

| layer | mechanism | holds against |
|---|---|---|
| database | the RLS policy above | any query, including one that explicitly asks to cross, and any path that forgets to scope |
| code | `sources_for(tenant_id, *, scope)` — `scope` is a **required keyword**, never defaulting to "unrestricted" | a caller resolving a client it has no right to; raises `TenantForbidden` rather than returning an empty list, because an empty list reads as "this client has no sources" |
| code | `bind_tenant()` uses `SET LOCAL` via `set_config()` with a bound parameter | a binding outliving its transaction and leaving a pooled connection bound to the previous caller's tenant; and a tenant id interpolated into SQL |
| file | the loader refuses any `connection` key matching `token|secret|password|credential|api_key|private` | a credential reaching a committed file, where no rotation removes it from the history |
| file | every `connection` key must be declared in the platform's `config_fields` | a typo becoming a silently ignored setting |

### The tests

`tests/integration/test_client_source_isolation.py` — six tests against a real
Postgres **as the real restricted role**, because the thing being tested is a
database policy and a fake session cannot refuse a query. The important ones
try to cross and must fail.

That file builds its `tip_app` connection explicitly rather than using
`DATABASE_SYNC_URL`, and asserts before anything else that it is not a
superuser and not the table's owner. **This was not caution — the first
version inherited `DATABASE_SYNC_URL` and read 2 rows from an unbound
session**, because on this box `.env` still points that variable at
`threatintel` for host-side use. Every assertion would have passed as the
owner and proved nothing. See "Still open" below.

`tests/unit/test_services/test_client_sources.py` — 29 tests on the map
itself: what it refuses, and that the three platforms reach the derived
catalogue rather than becoming a ninth hand-maintained list.

## The platforms

Declared in `app/services/client_sources.py` as `INTEGRATION_SPECS`, which
`integration_status_service.catalogue()` picks up alongside every other
integration. So the status page, the credential service's tool check and the
config-field schema all see them with nothing to update.

| platform | connection fields (in the YAML) | required | credential (API only) |
|---|---|---|---|
| **exabeam** | `base_url`, `data_lake_url`, `site_id` | `base_url` | `api_key` |
| **sentinelone** | `console_url`, `site_ids`, `account_id` | `console_url` | `api_token` |
| **cortex** | `api_url`, `tenant_name` | `api_url` | `api_key`, `api_key_id` |

A client may run any combination; `platforms:` is a list.

---

## What I need from you to fill this in

**1. The client list.** Per client: the `tenant_id` to use, and the display
name. `tenant_id` must match `tenants.tenant_id` — there are 4 rows in that
table today.

**2. Which platforms each client runs.** One of the three above, or several.
If a client runs something not in that list, say which and it gets a spec.

**3. The connection details per platform**, exactly the fields in the table
above. Nothing else is accepted — an undeclared key is refused rather than
ignored. If a field I have declared turns out not to exist for a given
deployment, or one is missing, that is a spec change and worth telling me.

**4. The credentials — but not to me, and not here.** Each goes in through the
API once there is a connector, one per (client, platform). The requirement
worth restating because it is the one that cannot be fixed later: **a key
scoped to more than one client's platform defeats the whole arrangement.** A
SentinelOne service user with access to two sites, or an Exabeam key valid
across instances, makes cross-tenant reach a property of the credential, and
no policy in this database can undo that. If the provider will only issue a
broad key, that is worth knowing before the structure is populated, because
the answer is a different integration design, not a different config file.

**5. Names are not needed — decided 2026-10-20.** The map carries `tenant_id`
only. A name in the file would duplicate `tenants.name` and could disagree
with the row it copies, and it would put the customer list in the
repository's history, which no rotation undoes. A `name:` key is now
**refused** by the loader rather than ignored, because a skipped key looks
like it worked and invites the whole list.

To read the map with names on, `scripts/apply_client_sources.py --render`
joins them from `tenants`:

```
zz-example  —  Example Client NV
    Exabeam (exabeam)
        base_url = https://aa.zz-example.internal
        data_lake_url = https://dl.zz-example.internal
        site_id = zz-example-main
        credentials (set via API, not shown here): api_key
    SentinelOne (sentinelone)
        account_id = a-3333333333
        console_url = https://zz-example.sentinelone.net
        site_ids = s-1111111111,s-2222222222
        credentials (set via API, not shown here): api_token
    Cortex XDR (cortex)
        api_url = https://api-zz-example.xdr.paloaltonetworks.com
        tenant_name = zz-example
        credentials (set via API, not shown here): api_key, api_key_id
```

A tenant in the map with no row in `tenants` renders as
`** NOT IN tenants — onboard this tenant first **` and exits 1, rather than
printing a blank name — a blank would read as a client whose name nobody
filled in, when the client does not exist in the database at all.

## What onboarding a new client would look like

Once this is populated, adding a client is five steps, of which only one is a
code change and none is a deployment:

1. **Create the tenant.** `PATCH /api/alert-investigations/tenants/{tenant_id}`
   — the onboarding action built earlier. Gives the client a row in `tenants`
   and a status.
2. **Add an entry to `config/client-sources.yaml`** with the platforms and
   connection details. **This is the reviewed step** — a diff showing a client
   gaining a platform is the point of the file.
3. **Apply it.** `scripts/apply_client_sources.py --apply`, then `--check` to
   confirm the database matches. Writes connection details only; never
   touches a credential.
4. **Set the credentials** through the integration API, one per platform.
   Write-only: nothing reads them back, and `tenant_integrations` is encrypted
   at rest and under the row-level policy.
5. **Verify.** "Test connection" per platform once connectors exist, and
   `scripts/check_db_privileges.sh` to confirm the policy is still in force.

No restart, no migration, no change to any other client. And the isolation
property is not something onboarding has to be careful about — a new client's
rows are invisible to every other client's queries by construction, not
because step 2 was done correctly.

---

## The host/container divergence, closed 2026-10-20

Until today `.env` pointed `DATABASE_SYNC_URL` at `threatintel` — superuser
and owner of every table — for host-side use, while the containers used
`tip_app`. **Row-level security exempts an owner**, so the policy protected
the containers and nothing run from the host venv. The isolation test caught
it only because one assertion checked the fail-closed direction and read 2
rows from a session bound to nobody; the cross-tenant assertion alone would
have gone green.

A control that holds in the container and not on a laptop is one ad-hoc script
away from a wrong conclusion about whether it holds at all.

**What changed:**

| variable | role | read by |
|---|---|---|
| `DATABASE_URL`, `DATABASE_SYNC_URL` | `tip_app` | everything that serves a request, in the container **and** on the host |
| `DATABASE_SANITIZER_URL` | `tip_sanitizer` | the token boundary alone |
| `DATABASE_MIGRATION_URL` | `threatintel` | `alembic/env.py`, `tests/integration/_scratch_db.py` (CREATE DATABASE), `scripts/apply_client_sources.py` — **nothing that serves a request** |

**Ownership is asked for by name.** There is no fallback: a caller that needs
DDL or a cross-tenant write names `database_migration_url`. Audited — those
three are its only readers, and every other consumer of a database URL takes
the application one.

**Two controls, so it cannot drift back:**

* `scripts/liveness.sh` has an **app role** limb. It connects on
  `DATABASE_SYNC_URL` from both the host venv and the api container and fails
  unless each answers `tip_app` and not-superuser. A role it cannot read is a
  failure too, because "could not check" is not "it matches". No dirty-tree
  exemption: the role a process connects as is not a property of the working
  tree.
* `tests/integration/test_client_source_isolation.py` now reads
  `database_sync_url` again — the real variable — and asserts the role it got
  is `tip_app`, not a superuser, and not the table's owner, before any
  isolation assertion runs. Together those make the test file a control on
  the divergence: re-point the URL and it fails loudly instead of passing
  vacuously, which is the opposite of what happened the first time.

## Still open

| | |
|---|---|
| ~~Host-side tooling connects as the owner.~~ **Closed 2026-10-20** — see "The host/container divergence" above. |
| **No connectors.** Nothing yet reads from Exabeam, SentinelOne or Cortex. The specs declare the shape; the query path that will use them does not exist. |
| **The credential columns are not separately restricted.** `tip_app` can read `tenant_integrations.secret_ciphertext` (it is encrypted, and `integration_credential_service` is the only decrypting module, write-only and scope-enforced). A column-level grant plus a dedicated role — the pattern used for the token map — would narrow it further. Not done: it needs the credential service to hold its own connection, which is a bigger change than this one. |
| **`apply --apply` never deletes.** A row in the database the file does not declare is reported and left alone. Deleting would mean a YAML edit can disconnect a client's platform. |
