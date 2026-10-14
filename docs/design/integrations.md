# Per-tenant integrations

Built 2026-10-14, enrichment pass. Phase 0 reconnaissance is in
`integrations-phase-0-recon.md`; this is what was built on it.

> **If `INTEGRATION_ENCRYPTION_KEY` is lost, every stored integration
> credential is unrecoverable.** There is no escrow, no recovery code and no
> backdoor — that is what encrypting them means. The remedy is re-entering
> each credential by hand. Keep the key wherever this deployment keeps the
> things it cannot regenerate.

## Why tenant and not client

C00 is a **tenant**, not a client. `clients` has one row (Expertware SRL,
keyed by domain) and `tenants` has one row (`tenant_id = "c00"`, "the estate
behind wm-c00.siembiot.int"). Both point at Expertware, which is why they are
easy to conflate.

Credentials live on the tenant axis because **that is the axis carrying
authorisation**: `users.tenant_ids`, `users.all_tenants` and
`api_keys.tenant_ids` all scope by tenant, and nothing in this schema
authorises on `clients`. Key integrations on `clients.id` and "may this user
see this credential?" has no answer in the data — only an invented join. A
secret on an axis with no access control is a cross-tenant leak by default
rather than by bug.

The Defender case dissolves rather than needing a side: the *integration* is
per tenant — that is the credential and the connection — and what it produces
carries whatever scope the output naturally has. An email Defender flags
arrives through the tenant's integration and is then attributed to a client.
Two different things.

The page says "customer"; the key underneath is `tenant_id`.

## The status model

**"Enabled" is the word that cost seven months.** ThreatFox was enabled,
configured, present in the registry, and returning HTTP 401 on every call for
seven months; every flag the platform had said healthy. So no state here is a
boolean somebody set. Each is derived from a fact that cannot be asserted
into existence:

| state | derived from |
|---|---|
| `not_implemented` | no connector declares this tool |
| `not_configured` | no `tenant_integrations` row for this tenant and tool |
| `configured_unverified` | a row exists and no real call has ever been made |
| `verified_ok` | the last real authenticated call succeeded, at T |
| `verified_failing` | the last real authenticated call failed, at T, with a reason |

`configured_unverified` is the state that did not exist before and matters
most: **saved is not working**, and the old vocabulary had no way to say so.

### Two directions, never one badge

`health` is JSONB keyed by direction. An integration that answers queries and
has stopped delivering detections is healthy by one measure and dead by the
other, and one status would show green through exactly that. The overall
badge is the **worst** direction. A tool reports only the directions it
actually has — Falcon is enrichment-only this pass, so it is not
`not_configured` for ingest; it does not have ingest.

## The catalogue is derived

From the collectors that set `integration = True` — a property a connector
opts into, not a registry of tool names. A list of tools would be the ninth
hand-maintained list here and the eight before it each swallowed a feature
silently. `test_integration_catalogue.py` fails if one appears, and the guard
tokenises the source first so it matches code rather than the comment
describing it.

Registering a connector gets three things for free: the integrations page,
the per-verdict `source_coverage` expected set, and a row in the answer-rate
check — `source_answer_rate_service` derives its integration sources from the
same catalogue, so **a tenant's EDR going quiet is caught by the machinery
rather than by someone noticing.**

## Secrets

| | |
|---|---|
| at rest | Fernet (`cryptography`, already a dependency), `app/security/secret_box.py` |
| key | `INTEGRATION_ENCRYPTION_KEY`, separate from `SESSION_SECRET` so rotating one does not force the other |
| no key configured | **refused**, never stored in the clear — an outage and a breach must not share a code path |
| readable back | never. `PUT` accepts them; no response model declares a secret field |
| blank field on save | means *unchanged*. The UI is never given the value, so treating blank as "clear" would wipe a credential on every unrelated edit |
| in the config column | refused — `config` is returned through the API, so a credential there would be the write-only rule defeated by the back door |
| in logs, errors, audit | redacted at the source; `OpenedCredential.__repr__` is overridden so a traceback rendering locals cannot print one |

`test_integration_secrets.py` is the five-assertion pattern from the abuse.ch
key work, applied to each of those directions separately — a single "no
secrets anywhere" assertion would pass while any one of them held.

### Rotation

Present from day one, because a rotation added later has to handle rows
written under two schemes at once.

1. generate a new key, put it in `INTEGRATION_ENCRYPTION_KEY`;
2. move the old one to `INTEGRATION_ENCRYPTION_KEYS_RETIRED` (comma-separated);
3. `POST /api/integrations/rotate-keys` (owner-only);
4. when it reports `complete: true`, remove the retired key.

Every row stores `secret_key_id`, a truncated digest of the key that sealed
it. Without it, "every row re-encrypted" is a claim nobody can check — a
missed row is indistinguishable from a done one until the old key is dropped
and the credential is gone. `rotate_all` reports `unopenable` **by name**,
because those credentials must be re-entered and a count tells nobody which.

## Isolation

Every read takes a `TenantScope` as a **required keyword** — not a default of
`None` meaning "no filter", because a parameter someone forgets to pass must
never be the one that opens a credential table up. A restricted scope with no
tenants resolves to SQL `false`, not an absent filter.

A tenant outside the scope is **404, never 403**: a 403 confirms the row
exists, and enumerating ids against it tells you how many integrations your
competitor has.

`test_integration_isolation.py` constructs a restricted principal, because
**no real user would catch the failure** — all 28 users in this deployment
have `all_tenants = true` and `tenant_ids = []`, so an unfiltered query
returns exactly the rows a filtered one does. It also asserts that the test
*can* fail: `test_the_guard_can_fail` builds the unscoped query and checks
the detection catches it.

## Falcon, measured rather than assumed

Endpoints probed against the live tenant on 2026-10-14:

```
/detects/queries/detects/v1     404   the legacy Detects API is gone
/alerts/queries/alerts/v1       200
/alerts/queries/alerts/v2       200   <- used
/devices/queries/devices/v1     200   <- used
/devices/queries/devices/v2     404
/intel/queries/indicators/v1    403   access denied, scope not permitted
/iocs/queries/indicators/v1     403   access denied, scope not permitted
```

The first verify attempt returned HTTP 404 because the code used the legacy
path. That is why `verify` makes a **real authenticated call** rather than
stopping at a token: a token proves the credential is valid and proves
nothing about whether the API client can do anything.

### A finding worth carrying into the ingest pass

**The Alerts API does not validate FQL field names.** Measured:
`behaviors.domain`, `domain`, `indicator_id`, `filename`,
`behaviors.ioc_value`, `ioc_value`, `sha256`, `behaviors.sha256`,
`device.hostname`, `hostname`, `local_ip` and the invented
`behaviors.ioc_type` **all returned HTTP 200 with zero resources.** A field
that does not exist is indistinguishable, from the response, from a field
that exists and matched nothing.

That is the absence-as-answer shape handed to us by a vendor: a typo would
read as "this tenant's EDR has nothing on that host" for ever. Two
mitigations, neither a fix: `verify` records `estate_has_alerts` so a
permanently-empty filtered result is interpretable, and `falcon` is a source
in the answer-rate check so a field that never matches surfaces as 0% over a
meaningful window.

The Devices API *does* validate — `local_ip:'example-host'` returns 400 — so
the risk is specific to Alerts.

### The token expiry is checked, not discovered

Falcon's token lasts 1,798 seconds. It is read from `expires_in`, exposed as
`Token.expires_at` / `expired`, and refreshed inside a 120-second margin
rather than on the first 401. A missing `expires_in` is **not** defaulted to
something comfortable — the safe direction is the short one.

It registers with `credential_expiry_service`, not a private timer, so one
place knows which credentials are near expiry. That exists because the
Spamhaus SIA token was a JWT whose `exp` decoded to the day its integration
was committed, sat readable in the database, and nothing read it for 98 days.

The register excludes credentials whose whole lifetime is under an hour —
access tokens refreshed in the ordinary course of work — and reports the
exclusion count so it is visible rather than silent. Two bugs were caught
there on the first live run, both by the tests for the dangerous direction:
keying the exclusion on the token's own `near_expiry` flag (which a fresh
30-minute token sets False, so every token reported as near-expiry), and then
`remaining <= 3600` silently excluding **already-expired** credentials,
because `-86400 <= 3600`.

## What was deliberately not built

**Ingest.** It needs `_create_alert_run` extracted from
`app/api/alert_investigations.py` into a service first — five callers, a
private API function, and a Celery task would be a sixth importing from an
API module. It also brings a field map, where unmapped Falcon fields are
quarantined as `no_field_map` and never inferred, and Falcon's own MITRE
attributions as a third technique namer that must not quietly join
`rule_only`.

**The tenant does not yet reach an investigation.** It lives on
`alert_body_investigation_runs.tenant_id` and `tenant_id` appears nowhere in
`alert_body_investigation_service`, so threading it is a multi-signature
change through that module. `spawn_investigation` is ready to receive it, and
`FalconCollector` reads `external_context["tenant_id"]` — **when it is
absent, it makes no call and records an absence rather than falling back to
any configured credential**, which would be the cross-tenant read this whole
design exists to prevent. A tenant that reached some paths and silently not
others would be indistinguishable from one that worked, so it is named rather
than half-threaded.

**A tenants management page.** The integrations page has a tenant selector,
which is what it needs.
