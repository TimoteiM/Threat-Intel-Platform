# Who submitted this investigation request — specification

Admin and owner need to see the submitting user for each request: alert,
domain, URL, file, IP. Configuration changes already carry `configured_by`;
this is about requests.

**Specification only. Nothing built.**

## 1. What is recorded today: nothing, and there is a decoy

| request type | table | submitter column |
|---|---|---|
| domain | `investigations` | **none** |
| URL | `investigations` | **none** |
| file | `investigations` | **none** |
| IP | `investigations` (+ `ip_lookups`) | **none** |
| alert | `alert_body_investigation_runs` | **none** |
| *(email, a sixth in practice)* | `email_investigation_runs` | **none** |

`investigations` has `analyst_iterations` and `max_analyst_iterations` — both
counters, neither an actor.

**The decoy is `alert_body_investigation_runs.entity_user`.** Its own comment
says *"Who the alert is about … written at ingest from the alert body"*. That
is the account named in the log — frequently the compromised one. Wiring
attribution to it would render the victim as the submitter, on the one surface
where that mistake would corrupt an investigation. It is the obvious column to
reach for and it is the wrong one.

**The one precedent, and it should not be copied.**
`sandbox_analyses.requested_by` is `String(64)` — a free-text name, not a
reference. It satisfies "render something" and fails "store the user id": a
rename orphans it, and two people with one display name are
indistinguishable. The `users` table already solved this for Entra by keying
on the immutable `external_id` rather than the address, for exactly this
reason.

## 2. Roles, and the fact that `admin` is not global

`ADMIN_ROLES = (ROLE_OWNER, ROLE_ADMIN)`; `users.role` is
`owner | admin | analyst`. Owner additionally cannot be deleted, demoted or
deactivated by anyone (`_refuse_if_owner`).

**Role and tenancy are orthogonal, and this is structural rather than
incidental:** `tenant_scope.scope_of` contains **zero** references to `role`.
It reads `all_tenants` and `tenant_ids` only. So a *client-restricted admin*
is representable today — `role="admin", all_tenants=False,
tenant_ids=["c00"]` — and would hold admin rights over one tenant's data.

That all 28 accounts currently have `all_tenants=true` is a fact about the
data, not the model, and it is the expiring justification in backlog 17. **A
design that reads "admin" as "may see everything" is relying on that data.**

## 3. Creation paths: six sites, three tables, no chokepoint

    Investigation(...)                  db/repository.py
                                        services/alert_investigation_spawn_service.py
                                        tasks/batch_task.py
                                        tasks/watchlist_task.py
    AlertBodyInvestigationRun(...)      api/alert_investigations.py
    EmailInvestigationRun(...)          api/email_investigations.py

`repository.create_investigation` is the closest thing to a chokepoint and
three other paths bypass it. **A seventh type, or a fifth `Investigation(`
site, would ship with no attribution and nothing would raise** — the
silent-registry class, eighth instance of which was found yesterday at 19.1%
of account nodes.

**What guards it: the schema, not a test.** A test that enumerates creation
sites has to be updated when a seventh appears — which is the event it exists
to catch, so it is policing rather than structure.

Instead `submitted_by_kind` ends as **`NOT NULL` with no default**, over an
enum covering every world. A seventh creation path then cannot insert at all
without choosing one: the failure is at the first `INSERT`, in development,
with the column name in the error. **The absence becomes impossible rather
than detectable.**

No default is the load-bearing part. A default of `automated_ingest` would
make a forgotten human submission look like the ingest pipeline, which is
worse than a crash and indistinguishable afterwards.

### But it arrives in four steps, because one step drops tenant alerts

`NOT NULL` applied in a single migration fails **every insert between the
migration and the code deploy** — and `alert_body_investigation_runs` rows
are created by incoming tenant alerts, not by anything this team controls the
timing of. Dropped alerts are worse than the mislabel the constraint
prevents.

**What happens to an alert whose insert fails in that window: it is lost, and
silently.** Established rather than assumed:

* ingest is a synchronous `POST /alert-investigations/tenants/{tenant_id}`;
* there is **no dead-letter table and no failed-ingest record** anywhere in
  the codebase — grep for `dead_letter`, `failed_ingest`, `ingest_error`,
  `rejected_alert` returns nothing;
* the insert is not wrapped in a handler that records the failure, so the
  only trace is a 500 in an access log;
* a retry *would* be safe — `find_run_by_external_ref` provides dedupe — but
  **whether TraceCat retries a 500 cannot be established from this
  repository.** The caller is outside it.

So the window is not "some alerts arrive late"; it is "some tenant alerts are
never analysed and nothing records which". Hence:

| step | change | safe because |
|---|---|---|
| 1 | add `submitted_by_kind` **nullable**, no default | existing inserts unaffected |
| 2 | deploy every writer to populate it | new rows correct; old rows still null |
| 3 | backfill existing rows to `predates_attribution` (and the classifications in backlog 19) | nothing is inserting null any more |
| 4 | `ALTER … SET NOT NULL` | the column is already fully populated and every writer supplies it |

Step 4 is the only one that can fail, and by then it fails *at migration
time* on a column it can verify — not at insert time on a tenant's alert.
This is the standing rule that a rename is not a deployment, applied to a
constraint: the schema change and the code change cannot be simultaneous, so
the order has to make each half safe alone.

A source-scanning test may still be added as a *second* line, but it is not
the guard and must not be described as one.

## 4. The absence is five states, not a blank

`NULL` would collapse four conditions that mean different things to someone
reading an investigation:

| kind | meaning | user id |
|---|---|---|
| `human` | a signed-in person submitted it | present |
| `service_account` | an API-key principal with an identity submitted it | present (the key's principal) |
| `automated_ingest` | arrived through ingest with **no human actor** — the alert pipeline | absent, correctly |
| `predates_attribution` | created before this field existed; **an actor existed and was not recorded** | absent, unknowably |
| `recorded_unresolvable` | an actor **was** recorded and cannot be matched to an account | absent, but evidence exists |

`predates_attribution` means *nobody knows*, not *nobody submitted it*.
Rendering it as a blank cell beside genuinely unattributed automated requests
is the collapse rule 16 names — two states, one observation — in the place
where it would most mislead.

**`recorded_unresolvable` is a fifth world and not a flavour of the fourth.**
`predates_attribution` says the actor was never written down.
`recorded_unresolvable` says it *was* written down and the string does not
resolve — `sandbox_analyses.requested_by = 'admin'` is the live instance: a
role name, a deleted account or a literal, and nothing distinguishes them.
The difference is operational: it tells a later auditor to **go and look for
other evidence** (access logs, the row's timestamps, the artefact itself)
rather than conclude none exists. Folding it into
`predates_attribution` would close an avenue that is still open.

So: `submitted_by_kind` (not null, one of the five) and
`submitted_by_user_id` (nullable, FK to `users.id`), with a check that the id
is present exactly for `human` and `service_account`.

### And a recorded actor is not the same evidence as a reconstructed one

Resolving a display name to an id today is **an inference about the past**. A
renamed-and-reused account, or two people who once shared a display name,
resolves confidently and wrongly — and nothing will ever flag it, because the
result looks exactly like an actor captured at creation.

So provenance is stored beside the id:

| field | values |
|---|---|
| `submitted_by_provenance` | `recorded_at_creation` \| `reconstructed_from_name` |
| `submitted_by_resolved_at` | the date the name resolution was run; null for recorded |

A reconstructed attribution is then **recoverable if it turns out wrong** —
the date says which resolution pass produced it, so a later correction can
find every row it touched. Without the provenance the audit trail cannot
distinguish evidence from reasoning, which is the one distinction an audit
trail exists to hold.

This is what makes resolving the 22 `sandbox_analyses` rows worth doing at
all (backlog 19): marked as reconstructed it is a defensible inference, and
stored bare it would be a fabrication with a confident face.

## 5. Store the id, render the name, survive deletion

Store `submitted_by_user_id`. Render `users.display_name`.

**A deleted account must still render as something**, and a render-time join
cannot do that — which is the ground-truth lesson already paid for here: a
snapshot that reads current state is not a snapshot. So the row also carries
`submitted_by_display` captured **at creation**, and the renderer prefers the
live join and falls back to the snapshot, labelled as historic.

Do **not** use `ON DELETE SET NULL` on the FK: it would turn `human` into an
indistinguishable blank and destroy the attribution the field exists for.
`ON DELETE RESTRICT`, or no FK constraint with the id kept as an opaque
reference — to be decided with whoever owns user deletion, since it changes
what deleting an account means.

## 6. Set at creation, never updatable

Not in any request model, not in any `PATCH`/`PUT` body, no service function
that writes it after insert. Enforced three ways, because one is a comment:

1. Absent from every Pydantic update model.
2. A test that greps the source for assignment to the attribute outside the
   creation sites.
3. Preferably a database trigger or `BEFORE UPDATE` rule rejecting a change —
   the only one of the three that survives a direct SQL fix.

Editable means it is a label. An audit record that can be rewritten answers a
different question from the one an investigation asks.

## 7. Can it ship before the tenancy gate? Qualified yes, enforced at the query layer

This exposes **staff identity across tenants**: a client-restricted principal
seeing *"submitted by <internal analyst>"* learns the names of the MSSP's
staff. Today no such principal exists — all 28 accounts are `all_tenants` —
but that is the data, not the model, and backlog 17 exists because it expires.

**It can ship, on one condition: the submitter is withheld from
client-restricted principals at the serialisation layer, not the UI.** The
mechanism already exists and is the right one — `tenant_scope.scope_of`
yields `all_tenants`, so:

* `all_tenants` principal → submitter rendered.
* client-restricted principal → the field is **absent from the payload**,
  not null and not empty-stringed, so a client UI cannot render a gap that
  looks like "nobody".

It must be absent rather than blanked for the same reason as everything else
in this document: a blank is a claim.

### Three conditions on shipping before the gate

**(a) The guard is dormant until onboarding, and that is a known property
rather than an oversight.** All 28 accounts are `all_tenants = true`, so the
restricted branch **never executes in production today**. Its first
production execution is the day a client account is created — the day it
matters most, and the worst possible day for a first run.

So the tests are the only real assurance, and they must be more than a
smoke check:

* a **synthetically restricted principal** (`all_tenants=False`,
  `tenant_ids=["c00"]`), constructed in the test rather than found in the
  database, since the database contains no such account;
* **all five request types** — alert, domain, URL, file, IP — because they do
  not share a path and the serialisers are separate;
* **the list endpoints as well as the detail ones.** A detail response is the
  obvious place to check and a list response is where a leak scales; the
  all-customers matrix already showed that a field attached to one view and
  not the other is the normal failure, not an unusual one.

**(b) Fail closed.** If `scope_of` cannot determine a scope — missing
identity, malformed `tenant_ids`, an exception — the submitter is **omitted**.
The error path is the one that gets exercised, and an error path that falls
through to *including* the field is a leak that only appears when something
else is already wrong. `scope_of` already returns
`TenantScope(all_tenants=False, tenant_ids=())` for an anonymous identity,
which is the right default; the serialiser must treat any failure to resolve
as restricted rather than as internal.

**(c) One enforcement point, or an asserted agreement.** Tenancy would then
be enforced in two places by two mechanisms — `tenant_scope` for row access
and a serialiser rule for field visibility — and **parallel enforcement
drifts.** Preference, in order:

1. Put the omission where `scope_of` already lives: a single
   `may_see_staff_identity(scope) -> bool` in `tenant_scope`, called by every
   serialiser, so there is one definition and the serialisers hold no policy.
2. Failing that, a test asserting the two agree across the matrix of scopes —
   but that is a second mechanism plus a test to keep them aligned, which is
   strictly worse.

**(d) Absent in the payload means absent in the UI.** Not an empty column: an
empty column reads as *"nobody submitted this"*, which is the collapse this
whole document is about, reintroduced at the last surface. The table renders
one fewer column for a restricted principal, and the column header is absent
too — a header over blank cells is the same claim.

## 8. The `entity_user` rename ships separately — backlog 20

The rename is right and **bundling it here was not.** 45 readers, a
dual-write release and a human verification step for the external API
contract is too much to carry alongside a security-sensitive feature, and it
makes the pair hard to revert: a problem with attribution would force a
decision about the rename, and vice versa.

**This change ships with the test only** — the submitter is never populated
from `entity_user`, asserted directly. That is necessary and admittedly
insufficient on its own; the name is what stops the next person, and the name
changes in its own release.

Specification and the 45-reader inventory: **backlog 20**.

## What this does not cover

* **Which** admin/owner may see it — the spec above says all of them, scoped
  as in §7. If submitter visibility should be owner-only, that is a different
  decision and changes §7.
* Retro-attribution from logs. Access logs may contain enough to reconstruct
  some pre-change submitters; §4 deliberately does not allow that to be
  written into `submitted_by_user_id`, because a reconstruction is a different
  grade of evidence from a recorded actor and would be indistinguishable
  afterwards.
