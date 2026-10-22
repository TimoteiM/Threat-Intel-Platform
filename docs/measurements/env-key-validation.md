# Every key in `.env`, validated in both directions

Run 2026-10-22 with `scripts/validate_env.py`. **Key names and verdicts only
— no value, value fragment, or value length is printed or recorded.**

Prompted by the Microsoft credential, which is in `.env` and not in the
running containers. The question was whether anything else is malformed, **in
either direction**: a key that should not be reaching a service and is, or —
the one with no symptom — a key that should be reaching a service and is not.

> ## ⚠ Correction, same day: the whitespace was not the cause
>
> This document first said the trailing whitespace in `MicrosoftClientId `
> made it an invalid environment-variable name which the container runtime
> silently dropped. **That was wrong**, and the error mattered because it
> pointed at a harmless detail and away from a live risk.
>
> Measured by running a throwaway container against today's `.env`:
> `docker compose config` **trims the key name**, and a freshly created
> container receives all three Microsoft keys **and** `ALERT_CALLBACK_SECRET`,
> with **clean values** — the leading space is stripped too (`len 36` for the
> GUIDs, not 37).
>
> **The real cause is container age.** `env_file` is read when a container is
> *created*. The `api` and `worker` containers were created `2026-10-20
> 07:19`; `beat` at `06:09`. The keys were added to `.env` afterwards. This
> is precisely the ENV-drift failure mode `liveness.sh` was written for.
>
> **Two consequences of the correction, both worse than the original claim:**
>
> 1. I said "the reason the credentials never reached the running services is
>    an accident, not a control". Also wrong. There is no accident protecting
>    anything — the isolation credential is **one `docker compose up -d
>    --force-recreate` away from being live in three services**. And that is
>    the exact command `liveness.sh` prints as the remediation for the drift
>    it is currently reporting. Following our own tooling's advice would load
>    it.
> 2. **The existing env-drift limb was never blind to this.** Run today it
>    prints `ENV DRIFT: api=4 worker=4 beat=4` and names
>    `MicrosoftClientId MicrosoftClientSecret MicrosoftTenantId` individually,
>    and it exits 1. It has presumably done so since 2026-10-20. The control
>    worked; its output was not read. That is a different and more
>    uncomfortable failure than a blind spot.

---

## The method, and why it is not a lint

A static check of `.env` can only tell you what the file says. The question is
what the **running services** actually have, so the forward direction is
measured by comparing the file against `env` inside the `api`, `worker` and
`beat` containers. A declaration agreeing with itself is not a measurement.

The backward direction compares `Settings.model_fields` against the env vars
present in the container, so a field quietly running on its code default is
visible.

---

## Result: only the three Microsoft keys are malformed

**102 assignment lines.** No CRLF, no BOM. Clean on every other structural
check: **no duplicate keys**, no quoted values, no inline `#` comments inside
values, no tabs, no `$` interpolation hazards.

**Hard faults — the ones that gate: none.** No duplicate keys, no inline `#`
inside a value, no tabs, no CRLF, no invalid names after trimming.

**Advisory, measured not to break anything:**

| problem | count | keys |
|---|---|---|
| key name has surrounding whitespace — compose trims it | 3 | `MicrosoftClientId`, `MicrosoftClientSecret`, `MicrosoftTenantId` (L251–253) |
| value has surrounding whitespace — compose trims it too | 3 | the same three |

Severity here is set by measurement, not by how alarming the fault looks. Both
were first filed as hard faults on the theory in the correction box above; a
throwaway container disproved it, so they are advisory. They are still worth
printing, because they sent me to the wrong cause once.

### Forward direction — what does not reach the services

| service | env vars present | well-formed keys in `.env` | missing |
|---|---|---|---|
| `api` | 107 | 102 | **3** |
| `worker` | 107 | 102 | **3** |
| `beat` | 107 | 102 | **3** |

The three are the Microsoft keys. **Every other key written in `.env` reaches
all three services.** The bug does not have a second instance.

### Backward direction — fields running on code defaults

**174 Settings fields; 86 backed by an env var, 88 on the code default.** That
is mostly by design — most are tunables with sensible defaults — so the raw
count is not a finding. Narrowing to credential-shaped names gives 9, and on
inspection **5 of those 9 are a regex artefact**: `brave_search_base_url`,
`hybrid_analysis_base_url`, `spamhaus_sia_base_url`, `s3_endpoint_url` and
`anyrun_api_key_fallback` matched on a `_url`/`fallback` suffix and have
correct code defaults. Stated rather than quietly dropped, because "9
credentials unset" would have been a wrong headline from a right query.

Two that do mean something:

| field | consequence of being unset |
|---|---|
| **`alert_callback_secret`** | `alert_ingest_service.sign_payload` returns `None` when it is empty, so **outbound alert callbacks are delivered unsigned** — the receiver cannot verify the payload came from us. Checked in code, not inferred. |
| `correlation_webhook_url` | `case_event_task` returns early, so correlation webhooks never fire. Plausibly deliberate. |

`bootstrap_admin_username` / `bootstrap_admin_password` are also unset, which
is the **desired** state — no bootstrap admin exists.

### Declared but empty — intent recorded, value absent

The most informative output, because each is someone having decided to
configure something and not finished:

| line | key | reading |
|---|---|---|
| L159 | `OIDC_CLIENT_ID` | the Entra SSO, known blocked on the Azure registration |
| L160 | `OIDC_CLIENT_SECRET` | same |
| L163 | `OIDC_REDIRECT_URL` | same |
| L99 | `PHISHTANK_API_KEY` | that feed cannot authenticate |
| L134 | `PROXY_PROFILES` | no proxy profiles configured |
| L246 | `INTEGRATION_ENCRYPTION_KEYS_RETIRED` | empty is correct — no retired keys yet |

---

## Now a liveness limb — and what it does NOT duplicate

`scripts/validate_env.py --strict` is wired into `scripts/liveness.sh` and
gates it (`(( lint_bad == 0 )) || exit 1`). The line now carries
`env lint ok`, or the summary of what failed.

**It deliberately does not re-check drift.** The existing env limb already
does that correctly, per the correction above. What it adds is the three
things that limb is structurally unable to see, because it starts from
`docker compose config`'s already-normalised view rather than from the bytes
a human typed:

1. **Structural faults in the file** — duplicate keys, an inline `#` that
   became part of a value, CRLF, tabs. None produces a name mismatch, so
   drift comparison cannot detect any of them.
2. **The backward direction** — a `Settings` field with no env var behind it
   anywhere is not "declared but absent"; it was never declared, so there is
   nothing for a drift check to find. **This is the one that mattered**: it is
   how `alert_callback_secret` sat empty while every outbound callback went
   unsigned. No existing control looked at it.
3. **Declared but empty** — intent recorded, value absent.

### Both directions of the control were exercised

Against fixtures, not by editing the live `.env` — a check that has to mutate
the real credentials file to prove itself is one nobody runs twice:

| fixture | exit |
|---|---|
| clean | **0** |
| duplicate key | 1 |
| inline `#` in a value | 1 |
| CRLF | 1 |
| invalid name after trimming | 1 |

The complement matters as much as the failures: a gate that cannot pass is as
useless as one that cannot fail.

### The exemption list, and its premise

`DELIBERATELY_UNSET` names the settings that are empty on purpose, each with
its reason, and it is keyed **by name rather than by count** — so a new
unexplained default is a failure even if an old one is fixed in the same
breath. A count would let one hide behind another.

A carve-out added to silence a false positive is how a true one stays hidden,
so each entry is a claim that can be checked rather than a name on a list.
Today that list holds four, and `alert_callback_secret` is **not** on it — it
is flagged as unexplained, which is correct: it is now in `.env` but not yet
in any container, so the signature is not live until the services are
recreated.
