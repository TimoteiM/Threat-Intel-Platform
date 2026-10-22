# Every key in `.env`, validated in both directions

Run 2026-10-22 with `scripts/validate_env.py`. **Key names and verdicts only
— no value, value fragment, or value length is printed or recorded.**

Prompted by the Microsoft credential, where the key name carried trailing
whitespace and the container runtime silently dropped it. The question was
whether anything else is malformed, **in either direction**: a key that
should not be reaching a service and is, or — the one with no symptom — a key
that should be reaching a service and is not.

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

| problem | count | keys |
|---|---|---|
| key name has surrounding whitespace → **invalid env var name, silently dropped** | 3 | `MicrosoftClientId`, `MicrosoftClientSecret`, `MicrosoftTenantId` (L251–253) |
| value has leading/trailing whitespace → would reach the app verbatim | 3 | the same three |

Those two findings compound: the names are invalid *and* the values carry a
leading space, so had the names been written correctly the credentials would
have arrived with a space in front and failed authentication in a way that
reads as a wrong secret rather than a malformed file.

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

## Why this is now a script rather than a one-off

`scripts/validate_env.py` is checked in because the failure it catches has no
symptom. A malformed key produces no error, no log line and no failed
startup — the service simply runs with a default, and the only way to notice
is to compare the file against the process. That is the same shape as the
hand-maintained registries this codebase keeps finding, and the answer is the
same: derive the check, do not remember to do it.

Worth adding to `scripts/liveness.sh` as a limb, so a key added without
reaching the services fails a check rather than passing by not being looked
at. **Not done yet** — noted here so it is a work item rather than an
intention.
