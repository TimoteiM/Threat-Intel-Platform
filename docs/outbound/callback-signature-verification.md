# Outbound callbacks are now signed — what the receiver must do

**From:** Threat Intel Platform engineering
**Date:** 2026-10-22
**Needs an answer from:** whoever owns the Tracecat workflows that receive our
callbacks.

We found that every callback this platform delivers was going out **unsigned**,
and we have fixed our half. **Your half is not done, and until it is, the
signature changes nothing.** That is the whole point of this note.

---

## What was wrong

`ALERT_CALLBACK_SECRET` was empty. `sign_payload()` returns `None` when it is,
so the `X-Alert-Signature` header was simply **omitted from every callback**.
Not a weak signature — no signature.

We do not know how long for. The setting has no default value and nothing logs
its absence, so there is no record to read.

## What we changed, today

A 32-byte random secret is generated and installed. Every callback from
`alert_callback_task` and `case_event_task` now carries:

```
X-Alert-Signature: sha256=<hex>
```

### The exact specification

| property | value |
|---|---|
| header name | `X-Alert-Signature` |
| format | `sha256=` followed by **64 lowercase hex characters** |
| algorithm | HMAC-SHA256 |
| key | the shared secret, as **UTF-8 bytes of the hex string** — not the decoded bytes |
| message | the **raw request body bytes, exactly as transmitted** |
| also present | `X-Alert-Event`, `X-Alert-Run-Id` (callbacks) / `X-Case-Event`, `X-Case-Key` (case events) |

Reference implementation — this is literally our code:

```python
import hmac, hashlib
signature = "sha256=" + hmac.new(
    secret.encode("utf-8"), body, hashlib.sha256
).hexdigest()
```

**Compute over the raw body, before any JSON parsing or re-serialisation.** A
receiver that parses the JSON and re-serialises it will produce different
bytes and every signature will fail. This is the single most common way an
HMAC integration fails.

### Confirming you have the right secret

The secret itself will be sent separately, through a password manager share —
not in this document, a ticket, or a chat message.

To confirm both sides hold the same value without transmitting it:

```
sha256(secret)[:16] = 8bb4ba6540fdc641
```

Compute `sha256` of the secret string you loaded, take the first 16 hex
characters, and check it matches. If it does not, you have the wrong value or
it has whitespace around it.

---

## The part that matters: verify, do not merely check

**Requirement: reject the request when the header is absent.**

We omit `X-Alert-Signature` entirely when our secret is unset. A workflow
written as *"if the signature header is present, verify it"* is **still
completely unauthenticated**, because anyone posting to your callback URL can
simply not send the header and take the other branch. The check must be:

1. Header absent → **reject**, HTTP 401. Do not process.
2. Header present but does not match → **reject**, HTTP 401.
3. Header present and matches → process.

Use a **constant-time** comparison (`hmac.compare_digest`, or your platform's
equivalent). A plain `==` on a hex string leaks timing information; it is a
weak attack but a free fix.

Reject on absence **and** on mismatch, with the same response, and log both.

---

## The question we need answered

**Can your Tracecat workflows verify an HMAC signature on an inbound webhook?**

We cannot determine this from our side. Tracecat appears in our codebase only
as a *sender* — it posts alerts to our ingest endpoint. The callback URL is
something Tracecat supplies to us per request, and we have no visibility into
what receives it or what that receiver checks.

So one of three answers, please:

| if | then |
|---|---|
| **Tracecat can verify** (a workflow action computing HMAC over the raw body, with the secret in its credential store) | tell us, we hand over the secret, and this is closed |
| **Tracecat can verify only with a custom action or pre-processing step** | tell us what you need from us to make that practical |
| **Tracecat cannot verify signatures at all** | then **the integration has no integrity check in either direction**, and that is a bigger conversation than this note — see below |

### If the answer is "it cannot"

Then signing is a precaution with no counterparty, and the honest statement is
that the Tracecat↔platform integration is authenticated by **network position
alone, in both directions**:

* **Inbound (Tracecat → us):** `INGEST_TRUSTED_CIDRS` on specific paths. A
  source-IP allow-list. No shared secret, no signature. Anything that can
  present a packet from a trusted CIDR can submit an alert.
* **Outbound (us → Tracecat):** unsigned until today, and unverified
  thereafter if nothing checks the header.

Network position is a real control and not a worthless one, but it is a single
factor, it fails open to anything inside the trusted range, and it cannot tell
two senders inside that range apart. Our recommendation in that case is a
shared bearer token on the inbound path as well, which is cheap on both sides
and does not depend on either product supporting HMAC.

We are not asking for that decision in this note. We are asking which of the
three answers above applies, so we know whether to close this or escalate it.

---

## Appendix — what we did on our side, for your records

* `ALERT_CALLBACK_SECRET` generated with a CSPRNG, 32 bytes, hex-encoded,
  installed via `scripts/set_callback_secret.py`, which refuses to overwrite an
  existing value so it cannot silently rotate out from under you.
* The secret is never printed by that script, never logged, and is not in
  version control.
* **The signature is not live until our services are recreated.** `env_file`
  is read when a container is created, so the running processes do not have
  the secret yet. Our liveness check currently reports this, by name, and
  fails. Callbacks are still unsigned until that recreate happens — we will
  confirm when it is done.
* We added an automated check (`scripts/validate_env.py`, wired into
  `scripts/liveness.sh`) that fails when a setting of this kind is unset
  without a recorded reason. It is what would have caught the empty secret,
  and it is the reason we found it at all.
