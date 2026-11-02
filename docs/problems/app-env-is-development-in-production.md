# `APP_ENV=development` on the live box — found while chasing SQL in the logs

> ## ⛔ SEQUENCING CONSTRAINT — read before starting either piece of work
>
> **CORS closes before or with TLS. Never after.**
>
> Adding TLS means setting `session_cookie_secure=True`. The moment `Secure`
> is available, `SameSite=None` becomes reachable — and `SameSite=Lax` is the
> *only* reason the wildcard `allow_origin_regex` + `allow_credentials=True`
> is latent rather than exploitable today. **The TLS remediation is what arms
> the CORS wildcard.**
>
> Severity read alone says fix TLS first: cleartext credentials outrank a
> latent misconfiguration. Doing so without closing CORS in the same change
> converts the latent finding into a live one on a platform holding customer
> alert data.
>
> Order: **1. real CORS origins → 2. `APP_ENV=production` → 3. TLS.**

Measured 2026-10-15. This supersedes the ingest-durability work in priority:
that is a hole which has never been hit, and this is **live and
browser-exploitable today**.

## How it was found

Half the api's log is SQLAlchemy echo carrying customer alert bodies. The
echo is not a deliberate production setting — `db/session.py` sets
`echo=settings.is_development` on all three engines, and
`is_development` is `app_env == "development"`. **The live value is
`development`.** The log volume was the symptom; the flag is the cause, and
the echo is the least of what it turns on.

## What the flag gates — five behaviours, one serious

| # | behaviour | live effect |
|---|---|---|
| 1 | **CORS `allow_origin_regex` matching any host, with credentials** | **latent** — see below; `SameSite=Lax` withholds the cookie from cross-site fetch |
| 2 | 500 responses return `f"{type(exc).__name__}: {exc}"` | internal detail to any caller |
| 3 | `Strict-Transport-Security` header suppressed | moot: the app has no TLS yet |
| 4 | `/api/docs` and `/api/openapi.json` mounted | **mitigated** — both 401 behind the default-deny middleware |
| 5 | SQLAlchemy echo on all three engines | tenant alert bodies into an uncontrolled log |

### 1, re-ranked: LATENT, not live — the cookie is why

The wildcard is real and the credentialed cross-origin request **does not
carry the session**, so it cannot read tenant data today. The reason is the
cookie's own attributes, read from `app/api/auth.py` and the live settings:

| attribute | value | source |
|---|---|---|
| name | `tip_session` | `security/credentials.py:45` |
| `HttpOnly` | **true** | hard-coded |
| `SameSite` | **`lax`** | hard-coded, not browser-defaulted |
| `Secure` | **false** | `settings.session_cookie_secure`, live value |
| `Max-Age` | 43200 (12h) | `session_ttl_seconds` |

`SameSite=Lax` sends the cookie on same-site requests and on **top-level
cross-site navigations**, and withholds it from cross-site `fetch`/XHR —
which is exactly what CORS enables. So a malicious page's
`fetch(..., {credentials: 'include'})` arrives **unauthenticated** and gets
401, which is what the empirical check below shows. The Lax default would
apply anyway over plain HTTP, since `SameSite=None` requires `Secure`; here
it is explicit rather than defaulted, which is stronger.

**So: same urgency, different description.** It is a misconfiguration waiting
for one of three changes to become exploitable, not an open door today.

### And the coupling that matters more than either finding

**Fixing TLS is what activates this.** Adding TLS means setting
`session_cookie_secure=True` — and the moment `Secure` is available, the
obvious next step for anyone supporting a cross-origin upload is
`SameSite=None`, which is precisely the combination the wildcard needs to
become live. The remediation for the more serious problem converts this
latent one into an exploitable one.

They must therefore be sequenced together, with CORS closed **before or with**
the TLS change, never after. See
[no-tls-on-the-live-box.md](no-tls-on-the-live-box.md).

### The wildcard itself, verified



```
allow_origin_regex=r"^https?://[A-Za-z0-9\.\-]+(:\d+)?$" if settings.is_development else None
allow_credentials=True
allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"]
```

That regex matches **every** hostname. Verified against the running service
rather than read off the source:

    OPTIONS /api/detections/correlated-cases
      Origin: https://evil.example.test
    → HTTP/1.1 200 OK
      access-control-allow-origin: https://evil.example.test
      access-control-allow-credentials: true
      access-control-allow-methods: GET, POST, PUT, PATCH, DELETE, OPTIONS

So **any website an analyst visits while holding a live session can read
tenant data and issue writes with their cookie**, and the response is
readable by that origin. The 401 in the test above is only the absence of a
session cookie in `curl`; a browser with a session supplies one.

On a platform holding customer alert content this would be the most serious
exposure found this week **if the cookie allowed it**. It does not, today —
see the re-ranking above. What makes it worth fixing at the same urgency is
that the TLS remediation is what would make it live.

### 5, which is what was being investigated

209,844 of 408,027 lines in a 16.7-hour window are SQL echo, carrying alert
bodies — roughly **200MB/day of customer data** into a `json-file` log with
no `max-size`, no retention policy and no access control. It is also what
made a tenant's alert body appear in an access-log scan and produce a
false finding (see the preserved evidence manifest).

## The fix is two changes in one order, and the order matters

**Do not simply set `APP_ENV=production`.** The CORS regex exists for a real
reason, stated in its own comment: *"In development, allow direct
frontend->backend calls from VM IP/hostname origins. This is needed when
bypassing Next.js proxy for large multipart uploads."* That path is live —
`frontend/src/lib/api.ts` builds
`${directBackendBase}/api/email-investigations/upload`. With the regex gone
and nothing replacing it, **email upload breaks.**

Current explicit origins are development-only:

    cors_origins_list = ['http://localhost:3000', 'http://localhost:5173']

So:

1. **Add the real browser origin(s) to `CORS_ORIGINS`** — whatever hostname
   analysts actually load, including the VM hostname/IP the direct upload
   uses. This needs a human: nothing in the repository records which origins
   are real.
2. **Then set `APP_ENV=production`**, which closes the wildcard, stops the
   exception detail, enables HSTS (inert until TLS) and turns off the echo.
3. Verify the upload path still works, and re-run the preflight check above
   expecting the arbitrary origin to be **refused**.

Both are `.env` changes, so they need `up -d --force-recreate` and not
`restart` — and that destroys the api's access log, which is why the
window was preserved first.

## What is lost by turning the echo off, and what to do about it

Nothing is known to depend on it. It is not referenced by any check script,
monitor or document — it is on because the environment flag is wrong, not
because anybody chose it. Anything genuinely needed for debugging becomes a
deliberate log line at the call site, which is the standing preference here:
a line someone chose, carrying the fields someone needs, rather than every
statement and every parameter.

The one thing to confirm before flipping it: that no runbook or deploy
document instructs an operator to read SQL from the api log. Nothing in
`docs/` does.
