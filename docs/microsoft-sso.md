# Signing in with a Microsoft work account

Everyone at Expertware already has an `@expertware.net` account in Entra ID. This
lets them use it here instead of a second password nobody wants to manage, and
means that removing someone from the directory removes their access to this
platform at the same moment.

Password sign-in keeps working throughout. Single sign-on is off until all four
settings below are filled in, and when it is off the sign-in page does not show
a Microsoft button at all.

---

## Before anything else: this needs HTTPS

**Entra ID refuses to register a redirect URI that is not `https://`.** The only
exception is `http://localhost`, which does not help here because people reach
the platform across the network.

The platform currently serves plain HTTP on `http://10.45.0.71:3000`, so sign-in
cannot complete until there is TLS in front of it. There is no way around this
from inside the application — it is Entra's rule, enforced at registration time.

Three ways out, cheapest first:

| Option | What it costs | Notes |
|---|---|---|
| **Internal CA certificate** | An hour, if Expertware already runs a CA | Issue a cert for a name like `tip.expertware.net`, point it at `10.45.0.71`, terminate TLS in a reverse proxy in front of port 3000. Browsers already trust the internal CA, so there is no warning. |
| **Public certificate** | A DNS name and Let's Encrypt | Only if the host is reachable for the ACME challenge, or use a DNS-01 challenge. |
| **Self-signed certificate** | Minutes | Entra is satisfied — it never inspects your certificate, it only redirects the browser. But every analyst gets a browser warning on every visit, so this is for proving the flow works, not for daily use. |

Whichever you choose, once the app answers on `https://<name>/`, set:

```
SESSION_COOKIE_SECURE=true
```

That flag is currently `false` because a `Secure` cookie is never sent over
plain HTTP — leaving it off once you are on HTTPS means session cookies travel
in clear text on your network.

---

## 1. Register the application in Entra ID

In the [Entra admin centre](https://entra.microsoft.com) → **Applications** →
**App registrations** → **New registration**:

- **Name**: `Threat Intel Platform`
- **Supported account types**: *Accounts in this organizational directory only
  (Expertware only — Single tenant)*. Do not pick a multi-tenant option; the
  platform rejects tokens from other tenants anyway, but there is no reason to
  ask for them.
- **Redirect URI**: platform **Web**, value exactly

  ```
  https://<your-host>/api/auth/oidc/callback
  ```

  It must match `OIDC_REDIRECT_URL` below character for character — scheme, host,
  port and path. A trailing slash is a different URI.

From the **Overview** page, copy:

- **Application (client) ID**
- **Directory (tenant) ID**

Then **Certificates & secrets** → **New client secret**. Copy the **Value**, not
the Secret ID; it is shown once. Note the expiry — sign-in stops working the day
it lapses, so put the date in a calendar.

Under **Token configuration**, add the optional claim **email** for ID tokens.
Without it the platform falls back to the UPN, which is normally the same
address — this just removes the guesswork.

No API permissions beyond the default `User.Read` are needed. The platform asks
only for `openid profile email`: it identifies people, it does not read mail.

## 2. Configure the platform

In `.env`:

```bash
OIDC_TENANT_ID=<Directory (tenant) ID>
OIDC_CLIENT_ID=<Application (client) ID>
OIDC_CLIENT_SECRET=<the secret Value>
OIDC_REDIRECT_URL=https://<your-host>/api/auth/oidc/callback

# Keep guests out. Guests are invited into your directory and authenticate
# against it successfully, but they are not staff.
OIDC_ALLOWED_DOMAINS=expertware.net

# Create an account the first time someone signs in. Set false to require an
# administrator to add people before they can use SSO.
OIDC_AUTO_PROVISION=true
OIDC_DEFAULT_ROLE=analyst

# Optional: these addresses get "admin" when they are first provisioned.
# Existing accounts keep whatever role they already have.
OIDC_ADMIN_EMAILS=
```

Then `docker compose up -d api frontend`. The Microsoft button appears on the
sign-in page once all four required values are present.

## 3. How accounts map

On each sign-in the platform looks for an existing account, in this order:

1. **The directory object ID** (`oid`) — immutable, so someone who changes their
   name keeps their investigation history.
2. **The email address**, against either `email` or an existing username. This is
   what links accounts that already exist here to the directory, so the `admin`
   account you use today does not become a second, separate record.
3. **Nothing matched** → an account is created, if `OIDC_AUTO_PROVISION` is on.

Roles are never changed by signing in. Whatever an administrator set stands.

Deactivating someone here blocks them even with a valid Microsoft account, and
removing them from Entra blocks them regardless of what this database says.

## 4. Checking it works

```bash
# Does the platform think SSO is configured?
curl -s https://<your-host>/api/auth/status | jq .providers
# {"password": true, "microsoft": true}
```

Then sign in from a browser. If it comes back to the sign-in page with a message,
the reason is in the API log:

```bash
docker compose logs --tail=50 api | grep -i "microsoft sign-in"
```

| Message on the page | Usual cause |
|---|---|
| *not configured on this deployment* | One of the four settings is missing or blank. |
| *could not be completed* | Wrong client secret, redirect URI mismatch, or the token failed validation. The log line says which. |
| *timed out* | More than 10 minutes between clicking the button and finishing, or cookies blocked. |
| *not set up on this platform* | `OIDC_AUTO_PROVISION=false` and nobody has added that person yet. |

## 5. Turning it off

Blank any of the four required settings and restart the API. The button
disappears and password sign-in carries on. Accounts created through SSO remain,
but have no password — give one to anybody who still needs to get in.
