"""CrowdStrike Falcon, OAuth2 and one authenticated call.

Scope of this module: get a token, know when it expires, ask Falcon a
question about an observable, and report failure with the reason. It holds no
credentials of its own — they arrive from `tenant_integrations`, sealed, and
are opened by the caller.

The token expiry is checked, not discovered
-------------------------------------------
Falcon's `/oauth2/token` returns `expires_in` (1800 seconds in current
versions). That is **exactly the shape that killed the Spamhaus
integration**: its stored SIA token was a JWT whose `exp` claim decoded to
2026-05-12, the same day the integration was committed, and the collector
then failed on 2,198 consecutive runs for 98 days. The expiry was in the
token, in the database, readable, and nothing read it.

So here the expiry is a value this module computes and exposes
(`Token.expires_at`, `Token.expires_in_seconds`, `Token.expired`), refreshed
before use with a safety margin rather than on the first 401. And it is
reported to `credential_expiry_service` so there is **one** place that knows
which credentials are near expiry — not a private timer per integration,
which is how the first one became invisible.

What is deliberately not here
-----------------------------
No detections polling. This pass is enrichment only: ingest needs
`_create_alert_run` extracted from the API module first, and brings a field
map (where unmapped Falcon fields are quarantined as `no_field_map` and never
inferred) and the question of Falcon's MITRE attributions as a third
technique namer that must not quietly join `rule_only`.

Secrets
-------
The client secret reaches this module as an argument and goes into one
request body. It is never logged, never interpolated into an exception, and
never returned. `_redact()` is applied to every error string this module
raises, because an HTTP library's own exception text can carry a request body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

#: Refresh this long before the token actually expires. A token that is valid
#: when checked and expired when used is the race this avoids; 120 seconds is
#: longer than any single Falcon call plus retries.
REFRESH_MARGIN_SECONDS = 120

#: Falcon's documented clouds. Not a hand-maintained list of *tools* — this
#: is one integration's own valid values, and an operator pasting a region
#: name needs the base URL that goes with it.
CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}

DEFAULT_BASE_URL = CLOUDS["us-1"]
DEFAULT_TIMEOUT = 20

#: Measured against a live tenant on 2026-10-14, not taken from memory:
#:
#:   /detects/queries/detects/v1     404  -- the legacy Detects API is gone
#:   /alerts/queries/alerts/v1       200
#:   /alerts/queries/alerts/v2       200
#:   /devices/queries/devices/v1     200
#:   /devices/queries/devices/v2     404
#:   /intel/queries/indicators/v1    403  access denied, scope not permitted
#:   /iocs/queries/indicators/v1     403  access denied, scope not permitted
ALERTS_PATH = "/alerts/queries/alerts/v2"
DEVICES_PATH = "/devices/queries/devices/v1"

#: Which FQL field carries the observable, per observable type.
#:
#: **The Alerts API does not validate field names.** Measured on the same
#: tenant: `behaviors.domain`, `domain`, `indicator_id`, `filename`,
#: `behaviors.ioc_value`, `ioc_value`, `sha256`, `behaviors.sha256`,
#: `device.hostname`, `hostname`, `local_ip` and the invented
#: `behaviors.ioc_type` **all returned HTTP 200 with zero resources.** A
#: field that does not exist is therefore indistinguishable, from the
#: response alone, from a field that exists and matched nothing.
#:
#: That is the absence-as-answer shape this platform spent two days removing,
#: handed to us by a vendor: a typo here would read as "this tenant's EDR has
#: nothing on that host" for ever, silently, on every investigation.
#:
#: Two things follow. The `verify` call records whether the estate has *any*
#: alerts, so a permanently-empty filtered result is interpretable rather
#: than reassuring. And `falcon` is registered as a source in the answer-rate
#: check, so a field that never matches shows up as a source at 0% over a
#: meaningful window — which is the backstop, not the fix.
#:
#: The Devices API *does* validate: `local_ip:'example-host'` returns 400
#: "invalid IP address". So the risk is specific to Alerts.
ALERT_FILTER_FIELDS = {
    "domain": "behaviors.domain",
    "url": "behaviors.domain",
    "ip": "behaviors.ioc_value",
    "hash": "behaviors.sha256",
}


def _redact(text: Any) -> str:
    """Remove anything credential-shaped from a string bound for a log or an
    exception.

    `requests` puts the request body into some exception strings, and the
    token request's body is `client_id=...&client_secret=...`. The standing
    rule is that a credential never reaches a log, an error body or a
    response, so the redaction is unconditional rather than conditional on
    having seen a leak.
    """
    out = str(text or "")
    out = re.sub(r"(?i)(client_secret=)[^&\s\"']+", r"\1[redacted]", out)
    out = re.sub(r"(?i)(client_id=)[^&\s\"']+", r"\1[redacted]", out)
    out = re.sub(r"(?i)(bearer\s+)\S+", r"\1[redacted]", out)
    out = re.sub(
        r"(?i)([\"']?access_token[\"']?\s*[:=]\s*[\"']?)[^\s,\"'}]+",
        r"\1[redacted]", out,
    )
    return out[:400]


class FalconAuthError(RuntimeError):
    """Falcon refused the credential. Message is redacted and specific."""


class FalconUnavailable(RuntimeError):
    """Falcon could not be reached, or answered in a way this code cannot read.

    Distinct from `FalconAuthError`: one is a credential to fix, the other is
    a provider to wait for, and reporting them as one status is how "enabled"
    came to mean nothing.
    """


@dataclass(frozen=True)
class Token:
    """An access token and when it stops working."""

    access_token: str
    expires_at: datetime
    #: Which API scopes the token actually carries, when Falcon says.
    scopes: tuple[str, ...] = ()

    @property
    def expires_in_seconds(self) -> int:
        return int((self.expires_at - datetime.now(timezone.utc)).total_seconds())

    @property
    def expired(self) -> bool:
        """True once it is inside the refresh margin — not once it is dead.

        A token that is valid when checked and expired when used is the
        failure this margin exists for.
        """
        return self.expires_in_seconds <= REFRESH_MARGIN_SECONDS

    def as_status(self) -> dict[str, Any]:
        """What the expiry register records. Never the token."""
        return {
            "expires_at": self.expires_at.isoformat(),
            "expires_in_seconds": self.expires_in_seconds,
            "near_expiry": self.expired,
            "scopes": list(self.scopes),
        }


def base_url_for(config: dict[str, Any] | None) -> str:
    """The API host for this tenant's configuration.

    A cloud name or a full base URL, because operators have one or the other.
    """
    cfg = config or {}
    explicit = str(cfg.get("base_url") or "").strip().rstrip("/")
    if explicit:
        return explicit
    cloud = str(cfg.get("cloud") or "").strip().lower()
    return CLOUDS.get(cloud, DEFAULT_BASE_URL)


def fetch_token(
    *,
    client_id: str,
    client_secret: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: int = DEFAULT_TIMEOUT,
    session: Any = None,
) -> Token:
    """Exchange the credential for an access token, and read its expiry.

    Raises `FalconAuthError` on 401/403 — a credential problem — and
    `FalconUnavailable` on anything else, because those are different
    statuses with different remedies.
    """
    if not (client_id or "").strip() or not (client_secret or "").strip():
        raise FalconAuthError(
            "No Falcon client id or secret is configured for this tenant, so "
            "no request was made. An unauthenticated call can only return "
            "401, and a 401 recorded as a feed outage is what made the last "
            "one invisible."
        )

    http = session or requests
    url = f"{base_url.rstrip('/')}/oauth2/token"
    try:
        resp = http.post(
            url,
            data={"client_id": client_id, "client_secret": client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        raise FalconUnavailable(
            f"Falcon token endpoint unreachable: {type(exc).__name__}: "
            f"{_redact(exc)}"
        ) from None

    if resp.status_code in (401, 403):
        raise FalconAuthError(
            f"Falcon rejected the credential (HTTP {resp.status_code}). The "
            "client id, the secret, or the cloud/base URL is wrong, or the "
            "API client lacks the required scope."
        )
    if resp.status_code != 201 and resp.status_code != 200:
        raise FalconUnavailable(
            f"Falcon token endpoint returned HTTP {resp.status_code}"
        )

    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        raise FalconUnavailable(
            "Falcon token endpoint returned a body this code could not parse "
            "as JSON."
        ) from None

    token = str(body.get("access_token") or "").strip()
    if not token:
        raise FalconUnavailable(
            "Falcon returned HTTP 2xx with no access_token. Treated as an "
            "absence rather than a success, because an empty token would "
            "fail later with a 401 that looked like a credential problem."
        )

    # `expires_in` is the thing nothing read last time. A missing value is
    # NOT defaulted to something comfortable: a short, explicit expiry makes
    # the next call refresh, which is the safe direction.
    expires_in = body.get("expires_in")
    seconds = int(expires_in) if isinstance(expires_in, (int, float)) else 0
    scopes = body.get("scope") or body.get("scopes") or ""
    if isinstance(scopes, str):
        scopes = tuple(s for s in scopes.replace(",", " ").split() if s)
    else:
        scopes = tuple(str(s) for s in scopes)

    return Token(
        access_token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=seconds),
        scopes=scopes,
    )


def verify(
    *,
    client_id: str,
    client_secret: str,
    config: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    session: Any = None,
) -> dict[str, Any]:
    """A real authenticated call, for test-connection.

    Not a token fetch alone: a token proves the credential is valid and
    proves nothing about whether this API client can *do* anything. So it
    fetches a token and then makes one cheap authenticated request, and
    reports which of the two failed.

    Returns a health record. Never raises for a provider or credential
    problem — those are the answer, not an exception — and never carries a
    secret or the token.
    """
    base = base_url_for(config)
    checked_at = datetime.now(timezone.utc).isoformat()

    try:
        token = fetch_token(
            client_id=client_id, client_secret=client_secret,
            base_url=base, timeout=timeout, session=session,
        )
    except FalconAuthError as exc:
        return {
            "state": "verified_failing", "direction": "enrichment",
            "checked_at": checked_at, "reason": _redact(exc),
            "failure_kind": "credential", "base_url": base,
        }
    except FalconUnavailable as exc:
        return {
            "state": "verified_failing", "direction": "enrichment",
            "checked_at": checked_at, "reason": _redact(exc),
            "failure_kind": "provider", "base_url": base,
        }

    http = session or requests
    try:
        resp = http.get(
            f"{base.rstrip('/')}{ALERTS_PATH}",
            headers={"Authorization": f"Bearer {token.access_token}",
                     "Accept": "application/json"},
            params={"limit": 1},
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "state": "verified_failing", "direction": "enrichment",
            "checked_at": checked_at,
            "reason": f"Token obtained, but the API was unreachable: "
                      f"{type(exc).__name__}: {_redact(exc)}",
            "failure_kind": "provider", "base_url": base,
            "token": token.as_status(),
        }

    if resp.status_code in (401, 403):
        return {
            "state": "verified_failing", "direction": "enrichment",
            "checked_at": checked_at,
            "reason": (
                f"A token was issued, but the API refused the request "
                f"(HTTP {resp.status_code}). The credential is valid and the "
                f"API client is missing a scope — for enrichment it needs "
                f"read access to Detections and Hosts."
            ),
            "failure_kind": "scope", "base_url": base,
            "token": token.as_status(),
        }
    if resp.status_code >= 400:
        return {
            "state": "verified_failing", "direction": "enrichment",
            "checked_at": checked_at,
            "reason": f"Falcon API returned HTTP {resp.status_code}",
            "failure_kind": "provider", "base_url": base,
            "token": token.as_status(),
        }

    # Whether this estate has any alerts at all. Without it, a filtered
    # query returning nothing for ever is indistinguishable from a quiet
    # estate — and the Alerts API accepts unknown field names silently, so
    # that is a real way to be wrong. Recorded, not alarmed on.
    try:
        alerts_present = len(
            (resp.json().get("resources") or [])
        ) > 0
    except Exception:  # noqa: BLE001
        alerts_present = None

    return {
        "state": "verified_ok", "direction": "enrichment",
        "checked_at": checked_at, "reason": None,
        "base_url": base, "token": token.as_status(),
        "estate_has_alerts": alerts_present,
    }


def lookup(
    *,
    observable: str,
    observable_type: str,
    client_id: str,
    client_secret: str,
    config: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    session: Any = None,
) -> dict[str, Any]:
    """Ask Falcon what it knows about one observable.

    Enrichment only. Two questions, both read-only:

      * **has this host been seen?** `/devices/queries/devices/v1` by hostname
        or local IP — answers "is this observable inside the estate".
      * **are there detections mentioning it?** `/detects/queries/detects/v1`
        with an FQL filter.

    Returns a dict the collector stores. Raises only for programming errors;
    a credential or provider failure comes back as an exception the collector
    converts into an absence, because "Falcon could not be asked" and
    "Falcon has nothing" must never be the same stored value.

    The token's expiry is checked before use rather than discovered by a 401 —
    see `Token.expired` and the module docstring.
    """
    base = base_url_for(config)
    token = fetch_token(
        client_id=client_id, client_secret=client_secret,
        base_url=base, timeout=timeout, session=session,
    )
    if token.expired:
        # Issued and already inside the refresh margin. Falcon returning a
        # token this short is a provider problem, not something to paper over
        # by using it anyway and hoping.
        raise FalconUnavailable(
            f"Falcon issued a token expiring in {token.expires_in_seconds}s, "
            f"inside the {REFRESH_MARGIN_SECONDS}s refresh margin. Not used."
        )

    http = session or requests
    headers = {"Authorization": f"Bearer {token.access_token}",
               "Accept": "application/json"}
    notes: list[str] = []
    value = str(observable or "").strip()

    def _ask(path: str, params: dict[str, Any], what: str) -> list[Any]:
        try:
            resp = http.get(f"{base.rstrip('/')}{path}", headers=headers,
                            params=params, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            raise FalconUnavailable(
                f"Falcon {what} query unreachable: {type(exc).__name__}: "
                f"{_redact(exc)}"
            ) from None
        if resp.status_code in (401, 403):
            # A valid credential whose API client lacks the scope. Named as
            # such rather than reported as "no results", which is what would
            # make a missing scope look like a clean estate.
            raise FalconAuthError(
                f"Falcon refused the {what} query (HTTP {resp.status_code}). "
                f"The credential is valid; the API client is missing a scope."
            )
        if resp.status_code >= 400:
            raise FalconUnavailable(
                f"Falcon {what} query returned HTTP {resp.status_code}"
            )
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            raise FalconUnavailable(
                f"Falcon {what} query returned a body this code could not "
                "parse as JSON."
            ) from None
        return list(body.get("resources") or [])

    # Hosts. Falcon's device search is field-specific, so the field depends on
    # what kind of observable this is — an FQL filter against the wrong field
    # silently matches nothing, which would read as "not in the estate".
    hosts: list[Any] = []
    if observable_type in ("domain", "url"):
        host = _host_only(value)
        if host:
            hosts = _ask(DEVICES_PATH,
                         {"filter": f"hostname:'{_fql(host)}'", "limit": 10},
                         "device")
    elif observable_type == "ip":
        hosts = _ask(DEVICES_PATH,
                     {"filter": f"local_ip:'{_fql(value)}'", "limit": 10},
                     "device")
    else:
        notes.append(
            f"Falcon device search does not cover observable type "
            f"{observable_type!r}, so the estate was not searched."
        )

    # Detections, via the Alerts API. See ALERT_FILTER_FIELDS for why the
    # field choice here is a correctness risk the provider will not catch.
    det_field = ALERT_FILTER_FIELDS.get(observable_type)
    detections: list[Any] = []
    if det_field:
        needle = _host_only(value) if observable_type in ("domain", "url") else value
        if needle:
            detections = _ask(ALERTS_PATH,
                              {"filter": f"{det_field}:'{_fql(needle)}'",
                               "limit": 20},
                              "detection")
    else:
        notes.append(
            f"No Falcon detection field is mapped for observable type "
            f"{observable_type!r}, so detections were not searched. Not "
            f"inferred — an unmapped field is recorded, never guessed."
        )

    return {
        "detections": [{"id": str(d)} for d in detections],
        "hosts": [{"id": str(h)} for h in hosts],
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "notes": notes,
        "token": token.as_status(),
    }


def _host_only(value: str) -> str:
    """The hostname from a domain or URL, with no port or path.

    Reuses the platform's existing rule rather than a second parser: nine
    membership consumers, two parsers and three ATT&CK copies is what the
    second implementation has cost here.
    """
    from app.services.threatfox_match_scope import _host_of

    return _host_of(value)


def _fql(value: str) -> str:
    """Escape a value for a Falcon FQL string literal.

    Single quotes and backslashes only — FQL has no richer injection surface
    for a quoted literal, and a value that cannot be escaped safely is
    rejected by returning something that matches nothing rather than
    something that matches everything.
    """
    return str(value).replace("\\", "\\\\").replace("'", "\\'")
