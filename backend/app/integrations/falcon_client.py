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
#: MEASURED against 200 real alerts on 2026-10-15. **The alert record has no
#: `behaviors` key** — 0 of 200 carried one. The Alerts v2 resource is flat:
#: `sha256`, `md5`, `sha1`, `filename`, `device.hostname`, `tactic`,
#: `technique`, 73 fields in all.
#:
#: Every entry in the previous version of this map was invented, and because
#: the Alerts API answers an unknown field with 200 and zero resources, each
#: one returned "the EDR has nothing". The same hash returns **17 rows** as
#: `sha256` and **0** as `behaviors.sha256`. The docstring two paragraphs
#: above predicted exactly this and the map was written anyway.
#:
#: Hash dispatch is by digest length, not one field name: an observable of
#: kind `hash` may be any of the three, and filtering a 32-character MD5
#: against `sha256` is the same silent zero one level down.
ALERT_HASH_FIELDS = {64: "sha256", 40: "sha1", 32: "md5"}

#: Kinds with NO filterable alert field, and why — so the absence is recorded
#: rather than rediscovered. All of these were probed and returned 200/0:
#:
#: * **domain** — no field carries one. `behaviors.domain`, `domain`,
#:   `data_domains`, `ioc_context.domain`, `ioc_value` all empty.
#:   `data_domains` is the trap: its value is `['Endpoint']`, a data
#:   *classification*, not a name. Same defect as `queryName` — a plausible
#:   field name answering a different question.
#: * **url** — follows from domain.
#: * **ip** — `source_ips` is populated, with values like `10.66.66.12`. They
#:   are *internal* source addresses, so a remote address (a mail sender, a
#:   C2) can never appear there. Valid field, valid value, structurally
#:   impossible match, and the Devices API's `local_ip` has the same problem.
#:
#: The intel and IOC endpoints that WOULD answer "is this indicator known
#: bad" are 403 scope-not-permitted (re-measured 2026-10-15), so there is no
#: alternative route for these kinds either.
ALERT_UNMAPPABLE_KINDS = {
    "domain": (
        "no Falcon alert field carries a domain; `data_domains` holds a data "
        "classification such as 'Endpoint', not a name"
    ),
    "url": "follows from domain — no alert field carries a name",
    "ip": (
        "`source_ips` holds internal source addresses only, so a remote "
        "address cannot appear in it"
    ),
}


def alert_filter_field(observable_type: str, value: str) -> str | None:
    """Which alert field answers for this observable, or None.

    None means *no field exists*, not "not implemented". The caller records
    `no_field_map` and does not search, because a search on a guessed field
    returns a clean-looking zero.
    """
    if observable_type != "hash":
        return None
    return ALERT_HASH_FIELDS.get(len(str(value or "").strip()))


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


class FalconFieldUnverified(RuntimeError):
    """The alert field could not be confirmed to filter, so nothing was asked.

    A third kind, distinct from both above, because it is neither a
    credential nor an outage: the provider is answering normally and the
    question may be meaningless. The Alerts API returns HTTP 200 with zero
    resources for a field name that does not exist, so a negative from an
    unconfirmed field is not a negative at all.
    """


#: How long a passing field control stands before it is re-run. The Alerts
#: API's refusal to validate field names is a permanent property of the
#: provider, not a bug awaiting a fix, so this is a standing control rather
#: than a one-off probe — but the thing it detects (a field renamed or
#: withdrawn) changes on the provider's release schedule, not on ours. An
#: hour bounds the blast radius of a rename to one hour of false negatives
#: per process while costing two requests per hour per field.
FIELD_CONTROL_TTL_SECONDS = 3600

#: Keyed by field name. Per process, deliberately: a cache shared across
#: processes would let a worker's pass stand in for the api's, which is the
#: warrant-substitution this platform already closed once for the log store.
_FIELD_CONTROL_CACHE: dict[str, dict[str, Any]] = {}


def _dotted(record: Any, path: str) -> Any:
    """`device.hostname` out of a nested record, or None."""
    node = record
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def alerts_field_control(
    field: str,
    *,
    base_url: str,
    headers: dict[str, str],
    http: Any,
    timeout: int = DEFAULT_TIMEOUT,
    now: Any = None,
    sample: int = 25,
) -> dict[str, Any]:
    """Confirm that `field` actually filters, by finding a known row with it.

    The only test of a field name that works against this API: take a value
    the API itself returned at that field, filter on exactly that value, and
    require the filter to find it. A filter that returns nothing for a value
    the API just gave us is a field the API is ignoring.

    **Never raises and never fails open.** Every way of not establishing the
    control returns `passed: False` with a reason, including an estate with no
    alerts to sample — that is `too_little_history`, not a pass, because a
    control that cannot run has not run.
    """
    from datetime import datetime, timedelta, timezone

    at = now or datetime.now(timezone.utc)
    cached = _FIELD_CONTROL_CACHE.get(field)
    if cached:
        age = at - datetime.fromisoformat(cached["checked_at"])
        if cached["passed"] and age < timedelta(seconds=FIELD_CONTROL_TTL_SECONDS):
            return cached

    def result(passed: bool, reason: str, **extra: Any) -> dict[str, Any]:
        out = {"field": field, "passed": passed, "reason": reason,
               "checked_at": at.isoformat(), **extra}
        # Only a pass is cached. A failure must be retried, because the usual
        # cause is a provider-side change that may be transient, and caching it
        # would turn one bad minute into an hour of refusals.
        if passed:
            _FIELD_CONTROL_CACHE[field] = out
        return out

    def _get(path: str, params: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        resp = http.get(f"{base_url.rstrip('/')}{path}", headers=headers,
                        params=params, timeout=timeout)
        try:
            return resp.status_code, resp.json() or {}
        except Exception:  # noqa: BLE001
            return resp.status_code, {}

    try:
        code, body = _get(ALERTS_PATH, {"limit": sample,
                                        "sort": "created_timestamp|desc"})
        if code >= 400:
            return result(False, f"the unfiltered probe query returned HTTP {code}.")
        ids = list(body.get("resources") or [])
        if not ids:
            return result(
                False,
                "this tenant has no Falcon alerts at all, so no row exists to "
                "confirm the field against. Not a pass: the control could not "
                "be run.",
                absence="too_little_history",
            )
        resp = http.post(
            f"{base_url.rstrip('/')}/alerts/entities/alerts/v2",
            headers={**headers, "Content-Type": "application/json"},
            json={"composite_ids": ids}, timeout=timeout,
        )
        if resp.status_code >= 400:
            return result(
                False,
                f"the alert detail request returned HTTP {resp.status_code}, "
                f"so no value could be read back.")
        records = list((resp.json() or {}).get("resources") or [])
        pair = next(
            ((r, _dotted(r, field)) for r in records
             if isinstance(_dotted(r, field), str) and _dotted(r, field).strip()),
            None,
        )
        if pair is None:
            return result(
                False,
                f"none of the {len(records)} most recent alerts carries a "
                f"value at {field!r}, so there is nothing to filter for. The "
                f"field may not exist, or may be populated too rarely to "
                f"confirm — either way a zero from it means nothing.",
                sampled=len(records),
            )
        record, value = pair
        code, body = _get(ALERTS_PATH,
                          {"filter": f"{field}:'{_fql(value)}'", "limit": 5})
        if code >= 400:
            return result(False, f"the confirming query returned HTTP {code}.")
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
        if not total:
            return result(
                False,
                f"a value read back from a real alert at {field!r} returned no "
                f"rows when filtered on. The API is ignoring this field name — "
                f"every negative from it would be false.",
                probe_total=total,
            )
        return result(
            True,
            f"a value read back at {field!r} returned {total} row(s) when "
            f"filtered on, so the field filters.",
            probe_total=total, sampled=len(records),
        )
    except Exception as exc:  # noqa: BLE001
        return result(
            False,
            f"the field control did not complete ({type(exc).__name__}: "
            f"{_redact(exc)}).")


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
      * **are there detections mentioning it?** `/alerts/queries/alerts/v2`
        with an FQL filter (`ALERT_FILTER_FIELDS`).

    This said `/detects/queries/detects/v1` until 2026-10-15. That endpoint is
    recorded four lines above the path constants as **404 — the legacy Detects
    API is gone**, and the code has always used `ALERTS_PATH`. The measurement
    and the prose were in the same file disagreeing with each other, which is
    why a reader has to be able to reach the constant rather than the
    sentence.

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
            f"Falcon's own device inventory cannot be searched by "
            f"{observable_type!r}, so no device question was asked. (This is "
            f"about Falcon's device list, not the OpenSearch log store — in "
            f"the indicator lookup that store is a separate source called "
            f"'estate', and the previous wording here said 'the estate was "
            f"not searched', which read as a claim about it.)"
        )

    # Detections, via the Alerts API. The field choice is a correctness risk
    # the provider will not catch — see ALERT_HASH_FIELDS — so it is dispatched
    # from measurement and gated on the standing control below.
    det_field = alert_filter_field(observable_type, value)
    detections: list[Any] = []
    unmappable: str | None = None
    if det_field:
        control = alerts_field_control(
            det_field, base_url=base, headers=headers, http=http, timeout=timeout,
        )
        if not control["passed"]:
            # The whole point of the control: without it a zero here is
            # indistinguishable from a field name the API silently ignored.
            raise FalconFieldUnverified(
                f"The Falcon alert field {det_field!r} could not be confirmed "
                f"to filter: {control['reason']} No detection search was run, "
                f"because an empty result from an unconfirmed field reads as "
                f"'the EDR has nothing'."
            )
        detections = _ask(ALERTS_PATH,
                          {"filter": f"{det_field}:'{_fql(value)}'",
                           "limit": 20},
                          "detection")
        notes.append(
            f"Detections searched on {det_field!r}, confirmed filterable by "
            f"the field control at {control['checked_at']}."
        )
    else:
        unmappable = ALERT_UNMAPPABLE_KINDS.get(observable_type)
        notes.append(
            f"No Falcon alert field answers for observable type "
            f"{observable_type!r}"
            + (f": {unmappable}. " if unmappable else ". ")
            + "Measured, not assumed — the alert record has no `behaviors` "
              "key and no field carries this kind. Nothing was searched, "
              "because a filter on a guessed field returns a clean-looking "
              "zero."
        )

    return {
        "detections": [{"id": str(d)} for d in detections],
        "hosts": [{"id": str(h)} for h in hosts],
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "notes": notes,
        "token": token.as_status(),
        # Which field answered, and why none could. The collector turns
        # `detections_unmappable` into a `no_field_map` absence ON the
        # detections field rather than leaving an empty list, because an empty
        # list and "there is no field to ask" are the two readings this whole
        # module exists to keep apart.
        "detections_field": det_field,
        "detections_unmappable": unmappable,
    }


#: Falcon's alert retention, measured rather than assumed — and re-measured,
#: because it is a rolling window.
#:
#: Measured on tenant c00, 2026-10-15: the oldest alert the API will return is
#: 2026-07-17T06:49:10Z, which is **exactly 90 days** earlier. Asking for
#: `created_timestamp > '2024-01-01'` returns the same 2,048 total as
#: `> '2026-06-01'`, so the API is not clamping a wider request silently — the
#: data genuinely begins there.
#:
#: Community sources agree on 90 days for detections and alerts, independent of
#: subscription tier (raw event telemetry is the part that varies with
#: licensing, commonly 7 days). No official CrowdStrike documentation page was
#: found saying so, so the measurement is the authority here and the figure
#: below is only a sanity bound on it.
#:
#: This matters for the same reason the DNS collection floor did: a 30-day
#: panel claim against an unmeasured retention is a bounded window reported as
#: complete, and absence-because-not-retained then renders as
#: absence-because-it-never-happened.
EXPECTED_ALERT_RETENTION_DAYS = 90

_RETENTION_FLOOR_CACHE: dict[str, dict[str, Any]] = {}

#: The floor moves forward one day per day, so an hour of staleness is at most
#: an hour of over-claim at the very edge of the window.
RETENTION_FLOOR_TTL_SECONDS = 3600


def alert_retention_floor(
    *,
    base_url: str,
    headers: dict[str, str],
    http: Any,
    timeout: int = DEFAULT_TIMEOUT,
    now: Any = None,
) -> dict[str, Any]:
    """The oldest alert this subscription will return, as a measured fact.

    Never raises. A floor that cannot be established comes back as
    `floor: None` with a reason, and the caller must then refuse to claim a
    window length rather than assuming one — an assumed floor is the whole
    defect.
    """
    from datetime import datetime, timedelta, timezone

    at = now or datetime.now(timezone.utc)
    key = base_url
    cached = _RETENTION_FLOOR_CACHE.get(key)
    if cached and cached.get("floor"):
        age = at - datetime.fromisoformat(cached["measured_at"])
        if age < timedelta(seconds=RETENTION_FLOOR_TTL_SECONDS):
            return cached

    def result(floor: Any, reason: str, **extra: Any) -> dict[str, Any]:
        out = {"floor": floor, "reason": reason,
               "measured_at": at.isoformat(), **extra}
        if floor:
            _RETENTION_FLOOR_CACHE[key] = out
        return out

    try:
        resp = http.get(f"{base_url.rstrip('/')}{ALERTS_PATH}", headers=headers,
                        params={"limit": 1, "sort": "created_timestamp|asc"},
                        timeout=timeout)
        if resp.status_code >= 400:
            return result(None, f"the floor probe returned HTTP {resp.status_code}.")
        body = resp.json() or {}
        ids = list(body.get("resources") or [])
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
        if not ids:
            return result(
                None,
                "this tenant has no Falcon alerts at all, so how far back the "
                "alert history reaches is unknown — not 'nothing happened'.",
                absence="too_little_history", total=total)
        detail = http.post(
            f"{base_url.rstrip('/')}/alerts/entities/alerts/v2",
            headers={**headers, "Content-Type": "application/json"},
            json={"composite_ids": ids}, timeout=timeout)
        if detail.status_code >= 400:
            return result(None, f"the oldest alert could not be read "
                                f"(HTTP {detail.status_code}).")
        records = list((detail.json() or {}).get("resources") or [])
        stamp = (records[0].get("created_timestamp") if records else None)
        parsed = None
        if stamp:
            try:
                parsed = datetime.fromisoformat(
                    str(stamp).replace("Z", "+00:00"))
            except ValueError:
                parsed = None
        if parsed is None:
            return result(None, "the oldest alert carries no readable "
                                "created_timestamp.")
        days = (at - parsed).total_seconds() / 86400.0
        return result(
            parsed.isoformat(),
            f"The oldest alert this subscription returns is "
            f"{parsed:%Y-%m-%d}, {round(days)} days ago.",
            days=round(days, 1), total=total)
    except Exception as exc:  # noqa: BLE001
        return result(None, f"the floor could not be measured "
                            f"({type(exc).__name__}: {_redact(exc)}).")


def lookup_host(
    *,
    hostname: str,
    client_id: str,
    client_secret: str,
    config: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    days: int = 30,
    row_cap: int = 500,
    session: Any = None,
) -> dict[str, Any]:
    """Everything Falcon knows about one host: the device, and its detections.

    The host question, as opposed to `lookup`'s indicator question. A tenant
    alert names a host, `hostname` is the one alert/device field this API
    actually validates, and 95.3% of alert runs in the last 7 days carry an
    `entity_host` (measured 2026-10-15).

    Returns raw records plus the field control's verdict; shaping belongs to
    `falcon_host_panel_service`, which is why no judgement is made here.
    """
    from datetime import datetime, timedelta, timezone

    base = base_url_for(config)
    token = fetch_token(client_id=client_id, client_secret=client_secret,
                        base_url=base, timeout=timeout, session=session)
    if token.expired:
        raise FalconUnavailable(
            f"Falcon issued a token expiring in {token.expires_in_seconds}s, "
            f"inside the {REFRESH_MARGIN_SECONDS}s refresh margin. Not used."
        )
    http = session or requests
    headers = {"Authorization": f"Bearer {token.access_token}",
               "Accept": "application/json"}
    host = str(hostname or "").strip()
    if not host:
        raise ValueError("lookup_host needs a hostname")

    def _get(path: str, params: dict[str, Any]) -> dict[str, Any]:
        resp = http.get(f"{base.rstrip('/')}{path}", headers=headers,
                        params=params, timeout=timeout)
        if resp.status_code in (401, 403):
            raise FalconAuthError(
                f"Falcon refused {path} (HTTP {resp.status_code}). The "
                f"credential is valid; the API client is missing a scope."
            )
        if resp.status_code >= 400:
            raise FalconUnavailable(f"Falcon {path} returned HTTP {resp.status_code}")
        try:
            return resp.json() or {}
        except Exception:  # noqa: BLE001
            raise FalconUnavailable(f"Falcon {path} returned unparseable JSON") from None

    # --- section A: the device. `hostname` is validated by this API, so an
    # empty result here is a real negative and needs no control.
    ids = list(_get(DEVICES_PATH,
                    {"filter": f"hostname:'{_fql(host)}'", "limit": 10}
                    ).get("resources") or [])
    device = None
    superseded: list[dict[str, Any]] = []
    if ids:
        # ALL matches, not `ids[0]`. Measured 2026-10-15: 5 of 175 hostnames
        # carry 2-3 device records, because a sensor re-install or a re-image
        # mints a new device id for the same hostname — each old record's
        # `last_seen` hands straight off to the next one's `first_seen`.
        #
        # Taking the first match is an arbitrary choice between them, and
        # picking a retired one reports a host that checked in this morning as
        # a stale sensor — which then discredits a detection list that was
        # complete. So the live record is the one with the newest `last_seen`,
        # and the others are reported as superseded rather than dropped.
        resp = http.get(f"{base.rstrip('/')}/devices/entities/devices/v2",
                        headers=headers, params={"ids": ids}, timeout=timeout)
        if resp.status_code < 400:
            recs = [r for r in ((resp.json() or {}).get("resources") or [])
                    if isinstance(r, dict)]
            recs.sort(key=lambda r: str(r.get("last_seen") or ""), reverse=True)
            if recs:
                device, superseded = recs[0], recs[1:]

    # --- the floor on any window claim. Measured, not assumed: see
    # `alert_retention_floor`. Fetched before the detection query so the
    # caller can shorten the claim rather than report 30 days it does not have.
    retention = alert_retention_floor(base_url=base, headers=headers,
                                      http=http, timeout=timeout)

    # --- section B: detections, gated on the standing control, because the
    # Alerts API answers an unknown field with 200 and zero rows.
    control = alerts_field_control("device.hostname", base_url=base,
                                   headers=headers, http=http, timeout=timeout)
    detections: list[Any] = []
    truncated_at: int | None = None
    if control["passed"]:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        alert_ids = list(_get(ALERTS_PATH, {
            "filter": f"device.hostname:'{_fql(host)}'+created_timestamp:>'{since}'",
            "limit": min(row_cap, 1000),
            "sort": "created_timestamp|desc",
        }).get("resources") or [])
        if len(alert_ids) >= min(row_cap, 1000):
            truncated_at = len(alert_ids)
        for start in range(0, len(alert_ids), 100):
            resp = http.post(
                f"{base.rstrip('/')}/alerts/entities/alerts/v2",
                headers={**headers, "Content-Type": "application/json"},
                json={"composite_ids": alert_ids[start:start + 100]},
                timeout=timeout,
            )
            if resp.status_code < 400:
                detections.extend((resp.json() or {}).get("resources") or [])

    return {
        "hostname": host,
        "device": device,
        "device_match_count": len(ids),
        # The retired enrolments for this hostname, newest-first after the
        # live one. Reported so a reader can see the host was re-enrolled
        # rather than wondering why first_seen is recent on an old machine.
        "superseded_devices": [
            {"first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"),
             "agent_version": r.get("agent_version")}
            for r in superseded
        ],
        "detections": detections,
        "control": control,
        "retention": retention,
        # A host cannot have detections from before its sensor existed. For a
        # re-enrolled hostname the EARLIEST enrolment is the bound, because
        # detections from the retired enrolment still carry this hostname.
        "enrolment_floor": min(
            [str(r.get("first_seen")) for r in ([device] + superseded)
             if isinstance(r, dict) and r.get("first_seen")],
            default=None),
        "truncated_at": truncated_at,
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
