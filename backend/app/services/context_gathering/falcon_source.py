"""The first real source for the gathering loop: CrowdStrike Falcon, read-only.

**Why this estate first.** `c00` is Expertware's own — CrowdStrike reports one
CID across 176 of 176 devices, every `machine_domain` an `expertware.net`
domain (`docs/measurements/POPULATION.md`). That makes it the right place to
put the first connector, not the wrong one: a read-only replay against our own
machines carries no customer-data risk, and it is the only tenant with enough
closed cases to measure the loop at all — 2,118 against 9 and 5 for the two
Exabeam tenants.

**Read-only by construction.** Two GETs, both of which `falcon_client` already
makes in `lookup_host`: the device record and the detections list. There is no
code path here that writes, contains, quarantines or deletes anything, and
nothing in this module takes an action id.

**Only templates Falcon can actually answer.** The temptation is to declare
the whole template set and let unanswerable ones fail; that produces a record
full of `check_failed` for questions that were never askable, which reads as
an outage. The three below map one-to-one onto a call that works:

| template | the call | the question |
|---|---|---|
| `host_threat_state` | `/devices/entities/devices/v2` | is this host managed, and is its sensor healthy and recent |
| `host_detections_window` | `/alerts/queries/alerts/v2` + hydrate | did the EDR see anything on this host around the alert |
| `hash_prevalence` | `/alerts/queries/alerts/v2` by sha256 | has this binary been seen anywhere in the estate |

`host_logons`, `user_sessions`, `source_address_logons` and
`user_risk_timeline` are SIEM templates. Falcon's alerts API cannot answer
them — raw logon events need Event Search, which this platform has no client
for — so this source declines them by name rather than returning nothing.
A decline is recorded as `check_failed` against **this** source with the
reason, which is honest, while an empty list would have been a real negative
that nobody measured.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.services.context_gathering.mock_source import SourceUnavailable

logger = logging.getLogger(__name__)

#: Templates this source answers. Anything else is declined by name.
ANSWERS = ("host_threat_state", "host_detections_window", "hash_prevalence")

#: How far either side of the alert `host_detections_window` looks. The alert
#: pipeline's own log window is 10 minutes; detections are rarer than log
#: lines, so a wider window is the useful one — and it is stated here rather
#: than left to a caller, so two callers cannot disagree about what the
#: record means.
WINDOW = timedelta(hours=6)

#: A bound, stated. Falcon pages, and an unpaged read would be a floor
#: reported as a total — the defect just fixed in the Exabeam connector.
MAX_DETECTIONS = 50


@dataclass
class FalconSource:
    """One tenant's Falcon, as a source the loop can query.

    `name` is the client-facing source name, because a `check_failed` that
    says "the source failed" without saying which source is the same defect
    one level up.
    """

    tenant_id: str
    name: str = "crowdstrike-falcon"
    kind: str = "edr"
    #: Every (template, primary value) asked, in order — the budget and the
    #: distinct-query ceiling are both assertions about this list.
    asked: list[tuple[str, str]] = field(default_factory=list)
    _token: Any = field(default=None, repr=False)
    _base: str = field(default="", repr=False)

    # -- the loop's interface ---------------------------------------------

    def query(self, template: str, arguments: dict[str, str]) -> list[dict[str, Any]]:
        """Run one template with REAL values and return normalised events.

        Arguments arrive detokenised: this is past the boundary, and the only
        side of it where a real hostname exists.
        """
        primary = str(arguments.get("host") or arguments.get("hash") or "")
        self.asked.append((template, primary))

        if template not in ANSWERS:
            raise SourceUnavailable(
                f"{self.name} cannot answer {template}: it is a SIEM template "
                f"and Falcon's alerts API holds detections, not raw events"
            )
        if not primary:
            raise SourceUnavailable(
                f"{self.name} was asked {template} with no selector value"
            )
        try:
            if template == "host_threat_state":
                return self._host_state(primary)
            if template == "host_detections_window":
                return self._host_detections(primary, arguments)
            return self._hash_detections(primary)
        except SourceUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            # Everything becomes `check_failed` with this source named. The
            # DNS-collector lesson: never "found nothing" for a source that
            # could not be read.
            raise SourceUnavailable(
                f"{self.name} could not be read for {template} "
                f"({type(exc).__name__})"
            ) from exc

    # -- the two calls ----------------------------------------------------

    def _headers(self) -> dict[str, str]:
        from app.integrations import falcon_client as fc
        from app.services import integration_credential_service as creds

        if self._token is None:
            cred = creds.open_for_tenant_sync(self.tenant_id, "falcon")
            secrets = getattr(cred, "secrets", None) or {}
            config = getattr(cred, "config", None) or {}
            self._base = fc.base_url_for(config)
            self._token = fc.fetch_token(
                client_id=secrets.get("client_id", ""),
                client_secret=secrets.get("client_secret", ""),
                base_url=self._base,
            )
        return {"Authorization": f"Bearer {self._token.access_token}"}

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        import requests

        headers = self._headers()
        resp = requests.get(f"{self._base.rstrip('/')}{path}",
                            headers=headers, params=params, timeout=45)
        if resp.status_code in (401, 403):
            raise SourceUnavailable(
                f"{self.name} refused {path} (HTTP {resp.status_code}) — the "
                f"credential is valid and the API client is missing a scope"
            )
        if resp.status_code >= 400:
            raise SourceUnavailable(
                f"{self.name} returned HTTP {resp.status_code} for {path}")
        return resp.json() or {}

    def _host_state(self, host: str) -> list[dict[str, Any]]:
        """The device record. One event describing the sensor, not a detection."""
        from app.integrations import falcon_client as fc

        ids = (self._get(fc.DEVICES_PATH,
                         {"filter": f"hostname:'{_fql(host)}'", "limit": 10})
               .get("resources") or [])
        if not ids:
            # A real negative, and a meaningful one: this host has no Falcon
            # sensor. `absent` rather than an exception, because "not managed"
            # is an answer and "could not ask" is not.
            return [_event(host, "falcon-unmanaged", {
                "rule": {"description": "no Falcon sensor for this hostname",
                         "level": 3},
                "falcon": {"managed": False},
            })]
        recs = (self._get("/devices/entities/devices/v2", {"ids": ids[:10]})
                .get("resources") or [])
        recs.sort(key=lambda r: str(r.get("last_seen") or ""), reverse=True)
        out = []
        for rec in recs[:1]:          # the live record; see lookup_host's note
            out.append(_event(host, f"falcon-device-{rec.get('device_id','?')}", {
                "rule": {"description": "Falcon device state", "level": 3},
                "falcon": {
                    "managed": True,
                    "device_id": rec.get("device_id"),
                    "cid": rec.get("cid"),
                    "os_version": rec.get("os_version"),
                    "agent_version": rec.get("agent_version"),
                    "status": rec.get("status"),
                    "last_seen": rec.get("last_seen"),
                    "machine_domain": rec.get("machine_domain"),
                    "ou": rec.get("ou"),
                },
            }))
        return out

    def _host_detections(self, host: str,
                         arguments: dict[str, str]) -> list[dict[str, Any]]:
        """Falcon detections on this host, in a stated window."""
        from app.integrations import falcon_client as fc

        centre = _parse_time(arguments.get("alert_time")) or datetime.now(timezone.utc)
        lo = (centre - WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
        hi = (centre + WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
        flt = (f"device.hostname:'{_fql(host)}'"
               f"+timestamp:>'{lo}'+timestamp:<'{hi}'")
        ids = (self._get(fc.ALERTS_PATH, {"filter": flt, "limit": MAX_DETECTIONS})
               .get("resources") or [])
        return self._hydrate(ids, host)

    def _hash_detections(self, sha256: str) -> list[dict[str, Any]]:
        from app.integrations import falcon_client as fc

        ids = (self._get(fc.ALERTS_PATH,
                         {"filter": f"sha256:'{_fql(sha256)}'",
                          "limit": MAX_DETECTIONS})
               .get("resources") or [])
        return self._hydrate(ids, "")

    def _hydrate(self, ids: list[str], host: str) -> list[dict[str, Any]]:
        if not ids:
            return []
        import requests

        resp = requests.post(
            f"{self._base.rstrip('/')}/alerts/entities/alerts/v2",
            headers={**self._headers(), "Content-Type": "application/json"},
            json={"composite_ids": list(ids[:MAX_DETECTIONS])}, timeout=60)
        if resp.status_code >= 400:
            raise SourceUnavailable(
                f"{self.name} could not hydrate detections "
                f"(HTTP {resp.status_code})")
        out = []
        for rec in (resp.json() or {}).get("resources") or []:
            if not isinstance(rec, dict):
                continue
            dev = rec.get("device") or {}
            out.append(_event(
                str(dev.get("hostname") or host or "?"),
                str(rec.get("composite_id") or rec.get("id") or "?"),
                {
                    "rule": {
                        "description": str(rec.get("description")
                                           or rec.get("name") or "Falcon detection"),
                        "level": _severity_to_level(rec.get("severity")),
                        "mitre_technique": str(rec.get("technique") or ""),
                    },
                    "process": {
                        "image": rec.get("filepath") or rec.get("filename") or "",
                        "command_line": rec.get("cmdline") or "",
                        "parent_image": rec.get("parent_details", {}).get("filepath", "")
                        if isinstance(rec.get("parent_details"), dict) else "",
                        "sha256": rec.get("sha256") or "",
                    },
                    "falcon": {
                        "tactic": rec.get("tactic"),
                        "technique": rec.get("technique"),
                        "pattern_id": rec.get("pattern_id"),
                        "status": rec.get("status"),
                    },
                    "timestamp": rec.get("timestamp") or rec.get("created_timestamp"),
                },
            ))
        return out


# ── helpers ───────────────────────────────────────────────────────────────

def _event(host: str, ident: str, extra: dict[str, Any]) -> dict[str, Any]:
    """One event in the shape the scorer and the loop already consume."""
    base: dict[str, Any] = {
        "key": f"falcon:{ident}",
        "id": ident,
        "timestamp": extra.pop("timestamp", None)
        or datetime.now(timezone.utc).isoformat(),
        "agent": {"name": host},
        "rule": {"id": "falcon", "level": 3, "description": "", "groups": ["falcon"],
                 "mitre_technique": ""},
        "event_id": "",
        "channel": "Falcon",
        "users": [],
        "process": {},
        "network": {},
    }
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = {**base[key], **value}
        else:
            base[key] = value
    return base


def _severity_to_level(severity: Any) -> int:
    """Falcon severity (0-100) onto the Wazuh-style level the scorer reads."""
    try:
        value = int(severity)
    except (TypeError, ValueError):
        return 3
    if value >= 80:
        return 12
    if value >= 60:
        return 10
    if value >= 40:
        return 7
    return 5


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _fql(value: str) -> str:
    """Escape a value for a Falcon FQL string literal."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")
