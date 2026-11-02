"""The SIEM source for the gathering loop: the Wazuh alert store, read-only.

**`sec.alerts` does not exist.** Asked the cluster directly on 2026-10-21:
`sec.alerts` is a 404, `sec.alerts-*` and `sec-*` resolve to zero indices, and
the only index matching `*sec*` is `.opendistro_security`, the security
plugin's own configuration. What exists is **`wazuh-alerts-4.x-*`, 120
concrete indices**, newest the current day, and it is actively read — 3,744 of
3,934 `alert_log_context` rows are `collected`, the newest minutes old.

So the answer to "can the alerts we already store serve the user-side
templates" is **yes, from `wazuh-alerts-4.x-*`**, and this module is that
wiring. Measured across 100,381 stored events from the 200 most recent
collections:

| field | present on |
|---|---|
| `agent.name` | **100.0%** |
| `users[]` | **94.5%** |
| `process.image` | 61.4% |
| `network.src_ip` | **0.0%** |

**`source_address_logons` is therefore declined**, not attempted: it is keyed
on `ip`, and `network.src_ip` is absent on all 100,381 events. Attempting it
would return empty on every call — a real negative asserted about data that
was never there, which is the absence-as-value defect this codebase keeps
re-finding. Declining it records `check_failed` naming this source and the
reason.

**It delegates rather than queries.** `alert_log_context_service.collect_for_alert`
is the path that demonstrably works: it is tenant-pinned on
`manager.name`, handles the point-in-time read, normalises hits and is the
code the live pipeline uses every few minutes. Writing fresh OpenSearch
queries here would be a second implementation of the hard part — and a first
attempt at one did return zero rows for every probe, because a `term` query
on an analysed field matches nothing. The working path is the evidence.

Read-only: `collect_for_alert` reads and returns; nothing here writes a row.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.services.context_gathering import event_fields as ef
from app.services.context_gathering.mock_source import SourceUnavailable

logger = logging.getLogger(__name__)

#: Templates this source answers.
#:
#: `process_tree` and `pipe_creator` were declared `EDR` and therefore went to
#: `FalconSource`, which cannot answer either — so they recorded `check_failed`
#: on every call while the data sat in this store. Everything they need is
#: already normalised: `processGuid` on 46,422 events, `parentProcessGuid` on
#: 699, `pipeName` on 1,005.
ANSWERS = ("host_logons", "user_sessions", "user_risk_timeline",
           "process_tree", "pipe_creator")

#: Declined by name, with the measurement that justifies it.
DECLINED = {
    "source_address_logons": (
        "keyed on ip, and network.src_ip is absent on all 100,381 stored "
        "events measured 2026-10-21 — an empty answer here would be a real "
        "negative about data that was never collected"
    ),
}

#: Windows logon family. `host_logons` filters to these; the others do not,
#: because a user's sessions and risk timeline are about everything they did.
LOGON_EVENT_IDS = frozenset({"4624", "4625", "4648", "4672", "4634"})

#: A bound, stated. The collector's own default is larger; this is the loop's
#: budget talking, not a claim about how much exists.
MAX_HITS = 200

#: Which selector each template is queried on. Every name in `ANSWERS` must
#: appear in exactly one of these two, and `query` raises if one appears in
#: neither — see the comment at the call site.
_BY_HOST = frozenset({"host_logons", "process_tree", "pipe_creator"})
_BY_USER = frozenset({"user_sessions", "user_risk_timeline"})


@dataclass
class SiemSource:
    """One tenant's Wazuh alert store, as a source the loop can query."""

    tenant_id: str
    #: The alert's own time. The window is built around it, so it is required
    #: rather than defaulted to `now` — a window centred on the wrong moment
    #: returns a confident answer about the wrong hours.
    alert_time: datetime
    name: str = "wazuh-opensearch"
    kind: str = "siem"
    window_minutes: int = 60
    asked: list[tuple[str, str]] = field(default_factory=list)

    def query(self, template: str, arguments: dict[str, str]) -> list[dict[str, Any]]:
        """Run one template with REAL values and return normalised events."""
        primary = str(arguments.get("host") or arguments.get("user")
                      or arguments.get("ip") or "")
        self.asked.append((template, primary))

        if template in DECLINED:
            raise SourceUnavailable(f"{self.name} cannot answer {template}: "
                                    f"{DECLINED[template]}")
        if template not in ANSWERS:
            raise SourceUnavailable(
                f"{self.name} cannot answer {template}: it is an EDR template "
                f"and this source holds SIEM alerts"
            )
        if not primary:
            raise SourceUnavailable(
                f"{self.name} was asked {template} with no selector value")

        # Which selector the store is actually queried on. Stated as a
        # mapping rather than as `if template == "host_logons"`, because that
        # expression silently sent every new host-keyed template to
        # `entity_user=None, entity_host=None` — `collect_for_alert` then
        # returns `skipped`, "the alert named neither a device nor an
        # account", and the template looks unanswerable rather than
        # misrouted. Adding a template to `ANSWERS` without adding it here
        # now fails loudly below instead.
        host = arguments.get("host") if template in _BY_HOST else None
        user = arguments.get("user") if template in _BY_USER else None
        if host is None and user is None:
            raise SourceUnavailable(
                f"{self.name} has no query key for {template}: it is in "
                f"ANSWERS but in neither _BY_HOST nor _BY_USER"
            )
        try:
            from app.services.alert_log_context_service import collect_for_alert

            context = collect_for_alert(
                event_time=_as_utc(self.alert_time),
                entity_host=host,
                entity_user=user,
                tenant_id=self.tenant_id,
                window_minutes=self.window_minutes,
                max_hits=MAX_HITS,
            )
        except Exception as exc:  # noqa: BLE001
            raise SourceUnavailable(
                f"{self.name} could not be read for {template} "
                f"({type(exc).__name__})"
            ) from exc

        status = str(getattr(context, "status", "") or "")
        # **Only three statuses mean the store was actually read.** The first
        # version of this check raised on `unavailable` and `failed` and let
        # everything else fall through to `logs or []`, which turned
        # `skipped` into an empty list — and the loop records an empty list
        # as `empty`, "the source answered with no matching events".
        #
        # Measured immediately: cases #61 and #892 carry the principal
        # `NT AUTHORITY\SYSTEM`, so `collect_for_alert` correctly returns
        # `skipped` with "the alert named neither a device nor an account
        # that can be queried" — nobody looked. It was reported as a real
        # negative. The absence-as-value defect, in code written minutes
        # after its own docstring described it.
        #
        # So the allow-list is explicit and anything else raises with the
        # collector's own reason attached, which is recorded as
        # `check_failed` naming this source.
        if status not in ("collected", "empty", "partial"):
            raise SourceUnavailable(
                f"{self.name} did not read the store (status {status!r})"
                + (f": {context.reason}" if getattr(context, "reason", None) else "")
            )

        logs = list(getattr(context, "logs", None) or [])
        if template == "host_logons":
            logs = [e for e in logs
                    if str((e or {}).get("event_id") or "") in LOGON_EVENT_IDS]
        elif template == "process_tree":
            logs = _process_tree(logs, str(arguments.get("process") or ""))
        elif template == "pipe_creator":
            logs = _pipe_creator(logs, str(arguments.get("pipe") or ""))
        return logs


def _process_tree(logs: list[dict[str, Any]], process: str) -> list[dict[str, Any]]:
    """The named process's events on this host, plus one hop of lineage.

    Two steps, and the order matters: **seed, then link.** Seeding on the
    process selector first keeps the tree about the process that was alerted
    on; linking first and filtering after would return the host's whole
    process population, which is what `MAX_HITS` events of a busy host is.
    """
    # **`source_image` as well as `image`, or class 10 never seeds.** Measured
    # over 1,500 recent c00 bodies: all 113 class-10 alerts (Sysmon
    # ProcessAccess) carry `sourceImage` and **none** carries `image` — and
    # class 10 is the one event class whose playbook row *is* `process_tree`.
    # Seeding on `image` alone returned nothing on 100% of the alerts this
    # template exists to serve. `sourceImage` is the accessing process, which
    # is the right subject of the tree; it stays a separate alias group
    # because on an event that has both they are different processes.
    seeds = (ef.having(logs, "image", process)
             or ef.having(logs, "source_image", process))
    if not seeds:
        # Nothing matched the selector. Return empty rather than falling back
        # to every event on the host: a tree about a different process,
        # labelled as this one's, is worse than no tree.
        return []
    return ef.link_parents(logs, seeds)


def _pipe_creator(logs: list[dict[str, Any]], pipe: str) -> list[dict[str, Any]]:
    """The events naming this pipe, plus the creating process's lineage.

    `exact=True` on the pipe name: pipe names collide by prefix — the
    measured `SfxCA_259434296` family differs only in the trailing digits —
    and a substring match would present one installer's pipe as another's.
    """
    seeds = ef.having(logs, "pipe_name", pipe, exact=True)
    if not seeds:
        return []
    return ef.link_parents(logs, seeds)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
