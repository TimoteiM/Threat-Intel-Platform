"""The logs around an alert: ten minutes either side, for the device and the user.

An alert says what a rule matched. It does not say what else the machine or the
account was doing at the time, which is the first question an analyst asks and
the one this platform could not answer. This module asks it of the log store the
alerts themselves come from.

Three things decide whether the answer is any good.

**Who the alert is about.** The run already carries `entity_host` and
`entity_user`, and both have known failure modes that matter more here than they
do in correlation, because a wrong value does not merely misfile a row — it
returns another machine's logs as this alert's evidence. Two guards, both
deliberate:

* A manager-forwarded alert names the *manager* in `agent.name`. Filtering on it
  matches every forwarded log in the estate. `entity_of()` already refuses to
  call that a host; this refuses to query it.
* `entity_user` is sometimes the domain half of `DOMAIN\\user` — measured at 318
  of 3,376 stored bodies carrying that form. Querying `CORP` as a username
  returns nothing at best and, if some account is called CORP, the wrong
  person's activity. `principal_of()` re-derives the principal from the body for
  query purposes only; the stored column is left alone, because correlation
  groups on it and changing it under a running case is a separate decision.

**How much is read.** This cluster takes about 23 million documents a day. A
twenty-minute window on a busy host is six figures of logs, so the read is
capped, paged with `search_after`, and reports the cap being hit rather than
quietly returning a slice.

**Whether the window has happened yet.** A real-time alert's window ends in the
future. What exists now is returned immediately and the rest is fetched by a
durable follow-up — see `tasks/alert_log_followup_task.py`. Every hit carries a
stable `index:id` key, so the follow-up merges rather than duplicates, however
many times it runs.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

from app.config import get_settings
from app.services import opensearch_client as osc
from app.services.alert_field_service import MANAGER_AGENT_ID, looks_like_host

logger = logging.getLogger(__name__)


# Accounts that are not a person or a service identity worth pivoting on. The
# host side of this platform already has its equivalent (`_DEVICE_CATEGORIES`);
# this is the user side, and it fails toward querying nothing rather than
# toward querying every machine in the estate at once.
NON_PRINCIPALS = frozenset({
    "system", "local system", "nt authority\\system", "anonymous",
    "anonymous logon", "network service", "local service", "-", "n/a",
    "unknown", "null", "none", "",
})

# Host fields, in the order a match is preferred. All are `keyword` in the
# live mapping, so these are exact term filters and never analysed matches.
HOST_FIELDS: tuple[str, ...] = (
    "agent.name",
    "data.win.system.computer",
    "data.Computer",
    "data.hostname",
    "predecoder.hostname",
)
HOST_IP_FIELDS: tuple[str, ...] = ("agent.ip",)

# User fields worth querying, chosen by measuring which are actually populated
# on a full day of this cluster rather than by reading the mapping: of 60-odd
# user-shaped fields, these are the ones with a non-trivial share of documents.
USER_FIELDS: tuple[str, ...] = (
    "data.win.eventdata.subjectUserName",   # 11.8% of a day
    "data.dstuser",                         #  6.7%
    "data.win.eventdata.user",              #  3.7%
    "data.win.eventdata.targetUserName",    #  3.6%
    "data.ms-graph.userPrincipalName",      #  1.1%
    "data.office365.UserId",                #  0.2%
    "data.srcuser",
    "data.ldap.user_name",
    "data.win.eventdata.userUPN",
    "data.win.eventdata.sourceUser",
)

# What is kept from a hit. The mapping has 1,644 leaf fields; a case that pulled
# whole documents would store megabytes of Windows event XML per alert.
SOURCE_FIELDS: tuple[str, ...] = (
    "timestamp", "@timestamp",
    "agent.id", "agent.name", "agent.ip", "manager.name",
    "rule.id", "rule.level", "rule.description", "rule.groups", "rule.mitre.technique",
    "decoder.name", "location", "full_log",
    "data.win.system.eventID", "data.win.system.computer",
    "data.win.eventdata.subjectUserName", "data.win.eventdata.targetUserName",
    "data.win.eventdata.user", "data.win.eventdata.image",
    "data.win.eventdata.commandLine", "data.win.eventdata.parentImage",
    "data.srcuser", "data.dstuser", "data.srcip", "data.dstip",
    "data.ms-graph.userPrincipalName", "data.office365.UserId",
)

_FULL_LOG_CHARS = 600
_DOMAIN_USER = re.compile(r"(?<![\w.\\])(?P<domain>[A-Za-z0-9][A-Za-z0-9._-]{1,30})\\(?P<user>[A-Za-z0-9][\w.$@-]{0,63})")


# ── who the alert is about ───────────────────────────────────────────────────


@dataclass
class Principal:
    """A user, in the spellings a log store might hold them under."""

    account: str | None = None       # bare sAMAccountName, e.g. jdoe
    domain: str | None = None        # NetBIOS or DNS domain, when one was given
    upn: str | None = None           # user@domain.tld, when one was given
    rejected_reason: str | None = None

    @property
    def usable(self) -> bool:
        return bool(self.account or self.upn)

    def spellings(self) -> list[str]:
        """Every form this principal plausibly appears as, deduplicated.

        One principal wears three costumes across a Wazuh estate — `jdoe`,
        `CORP\\jdoe` and `jdoe@corp.tld` — and they land in different fields of
        different documents. Querying one spelling finds one third of the
        activity.
        """
        out: list[str] = []
        for value in (
            self.account,
            self.upn,
            f"{self.domain}\\{self.account}" if self.domain and self.account else None,
            self.account.upper() if self.account else None,
            self.account.lower() if self.account else None,
        ):
            if value and value not in out:
                out.append(value)
        return out


def principal_of(entity_user: str | None, *, alert_body: str | None = None) -> Principal:
    """The account to query for, from the stored value and the body behind it.

    The stored `entity_user` is used as written unless the body shows it to be
    the domain half of a `DOMAIN\\user` pair, which is a known and measured
    extractor bug. Re-deriving here rather than fixing the extractor is a
    deliberate narrowing: correlation groups cases on that column, and changing
    it would re-key live cases. This only decides what to ask the log store.
    """
    raw = str(entity_user or "").strip()
    body = str(alert_body or "")

    # `CORP\jdoe` stored as `CORP`. Only overridden when the body actually shows
    # that form with this value as the domain — an account legitimately called
    # CORP is otherwise queried as itself.
    if raw and body:
        for match in _DOMAIN_USER.finditer(body):
            if match.group("domain").casefold() == raw.casefold():
                return Principal(account=match.group("user"), domain=match.group("domain"))

    if not raw:
        return Principal(rejected_reason="the alert named no user")

    if "\\" in raw:
        domain, _, account = raw.partition("\\")
        principal = Principal(account=account.strip() or None, domain=domain.strip() or None)
    elif "@" in raw and "." in raw.rsplit("@", 1)[-1]:
        principal = Principal(account=raw.split("@", 1)[0], upn=raw, domain=raw.rsplit("@", 1)[-1])
    else:
        principal = Principal(account=raw)

    if (principal.account or "").casefold() in NON_PRINCIPALS or raw.casefold() in NON_PRINCIPALS:
        # Not a principal. Querying `system` returns every machine's activity
        # and would present it as one account's — the user-side equivalent of
        # the fabricated-campaign failure the host denylist exists to prevent.
        return Principal(rejected_reason=f"{raw!r} is not a principal")
    if principal.account and principal.account.endswith("$"):
        return Principal(rejected_reason=f"{raw!r} is a machine account")

    return principal


@dataclass
class Device:
    name: str | None = None
    ip: str | None = None
    rejected_reason: str | None = None

    @property
    def usable(self) -> bool:
        return bool(self.name or self.ip)


def device_of(entity_host: str | None, *, alert_fields: dict[str, Any] | None = None) -> Device:
    """The machine to query for, refusing the manager.

    A Wazuh alert forwarded by the manager carries the manager in `agent.name`
    and `agent.id` `000`. Filtering logs on that name returns every forwarded
    log in the estate, which would look like an extremely busy host rather than
    like a mistake.
    """
    fields = alert_fields or {}
    if str(fields.get("agent_id") or "").strip() == MANAGER_AGENT_ID:
        ip = str(fields.get("agent_ip") or "").strip()
        if looks_like_host(ip):
            return Device(ip=ip)
        return Device(rejected_reason="the alert was forwarded by the manager, which names no device")

    host = str(entity_host or "").strip()
    if not host:
        ip = str(fields.get("agent_ip") or "").strip()
        if looks_like_host(ip):
            return Device(ip=ip)
        return Device(rejected_reason="the alert named no device")
    if not looks_like_host(host):
        return Device(rejected_reason=f"{host!r} describes a device rather than naming one")

    if re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+", host):
        return Device(ip=host)
    return Device(name=host, ip=(str(fields.get("agent_ip") or "").strip() or None))


# ── the window ───────────────────────────────────────────────────────────────


@dataclass
class LogWindow:
    start: datetime
    end: datetime
    covered_until: datetime
    complete: bool

    @property
    def pending_seconds(self) -> float:
        return max(0.0, (self.end - self.covered_until).total_seconds())


def window_for(event_time: datetime, *, minutes: int | None = None,
               now: datetime | None = None) -> LogWindow:
    """Ten minutes either side, clipped to the present.

    A real-time alert's window ends in the future, so `covered_until` says how
    much of it has happened. The follow-up picks up from exactly there.
    """
    settings = get_settings()
    span = timedelta(minutes=int(minutes if minutes is not None else settings.alert_log_window_minutes))
    now = now or datetime.now(timezone.utc)
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    start, end = event_time - span, event_time + span
    covered = min(end, now)
    return LogWindow(start=start, end=end, covered_until=covered, complete=covered >= end)


# ── the query ────────────────────────────────────────────────────────────────


def follow_up_start(
    *, window_start: datetime, covered_until: datetime, overlap_seconds: int
) -> datetime:
    """Where a follow-up read begins: before the high-water mark, not at it.

    A document whose event time fell inside the covered slice can be indexed
    after that slice was read. Measured on this cluster over two hours, the gap
    between a document's event time and its indexing is p50 0.53s, p99 4.2s,
    p99.9 11.4s and at most 15.8s — small, but never zero, and a follow-up
    starting exactly at the mark would step over those documents permanently.

    Re-reading the overlap costs a handful of duplicate hits, which merge away
    on each document's own index:id. Missing a log does not announce itself.
    """
    if covered_until.tzinfo is None:
        covered_until = covered_until.replace(tzinfo=timezone.utc)
    if window_start.tzinfo is None:
        window_start = window_start.replace(tzinfo=timezone.utc)
    return max(window_start, covered_until - timedelta(seconds=max(0, int(overlap_seconds))))


def build_query(
    *,
    device: Device,
    principal: Principal,
    start: datetime,
    end: datetime,
    timestamp_field: str,
    tenant_field: str | None = None,
    tenant_values: Sequence[str] | None = None,
) -> dict[str, Any] | None:
    """A bool query over one time range and whichever entities are usable.

    The entity clauses are `should` with `minimum_should_match: 1`: logs *about
    the device* or *about the account*, which is what "what else was happening"
    means. With neither usable there is nothing to ask, and returning None is
    how the caller learns that — an unfiltered window would return ten minutes
    of the entire estate.
    """
    entity_clauses: list[dict[str, Any]] = []

    if device.name:
        entity_clauses.append({"terms": {HOST_FIELDS[0]: [device.name]}})
        for field_name in HOST_FIELDS[1:]:
            entity_clauses.append({"term": {field_name: device.name}})
    if device.ip:
        for field_name in HOST_IP_FIELDS:
            entity_clauses.append({"term": {field_name: device.ip}})

    if principal.usable:
        spellings = principal.spellings()
        for field_name in USER_FIELDS:
            entity_clauses.append({"terms": {field_name: spellings}})

    if not entity_clauses:
        return None

    filters: list[dict[str, Any]] = [{
        "range": {
            timestamp_field: {
                "gte": start.astimezone(timezone.utc).isoformat(),
                "lte": end.astimezone(timezone.utc).isoformat(),
                "format": "strict_date_optional_time",
            }
        }
    }]
    # A `filter`, not a `should`: this one is not negotiable against the entity
    # match. A query that can return another tenant's logs if the entity clause
    # happens to match is not pinned at all.
    if tenant_field and tenant_values:
        filters.append({"terms": {tenant_field: list(tenant_values)}})

    return {
        "bool": {
            "filter": filters,
            "should": entity_clauses,
            "minimum_should_match": 1,
        }
    }


def _get(source: dict[str, Any], path: str) -> Any:
    """Read a dotted path from a hit's _source, which may be nested or flat."""
    if path in source:
        return source[path]
    node: Any = source
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def normalise_hit(hit: dict[str, Any], *, device: Device, principal: Principal) -> dict[str, Any]:
    """One log line, small enough to store and explicit about why it matched.

    `matched_on` is what makes a retrieved log traceable back to the reason it
    is in the report: an analyst reading "why is this here" gets "the device"
    or "the account", not a silent union.
    """
    source = hit.get("_source") or {}
    agent_name = _get(source, "agent.name")
    agent_ip = _get(source, "agent.ip")

    users = [
        str(_get(source, f)) for f in USER_FIELDS
        if _get(source, f) not in (None, "")
    ]
    spellings = {s.casefold() for s in principal.spellings()}
    matched: list[str] = []
    if device.name and str(agent_name or "").casefold() == device.name.casefold():
        matched.append("device")
    elif device.ip and str(agent_ip or "") == device.ip:
        matched.append("device")
    if spellings and any(u.casefold() in spellings or u.casefold().endswith("\\" + next(iter(spellings), "")) for u in users):
        matched.append("user")

    full_log = source.get("full_log")
    return {
        "key": f"{hit.get('_index')}:{hit.get('_id')}",
        "index": hit.get("_index"),
        "id": hit.get("_id"),
        "timestamp": _get(source, "timestamp") or _get(source, "@timestamp"),
        "agent": {"id": _get(source, "agent.id"), "name": agent_name, "ip": agent_ip},
        "manager": _get(source, "manager.name"),
        "rule": {
            "id": _get(source, "rule.id"),
            "level": _get(source, "rule.level"),
            "description": _get(source, "rule.description"),
            "groups": _get(source, "rule.groups"),
            "mitre_technique": _get(source, "rule.mitre.technique"),
        },
        "event_id": _get(source, "data.win.system.eventID"),
        "users": users[:4],
        "process": {
            "image": _get(source, "data.win.eventdata.image"),
            "command_line": (str(_get(source, "data.win.eventdata.commandLine"))[:400]
                             if _get(source, "data.win.eventdata.commandLine") else None),
            "parent_image": _get(source, "data.win.eventdata.parentImage"),
        },
        "network": {"src_ip": _get(source, "data.srcip"), "dst_ip": _get(source, "data.dstip")},
        "decoder": _get(source, "decoder.name"),
        "location": _get(source, "location"),
        "full_log": (str(full_log)[:_FULL_LOG_CHARS] if full_log else None),
        "matched_on": matched or ["window"],
    }


# ── the read ─────────────────────────────────────────────────────────────────


@dataclass
class LogContext:
    """Everything a report needs to show the logs and say where they came from."""

    status: str = "unavailable"          # collected | partial | empty | unavailable | skipped
    reason: str | None = None
    logs: list[dict[str, Any]] = field(default_factory=list)
    window: dict[str, Any] = field(default_factory=dict)
    sources: dict[str, Any] = field(default_factory=dict)
    selectors: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "log_count": len(self.logs),
            "truncated": self.truncated,
            "window": self.window,
            "selectors": self.selectors,
            "sources": self.sources,
            "logs": self.logs,
        }


def collect_for_alert(
    *,
    event_time: datetime | None,
    entity_host: str | None,
    entity_user: str | None,
    alert_body: str | None = None,
    alert_fields: dict[str, Any] | None = None,
    window_minutes: int | None = None,
    max_hits: int | None = None,
    start_override: datetime | None = None,
    now: datetime | None = None,
    client: Any = None,
    settings: Any = None,
) -> LogContext:
    """Logs around one alert.

    `start_override` exists for the follow-up: it re-reads only the slice that
    had not happened yet, so a completed run is never re-fetched.

    Never raises. Every failure mode — no cluster, no entity, no time, a node
    down — comes back as a `LogContext` with a status and a reason, because an
    alert must be analysed whether or not its logs could be read.
    """
    settings = settings or get_settings()
    context = LogContext()

    if not getattr(settings, "alert_log_context_enabled", True):
        context.status = "skipped"
        context.reason = "Log context retrieval is disabled."
        return context
    if not getattr(settings, "opensearch_enabled", True):
        context.status = "skipped"
        context.reason = "OpenSearch is disabled."
        return context
    if event_time is None:
        context.reason = "The alert carried no parseable event time, so there is no window to read."
        return context

    device = device_of(entity_host, alert_fields=alert_fields)
    principal = principal_of(entity_user, alert_body=alert_body)
    context.selectors = {
        "device": {"name": device.name, "ip": device.ip, "rejected": device.rejected_reason},
        "user": {
            "account": principal.account,
            "domain": principal.domain,
            "upn": principal.upn,
            "spellings": principal.spellings(),
            "rejected": principal.rejected_reason,
        },
    }

    window = window_for(event_time, minutes=window_minutes, now=now)
    effective_start = start_override or window.start
    context.window = {
        "event_time": event_time.astimezone(timezone.utc).isoformat(),
        "start": window.start.astimezone(timezone.utc).isoformat(),
        "end": window.end.astimezone(timezone.utc).isoformat(),
        "covered_until": window.covered_until.astimezone(timezone.utc).isoformat(),
        "complete": window.complete,
        "minutes_either_side": int(
            window_minutes if window_minutes is not None else settings.alert_log_window_minutes
        ),
    }

    if not (device.usable or principal.usable):
        context.status = "skipped"
        context.reason = (
            "The alert named neither a device nor an account that can be queried"
            + (f" ({device.rejected_reason})" if device.rejected_reason else "")
            + (f" ({principal.rejected_reason})" if principal.rejected_reason else "")
            + ". An unfiltered window would return every log in the estate."
        )
        return context

    if effective_start >= window.covered_until:
        context.status = "partial" if not window.complete else "empty"
        context.reason = "The window has not happened yet; a follow-up will read it."
        context.sources = {"pending_seconds": round(window.pending_seconds)}
        return context

    timestamp_field = str(getattr(settings, "opensearch_timestamp_field", "timestamp"))
    tenant_field = str(getattr(settings, "opensearch_tenant_field", "") or "")
    tenant_values = list(getattr(settings, "opensearch_tenant_value_list", []) or [])
    query = build_query(
        device=device, principal=principal,
        start=effective_start, end=window.covered_until,
        timestamp_field=timestamp_field,
        tenant_field=tenant_field, tenant_values=tenant_values,
    )
    if query is None:  # pragma: no cover — guarded by the usable check above
        context.status = "skipped"
        context.reason = "No entity to filter on."
        return context

    owns_client = client is None
    if client is None:
        try:
            client = osc.OpenSearchClient(settings=settings)
        except osc.OpenSearchNotConfigured as exc:
            # Carries the specific reason — no nodes, no credentials, or a CA
            # bundle that is not on disk — rather than one word for all three.
            context.reason = f"{exc} The alert was analysed without its logs."
            return context
        except Exception as exc:  # noqa: BLE001
            context.reason = f"OpenSearch client unavailable: {osc.redact(exc)[:200]}"
            return context

    try:
        indices = osc.describe_indices(
            pattern=str(settings.opensearch_index_pattern),
            start=effective_start, end=window.covered_until, client=client,
        )
        result = client.search_all(
            indices=indices,
            query=query,
            # `_id` last so paging is stable: two documents sharing a millisecond
            # would otherwise make search_after loop or skip.
            sort=[{timestamp_field: {"order": "asc"}}, {"_id": {"order": "asc"}}],
            source_fields=SOURCE_FIELDS,
            page_size=int(settings.alert_log_page_size),
            max_hits=int(max_hits if max_hits is not None else settings.alert_log_max_hits),
            use_pit=bool(getattr(settings, "opensearch_use_point_in_time", True)),
        )
    except osc.OpenSearchUnavailable as exc:
        context.reason = f"No OpenSearch node answered; the alert was analysed without its logs. {osc.redact(exc)[:200]}"
        logger.warning("Log context unavailable: %s", osc.redact(exc)[:300])
        return context
    except osc.OpenSearchError as exc:
        context.reason = f"OpenSearch could not answer: {osc.redact(exc)[:200]}"
        logger.warning("Log context query failed: %s", osc.redact(exc)[:300])
        return context
    finally:
        if owns_client and client is not None:
            client.close()

    context.logs = [normalise_hit(h, device=device, principal=principal) for h in result.hits]
    context.truncated = result.truncated
    context.sources = {
        "cluster_index_pattern": str(settings.opensearch_index_pattern),
        "indices": result.indices_searched,
        "nodes_used": result.nodes_used,
        "node_failures": result.node_failures,
        "timestamp_field": timestamp_field,
        # Stated either way. "No tenant filter" is a fact a reader should see,
        # not an absence they have to notice.
        "tenant_filter": (
            {"field": tenant_field, "values": tenant_values}
            if tenant_field and tenant_values else None
        ),
        "pages": result.pages,
        "consistent_pagination": bool(getattr(result, "consistent", False)),
        "took_ms": result.took_ms,
        "max_hits": int(max_hits if max_hits is not None else settings.alert_log_max_hits),
        "queried_from": effective_start.astimezone(timezone.utc).isoformat(),
        "queried_to": window.covered_until.astimezone(timezone.utc).isoformat(),
    }
    if not window.complete:
        context.status = "partial"
        context.reason = (
            f"The alert is live: {round(window.pending_seconds)}s of its window has not happened yet. "
            "A follow-up will read the remainder."
        )
    elif context.logs:
        context.status = "collected"
    else:
        context.status = "empty"
        context.reason = "No logs matched this device or account in the window."
    return context


def merge_logs(existing: Sequence[dict[str, Any]], incoming: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Union by `index:id`, ordered by time.

    This is what makes the follow-up safe to retry: the key is the document's
    own identity in the cluster, so re-reading an overlapping slice adds
    nothing, whether it is re-read once or ten times.
    """
    merged: dict[str, dict[str, Any]] = {}
    for record in list(existing) + list(incoming):
        key = str(record.get("key") or f"{record.get('index')}:{record.get('id')}")
        merged.setdefault(key, record)
    return sorted(merged.values(), key=lambda r: (str(r.get("timestamp") or ""), str(r.get("key") or "")))
