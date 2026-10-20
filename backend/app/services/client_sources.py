"""The per-client source map: which platforms a client runs, and how to reach them.

Three pieces, and the division between them is the point.

**`config/client-sources.yaml` is the authoring surface.** Non-secret: which
client runs which platform, and the connection details for each. A client
gaining or losing a platform is a change worth reviewing, and a diff is how
that gets reviewed.

**`tenant_integrations` is the enforcement surface.** One row per (tenant,
platform), carrying the same connection config plus the encrypted credential.
`apply()` writes the file into it and `reconcile()` reports any difference, so
the file is a *control over* the database rather than a second thing that
claims to know. This codebase has had eight registries where two places both
knew something, and they have been the bug every time.

**Postgres is what actually stops a cross-tenant read.** Not this module.
`tenant_integrations` has row-level security enabled and forced, with a policy
of `tenant_id = current_setting('app.tenant_id')`. The application connects as
`tip_app`, which is neither the table's owner nor `BYPASSRLS` — that is what
makes the policy bind, and it is the reason the role split in
`scripts/db_roles.sql` had to come first.

Measured on 2026-10-19, as `tip_app`:

    SET app.tenant_id = 'c00';
    SELECT count(*) FROM tenant_integrations;                     -- c00's rows
    SELECT count(*) FROM tenant_integrations WHERE tenant_id='c01';  -- 0
    RESET app.tenant_id;
    SELECT count(*) FROM tenant_integrations;                     -- 0

The second line is the control: a query that *explicitly asks* for another
tenant returns nothing. The fourth is the one that matters more — with no
binding at all the table is empty, so a code path that forgets to scope reads
nothing rather than everything. Fails closed.

A convention cannot give that. A `WHERE tenant_id = :tid` holds on the queries
somebody remembered; this holds on the ones they did not write yet.

Credentials are not returned by anything here. Opening one goes through
`integration_credential_service.open_for_tenant`, which is already write-only
and scope-enforced, and whose only callers are connectors.

No connectors exist for these platforms yet. This is the structure, the
enforcement and the test.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.services import tenant_scope as tenant_scope_module
from app.services.tenant_scope import TenantForbidden, TenantScope

#: Where the authoring surface lives.
#:
#: Resolved by trying candidates rather than by one hard-coded relative path,
#: because the layouts differ: on a developer machine this module is at
#: `<repo>/backend/app/services/`, and in the container `backend/` is mounted
#: at `/app` with `config/` mounted separately at `/config`. The first version
#: computed `parents[3]` and got `/config/client-sources.yaml` in the
#: container and the right path on the host — correct by accident in one place
#: and wrong in the other.
_MAP_CANDIDATES = (
    Path("/config/client-sources.yaml"),
    Path(__file__).resolve().parents[3] / "config" / "client-sources.yaml",
    Path(__file__).resolve().parents[2] / "config" / "client-sources.yaml",
)


def default_map_path() -> Path:
    """The first candidate that exists, else the first candidate.

    Returning a non-existent path rather than raising here: `load()` is the
    one place that decides what a missing map means, and it has a longer
    explanation than this function could give.
    """
    override = (os.environ.get("CLIENT_SOURCES_PATH") or "").strip()
    if override:
        return Path(override)
    for candidate in _MAP_CANDIDATES:
        if candidate.exists():
            return candidate
    return _MAP_CANDIDATES[0]

#: The session variable the row-level policy reads. Re-exported from
#: `tenant_scope`, which owns it, rather than spelled again here — the policy
#: moved from a single tenant to a scope in migration 073 and two spellings
#: would have meant one of them silently binding nothing.
TENANT_SETTING = tenant_scope_module.SCOPE_SETTING


# ── the platforms ────────────────────────────────────────────────────────
#
# Declared as `INTEGRATION_SPECS` so `integration_status_service.catalogue()`
# picks them up with the rest. The catalogue is derived rather than
# enumerated, and these join it the same way every other integration does —
# a second list of platform names here would be the ninth hand-maintained
# registry.
#
# `managed: "credential_store"` is the platform's existing vocabulary for "the
# credential is per-tenant and lives in `tenant_integrations`", as against
# `"deployment"` for something configured from the environment like OpenSearch.
# The first version of this said `"tenant"`, which meant the same thing in a
# word nothing else uses — `test_every_tool_declares_how_it_is_managed` caught
# it, because the UI decides whether to offer a credential form from this
# value and an unrecognised one offers nothing.
#
# `config_fields` is also the validator: a key under `connection:` in the YAML
# that is not declared here is a refusal. `required` is separate, because a
# field can be meaningful and optional.

@dataclass(frozen=True)
class PlatformSpec:
    tool: str
    label: str
    category: str
    #: field name -> what it is, for the operator filling it in
    config_fields: Mapping[str, str]
    #: field name -> what it is. Set through the API; never in the YAML.
    secret_fields: Mapping[str, str]
    #: which config fields must be present and non-empty
    required: tuple[str, ...]
    directions: tuple[str, ...] = ("ingest",)

    def as_spec(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "label": self.label,
            "category": self.category,
            "managed": "credential_store",
            "directions": self.directions,
            "config_fields": dict(self.config_fields),
            "secret_fields": dict(self.secret_fields),
        }


PLATFORMS: dict[str, PlatformSpec] = {
    "exabeam": PlatformSpec(
        tool="exabeam",
        label="Exabeam",
        category="siem",
        config_fields={
            "base_url": "Advanced Analytics base URL, e.g. https://aa.client.example",
            "data_lake_url": "Data Lake / search base URL, if separate from base_url.",
            "site_id": "The site or instance identifier, when the client runs more than one.",
        },
        secret_fields={
            "api_key": "API key for this client's instance. Never shared between clients.",
        },
        required=("base_url",),
    ),
    "sentinelone": PlatformSpec(
        tool="sentinelone",
        label="SentinelOne",
        category="edr",
        config_fields={
            "console_url": "Management console URL, e.g. https://client.sentinelone.net",
            "site_ids": "Comma-separated site id(s) this client owns in that console.",
            "account_id": "Account id, when the console hosts more than one account.",
        },
        secret_fields={
            "api_token": "Service-user API token scoped to this client's site(s) only.",
        },
        required=("console_url",),
    ),
    "cortex": PlatformSpec(
        tool="cortex",
        label="Cortex XDR",
        category="edr",
        config_fields={
            "api_url": "Tenant API URL, e.g. https://api-client.xdr.paloaltonetworks.com",
            "tenant_name": "The Cortex tenant name, for reports and for telling two apart.",
        },
        secret_fields={
            "api_key": "API key for this client's tenant.",
            "api_key_id": "The key id that accompanies it.",
        },
        required=("api_url",),
    ),
}

#: Picked up by `integration_status_service._declared_elsewhere`.
INTEGRATION_SPECS: list[dict[str, Any]] = [p.as_spec() for p in PLATFORMS.values()]

#: Any `connection` key matching this is refused outright. The one thing this
#: file must never carry is the thing that grants access, and "we will
#: remember not to" is not a control.
_SECRET_SHAPED = re.compile(r"(token|secret|password|passwd|credential|api_?key|private)", re.I)


class SourceMapInvalid(ValueError):
    """The source map is malformed.

    Raised for the whole file rather than skipping the bad entry. A source map
    that silently drops a client is a client whose alerts quietly stop being
    enriched, and the failure would surface days later as "no data from that
    platform" rather than as a startup error.
    """


@dataclass(frozen=True)
class ClientSource:
    """One platform, for one client."""

    tenant_id: str
    platform: str
    connection: Mapping[str, str]

    @property
    def spec(self) -> PlatformSpec:
        return PLATFORMS[self.platform]


@dataclass(frozen=True)
class ClientEntry:
    """One client and every platform it runs.

    **No name.** The client's name is `tenants.name` in the database, and a
    copy of it here could disagree with the row it duplicates. It also keeps
    the customer list out of the repository's history, which no rotation
    undoes. `scripts/apply_client_sources.py --render` joins the names back on
    for anyone who wants to read the map.
    """

    tenant_id: str
    sources: tuple[ClientSource, ...] = field(default_factory=tuple)

    def platforms(self) -> tuple[str, ...]:
        return tuple(s.platform for s in self.sources)


def load(path: Path | str | None = None) -> dict[str, ClientEntry]:
    """The source map, validated, keyed by tenant_id.

    Refuses the file on any problem — see `SourceMapInvalid`.
    """
    import yaml

    target = Path(path) if path is not None else default_map_path()
    if not target.exists():
        looked = ", ".join(str(c) for c in _MAP_CANDIDATES)
        raise SourceMapInvalid(
            f"no source map at {target}. This is not an empty map: a missing "
            f"file and a file declaring no clients are different states, and "
            f"only the second one is a deployment that has been configured. "
            f"Looked in: {looked}."
        )
    raw = yaml.safe_load(target.read_text()) or {}
    if not isinstance(raw, dict):
        raise SourceMapInvalid(f"{target}: top level must be a mapping")

    version = raw.get("version")
    if version != 1:
        raise SourceMapInvalid(
            f"{target}: unsupported version {version!r}. Refused rather than "
            f"assumed: a format change that reads as the old one is how a "
            f"connection detail silently becomes the wrong value."
        )

    clients = raw.get("clients")
    if clients is None:
        clients = []
    if not isinstance(clients, list):
        raise SourceMapInvalid(f"{target}: `clients` must be a list")

    out: dict[str, ClientEntry] = {}
    for index, entry in enumerate(clients):
        where = f"{target}: clients[{index}]"
        if not isinstance(entry, dict):
            raise SourceMapInvalid(f"{where} must be a mapping")
        tenant_id = str(entry.get("tenant_id") or "").strip()
        if not tenant_id:
            raise SourceMapInvalid(f"{where} has no tenant_id")
        if tenant_id in out:
            raise SourceMapInvalid(
                f"{where}: tenant_id {tenant_id!r} appears more than once. "
                f"Two entries for one client means one of them is being "
                f"ignored, and which one depends on iteration order."
            )
        # Refused, not ignored. A `name:` that the loader skipped would look
        # like it worked, and the next person would add the whole customer
        # list — which is the thing this decision keeps out of the repository.
        # The error says where the name actually lives.
        if "name" in entry:
            raise SourceMapInvalid(
                f"{where}: `name` is not part of the source map. A client's "
                f"name is `tenants.name` in the database; a copy here can "
                f"disagree with it, and committing it puts the customer list "
                f"in the repository's history. Use "
                f"`scripts/apply_client_sources.py --render` to read the map "
                f"with names joined on."
            )
        platforms = entry.get("platforms") or []
        if not isinstance(platforms, list):
            raise SourceMapInvalid(f"{where}: `platforms` must be a list")

        sources: list[ClientSource] = []
        seen: set[str] = set()
        for p_index, platform_entry in enumerate(platforms):
            p_where = f"{where}.platforms[{p_index}]"
            if not isinstance(platform_entry, dict):
                raise SourceMapInvalid(f"{p_where} must be a mapping")
            platform = str(platform_entry.get("platform") or "").strip()
            if platform not in PLATFORMS:
                raise SourceMapInvalid(
                    f"{p_where}: unknown platform {platform!r}. Known: "
                    f"{', '.join(sorted(PLATFORMS))}. A platform nothing "
                    f"implements is a connection detail held for no reason."
                )
            if platform in seen:
                raise SourceMapInvalid(
                    f"{p_where}: {platform!r} declared twice for {tenant_id!r}"
                )
            seen.add(platform)

            connection = platform_entry.get("connection") or {}
            if not isinstance(connection, dict):
                raise SourceMapInvalid(f"{p_where}: `connection` must be a mapping")
            spec = PLATFORMS[platform]
            for key, value in connection.items():
                if _SECRET_SHAPED.search(str(key)):
                    raise SourceMapInvalid(
                        f"{p_where}: `{key}` looks like a secret. Credentials are "
                        f"set through the API into tenant_integrations, encrypted; "
                        f"they are never written to this file and never committed. "
                        f"If this is genuinely not a secret, rename it."
                    )
                if key not in spec.config_fields:
                    raise SourceMapInvalid(
                        f"{p_where}: `{key}` is not a config field of {platform!r}. "
                        f"Declared: {', '.join(sorted(spec.config_fields))}. A key "
                        f"this platform does not read would be silently ignored, "
                        f"which is how a connection points at nothing."
                    )
                if value is None or str(value).strip() == "":
                    raise SourceMapInvalid(f"{p_where}: `{key}` is empty")
            missing = [f for f in spec.required if not str(connection.get(f) or "").strip()]
            if missing:
                raise SourceMapInvalid(
                    f"{p_where}: {platform!r} requires {', '.join(missing)}"
                )
            sources.append(ClientSource(
                tenant_id=tenant_id,
                platform=platform,
                connection={k: str(v) for k, v in connection.items()},
            ))

        out[tenant_id] = ClientEntry(tenant_id=tenant_id, sources=tuple(sources))
    return out


# ── the enforced read ────────────────────────────────────────────────────


def sources_for(
    tenant_id: str,
    *,
    scope: TenantScope,
    map_path: Path | str | None = None,
) -> tuple[ClientSource, ...]:
    """Every source belonging to this client, and nothing else.

    `scope` is a **required keyword**. Not `scope: TenantScope | None = None`
    meaning "no restriction": a parameter somebody forgets to pass must never
    be the one that opens a read up. `integration_credential_service` takes
    the same decision for the same reason, and this is the same kind of table.

    Raises `TenantForbidden` when the caller's scope does not include the
    tenant. That is a refusal, not an empty list — an empty list would read as
    "this client has no sources", which is a different and reassuring fact.
    """
    tenant = str(tenant_id or "").strip()
    if not tenant:
        raise TenantForbidden(
            "a source lookup needs a tenant; refusing to resolve an unscoped map"
        )
    if not scope.may_read(tenant):
        raise TenantForbidden(
            f"scope held by {scope.actor!r} does not include tenant {tenant!r}"
        )
    entry = load(map_path).get(tenant)
    return entry.sources if entry else ()


def platforms_for(tenant_id: str, *, scope: TenantScope,
                  map_path: Path | str | None = None) -> tuple[str, ...]:
    """Which platforms this client runs. Same enforcement as `sources_for`."""
    return tuple(s.platform for s in sources_for(tenant_id, scope=scope, map_path=map_path))


def bind_tenant(session: Any, tenant_id: str) -> None:
    """Bind a synchronous session to one tenant, for the row-level policy.

    A thin wrapper over `tenant_scope.bind_sync` with a single-tenant scope,
    kept because reading one client's sources is the common case and spelling
    a `TenantScope` at every call site invites someone to spell a wider one.

    The policy reads a scope rather than a tenant since migration 073: it had
    to, because `rotate_all` and the status listing legitimately cross
    tenants, and a single-id policy made those return nothing.
    """
    tenant = str(tenant_id or "").strip()
    if not tenant:
        raise TenantForbidden("refusing to bind a session to an empty tenant")
    tenant_scope_module.bind_sync(
        session, TenantScope(tenant_ids=(tenant,), actor="client-sources")
    )


def reconcile(
    db_rows: Iterable[Mapping[str, Any]],
    map_path: Path | str | None = None,
) -> dict[str, list[str]]:
    """Differences between the file and the database.

    Returns a dict of finding -> descriptions, empty when they agree. This is
    what makes the file a control rather than a second authority: the file is
    reviewed, the database is enforced, and a difference between them is a
    reportable fact instead of a question about which one is right.

    `db_rows` is passed in rather than queried here so this stays testable
    without a database and so the caller decides the tenant binding.
    """
    expected = load(map_path)
    findings: dict[str, list[str]] = {
        "in_file_not_in_database": [],
        "in_database_not_in_file": [],
        "connection_differs": [],
        "unknown_platform_in_database": [],
    }

    wanted = {
        (entry.tenant_id, source.platform): source
        for entry in expected.values() for source in entry.sources
    }
    present: dict[tuple[str, str], Mapping[str, Any]] = {}
    for row in db_rows:
        tenant = str(row.get("tenant_id") or "")
        tool = str(row.get("tool") or "")
        present[(tenant, tool)] = row
        if tool not in PLATFORMS:
            # Not a finding against the file: OpenSearch and the enrichment
            # integrations legitimately live in this table and are not part of
            # the client source map. Only reported when it is neither.
            continue

    for key, source in sorted(wanted.items()):
        if key not in present:
            findings["in_file_not_in_database"].append(f"{key[0]}/{key[1]}")
            continue
        stored = present[key].get("config") or {}
        if not isinstance(stored, dict):
            stored = {}
        differs = sorted(
            k for k in set(source.connection) | set(stored)
            if str(source.connection.get(k) or "") != str(stored.get(k) or "")
        )
        if differs:
            findings["connection_differs"].append(
                f"{key[0]}/{key[1]}: {', '.join(differs)}"
            )

    for key in sorted(present):
        if key[1] in PLATFORMS and key not in wanted:
            findings["in_database_not_in_file"].append(f"{key[0]}/{key[1]}")

    return {k: v for k, v in findings.items() if v}
