"""The per-client source map: structure, validation, and what it refuses.

The isolation control is in `tests/integration/test_client_source_isolation.py`,
because it is a database policy and a fake session cannot refuse a query.
This file is about the map itself: that a malformed entry is a refusal rather
than a silently dropped client, and that a secret cannot be written into a
file that gets committed.
"""

from __future__ import annotations

import pytest

from app.services import client_sources as cs
from app.services.client_sources import PLATFORMS, SourceMapInvalid
from app.services.tenant_scope import TenantForbidden, TenantScope

ALL = TenantScope(all_tenants=True, actor="test")


def _write(tmp_path, body: str):
    path = tmp_path / "map.yaml"
    path.write_text(body)
    return path


VALID = """
version: 1
clients:
  - tenant_id: c00
    platforms:
      - platform: exabeam
        connection:
          base_url: https://aa.c00.example
      - platform: sentinelone
        connection:
          console_url: https://c00.sentinelone.net
          site_ids: s-1,s-2
"""


# ── the shipped file ─────────────────────────────────────────────────────


def test_the_committed_map_loads_and_declares_no_clients():
    """It ships empty on purpose: the structure and the enforcement first, the
    client list when the deployment owner provides it. An empty map is a
    different state from a missing file, and only this one is "configured but
    not populated"."""
    assert cs.load() == {}


def test_a_missing_file_is_a_refusal_not_an_empty_map(tmp_path):
    """The two states must not collapse. A deployment whose map was never
    written and one whose map declares no clients need different answers —
    the first is a mistake and the second is a stage."""
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(tmp_path / "nothing-here.yaml")
    assert "not an empty map" in str(exc.value)


# ── the platforms ────────────────────────────────────────────────────────


def test_the_three_platforms_are_declared_with_their_fields():
    assert set(PLATFORMS) == {"exabeam", "sentinelone", "cortex"}
    for name, spec in PLATFORMS.items():
        assert spec.config_fields, name
        assert spec.secret_fields, f"{name} has no credential; every platform needs one"
        assert spec.required, name
        for required in spec.required:
            assert required in spec.config_fields, f"{name}: {required} is not a field"
        # A credential must never be declared as a config field: config goes
        # in the committed YAML and secrets go in the encrypted store.
        overlap = set(spec.config_fields) & set(spec.secret_fields)
        assert not overlap, f"{name}: {overlap} is both config and secret"


def test_the_platforms_reach_the_derived_catalogue():
    """Not a second registry. `integration_status_service.catalogue()` is
    derived, and these join it the way every other integration does — so the
    status page, the credential service's tool check and the config-field
    schema all see them with nothing to update."""
    from app.services.integration_status_service import catalogue

    cat = catalogue()
    for name, spec in PLATFORMS.items():
        assert name in cat, f"{name} is declared but not in the catalogue"
        # `credential_store`, the platform's existing word for "per-tenant
        # credential in tenant_integrations". Asserted against the value the
        # rest of the code already understands rather than a new one: the UI
        # decides whether to offer a credential form from this field, and
        # `test_every_tool_declares_how_it_is_managed` enumerates the allowed
        # values.
        assert cat[name].managed == "credential_store", (
            f"{name} must be credential-store managed: its credential is "
            f"per-client, unlike the deployment-configured integrations"
        )
        assert set(cat[name].secret_fields) == set(spec.secret_fields)


def test_the_credential_service_accepts_these_tools():
    """The control for the test above: being in the catalogue is what makes a
    credential storable, and `IntegrationToolUnknown` is raised from it."""
    from app.services.integration_status_service import catalogue

    for name in PLATFORMS:
        assert catalogue().get(name) is not None


# ── what the loader refuses ──────────────────────────────────────────────


def test_a_valid_map_loads(tmp_path):
    loaded = cs.load(_write(tmp_path, VALID))
    assert set(loaded) == {"c00"}
    assert loaded["c00"].platforms() == ("exabeam", "sentinelone")
    assert not hasattr(loaded["c00"], "name"), (
        "the map carries a client name again; it duplicates tenants.name and "
        "puts the customer list in the repository"
    )
    assert loaded["c00"].sources[0].connection["base_url"] == "https://aa.c00.example"


@pytest.mark.parametrize("key", ["api_key", "api_token", "password", "client_secret",
                                 "private_key", "APIKey"])
def test_a_secret_shaped_key_is_refused(tmp_path, key):
    """**The refusal that matters most.** This file is committed. A credential
    in it is a credential in the repository's history, where no rotation
    removes it."""
    body = VALID.replace("          site_ids: s-1,s-2", f"          {key}: whatever")
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(_write(tmp_path, body))
    assert key in str(exc.value)
    assert "never committed" in str(exc.value)


def test_an_undeclared_connection_key_is_refused(tmp_path):
    """A typo must not be a setting that is silently ignored — that is how a
    connection ends up pointing at a default nobody chose."""
    body = VALID.replace("          site_ids: s-1,s-2", "          base_rul: oops")
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(_write(tmp_path, body))
    assert "base_rul" in str(exc.value)
    assert "not a config field" in str(exc.value)


def test_an_unknown_platform_is_refused(tmp_path):
    body = VALID.replace("      - platform: exabeam", "      - platform: splunk")
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(_write(tmp_path, body))
    assert "splunk" in str(exc.value)


def test_a_missing_required_field_is_refused(tmp_path):
    body = """
version: 1
clients:
  - tenant_id: c00
    platforms:
      - platform: cortex
        connection:
          tenant_name: c00
"""
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(_write(tmp_path, body))
    assert "api_url" in str(exc.value)


def test_an_empty_value_is_refused(tmp_path):
    body = VALID.replace("          site_ids: s-1,s-2", '          site_ids: ""')
    with pytest.raises(SourceMapInvalid):
        cs.load(_write(tmp_path, body))


def test_a_duplicate_tenant_is_refused(tmp_path):
    body = VALID + """
  - tenant_id: c00
    platforms: []
"""
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(_write(tmp_path, body))
    assert "more than once" in str(exc.value)


def test_a_duplicate_platform_for_one_client_is_refused(tmp_path):
    body = VALID + """
      - platform: exabeam
        connection:
          base_url: https://second.c00.example
"""
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(_write(tmp_path, body))
    assert "twice" in str(exc.value)


def test_an_unknown_version_is_refused(tmp_path):
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(_write(tmp_path, "version: 2\nclients: []\n"))
    assert "unsupported version" in str(exc.value)


# ── the scope keyword ────────────────────────────────────────────────────


def test_scope_is_a_required_keyword():
    """Not `scope=None` meaning unrestricted. A parameter somebody forgets to
    pass must never be the one that opens a read up — the same decision
    `integration_credential_service` takes, on the same kind of table."""
    import inspect

    for fn in (cs.sources_for, cs.platforms_for):
        signature = inspect.signature(fn)
        scope = signature.parameters["scope"]
        assert scope.kind is inspect.Parameter.KEYWORD_ONLY, fn.__name__
        assert scope.default is inspect.Parameter.empty, (
            f"{fn.__name__} has a default scope; a forgotten argument would "
            f"become an unscoped read"
        )


def test_a_restricted_scope_cannot_read_another_client(tmp_path):
    path = _write(tmp_path, VALID)
    other = TenantScope(tenant_ids=("c01",), actor="c01-user")
    with pytest.raises(TenantForbidden):
        cs.sources_for("c00", scope=other, map_path=path)
    # The control: the same map, the right scope, returns the sources.
    mine = TenantScope(tenant_ids=("c00",), actor="c00-user")
    assert len(cs.sources_for("c00", scope=mine, map_path=path)) == 2


def test_a_client_with_no_entry_is_empty_not_an_error(tmp_path):
    """Distinct from a forbidden read. "This client runs no platforms we know
    of" is a fact; "you may not ask about this client" is a refusal."""
    assert cs.sources_for("c99", scope=ALL, map_path=_write(tmp_path, VALID)) == ()


# ── reconciliation: the file is a control, not a second authority ────────


def test_reconcile_is_silent_when_the_file_and_the_database_agree(tmp_path):
    rows = [
        {"tenant_id": "c00", "tool": "exabeam",
         "config": {"base_url": "https://aa.c00.example"}},
        {"tenant_id": "c00", "tool": "sentinelone",
         "config": {"console_url": "https://c00.sentinelone.net", "site_ids": "s-1,s-2"}},
    ]
    assert cs.reconcile(rows, _write(tmp_path, VALID)) == {}


def test_reconcile_reports_a_client_in_the_file_but_not_configured(tmp_path):
    findings = cs.reconcile([], _write(tmp_path, VALID))
    assert findings["in_file_not_in_database"] == ["c00/exabeam", "c00/sentinelone"]


def test_reconcile_reports_a_platform_configured_but_not_declared(tmp_path):
    rows = [
        {"tenant_id": "c00", "tool": "exabeam",
         "config": {"base_url": "https://aa.c00.example"}},
        {"tenant_id": "c00", "tool": "sentinelone",
         "config": {"console_url": "https://c00.sentinelone.net", "site_ids": "s-1,s-2"}},
        {"tenant_id": "c42", "tool": "cortex", "config": {"api_url": "https://x"}},
    ]
    findings = cs.reconcile(rows, _write(tmp_path, VALID))
    assert findings["in_database_not_in_file"] == ["c42/cortex"]


def test_reconcile_reports_a_connection_that_drifted(tmp_path):
    rows = [
        {"tenant_id": "c00", "tool": "exabeam",
         "config": {"base_url": "https://CHANGED.example"}},
        {"tenant_id": "c00", "tool": "sentinelone",
         "config": {"console_url": "https://c00.sentinelone.net", "site_ids": "s-1,s-2"}},
    ]
    findings = cs.reconcile(rows, _write(tmp_path, VALID))
    assert findings["connection_differs"] == ["c00/exabeam: base_url"]


def test_reconcile_ignores_integrations_that_are_not_client_platforms(tmp_path):
    """`tenant_integrations` legitimately holds deployment-managed tools such
    as OpenSearch. They are not part of the client source map and must not be
    reported as undeclared, or the check becomes noise and stops being read."""
    rows = [
        {"tenant_id": "c00", "tool": "exabeam",
         "config": {"base_url": "https://aa.c00.example"}},
        {"tenant_id": "c00", "tool": "sentinelone",
         "config": {"console_url": "https://c00.sentinelone.net", "site_ids": "s-1,s-2"}},
        {"tenant_id": "c00", "tool": "opensearch", "config": {"nodes": "https://os"}},
    ]
    assert cs.reconcile(rows, _write(tmp_path, VALID)) == {}


# ── the binding helper ───────────────────────────────────────────────────


def test_bind_tenant_refuses_an_empty_tenant():
    class _Session:
        def execute(self, *_a, **_k):  # pragma: no cover - must not be reached
            raise AssertionError("executed a statement for an empty tenant")

    with pytest.raises(TenantForbidden):
        cs.bind_tenant(_Session(), "")


def test_bind_tenant_passes_the_tenant_as_a_parameter_not_as_sql():
    """`SET LOCAL` takes no parameters, so the obvious implementation
    interpolates the tenant id into the statement. On the one table where a
    cross-tenant read matters most, that is an injection point —
    `set_config()` takes bound parameters and is used instead."""
    seen = {}

    class _Session:
        # `.info` because the binding is also remembered on the session, so it
        # can be re-applied to each new transaction — a read after a commit
        # would otherwise be unbound, which is how configuring an integration
        # broke on 2026-10-20.
        info: dict = {}

        def execute(self, statement, params=None):
            seen["sql"] = str(statement)
            seen["params"] = params

    cs.bind_tenant(_Session(), "c00'; RESET ROLE; --")
    assert "set_config" in seen["sql"]
    assert "c00" not in seen["sql"], "the tenant id was formatted into the SQL"
    assert seen["params"]["value"] == "c00'; RESET ROLE; --"
    assert seen["params"]["name"] == cs.TENANT_SETTING


# ── the name belongs to the database, not the file ───────────────────────


def test_a_client_name_in_the_file_is_refused(tmp_path):
    """Refused, not ignored.

    A `name:` the loader skipped would look like it worked, and the next
    person would add the whole customer list — which is the thing keeping it
    out of the repository prevents. The refusal names where the value lives.
    """
    body = VALID.replace("  - tenant_id: c00\n",
                         "  - tenant_id: c00\n    name: Client Zero\n")
    with pytest.raises(SourceMapInvalid) as exc:
        cs.load(_write(tmp_path, body))
    message = str(exc.value)
    assert "tenants.name" in message
    assert "--render" in message, "the refusal must say how to read the map instead"


def test_the_entry_exposes_no_name_attribute():
    """Asserted on the type, not on an instance, so an entry built by any path
    cannot carry one."""
    import dataclasses

    fields = {f.name for f in dataclasses.fields(cs.ClientEntry)}
    assert fields == {"tenant_id", "sources"}, fields
