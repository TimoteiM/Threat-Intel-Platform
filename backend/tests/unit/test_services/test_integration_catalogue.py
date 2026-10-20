"""The tool catalogue is derived, and must not become list number nine.

Eight hand-maintained lists in this codebase have swallowed a feature with no
error. A list of integration *tool names* would be the ninth, and the failure
would be the worst kind: a connector absent from it would be unconfigurable
with nothing to say so.

So the catalogue is derived from the collectors that declare
`integration = True`, and this file fails if a hard-coded list appears —
the same guard as `test_brand_reference_signal.py`'s `BRAND_OWNERS` check.

Also here: the five states, and the two-direction rule. "Enabled" is the word
that cost seven months, so every assertion below is about a state being
*derived* from a fact rather than asserted by a flag.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from app.services import integration_status_service as st


# ─── derived, not listed ─────────────────────────────────────────────────

def test_every_catalogue_entry_declares_itself_somewhere_it_is_not_listed():
    """Broadened, not weakened.

    The original form asserted every tool is a collector with
    `integration = True`. That invariant was too narrow: the log store is an
    integration and not a collector, so it was absent from the page entirely —
    the one carrying 154M documents and feeding every alert's log context, and
    when it stopped on 2026-10-12 there was no row for any state to be red on.

    The property that actually matters is unchanged and still enforced here:
    **no tool is listed in `integration_status_service` itself.** Each entry
    comes either from a collector declaring `integration = True` or from a
    module exposing its own `INTEGRATION_SPEC`. A list of tools inside the
    consumer is the position the eighth silent registry occupied, and
    `test_the_catalogue_names_no_tool_in_the_service_source` below refuses it
    by reading the source.
    """
    from app.collectors.registry import COLLECTOR_REGISTRY

    cat = st.catalogue()
    assert cat, "the catalogue is empty; nothing declares itself"
    for tool in cat:
        from_collector = (
            tool in COLLECTOR_REGISTRY
            and getattr(COLLECTOR_REGISTRY[tool], "integration", False) is True
        )
        from_own_module = tool in st._declared_elsewhere()
        assert from_collector or from_own_module, (
            f"{tool!r} is in the catalogue but declares itself nowhere — "
            f"which means it is hand-listed in the service"
        )


def test_the_catalogue_names_no_tool_in_the_service_source():
    """The invariant the narrower test was protecting, asserted directly.

    Tokenised so a tool name in a comment or docstring does not count: this
    module's docstrings discuss `opensearch` and `falcon` at length, and a
    plain substring search would pass or fail for the wrong reason.
    """
    import io
    import pathlib as _p
    import tokenize

    src = _p.Path(st.__file__).read_text()
    literals: set[str] = set()
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.STRING:
            literals.add(tok.string.strip("\"'"))
    for tool in st.catalogue():
        assert tool not in literals, (
            f"{tool!r} is a string literal in integration_status_service; "
            f"tools declare themselves, they are not listed in the consumer"
        )


def test_a_newly_registered_integration_appears_with_nothing_to_update(monkeypatch):
    """The property that makes it a derivation. A connector added to the
    registry is configurable immediately — no list, no migration, no enum."""
    from app.collectors import registry
    from app.collectors.base import BaseCollector

    class _Newcomer(BaseCollector):
        name = "newcomer_edr"
        supported_types = frozenset({"domain"})
        integration = True
        integration_label = "Newcomer EDR"
        integration_directions = ("enrichment", "ingest")
        integration_secret_fields = {"api_key": "its key"}

    monkeypatch.setitem(registry.COLLECTOR_REGISTRY, "newcomer_edr", _Newcomer)
    cat = st.catalogue()
    assert "newcomer_edr" in cat
    assert cat["newcomer_edr"].label == "Newcomer EDR"
    assert cat["newcomer_edr"].directions == ("enrichment", "ingest")


def test_a_platform_wide_provider_is_not_an_integration():
    """VirusTotal, urlscan and abuse.ch use one key for every tenant and it
    lives in `.env`. They must not appear as per-tenant integrations."""
    cat = st.catalogue()
    for tool in ("vt", "urlscan", "threat_feeds", "intel", "dns", "http"):
        assert tool not in cat


def _code_only(module) -> str:
    """A module's source with comments and string literals removed.

    The first version of the guard below scanned raw source and failed on
    this file's own docstring — the one explaining why not to branch on a
    tool name. A source-text assertion cannot tell code from the comment
    describing it, which is the second time today that caught me out (the
    first was `_subject_snapshot`). So the text is tokenised and the prose
    dropped before anything is matched.
    """
    import io
    import tokenize

    src = inspect.getsource(module)
    out: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            out.append(tok.string)
    except tokenize.TokenError:            # pragma: no cover - malformed source
        return src
    return " ".join(out)


def test_no_hard_coded_tool_list_exists():
    """The ninth-list guard. A dict or tuple of tool names anywhere in the
    integrations modules is the failure this derivation exists to prevent."""
    import app.api.integrations as api
    import app.services.integration_credential_service as creds

    for module in (st, api, creds):
        code = _code_only(module)
        for banned in ("TOOL_LIST", "KNOWN_TOOLS", "INTEGRATION_TOOLS",
                       "SUPPORTED_TOOLS", "TOOL_CATALOGUE"):
            assert banned not in code, (
                f"{module.__name__} declares {banned!r} — the catalogue is "
                "derived from the collectors precisely so no list exists"
            )
        # And no branch on a specific tool name, which is a list wearing an
        # if-statement. Checked against code with the prose removed.
        assert "falcon" not in code, (
            f"{module.__name__} names a specific tool in code; the catalogue "
            "is derived so that none of these modules knows one"
        )


def test_the_no_list_guard_can_fail():
    """What that guard would print if a list appeared. A guard that passes
    for want of a failure mode is decoration."""
    import types

    fake = types.ModuleType("fake")
    fake.__dict__["__source__"] = ""
    src = 'KNOWN_TOOLS = ["falcon"]\nif tool == "falcon":\n    pass\n'

    import io
    import tokenize

    code = " ".join(
        t.string for t in tokenize.generate_tokens(io.StringIO(src).readline)
        if t.type not in (tokenize.COMMENT, tokenize.STRING)
    )
    assert "KNOWN_TOOLS" in code, "the guard would not notice a declared list"


# ─── the five states, each derived from a fact ───────────────────────────

def test_there_are_six_states_and_enabled_is_not_one_of_them():
    """`stopped` is the sixth, added 2026-10-14 and deliberately.

    The count is pinned so a state cannot be added without someone stating
    why. `stopped` exists because `verified_failing` catches "configured but
    unusable" and does NOT catch a configuration that vanished — which reads
    as `not_configured`, and on a page of unconfigured tools is invisible.
    That is the two-day log-context outage.

    And `enabled` is still not among them, which is the original point: every
    state here is derived from a fact, never from a flag somebody set.
    """
    assert len(st.STATES) == 6
    assert "enabled" not in st.STATES
    assert set(st.STATES) == {
        "not_implemented", "not_configured", "configured_unverified",
        "verified_ok", "verified_failing", "stopped",
    }
    # Worst first: the overall badge is min() by this index, so a stopped
    # direction must not be able to hide behind a healthy one.
    assert st.STATES[0] == st.STOPPED


def test_a_tool_no_connector_implements_is_not_implemented():
    out = st.status_of(None, None, "sentinel_one")
    assert out["overall"] == st.NOT_IMPLEMENTED
    # And it says why, as an absence rather than an error.
    assert out["note"]["absent"] is True
    assert out["note"]["kind"] == "out_of_scope"


def test_a_tool_with_no_row_is_not_configured():
    spec = st.catalogue()["falcon"]
    out = st.status_of(spec, None, "falcon")
    assert out["overall"] == st.NOT_CONFIGURED
    assert out["configured"] is False
    assert out["directions"]["enrichment"]["state"] == st.NOT_CONFIGURED


def test_a_stored_credential_never_verified_is_its_own_state():
    """The state that did not exist before and matters most: saved is not
    working, and the old vocabulary had no way to say so."""
    spec = st.catalogue()["falcon"]
    row = SimpleNamespace(tool="falcon", health={}, secret_ciphertext="x",
                          secret_set_at=None, config={}, configured_by="a",
                          updated_at=None)
    out = st.status_of(spec, row, "falcon")
    assert out["overall"] == st.CONFIGURED_UNVERIFIED
    # The state, not the prose: asserting on wording makes the test brittle
    # against the message it is meant to accompany.
    assert out["directions"]["enrichment"]["checked_at"] is None
    assert out["directions"]["enrichment"]["reason"]


def test_a_verified_failing_tool_keeps_its_reason_and_timestamp():
    spec = st.catalogue()["falcon"]
    row = SimpleNamespace(
        tool="falcon", secret_ciphertext="x", secret_set_at=None, config={},
        configured_by="a", updated_at=None,
        health={"enrichment": {"state": "verified_failing",
                               "checked_at": "2026-10-14T10:00:00+00:00",
                               "reason": "HTTP 401", "failure_kind": "credential"}},
    )
    out = st.status_of(spec, row, "falcon")
    assert out["overall"] == st.VERIFIED_FAILING
    assert out["directions"]["enrichment"]["reason"] == "HTTP 401"
    assert out["directions"]["enrichment"]["failure_kind"] == "credential"


def test_an_unrecognised_stored_state_is_not_read_as_working():
    """A stored value this code does not know must not default to healthy —
    the absence convention's own failure mode, committed inside it."""
    spec = st.catalogue()["falcon"]
    row = SimpleNamespace(
        tool="falcon", secret_ciphertext="x", secret_set_at=None, config={},
        configured_by="a", updated_at=None,
        health={"enrichment": {"state": "fine", "checked_at": "2026-10-14T10:00:00+00:00"}},
    )
    out = st.status_of(spec, row, "falcon")
    assert out["overall"] == st.VERIFIED_FAILING
    assert out["directions"]["enrichment"]["failure_kind"] == "unrecognised"


# ─── two directions, never one badge ─────────────────────────────────────

def test_a_tool_healthy_one_way_and_dead_the_other_does_not_read_green(monkeypatch):
    """The specific failure one status would hide: an integration answering
    queries while delivering no detections."""
    from app.collectors import registry
    from app.collectors.base import BaseCollector

    class _Both(BaseCollector):
        name = "both_ways"
        integration = True
        integration_label = "Both Ways"
        integration_directions = ("enrichment", "ingest")

    monkeypatch.setitem(registry.COLLECTOR_REGISTRY, "both_ways", _Both)
    spec = st.catalogue()["both_ways"]
    row = SimpleNamespace(
        tool="both_ways", secret_ciphertext="x", secret_set_at=None, config={},
        configured_by="a", updated_at=None,
        health={
            "enrichment": {"state": "verified_ok",
                           "checked_at": "2026-10-14T10:00:00+00:00"},
            "ingest": {"state": "verified_failing",
                       "checked_at": "2026-10-14T10:00:00+00:00",
                       "reason": "no detections delivered in 14 days"},
        },
    )
    out = st.status_of(spec, row, "both_ways")
    assert out["overall"] == st.VERIFIED_FAILING, (
        "a tool answering queries while delivering nothing read as healthy"
    )
    assert out["directions"]["enrichment"]["state"] == st.VERIFIED_OK
    assert out["directions"]["ingest"]["state"] == st.VERIFIED_FAILING


def test_a_tool_reports_no_status_for_a_direction_it_does_not_have():
    """Falcon is enrichment-only this pass. It must not be `not_configured`
    for ingest — it does not have ingest."""
    spec = st.catalogue()["falcon"]
    row = SimpleNamespace(tool="falcon", health={}, secret_ciphertext="x",
                          secret_set_at=None, config={}, configured_by="a",
                          updated_at=None)
    out = st.status_of(spec, row, "falcon")
    assert set(out["directions"]) == {"enrichment"}
    assert "ingest" not in out["directions"]


def test_both_directions_green_is_the_only_green():
    """The control for the worst-direction rule."""
    spec = st.catalogue()["falcon"]
    row = SimpleNamespace(
        tool="falcon", secret_ciphertext="x", secret_set_at=None, config={},
        configured_by="a", updated_at=None,
        health={"enrichment": {"state": "verified_ok",
                               "checked_at": "2026-10-14T10:00:00+00:00"}},
    )
    assert st.status_of(spec, row, "falcon")["overall"] == st.VERIFIED_OK


def test_configured_unverified_counts_as_not_working():
    assert st.CONFIGURED_UNVERIFIED in st.NOT_WORKING
    assert st.VERIFIED_OK not in st.NOT_WORKING


# --- grouping: declared at the connector, never listed in the UI ----------


def test_every_tool_declares_a_category():
    """The page groups on this, so an absent category is a missing card."""
    for name, spec in st.catalogue().items():
        assert spec.category, f"{name} has no integration_category"


def test_falcon_is_an_edr():
    assert st.catalogue()["falcon"].category == "edr"


def test_the_category_reaches_the_json_payload():
    """The page reads `category` off the tool entry, not off a second fetch."""
    for spec in st.catalogue().values():
        assert "category" in spec.as_json()


def test_an_uncategorised_connector_gets_other_not_a_crash():
    """`other` is the honest default — an uncategorised tool still renders.

    A missing declaration must not drop the tool or raise; it lands under
    "Other", which is visible, rather than vanishing from the grid.
    """
    class Bare:
        integration = True
        integration_directions = ("enrichment",)
        integration_label = "Bare Tool"
        # no integration_category

    import app.collectors.registry as reg
    original = dict(reg.COLLECTOR_REGISTRY)
    try:
        reg.COLLECTOR_REGISTRY["bare"] = Bare
        spec = st.catalogue()["bare"]
        assert spec.category == "other"
    finally:
        reg.COLLECTOR_REGISTRY.clear()
        reg.COLLECTOR_REGISTRY.update(original)


def test_the_category_is_not_hard_coded_in_the_status_service():
    """Grouping must come from the connectors, not a list in the service.

    The eighth silent registry was a hand-kept list in exactly this position.
    Tokenised so a category named in a comment or docstring does not pass.
    """
    import io
    import pathlib
    import tokenize

    src = pathlib.Path(st.__file__).read_text()
    literals: list[str] = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.STRING:
            literals.append(tok.string.strip("\"'"))
    # "other" is the documented default and is allowed; a list of real
    # category names in here would mean the grouping had been duplicated.
    for banned in ("edr", "firewall", "email", "siem", "sandbox"):
        assert banned not in literals, (
            f"{banned!r} is a string literal in integration_status_service; "
            "categories belong on the collectors"
        )


# ── a spec is not a connector ────────────────────────────────────────────
#
# On 2026-10-20 an operator configured Exabeam seven times and was told each
# attempt failed with HTTP 400. Every one had saved correctly: the 400 came
# from the verification step afterwards, where `_verifier_for` imports
# `app.integrations.exabeam_client` and there is no such module.
#
# The cause was mine. `not_implemented` had meant "absent from the
# catalogue", so declaring the Exabeam/SentinelOne/Cortex specs — which exist
# so their connection fields have one definition — silently promoted three
# platforms to configurable-and-testable.


def test_declaring_a_spec_does_not_claim_a_connector():
    from app.services.integration_status_service import catalogue, has_connector

    cat = catalogue()
    # Exabeam moved on 2026-10-20: `app/integrations/exabeam_client.py` was
    # built against the published search API, so it is no longer in this
    # list. The test said that would happen and it did.
    for tool in ("sentinelone", "cortex"):
        assert tool in cat, f"{tool} should still be in the catalogue"
        assert has_connector(tool) is False, (
            f"{tool} reports a connector; if one was built, this test and the "
            f"'no connector yet' copy in the UI are both stale"
        )
    # The control: a tool that DOES have a connector must say so, or the
    # check above would pass with `has_connector` returning False always.
    assert has_connector("falcon") is True
    assert has_connector("exabeam") is True
    assert has_connector("opensearch") is True, (
        "deployment-managed tools answer through their verifier, not an "
        "app.integrations module"
    )


def test_has_connector_is_derived_not_listed():
    """Resolved by import, like every other dispatch in this module. A list of
    implemented tools would be the tenth hand-maintained registry, and a tool
    missing from it would be unconfigurable with nothing to say so."""
    import inspect

    from app.services import integration_status_service as st

    source = inspect.getsource(st.has_connector)
    assert "find_spec" in source
    for tool in ("exabeam", "sentinelone", "cortex", "falcon"):
        assert f'"{tool}"' not in source, f"{tool} is named in has_connector"


def test_an_unknown_tool_has_no_connector():
    from app.services.integration_status_service import has_connector

    assert has_connector("no-such-tool") is False
    assert has_connector("") is False


def test_the_catalogue_payload_tells_the_ui_which_are_testable():
    """The UI needs the difference: a platform with a spec and no connector
    can have its connection details recorded and cannot be tested. Offering
    'Save and test' for one of those is what produced the 400s."""
    from app.services.integration_status_service import catalogue

    payload = {spec.tool: spec.as_json() for spec in catalogue().values()}
    assert payload["falcon"]["implemented"] is True
    assert payload["exabeam"]["implemented"] is True
    assert payload["sentinelone"]["implemented"] is False
    # The fields are still declared, so the form can still be rendered.
    assert payload["sentinelone"]["config_fields"]
    assert payload["sentinelone"]["secret_fields"]


def test_the_verify_path_records_a_state_instead_of_raising():
    """`_verify_now` must not raise for a tool with no connector.

    Asserted on the source rather than by calling it, because calling it needs
    a database and an opened credential; the behaviour under test is the
    branch order — the `has_connector` check has to come BEFORE
    `_verifier_for`, which is what raised the 400.
    """
    import inspect

    from app.api import integrations as api

    source = inspect.getsource(api._verify_now)
    guard = source.index("has_connector")
    # `verifier = _verifier_for(tool)`, the whole assignment: searching for
    # `_verifier_for(tool)` alone also matches `deployment_verifier_for(tool)`
    # thirty lines earlier, which made this assertion compare the wrong two
    # positions and fail for the wrong reason.
    lookup = source.index("verifier = _verifier_for(tool)")
    assert guard < lookup, (
        "_verifier_for runs before the has_connector guard, so a tool with no "
        "connector still raises instead of recording a state"
    )
    assert "CONFIGURED_UNVERIFIED" in source
    assert "not_implemented" in source


def test_an_untestable_tool_is_not_told_to_run_a_test():
    """The copy an operator reads when a credential is stored and no connector
    exists.

    They configured Exabeam correctly with the credentials from a working
    TraceCat automation and the card said *"Saved is not working — run Test
    connection"*, beside a Test connection button. Both were instructions they
    could not carry out: there is no code to try the credential with.
    """
    from types import SimpleNamespace

    from app.services.integration_status_service import (
        CONFIGURED_UNVERIFIED, INGEST, _state_for_direction,
    )

    no_connector = SimpleNamespace(tool="sentinelone", health={})
    out = _state_for_direction(no_connector, INGEST)
    assert out["state"] == CONFIGURED_UNVERIFIED
    assert out["failure_kind"] == "not_implemented"
    assert "no connector" in out["reason"].lower()
    assert "Test connection" not in out["reason"]
    assert "SentinelOne" in out["reason"], "the label should name the tool"

    # The control: a tool that HAS a connector still gets the instruction,
    # because for that one it is an instruction worth following.
    has_connector_row = SimpleNamespace(tool="falcon", health={})
    out = _state_for_direction(has_connector_row, INGEST)
    assert "Test connection" in out["reason"]


def test_record_health_stamps_the_timestamp_the_reader_requires():
    """A field a reader requires is guaranteed by the writer.

    `_state_for_direction` treats an entry with no `checked_at` as "no call
    has ever been made" and discards the rest of it, so a caller that forgot
    the stamp wrote a reason nobody would ever see. One did, and the page
    showed the generic copy over a perfectly good explanation.
    """
    import inspect

    from app.services import integration_credential_service as creds

    source = inspect.getsource(creds.record_health)
    assert 'setdefault("checked_at"' in source, (
        "record_health no longer guarantees checked_at; every caller must "
        "now remember it, and one will not"
    )


def test_a_non_outcome_in_the_health_map_is_not_read_as_a_failure():
    """A health entry is the outcome of a real call. The other states describe
    the absence of one.

    On 2026-10-20 a "no connector yet" result was written into this map. Once
    it carried a timestamp it reached the unrecognised-state branch and the
    card read **FAILING** — to an operator whose credential was correct, taken
    from a working automation. Three wrong answers in a row from the same
    small mistake: first "run Test connection", then "not verified", then
    "failing".
    """
    from types import SimpleNamespace

    from app.services.integration_status_service import (
        CONFIGURED_UNVERIFIED, INGEST, VERIFIED_FAILING, _state_for_direction,
    )

    stored = {INGEST: {
        "state": CONFIGURED_UNVERIFIED,
        "reason": "Saved. SentinelOne has no connector in this platform yet.",
        "checked_at": "2026-10-20T10:26:28+00:00",
        "failure_kind": "not_implemented",
    }}
    out = _state_for_direction(SimpleNamespace(tool="sentinelone", health=stored), INGEST)
    assert out["state"] == CONFIGURED_UNVERIFIED, "a non-outcome read as a verdict"
    assert "no connector" in out["reason"].lower()
    assert "does not recognise" not in out["reason"]

    # The control, and the reason that branch exists: a state this code has
    # genuinely never seen must NOT be read as working.
    unknown = {INGEST: {"state": "something_new",
                        "checked_at": "2026-10-20T10:26:28+00:00"}}
    out = _state_for_direction(SimpleNamespace(tool="falcon", health=unknown), INGEST)
    assert out["state"] == VERIFIED_FAILING
    assert out["failure_kind"] == "unrecognised"


def test_the_verify_path_writes_nothing_when_there_was_no_call():
    """The fix for the above at the writing end.

    Deriving the absence is right; recording it as an outcome is a category
    error — "no call happened" does not belong in the map that answers "what
    happened when we called".
    """
    import inspect

    from app.api import integrations as api

    source = inspect.getsource(api._verify_now)
    guard = source.index("has_connector")
    after = source[guard:source.index("verifier = _verifier_for(tool)")]
    assert "record_health" not in after, (
        "the no-connector branch records health again; that entry is what "
        "made a correct credential report FAILING"
    )
