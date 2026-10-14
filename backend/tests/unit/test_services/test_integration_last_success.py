"""`not_configured` and "worked until Monday" must not be the same row.

The defect this closes removed the state that would have been red. SIEM log
enrichment stopped on 2026-10-12 because `OPENSEARCH_TENANT_VALUES` went
empty, which makes the integration read as **not_configured** — and on a page
listing unconfigured tools, that is invisible. `verified_failing` catches
"configured but unusable"; it does not catch "configuration vanished", because
a vanished configuration is indistinguishable from one never made.

The distinguishing fact is already stored: `alert_log_context` rows up to
2026-10-12 and none after. So the status carries `last_succeeded_at`, and a
tool that is not working *and has a last success* is an incident rather than
an absence.

Fourth split of one state into two this week: checked from listed, failed from
not_attempted, verified from consulted, and now never-configured from
configured-and-stopped.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services import absence
from app.services import integration_status_service as st

NOW = datetime(2026, 10, 14, 14, 0, tzinfo=timezone.utc)
MONDAY = datetime(2026, 10, 12, 12, 26, 32, tzinfo=timezone.utc)


# --- the dangerous direction ---------------------------------------------


def test_a_tool_that_stopped_is_not_reported_as_never_configured():
    """The exact shape of the two-day outage."""
    verdict = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=MONDAY, now=NOW,
        expected_interval_hours=6,
    )
    assert verdict["stopped"] is True, (
        "an integration with a last success is not an absence of "
        "configuration; it is an incident"
    )
    assert verdict["state"] == st.STOPPED
    assert verdict["silent_for_hours"] >= 48


def test_a_tool_that_never_worked_stays_not_configured():
    """The control. Without it, every unconfigured tool reads as an incident."""
    verdict = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=None, now=NOW,
    )
    assert verdict["stopped"] is False
    assert verdict["state"] == st.NOT_CONFIGURED


def test_never_worked_is_an_absence_not_a_date():
    """`last_succeeded_at` of None must not render as a zero date or 'never
    observed' masquerading as a measurement."""
    verdict = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=None, now=NOW,
    )
    assert absence.is_absent(verdict["last_success"])
    assert verdict["last_success"]["kind"] == absence.NEVER_OBSERVED


def test_a_working_tool_is_not_flagged_even_with_an_old_success():
    verdict = st.continuity(
        state=st.VERIFIED_OK, last_succeeded_at=MONDAY, now=NOW,
    )
    assert verdict["stopped"] is False
    assert verdict["state"] == st.VERIFIED_OK


def test_verified_failing_with_a_last_success_is_still_stopped():
    """Failing-and-previously-working is the same incident, louder."""
    verdict = st.continuity(
        state=st.VERIFIED_FAILING, last_succeeded_at=MONDAY, now=NOW,
        expected_interval_hours=6,
    )
    assert verdict["stopped"] is True
    assert verdict["state"] == st.STOPPED


def test_a_tool_no_connector_implements_is_never_an_incident():
    verdict = st.continuity(
        state=st.NOT_IMPLEMENTED, last_succeeded_at=None, now=NOW,
    )
    assert verdict["stopped"] is False
    assert verdict["state"] == st.NOT_IMPLEMENTED


def test_a_future_last_success_does_not_produce_negative_silence():
    """Clock skew must not make a stopped tool look fine."""
    verdict = st.continuity(
        state=st.NOT_CONFIGURED,
        last_succeeded_at=NOW + timedelta(hours=3), now=NOW,
    )
    assert verdict["silent_for_hours"] >= 0


def test_stopped_is_the_worst_state_so_it_wins_the_overall_badge():
    """The page takes the worst direction. `stopped` must outrank the rest or
    a stopped tool hides behind a healthy second direction."""
    assert st.STOPPED in st.STATES
    assert st.STATES.index(st.STOPPED) == 0, (
        "STATES is worst-first and the overall badge is min() by this index"
    )


# --- the log store, which was not on the page at all --------------------


def test_the_log_store_is_a_listed_integration():
    """It carries 154M documents and feeds every alert's context, and it was
    absent from the catalogue because it is not a collector. A page that omits
    the integration most likely to break cannot report it breaking."""
    cat = st.catalogue()
    assert "opensearch" in cat, (
        f"the log store is not listed; catalogue has {sorted(cat)}"
    )
    spec = cat["opensearch"]
    assert spec.category == "siem"
    assert "enrichment" in spec.directions


def test_the_non_collector_integrations_are_derived_not_hand_listed():
    """This is a second source for the catalogue, so it is the exact position
    the eighth silent registry occupied. Each entry must declare itself."""
    for name, spec in st.catalogue().items():
        assert spec.label, f"{name} has no label"
        assert spec.directions, f"{name} declares no directions"
        assert spec.category, f"{name} declares no category"


# --- deployment-configured integrations verify differently ---------------
#
# "Test connection" on the log store returned HTTP 400 "opensearch is not
# configured for tenant 'c00'" even though .env configures it correctly. The
# verify path goes through the per-tenant CREDENTIAL STORE
# (`tenant_integrations` rows), and the log store is configured from the
# deployment instead — global `OPENSEARCH_*` read by `_legacy_c00`. It has no
# row and never will, so the lookup is asking the wrong place.
#
# The per-tenant env scheme is `OPENSEARCH_TENANT_C00_NODES` etc.; the global
# names are a separate, deliberate path. Renaming the globals to
# `OPENSEARCH_NODE1_C00` would be read by nothing.


def test_the_log_store_declares_that_the_deployment_configures_it():
    """So the UI does not offer a credential form that cannot be saved."""
    spec = st.catalogue()["opensearch"]
    assert spec.managed == "deployment"


def test_a_credential_managed_tool_still_says_so():
    """The control: falcon's credentials really are stored per tenant."""
    assert st.catalogue()["falcon"].managed == "credential_store"


def test_every_tool_declares_how_it_is_managed():
    for name, spec in st.catalogue().items():
        assert spec.managed in ("deployment", "credential_store"), (
            f"{name} does not say where its configuration lives, so the UI "
            f"cannot know whether to offer a form"
        )


def test_a_deployment_managed_tool_exposes_no_secret_fields():
    """A secret field implies a form that writes it; there is no such path."""
    spec = st.catalogue()["opensearch"]
    assert spec.secret_fields == {}


def test_verifying_the_log_store_reports_which_processes_hold_the_config():
    """The trap today's outage set.

    Verify runs in the **api**. The api was recreated at 14:21 and has
    OPENSEARCH_TENANT_VALUES; the worker and beat were not and do not — and
    the worker is where alert log context is actually collected. A green
    "Test connection" that says nothing about the worker is precisely the
    false comfort this platform keeps being bitten by, so the result names
    the process it ran in and does not generalise.
    """
    from app.services import opensearch_tenants as ost

    assert hasattr(ost, "verify"), "the owning module provides no verifier"
    import inspect
    src = inspect.getsource(ost.verify)
    for needed in ("api", "worker"):
        assert needed in src, (
            f"the verifier does not mention {needed!r}; a check that cannot "
            f"distinguish the process it ran in from the one doing the work "
            f"reports a green that is not true of the pipeline"
        )


# --- stopped must mean SILENT, not merely "not verified_ok" -------------
#
# The log-store card read STOPPED ("an outage") directly above "silent 0.2h".
# Twelve minutes is not an outage. Both numbers were right and the model
# behind them was wrong: `continuity()` upgraded any non-ok state to `stopped`
# the moment a last success existed, so an integration that produced evidence
# minutes ago was reported as down.
#
# That is the cry-wolf failure the source-coverage work already paid for once:
# a badge that goes red while the thing works trains people to ignore it, and
# then it cannot report the real outage either.

HOUR = timedelta(hours=1)


def test_a_tool_that_produced_evidence_minutes_ago_is_not_stopped():
    """The exact card. 0.2h of silence is not an outage."""
    v = st.continuity(
        state=st.CONFIGURED_UNVERIFIED,
        last_succeeded_at=NOW - timedelta(minutes=12),
        now=NOW,
        expected_interval_hours=6,
    )
    assert v["stopped"] is False, (
        "12 minutes of silence reported as an outage; this is the cry-wolf "
        "shape that makes the badge unreadable"
    )
    assert v["state"] == st.CONFIGURED_UNVERIFIED


def test_a_tool_silent_well_past_its_expectation_is_stopped():
    v = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=MONDAY, now=NOW,
        expected_interval_hours=6,
    )
    assert v["stopped"] is True
    assert v["state"] == st.STOPPED
    assert v["silent_for_hours"] >= 48


def test_without_a_declared_expectation_stopped_is_not_claimed():
    """No threshold, no claim. A guessed interval would invent outages."""
    v = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=MONDAY, now=NOW,
        expected_interval_hours=None,
    )
    assert v["stopped"] is False
    assert absence.is_absent(v["silence_verdict"])
    assert v["silence_verdict"]["kind"] == absence.TOO_LITTLE_HISTORY


def test_the_boundary_is_stated_in_the_payload_not_hidden():
    v = st.continuity(
        state=st.NOT_CONFIGURED, last_succeeded_at=MONDAY, now=NOW,
        expected_interval_hours=6,
    )
    assert v["expected_interval_hours"] == 6
    assert v["threshold_hours"] >= 6


# --- deployment-managed tools are not judged by credential rules --------


def test_a_deployment_managed_tool_never_claims_a_credential_is_stored():
    """The card said NOT VERIFIED — "A credential is stored" — above a footer
    saying "no credential stored".

    My first version of this test banned the *state* `configured_unverified`,
    which was the wrong target: that state is semantically right here. The
    tool IS configured (from the deployment) and is NOT verified. What is
    false by construction is the **claim about a credential**, which lives in
    the reason text and in the UI's copy for that state.

    So this asserts the claim, not the label.
    """
    spec = st.catalogue()["opensearch"]
    out = st.status_of(spec, None, "opensearch")
    assert out["overall"] == st.CONFIGURED_UNVERIFIED
    assert out["configured"] is True, "it is configured, from the deployment"
    for direction in out["directions"].values():
        reason = (direction.get("reason") or "").lower()
        assert "credential is stored" not in reason
        assert "no credential is stored" not in reason
        assert "deployment" in reason, (
            "the reason must say where the configuration lives, or a reader "
            "looks for a credential that does not exist"
        )


def test_a_deployment_managed_tool_does_not_claim_a_secret_is_set():
    spec = st.catalogue()["opensearch"]
    out = st.status_of(spec, None, "opensearch")
    assert out.get("secret_set") in (None, False)
    assert out.get("managed") == "deployment"


def test_a_credential_managed_tool_still_uses_credential_rules():
    """The control: falcon with no row is genuinely not configured."""
    spec = st.catalogue()["falcon"]
    out = st.status_of(spec, None, "falcon")
    assert out["overall"] == st.NOT_CONFIGURED


# --- a stray credential row must not change a deployment verdict --------
#
# The UI offered a Configure form for the log store before that was removed,
# and a real operator filled it in: `tenant_integrations` gained an
# `opensearch` row at 14:47:13 with
# `{'nodes': '...', 'tenant_field': 'c00'}` — where `c00` is a tenant *id* in
# the slot a *field name* belongs (`manager.name`). Nothing reads the row, so
# it does nothing; but `status_of` branched on `row is None`, so its mere
# existence flipped the log store back to credential-store rules and the
# false "A credential is stored".
#
# Two separate failures: a verdict that depends on a row nobody reads, and an
# endpoint that accepts a write with no effect.


def test_a_stray_row_does_not_change_a_deployment_managed_verdict():
    """The verdict must come from the deployment, row or no row."""
    spec = st.catalogue()["opensearch"]

    class _StrayRow:
        tool = "opensearch"
        tenant_id = "c00"
        config = {"nodes": "https://x", "tenant_field": "c00"}
        secret_ciphertext = None
        secret_set_at = None
        configured_by = "someone"
        updated_at = None
        health = {}

    with_row = st.status_of(spec, _StrayRow(), "opensearch")
    without = st.status_of(spec, None, "opensearch")
    assert with_row["overall"] == without["overall"], (
        "a row nobody reads changed the verdict"
    )
    for direction in with_row["directions"].values():
        assert "credential is stored" not in (direction.get("reason") or "").lower()


def test_a_stray_row_is_surfaced_not_silently_ignored():
    """Ignoring it would leave an operator believing they configured something."""
    spec = st.catalogue()["opensearch"]

    class _StrayRow:
        tool = "opensearch"
        tenant_id = "c00"
        config = {"tenant_field": "c00"}
        secret_ciphertext = None
        secret_set_at = None
        configured_by = "timotei.moscaliuc"
        updated_at = None
        health = {}

    out = st.status_of(spec, _StrayRow(), "opensearch")
    stray = out.get("stray_credential_row")
    assert stray, "the unread row is invisible, so nobody will delete it"
    assert "timotei.moscaliuc" in str(stray.get("configured_by"))
    assert "not read" in str(stray.get("note")).lower()


def test_the_api_refuses_to_configure_a_deployment_managed_tool():
    """The UI hiding the button is cosmetic; the endpoint is what writes."""
    import inspect
    from app.api import integrations as api_mod

    src = inspect.getsource(api_mod.configure)
    assert "deployment" in src, (
        "the configure endpoint does not check `managed`, so a form that is "
        "hidden in one client can still write through another"
    )


# --- a diagnostic must not refresh the field it diagnoses ---------------
#
# Pinned even though the current implementation is already clean, because the
# failure it guards against is one this project has hit twice: a measurement
# that moves the thing it measures. If "Test connection" ever came to write a
# success record that the outage detector reads, then "last worked jumps to
# today" would stop meaning "collection is flowing" and start meaning
# "somebody clicked a button" — and the instrument would be gone with no
# error anywhere.


def test_verify_writes_nothing_the_stopped_classifier_reads():
    """The verify path for a deployment-managed tool must not persist."""
    import inspect
    from app.api import integrations as api_mod

    src = inspect.getsource(api_mod._verify_now)
    head = src.split('if _spec.managed == "deployment"' if
                     '_spec.managed == "deployment"' in src else
                     'if spec.managed == "deployment":')[-1]
    branch = head.split("try:")[0]
    for writer in ("record_health", "db.add", "db.commit", "db.execute"):
        assert writer not in branch, (
            f"the deployment-verify branch calls {writer!r}; a ping that "
            f"writes a success record contaminates the silence clock the "
            f"SIEM card uses to claim an outage"
        )


def test_the_silence_clock_reads_collection_evidence_only():
    """`last_success` for the log store comes from alert_log_context rows —
    evidence the COLLECTION path produced — and from nothing a diagnostic
    touches."""
    import inspect
    from app.services import opensearch_tenants as ost

    src = inspect.getsource(ost.last_success)
    assert "alert_log_context" in src
    for not_evidence in ("tenant_integrations", "health", "ping"):
        assert not_evidence not in src, (
            f"the silence clock reads {not_evidence!r}, which a verify can "
            f"move; it must read only what collection produced"
        )
