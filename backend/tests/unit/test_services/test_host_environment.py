"""Which machines are the estate, and which are a test rig.

Measured 2026-10-12 on `alert_body_investigation_runs` over 2026-09-18..09-24,
the last full week before the ingestion collapse: 5,477 alerts from 100 hosts,
of which 2,579 (47%) came from `Windows-Test-Device` and 4,237 (77%) from that
host plus `EXP-4LWK334`.

So an estate-wide figure computed without this filter is substantially a figure
about one test machine. Confirmed against the whole store: excluding it moves
the median `indicator_risk_score` from 0 to 35, and takes corroborated ATT&CK
technique nodes from 10 to 0 — all ten were on the test rig.
"""

from __future__ import annotations

import re

import pytest

from app.cli.seed_host_environment import _NEAR, _TEST_TOKEN
from app.services.asset_criticality_service import (
    CONFIRMED,
    ENVIRONMENTS,
    EstateScope,
    PRODUCTION,
    PROPOSED,
    TEST,
    UNKNOWN,
)


class TestTheNamePatternIsAnchored:
    """`EXP-DC-01` matches `-DC-` and so does `EXP-DCOM-02`. Eleven
    delimiter-boundary bugs in this codebase came from deciding such questions
    with an unanchored pattern."""

    @pytest.mark.parametrize("host", [
        "windows-test-device", "test-rig-01", "srv_test_02", "lab-01",
        "sandbox.corp", "demo-win11", "tst-04",
    ])
    def test_a_token_matches(self, host):
        assert _TEST_TOKEN.search(host)

    @pytest.mark.parametrize("host", [
        # The one that proves the anchor earns its keep: it begins with `lab`
        # and is a real host in this estate.
        "laboratorvm001",
        "latest-build-01", "contest02", "protestant-srv", "attestation01",
        "exp-fin-034", "expsql003",
    ])
    def test_a_substring_does_not(self, host):
        assert not _TEST_TOKEN.search(host), f"{host} would be misclassified"

    def test_near_misses_are_surfaced_not_guessed(self):
        """`siembiot-package-teste-1` is probably a test rig and
        `pftest-win11` probably is too, but neither matches the token. They are
        printed for a person rather than decided by the pattern."""
        for host in ("siembiot-package-teste-1", "pftest-win11", "laboratorvm001"):
            assert _NEAR.search(host)
            if host != "laboratorvm001":
                assert not _TEST_TOKEN.search(host)


class TestUnknownIsNotProduction:
    def test_the_three_values(self):
        assert ENVIRONMENTS == (PRODUCTION, TEST, UNKNOWN)

    def test_the_scope_reports_what_it_excluded_and_what_it_could_not_judge(self):
        scope = EstateScope(
            excluded_test=("windows-test-device",),
            unknown_hosts=37,
            production_hosts=58,
            include_proposed=True,
        )
        payload = scope.as_json()
        assert payload["excluded_test_count"] == 1
        assert payload["unclassified_hosts"] == 37
        assert "not as\nproduction" in payload["note"] or "not as production" in (
            payload["note"].replace("\n", " ")
        )

    def test_an_unclassified_host_is_counted_as_unknown_not_production(self):
        """Counting unknowns as production is how a test rig ends up inside an
        estate figure; dropping them is how a real machine vanishes from one."""
        scope = EstateScope(
            excluded_test=(), unknown_hosts=3, production_hosts=0,
            include_proposed=False,
        )
        assert scope.as_json()["production_hosts"] == 0
        assert scope.as_json()["unclassified_hosts"] == 3


class TestAProposalDoesNotSilentlyRemoveAHost:
    def test_confirmed_and_proposed_are_distinct_states(self):
        assert CONFIRMED != PROPOSED

    def test_the_default_exclusion_is_confirmed_only(self):
        """A proposal nobody agreed to must not quietly change an estate
        figure. `test_hosts` takes `include_proposed` and defaults to off."""
        import inspect

        from app.services.asset_criticality_service import test_hosts

        sig = inspect.signature(test_hosts)
        assert sig.parameters["include_proposed"].default is False

    def test_the_scope_records_which_exclusion_was_used(self):
        for flag in (True, False):
            scope = EstateScope(
                excluded_test=(), unknown_hosts=0, production_hosts=1,
                include_proposed=flag,
            )
            assert scope.as_json()["proposed_included"] is flag
