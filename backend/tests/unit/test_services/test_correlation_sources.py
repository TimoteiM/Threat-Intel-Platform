"""
Correlation must never join alerts across senders.

Two platforms watching the same estate name hosts their own way. A chain
assembled from a Siembiot endpoint alert and an unrelated session alert about a
similarly named host is a fabrication — and the most damaging kind, because it
looks exactly like the finding the feature exists to produce.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.services.alert_correlation_service import correlate_alerts


class _Run:
    def __init__(self, host, source, rule, verdict="suspicious", event_time=None):
        self.id = uuid4()
        self.title = f"{rule} on {host}"
        self.created_at = datetime.now(timezone.utc)
        # Modelled explicitly rather than defaulted: the service orders and
        # builds its baseline from event time, so a stub without one tests a
        # different function than the one that runs.
        self.event_time = event_time or self.created_at
        self.entity_host = host
        self.entity_user = None
        self.alert_source = source
        self.alert_client = "unknown"
        self.alert_kind = "alert"
        self.detection_rule_id = rule
        self.detection_rule_name = rule
        self.overall_verdict = verdict
        self.highest_risk_score = 40
        self.result_attack_assessment = None


class _DB:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, _query):
        class _R:
            def __init__(self, rows):
                self._rows = rows

            def all(self):
                return self._rows

        return _R(self._rows)


@pytest.mark.asyncio
async def test_two_sources_on_one_hostname_are_not_one_case():
    """
    One rule from each platform is not two independent detections agreeing —
    it is two platforms each seeing one thing, about hosts that merely share a
    name.
    """
    rows = [_Run("SRV-01", "Siembiot", "rule-a"), _Run("SRV-01", "tracecat", "rule-b")]
    result = await correlate_alerts(_DB(rows), hours=48)
    assert result["total_cases"] == 0
    # Counted as two separate entity groups, not one.
    assert result["entities_seen"] == 2
    assert result["sources_seen"] == 2


@pytest.mark.asyncio
async def test_a_case_still_forms_within_one_source():
    rows = [_Run("SRV-01", "Siembiot", "rule-a"), _Run("SRV-01", "Siembiot", "rule-b")]
    result = await correlate_alerts(_DB(rows), hours=48)
    assert result["total_cases"] == 1
    case = result["cases"][0]
    assert case["source"] == "Siembiot"
    assert case["distinct_rules"] == 2


@pytest.mark.asyncio
async def test_an_absent_source_does_not_pool_every_platform():
    """
    A null source would otherwise make one bucket of every unlabelled feed, so
    it is named rather than left empty.
    """
    rows = [_Run("SRV-01", None, "rule-a"), _Run("SRV-01", "Siembiot", "rule-b")]
    result = await correlate_alerts(_DB(rows), hours=48)
    assert result["total_cases"] == 0
    assert {c for c in result} and result["entities_seen"] == 2


@pytest.mark.asyncio
async def test_two_clients_sharing_a_hostname_are_not_one_case():
    """
    Both feeds carry other organisations' alerts, and two customers can each own
    a host called DC01. Joining them builds a chain across companies — wrong as
    analysis, and a confidentiality problem besides.
    """
    a = _Run("DC01", "Siembiot", "rule-a")
    a.alert_client = "ACME"
    b = _Run("DC01", "Siembiot", "rule-b")
    b.alert_client = "GLOBEX"
    result = await correlate_alerts(_DB([a, b]), hours=48)
    assert result["total_cases"] == 0
    assert result["clients_seen"] == 2


@pytest.mark.asyncio
async def test_a_case_forms_within_one_client():
    a = _Run("DC01", "Siembiot", "rule-a")
    b = _Run("DC01", "Siembiot", "rule-b")
    a.alert_client = b.alert_client = "ACME"
    result = await correlate_alerts(_DB([a, b]), hours=48)
    assert result["total_cases"] == 1
    assert result["cases"][0]["client"] == "ACME"


@pytest.mark.asyncio
async def test_an_incident_is_never_a_member_of_a_case():
    """A payload that is already a session is a case, not one of its own parts."""
    incident = _Run("mvapsupm01", "tracecat", "AA Session")
    incident.alert_kind = "incident"
    other = _Run("mvapsupm01", "tracecat", "another rule")
    other.alert_kind = "alert"
    result = await correlate_alerts(_DB([incident, other]), hours=48)
    assert result["total_cases"] == 0
