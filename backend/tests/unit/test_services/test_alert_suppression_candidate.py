"""Creating an exclusion from the fields an alert actually carries."""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api import alert_investigations as mod
from app.services.alert_field_service import SUPPRESSIBLE_FIELDS, detection_name_of

BODY = (
    "Alert: exprevpxy002 - Shell Execution Of Process Located In Tmp Directory | "
    "Unknown problem somewhere in the system.\n"
    "Rule: 1002\n"
    "Rule level: 2\n"
    "Agent: exprevpxy002 | 1445\n"
    "Agent IP: 172.20.20.5\n"
    "Event ID: FileActivity\n"
    "Manager: Siembiot\n"
)

INTERNAL = SimpleNamespace(
    state=SimpleNamespace(identity={"kind": "user", "all_tenants": True, "tenant_ids": []})
)


class _DB:
    def __init__(self, run):
        self._run = run

    async def get(self, _model, _id):
        return self._run


def _run():
    return SimpleNamespace(
        id=uuid4(), title="exprevpxy002 - Shell Execution Of Process Located In Tmp Directory",
        alert_body=BODY, detection_rule_id="1002",
        detection_rule_name="Unknown problem somewhere in the system.",
        detection_name="Shell Execution Of Process Located In Tmp Directory",
        entity_host="exprevpxy002", entity_user=None, tenant_id="c00", result_json={},
    )


def test_the_route_takes_a_request_so_it_can_scope():
    """It did not, and called _scope(request) anyway.

    Every call raised NameError, so the suppression dialog — which exists and
    is complete — failed the moment it opened. The feature had been built and
    never worked.
    """
    import inspect

    assert "request" in inspect.signature(mod.get_suppression_candidate).parameters


def test_the_candidate_offers_the_fields_present_in_the_alert_body():
    out = asyncio.run(mod.get_suppression_candidate(uuid4(), _DB(_run()), request=INTERNAL))

    offered = {f["field"]: f["value"] for f in out["fields"]}
    assert offered["agent"] == "exprevpxy002"
    assert offered["rule_id"] == "1002"
    assert offered["event_id"] == "FileActivity"
    assert offered["detection_name"] == "Shell Execution Of Process Located In Tmp Directory"


def test_the_proposal_names_the_detection_not_only_the_carrier_rule():
    """Suppressing rule 1002 silences everything it carries — on this data that
    is "Disable Or Stop Services" as well as the shell execution being looked
    at. The detection is the narrower, correct thing to suppress on."""
    out = asyncio.run(mod.get_suppression_candidate(uuid4(), _DB(_run()), request=INTERNAL))

    assert "detection_name" in out["proposed"]
    assert out["proposed"]["detection_name"].startswith("Shell Execution")
    # And still narrow: the agent is in there too, so the same detection on
    # another machine is still investigated.
    assert "agent" in out["proposed"]


def test_severity_fields_are_offered_but_flagged():
    # key=value, which is the shape these arrive in; a "key: value" line is
    # read as prose by the extractor.
    body = BODY + "eventSeverity=Info\neventPriority=Low\n"
    run = _run()
    run.alert_body = body

    out = asyncio.run(mod.get_suppression_candidate(uuid4(), _DB(run), request=INTERNAL))

    severities = [f for f in out["fields"] if f["severity_only"]]
    assert severities, "severity is still offered"
    assert all(f["field"] not in out["proposed"] for f in severities)


def test_the_detection_name_is_a_suppressible_field():
    assert "detection_name" in SUPPRESSIBLE_FIELDS


def test_the_detection_name_is_parsed_from_the_alert_line():
    assert detection_name_of(BODY) == "Shell Execution Of Process Located In Tmp Directory"
    assert detection_name_of("no alert line here") is None
