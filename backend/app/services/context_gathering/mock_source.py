"""A source that answers from canned events, so the loop can be built first.

**No connector, no credentials, no network.** The loop, the budget, the stop
rule and the record are the things being built; a real platform would make
them untestable and would make every run cost somebody's quota. This stands in
the slot a connector will occupy and answers in the shape the scorer already
reads.

The event shape is fixed and it is **the scorer's, not a vendor's**
(design note §1): `key, id, timestamp, agent, rule, event_id, channel, domain,
users, process, network, full_log, matched_on`. An event that does not land in
that shape is invisible to selection, to the digest and to the model — it
would be gathered and never read.

The corpus is deliberately small and deliberately shaped like the measured
one: Sysmon 10 and 18 dominate, one SQL logon failure, one account change.
Three properties are built in because the loop has to be tested against them:

* **a hash that is on several hosts**, so the second hop has something real to
  find and the fan-out cap has something to cap;
* **a host that answers nothing**, so "no events" is distinguishable from
  "could not ask";
* **a source that fails**, so `check_failed` is exercised with the source
  named rather than inferred from an empty list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

#: The window every canned event sits in, so a loop filtering on time finds
#: them. Fixed rather than "now", because a test that depends on the clock
#: fails at midnight.
CORPUS_TIME = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)

#: The hash the mock puts on several hosts. The second hop exists to find
#: something the alert did not carry, so the corpus has to contain one.
SPREAD_HASH = "a3f1c90e55b2d47e8c01f6b7a2d9e4c3b8f0a1d2e3c4b5a697887766554433221"

#: A host that is in the corpus and has no events. "Asked and found nothing"
#: and "never asked" are different answers and the loop must not merge them.
QUIET_HOST = "EXPQUIET01"


def _event(
    *,
    event_id: str,
    host: str,
    image: str = "",
    parent: str = "",
    sha256: str = "",
    user: str = "",
    src_ip: str = "",
    pipe: str = "",
    offset_seconds: int = 0,
    description: str = "",
) -> dict[str, Any]:
    """One event in the normalised shape.

    Every key the scorer reads is present even when empty, because a missing
    key and an empty one are read differently downstream and a mock that
    omits keys would hide that.
    """
    stamp = CORPUS_TIME + timedelta(seconds=offset_seconds)
    return {
        "key": f"{host}:{event_id}:{offset_seconds}",
        "id": f"mock-{host}-{event_id}-{offset_seconds}",
        "timestamp": stamp.isoformat(),
        "agent": {"name": host, "ip": "10.45.0.10"},
        "rule": {
            "id": f"rule-{event_id}",
            "level": 7,
            "description": description or f"Sysmon event {event_id}",
            "groups": ["sysmon", "windows"],
            "mitre_technique": "",
        },
        "event_id": event_id,
        "channel": "ThreatHunting",
        "domain": "INT",
        "users": [user] if user else [],
        "process": {
            "image": image,
            "command_line": f"{image} --quiet" if image else "",
            "parent_image": parent,
            "sha256": sha256,
        },
        "network": {"src_ip": src_ip, "dst_ip": ""},
        "full_log": (
            f"EventID={event_id} host={host} image={image} user={user} "
            f"pipe={pipe} sha256={sha256}"
        ),
        "matched_on": "",
    }


#: What each template returns, by the value it was asked about.
#:
#: Keyed by (template, the primary selector's value) so a query for a host
#: that is not in the corpus returns an empty list — a real "found nothing" —
#: rather than a KeyError or, worse, somebody else's events.
_CORPUS: dict[tuple[str, str], list[dict[str, Any]]] = {
    ("process_tree", "EXPDC001"): [
        _event(event_id="10", host="EXPDC001", image="C:\\Windows\\lsass.exe",
               parent="C:\\Windows\\services.exe", sha256=SPREAD_HASH,
               description="Process accessed lsass"),
        _event(event_id="10", host="EXPDC001", image="C:\\Temp\\rundll32.exe",
               parent="C:\\Windows\\lsass.exe", sha256=SPREAD_HASH,
               offset_seconds=30),
    ],
    ("process_tree", "EXPWEB02"): [
        _event(event_id="1", host="EXPWEB02", image="C:\\Temp\\rundll32.exe",
               parent="C:\\Windows\\explorer.exe", sha256=SPREAD_HASH,
               offset_seconds=60),
    ],
    # The same hash on three hosts. This is what makes the second hop worth
    # taking: the alert named one host and the hash reaches two more.
    ("hash_prevalence", SPREAD_HASH): [
        _event(event_id="1", host="EXPDC001", image="C:\\Temp\\rundll32.exe",
               sha256=SPREAD_HASH),
        _event(event_id="1", host="EXPWEB02", image="C:\\Temp\\rundll32.exe",
               sha256=SPREAD_HASH, offset_seconds=60),
        _event(event_id="1", host="EXPFIN07", image="C:\\Temp\\rundll32.exe",
               sha256=SPREAD_HASH, offset_seconds=120),
    ],
    ("pipe_creator", "EXPDC001"): [
        _event(event_id="18", host="EXPDC001", image="C:\\Temp\\rundll32.exe",
               parent="C:\\Windows\\explorer.exe", pipe="\\\\.\\pipe\\atsvc",
               sha256=SPREAD_HASH),
    ],
    ("host_logons", "EXPSQL03"): [
        _event(event_id="18456", host="EXPSQL03", user="INT\\svc_report",
               src_ip="10.45.0.71", description="SQL logon failure"),
    ],
    ("source_address_logons", "10.45.0.71"): [
        _event(event_id="18456", host="EXPSQL03", user="INT\\svc_report",
               src_ip="10.45.0.71"),
        _event(event_id="4625", host="EXPFIN07", user="INT\\svc_report",
               src_ip="10.45.0.71", offset_seconds=45),
    ],
    ("user_sessions", "INT\\svc_report"): [
        _event(event_id="4624", host="EXPSQL03", user="INT\\svc_report",
               src_ip="10.45.0.71"),
    ],
    ("user_risk_timeline", "INT\\svc_report"): [
        _event(event_id="risk", host="EXPSQL03", user="INT\\svc_report",
               description="risk score 61, rising"),
    ],
    ("host_threat_state", "EXPDC001"): [
        _event(event_id="threat", host="EXPDC001",
               description="no active threats"),
    ],
    # Present, and empty. The loop must report this as "asked, found nothing".
    ("host_threat_state", QUIET_HOST): [],
    ("process_tree", QUIET_HOST): [],
}


class SourceUnavailable(RuntimeError):
    """This source could not be read at all.

    Raised rather than returning `[]`, because the two are different answers
    and the DNS collector reported an outage as "no records" for 2,602 runs
    by conflating them. The loop turns this into `check_failed` **with the
    source named**.
    """


@dataclass
class MockSource:
    """A stand-in for a platform connector.

    `name` is what a `check_failed` names, so it is the client-facing source
    name rather than "mock" — a record that says "the source failed" without
    saying which source is the same defect one level up.
    """

    name: str
    kind: str
    #: Templates this source refuses, to exercise the failure path.
    failing_templates: frozenset[str] = frozenset()
    #: Every (template, value) it was asked, in order. The budget and the
    #: distinct-query ceiling are both assertions about this list.
    asked: list[tuple[str, str]] = field(default_factory=list)

    def query(self, template: str, arguments: dict[str, str]) -> list[dict[str, Any]]:
        """Run one template with REAL values and return normalised events.

        Arguments arrive detokenised — this is past the boundary, and it is
        the only side of it where a real hostname exists.
        """
        primary = _primary_value(template, arguments)
        self.asked.append((template, primary))
        if template in self.failing_templates:
            raise SourceUnavailable(
                f"{self.name} did not answer the {template} query"
            )
        return [dict(event) for event in _CORPUS.get((template, primary), [])]


def _primary_value(template: str, arguments: dict[str, str]) -> str:
    """The argument the corpus is keyed on.

    The first declared selector of the template, which is the thing the query
    is *about*. Declared by the template rather than guessed per call, so a
    template with two selectors cannot be looked up under the wrong one.
    """
    from app.services.context_gathering.playbook import TEMPLATES

    spec = TEMPLATES.get(template)
    if spec is None:
        return ""
    for selector in spec.selectors:
        value = arguments.get(selector)
        if value:
            return value
    return ""


def default_registry() -> dict[str, MockSource]:
    """One source per kind, as a tenant's map would resolve to.

    Separate instances so a test can assert which kind was asked, and so a
    failure in one does not look like a failure in the other.
    """
    from app.services.context_gathering.playbook import EDR, SIEM

    return {
        SIEM: MockSource(name="mock-siem", kind=SIEM),
        EDR: MockSource(name="mock-edr", kind=EDR),
    }
