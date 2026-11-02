"""`<EventID>` is read; `<EventRecordID>` must never be.

The Exabeam-forwarded bodies carry the Windows event id as an XML element and
none of the four forms the extractor already knew — header, `key=value`,
JSON, dotted. Measured 2026-10-22: **25 of 52 `lin` and `pov` runs had an id
in the body and nothing in `alert_fields`**, which is why those tenants
matched no playbook row.

This codebase has twelve recorded extractor delimiter faults, and one of them
was inside the fix for another, so the dangerous direction gets the first
test: `<EventRecordID>` is a per-channel sequence number in the hundreds of
thousands and sits in **every one of these bodies**, next to the element we
want.
"""

from __future__ import annotations

import pytest

from app.services.alert_field_service import extract_alert_fields as extract


def test_event_record_id_is_not_read_as_an_event_id():
    """The trap. `918273` is a sequence number, not an event.

    Ordered with the record id FIRST, because a pattern that scans forward
    and stops at the first digits would take it.
    """
    body = ("<Event><System>"
            "<EventRecordID>918273</EventRecordID>"
            "<EventID>5145</EventID>"
            "</System></Event>")
    assert extract(body).get("event_id") == "5145"


def test_a_body_with_only_a_record_id_yields_no_event_id():
    """It must report nothing rather than invent a plausible number.

    An id manufactured here would key a playbook row, which would run queries
    about an event that never happened.
    """
    body = "<Event><System><EventRecordID>918273</EventRecordID></System></Event>"
    assert extract(body).get("event_id") is None


@pytest.mark.parametrize("body,expected", [
    ("<EventID>4688</EventID>", "4688"),
    ('<EventID Qualifiers="16384">4697</EventID>', "4697"),
    ("<EventID >4624</EventID>", "4624"),
    ("<EventID>\t5140\t</EventID>", "5140"),
])
def test_the_real_shapes_are_read(body, expected):
    assert extract(body).get("event_id") == expected


@pytest.mark.parametrize("body", [
    "<EventID>1234567</EventID>",          # 7 digits: not a Windows event id
    "<EventID>notanumber</EventID>",
    "<EventID></EventID>",
    "<EventIDish>4688</EventIDish>",       # a different element
])
def test_shapes_that_must_not_match(body):
    assert extract(body).get("event_id") is None


def test_an_existing_form_still_wins():
    """The XML form is appended LAST, and that is why c00 did not change.

    Measured over the corpus: 16,644 c00 runs, **0 changed**. This asserts the
    mechanism behind that number — a body carrying both forms keeps the value
    the older form gave it, so adding the pattern cannot rewrite history.
    """
    assert extract("event_id=4738\n<EventID>9999</EventID>")["event_id"] == "4738"
    assert extract("Event ID: 1102\n<EventID>9999</EventID>")["event_id"] == "1102"
    assert extract('"event_id": "29"\n<EventID>9999</EventID>')["event_id"] == "29"


def test_the_seven_recovered_classes_all_have_a_playbook_row():
    """Extraction without a row would gain a class and still gather nothing."""
    from app.services.context_gathering import playbook as pb

    for cls in ("4624", "4625", "4688", "4697", "5140", "5145", "4768"):
        assert cls in pb.PLAYBOOK, f"{cls} is extracted but has no playbook row"
        chosen, _ = pb.templates_for(cls, {"ip": "203.0.113.9"})
        assert chosen, f"{cls} has a row but nothing fires on an IP alone"
