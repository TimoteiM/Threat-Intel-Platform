"""Analyst feedback must record what the analyst saw, not what the system
thinks at the moment of writing.

`_subject_snapshot` copied `investigation.classification` onto the feedback
row at insert time. Its own docstring stated the right intent — "the feedback
is about the answer as it was given, not as it now stands" — and the
implementation did the opposite.

That is worse than a wrong verdict. Analyst feedback is the ground truth this
platform would use to *measure* its verdicts: `detection_quality_service`
reads `platform_classification` against the analyst's call to count misses
and over-flags. A snapshot stamped with current state silently re-grades the
history it is supposed to anchor.

Live consequence, 2026-10-13: `live.com` was judged malicious/90, then
re-analysed to suspicious/40 three hours later. Any feedback recorded after
that re-analysis would assert the platform had said suspicious — erasing the
verdict the analyst would have been reacting to.

The dangerous direction throughout is a *plausible* snapshot: a value that
looks like a record and is actually a reading of the present.
"""

from __future__ import annotations

import pytest

from app.services.absence import is_absent


# ─── the inversion, asserted against the shape rather than the wording ───

@pytest.mark.asyncio
async def test_the_snapshot_does_not_read_the_subjects_current_verdict():
    """The behaviour, not the source text.

    The first version of this test grepped `inspect.getsource` for
    `investigation.classification` — and failed, because the fixed
    function's *docstring* explains the old predicate. A source-text
    assertion cannot tell code from the comment describing it, which is the
    same confusion as trusting a comment over an implementation, inverted.
    So: call it, and assert the returned keys.
    """
    from types import SimpleNamespace

    from app.api import detections

    subject = SimpleNamespace(
        classification="malicious", risk_score=90,
        overall_verdict="malicious", indicator_risk_score=90,
        detection_rule_id="rule-1",
    )

    class _DB:
        async def get(self, model, ident):
            return subject

    snap = await detections._subject_snapshot(_DB(), "investigation", "x")
    assert snap is not None
    assert "platform_classification" not in snap, (
        "the snapshot carries the investigation's CURRENT classification"
    )
    assert "platform_risk_score" not in snap

    snap = await detections._subject_snapshot(_DB(), "alert_run", "x")
    assert "platform_classification" not in snap, (
        "the snapshot carries the alert run's CURRENT verdict"
    )
    # The one fact that cannot change still travels.
    assert snap["detection_rule_id"] == "rule-1"


@pytest.mark.asyncio
async def test_a_missing_subject_is_still_a_404():
    """The control for the change above: dropping the verdict read must not
    drop the existence check, or feedback could be filed against nothing."""
    from app.api import detections

    class _DB:
        async def get(self, model, ident):
            return None

    assert await detections._subject_snapshot(_DB(), "investigation", "x") is None
    assert await detections._subject_snapshot(_DB(), "alert_run", "x") is None


def test_an_undeclared_snapshot_is_an_absence_not_a_value():
    """When the caller does not say what it displayed, the row must say so.

    Stamping current state here is what corrupts the ground truth, and a
    blank would be the same error wearing a different value — so the
    serialized payload carries a reason."""
    from app.api.detections import _snapshot_from_declaration

    snap = _snapshot_from_declaration(None, None)
    assert snap["platform_classification"] is None
    assert snap["platform_risk_score"] is None


def test_a_declared_snapshot_is_recorded_verbatim():
    """The caller knows what it rendered. That is the only honest source for
    'what the analyst saw', so it is taken at face value."""
    from app.api.detections import _snapshot_from_declaration

    snap = _snapshot_from_declaration("malicious", 90)
    assert snap["platform_classification"] == "malicious"
    assert snap["platform_risk_score"] == 90


def test_the_serializer_reports_an_absence_when_nothing_was_recorded():
    """A reader of this row must be able to tell 'the platform said
    malicious' from 'nobody recorded what the platform said'."""
    from types import SimpleNamespace

    from app.api.detections import _serialize

    row = SimpleNamespace(
        id="00000000-0000-0000-0000-000000000000",
        subject_type="investigation",
        subject_id="00000000-0000-0000-0000-000000000001",
        verdict="false_positive",
        platform_classification=None,
        platform_risk_score=None,
        detection_rule_id=None,
        note=None,
        analyst=None,
        created_at=None,
        updated_at=None,
    )
    out = _serialize(row)
    assert is_absent(out["platform_classification"]), (
        "an unrecorded platform verdict serialised as a blank, which reads "
        "as 'the platform said nothing'"
    )
    assert "not recorded" in out["platform_classification"]["reason"].lower()


def test_a_recorded_snapshot_serialises_as_a_plain_value():
    """The control. A serializer that wrapped everything in an absence would
    pass the test above and destroy the field."""
    from types import SimpleNamespace

    from app.api.detections import _serialize

    row = SimpleNamespace(
        id="00000000-0000-0000-0000-000000000000",
        subject_type="investigation",
        subject_id="00000000-0000-0000-0000-000000000001",
        verdict="false_positive",
        platform_classification="malicious",
        platform_risk_score=90,
        detection_rule_id=None,
        note=None,
        analyst=None,
        created_at=None,
        updated_at=None,
    )
    out = _serialize(row)
    assert out["platform_classification"] == "malicious"
    assert out["platform_risk_score"] == 90


def test_revising_a_verdict_does_not_restamp_the_snapshot():
    """An analyst changing their mind is a correction to their call, not a
    new reading of the platform. The context of the original judgement has
    to survive the revision — and this is the property that made the
    ordering trap irreversible: `create_feedback` never re-snapshots, so a
    row inserted after a verdict changed could not be repaired."""
    import inspect

    from app.api import detections

    src = inspect.getsource(detections.create_feedback)
    revise = src[src.index("if existing is not None:"):src.index("row = AnalystFeedback")]
    assert "platform_classification" not in revise, (
        "the revision path re-stamps the platform snapshot"
    )
