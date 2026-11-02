"""Which closures answer a case — and the guard that catches the next kind.

`/detections/sla` excluded `aged_out`, and nothing in this codebase has ever
written that value: the expiry path writes `expired`. So the filter had never
once fired, and every `expired`, `merged` and `unreadable` closure counted as a
resolution. A filter true of no row cannot exclude, any more than a
discriminator true of every row can link.

The fix is one declaration. The guard below is the part that matters more:
`unreadable` is written by `case_closure_task` and is not in
`CaseClosureKind`, so a kind has already escaped the enum once, silently, and
was counted as an answered case for as long as it existed.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from app.models.enums import CaseClosureKind
from app.services.alert_case_closure_service import (
    JUDGEMENT,
    JUDGEMENT_KINDS,
    NOT_A_JUDGEMENT,
    NOT_A_JUDGEMENT_KINDS,
    UNCLASSIFIED,
    classify_closure,
    summarise,
)

APP = pathlib.Path(__file__).resolve().parents[3] / "app"


def _kinds_the_code_can_write() -> dict[str, list[str]]:
    """Every literal this codebase assigns to `closure_kind`, by file.

    Found by parsing rather than grepping, so `closure_kind="x"` as a keyword
    argument and `row.closure_kind = "x"` as an attribute assignment are both
    caught, and a commented-out line is not.
    """
    found: dict[str, list[str]] = {}

    def record(path: pathlib.Path, value: object) -> None:
        if isinstance(value, str) and value:
            found.setdefault(value, []).append(path.name)

    for path in APP.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:  # pragma: no cover - a broken file is its own test
            continue
        for node in ast.walk(tree):
            # closure_kind="expired"
            if isinstance(node, ast.keyword) and node.arg == "closure_kind":
                if isinstance(node.value, ast.Constant):
                    record(path, node.value.value)
                # closure_kind="inherited" if inherited else "auto"
                elif isinstance(node.value, ast.IfExp):
                    for branch in (node.value.body, node.value.orelse):
                        if isinstance(branch, ast.Constant):
                            record(path, branch.value)
            # row.closure_kind = "merged"
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "closure_kind":
                        record(path, node.value.value)
    return found


class TestTheGuard:
    def test_every_kind_the_code_writes_is_classified(self):
        """The eleventh kind must not silently count as a resolution.

        This test is the reason the fix is worth more than the fix: it fails
        the moment someone adds a closure kind without saying whether it
        answers a case.
        """
        written = _kinds_the_code_can_write()
        assert written, "the parser found no closure_kind writes at all"
        unclassified = {
            kind: files for kind, files in written.items()
            if classify_closure(kind) == UNCLASSIFIED
        }
        assert not unclassified, (
            "these closure kinds are written by the code but classified "
            "nowhere, so /detections/sla cannot say whether they answered a "
            f"case: {unclassified}. Add each to JUDGEMENT_KINDS or "
            "NOT_A_JUDGEMENT_KINDS in alert_case_closure_service."
        )

    def test_the_kind_that_escaped_the_enum_is_covered(self):
        """`unreadable` is written by case_closure_task and is absent from
        CaseClosureKind. The guard has to catch a kind the enum does not know
        about, or it only re-checks the enum."""
        assert "unreadable" not in {k.value for k in CaseClosureKind}
        assert "unreadable" in _kinds_the_code_can_write()
        assert classify_closure("unreadable") == NOT_A_JUDGEMENT

    def test_every_enum_member_is_classified_too(self):
        for member in CaseClosureKind:
            assert classify_closure(member.value) != UNCLASSIFIED, member

    def test_the_two_lists_do_not_overlap(self):
        assert not (JUDGEMENT_KINDS & NOT_A_JUDGEMENT_KINDS)


class TestClassification:
    @pytest.mark.parametrize("kind", sorted(JUDGEMENT_KINDS))
    def test_an_answered_case_is_a_judgement(self, kind):
        assert classify_closure(kind) == JUDGEMENT

    @pytest.mark.parametrize("kind", sorted(NOT_A_JUDGEMENT_KINDS))
    def test_an_unanswered_case_is_not(self, kind):
        assert classify_closure(kind) == NOT_A_JUDGEMENT

    def test_the_historical_spelling_is_still_excluded(self):
        """`aged_out` is what the old filter named. Nothing writes it, but a
        stored row could still carry it, so dropping it from the lists would
        turn a real exclusion into an unclassified one."""
        assert classify_closure("aged_out") == NOT_A_JUDGEMENT

    def test_an_unknown_kind_is_neither_and_says_so(self):
        assert classify_closure("something_new") == UNCLASSIFIED
        assert classify_closure(None) == UNCLASSIFIED
        assert classify_closure("") == UNCLASSIFIED
        assert classify_closure("  auto  ") == JUDGEMENT


class TestUncountedCasesAreNotSingleAlertCases:
    """`alert_count or 1` filed every case whose size was never recorded as a
    single-alert case. 63 live rows carry `alerts_at_close = 0`, which means
    nobody counted — not that there was one."""

    def _case(self, size, resolve=120.0):
        return {"alert_count": size, "detect_seconds": 10.0,
                "resolve_seconds": resolve, "open": False}

    def test_an_uncounted_case_is_its_own_population(self):
        out = summarise(
            [self._case(None), self._case(0), self._case(1), self._case(5)],
            target_seconds=3600.0,
        )
        assert out["size_never_counted"]["cases"] == 2
        assert out["single_alert"]["cases"] == 1
        assert out["multi_alert"]["cases"] == 1

    def test_its_timings_still_count_toward_the_whole(self):
        """The size is unknown; the resolution time is not."""
        out = summarise([self._case(None), self._case(3)], target_seconds=3600.0)
        assert out["all"]["cases"] == 2
        assert out["all"]["closed"] == 2

    def test_it_is_not_quietly_counted_as_single(self):
        out = summarise([self._case(None)], target_seconds=3600.0)
        assert out["single_alert"]["cases"] == 0
        assert out["size_never_counted"]["cases"] == 1
