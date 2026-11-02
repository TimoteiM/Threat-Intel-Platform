"""Cases whose conclusion covers fewer alerts than they now hold.

56 cases in this estate. All 56 were decided automatically — none was signed
off by a person — which the flag has to say, because an analyst reading "this
verdict was formed on 5 of 20 alerts" will reasonably ask whose work is being
questioned.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.services.case_disposition_review_service import DISPOSITIONS, review_for

CLOSED = datetime(2026, 10, 8, 9, 30, tzinfo=timezone.utc)


def test_a_conclusion_covering_part_of_the_case_is_flagged():
    review = review_for(
        case_number=1074, resolution="false_positive", alerts_at_close=2,
        current_run_ids=[f"r{i}" for i in range(57)], closed_at=CLOSED,
    )
    assert review is not None
    payload = review.as_json()
    assert payload["judged_on"] == 2
    assert payload["holds_now"] == 57
    assert payload["proportion_judged"] == round(2 / 57, 3)
    assert "covers 4% of what is in the case" in payload["attribution"]
    assert "2026-10-08" in payload["attribution"]


def test_the_flag_says_whose_judgement_is_in_question_and_it_is_not_the_analysts():
    """All 56 closed automatically with no `closed_by`. Saying so is the point:
    the defect was in when a case closed, not in anyone's assessment."""
    review = review_for(
        case_number=464, resolution="false_positive", alerts_at_close=5,
        current_run_ids=[f"r{i}" for i in range(20)], closed_by=None,
        closed_at=CLOSED,
    )
    assert review is not None and review.automatic
    whose = review.as_json()["whose_judgement"]
    assert "not by an analyst" in whose
    assert "nobody's assessment is in question" in whose


def test_a_case_a_person_signed_off_is_attributed_to_them_without_blame():
    """None exists today, but the wording must be right before one does: the
    extra evidence was not available to them."""
    review = review_for(
        case_number=7, resolution="true_positive", alerts_at_close=3,
        current_run_ids=["a", "b", "c", "d"], closed_by="tudor", closed_at=CLOSED,
    )
    assert review is not None and not review.automatic
    whose = review.as_json()["whose_judgement"]
    assert "tudor" in whose
    assert "never available to them" in whose


def test_nothing_is_reopened_and_no_verdict_is_changed():
    review = review_for(
        case_number=1, resolution="false_positive", alerts_at_close=1,
        current_run_ids=["a", "b"], closed_at=CLOSED,
    )
    assert review is not None
    payload = review.as_json()
    assert "Nothing has been reopened" in payload["what_to_do"]
    assert payload["resolution"] == "false_positive"


def test_a_case_that_never_counted_its_alerts_is_not_flagged_here():
    """199 cases closed with `alerts_at_close = 0`, which means never counted
    rather than counted as none. A case that was never assessed cannot have
    been assessed on partial evidence, and including them would inflate this
    finding sevenfold with cases carrying no verdict. They report
    `membership_unknown` instead."""
    for count in (0, None):
        assert review_for(
            case_number=1, resolution="expired", alerts_at_close=count,
            current_run_ids=["a", "b", "c"],
        ) is None


def test_expired_and_merged_are_not_dispositions():
    assert "expired" not in DISPOSITIONS
    assert "merged" not in DISPOSITIONS
    assert review_for(
        case_number=1, resolution="expired", alerts_at_close=5,
        current_run_ids=["a"] * 10,
    ) is None


def test_a_complete_conclusion_is_silent():
    """Asked on every case page, so the common answer has to be cheap and
    quiet."""
    assert review_for(
        case_number=1440, resolution="true_positive", alerts_at_close=8,
        current_run_ids=[f"r{i}" for i in range(8)],
    ) is None
    assert review_for(
        case_number=1440, resolution="true_positive", alerts_at_close=9,
        current_run_ids=[f"r{i}" for i in range(8)],
    ) is None


def test_duplicate_run_ids_do_not_manufacture_growth():
    assert review_for(
        case_number=1, resolution="false_positive", alerts_at_close=2,
        current_run_ids=["a", "a", "b", "b"],
    ) is None


# —— the 100-member cap ————————————————————————————————————————————————

def test_a_count_recorded_at_the_old_cap_is_a_floor_not_a_number():
    """24 of the flagged cases read exactly 100 because the member list they
    were counted from was capped there. "Judged on 100" asserts a count nobody
    took; the payload carries an absence saying it is a floor."""
    from app.services.absence import LOWER_BOUND

    review = review_for(
        case_number=71, resolution="needs_review", alerts_at_close=100,
        current_run_ids=[f"r{i}" for i in range(1217)], closed_at=CLOSED,
    )
    payload = review.as_json()
    judged = payload["judged_on"]
    assert judged != 100 and judged["absent"] is True
    assert judged["kind"] == LOWER_BOUND
    assert judged["raw"] == "100"
    assert "at least" in judged["reason"]
    assert payload["proportion_judged"] is None
    assert "covers" not in payload["attribution"]


def test_the_lifecycle_payload_carries_the_floor_too():
    """The same 100 travelled raw in every case payload's lifecycle."""
    from app.services.case_disposition_review_service import alerts_at_close_payload

    assert alerts_at_close_payload(100)["kind"] == "lower_bound"
    assert alerts_at_close_payload(99) == 99
    assert alerts_at_close_payload(101) == 101
    assert alerts_at_close_payload(None) is None


# —— whose judgement ——————————————————————————————————————————————————————

def test_an_analyst_close_with_no_recorded_name_is_not_called_automatic():
    """#61 and #892 were closed by a person before `closed_by` existed. Reading
    the missing name as "automatic" told #61's reader that nobody's assessment
    was in question when a person's was."""
    review = review_for(
        case_number=61, resolution="inconclusive", alerts_at_close=100,
        current_run_ids=[f"r{i}" for i in range(561)], closed_by=None,
        closed_at=CLOSED, closure_kind="analyst",
    )
    assert review is not None and not review.automatic
    payload = review.as_json()
    assert payload["decided_automatically"] is False
    whose = payload["whose_judgement"]
    assert "not by an analyst" not in whose
    assert "name was not recorded" in whose
    assert "at least 100" in whose


def test_an_automatic_close_is_still_automatic_when_its_kind_is_stated():
    review = review_for(
        case_number=464, resolution="false_positive", alerts_at_close=5,
        current_run_ids=[f"r{i}" for i in range(20)], closure_kind="auto",
        closed_at=CLOSED,
    )
    assert review.automatic
