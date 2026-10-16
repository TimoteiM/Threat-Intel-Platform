

# --- the counters cannot contradict the steps -----------------------------
#
# The original defect was a record contradicting ITSELF: the header read "0
# model calls" while the footer named one at step 6. The sentence was rewritten
# and then derived from `cost.model_calls`, which is the right fix for the
# prose — but the fix for a self-contradiction is a constraint that makes it
# impossible, not a better sentence in one of the two places.
#
# Measured over all 73 live records, the invariant already held. Nothing
# asserted it.


def _rec():
    from app.services.investigation_recorder import InvestigationRecorder

    return InvestigationRecorder(origin_surface="test", origin_id="t1")


def test_the_model_call_counter_equals_the_sum_of_the_steps():
    r = _rec()
    r.step("a", "Q?", fields={}, cost={})
    r.step("b", "Q?", fields={}, cost={"model_calls": 1})
    r.step("c", "Q?", fields={}, cost={"external_calls": 3})
    r.step("d", "Q?", fields={}, cost={"model_calls": 2})
    payload = r.as_record()

    from_steps = sum(int((s.get("cost") or {}).get("model_calls") or 0)
                     for s in r.ordered_steps())
    assert payload["model_calls"] == from_steps == 3, (
        "the header's model-call count and the steps' own costs disagree, "
        "which is a record contradicting itself"
    )


def test_steps_run_equals_the_number_of_steps():
    r = _rec()
    for i in range(5):
        r.step(f"k{i}", "Q?", fields={}, cost={})
    payload = r.as_record()
    assert payload["steps_run"] == len(r.ordered_steps()) == 5


def test_a_step_with_no_cost_contributes_nothing_rather_than_breaking_the_sum():
    """The dangerous direction: a missing cost dict must not make the counter
    diverge from the steps, because the UI now derives the model-call ORDINAL
    from those costs and would name a step the counter does not know about."""
    r = _rec()
    r.step("a", "Q?", fields={})
    r.step("b", "Q?", fields={}, cost=None)
    r.step("c", "Q?", fields={}, cost={"model_calls": 1})
    payload = r.as_record()
    ordinals = [s["ordinal"] for s in r.ordered_steps()
                if int((s.get("cost") or {}).get("model_calls") or 0) > 0]
    assert payload["model_calls"] == len(ordinals) == 1
    assert ordinals == [3]
