# Analyst Prompt Too Long Retry Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add tiered analyst prompt compaction and retry so prompt-overflow errors preserve detailed reasoning whenever a smaller evidence payload can succeed.

**Architecture:** Keep the current analyst flow as the first attempt, then retry with progressively smaller evidence payloads only for prompt-size invalid-request failures. Centralize compaction logic in the analysis task so prompt construction stays consistent and the fallback report path remains unchanged.

**Tech Stack:** Python, pytest, OpenAI Responses API integration, existing analyst task/orchestrator pipeline

---

### Task 1: Add failing tests for compaction tiers

**Files:**
- Modify: `backend/tests/unit/test_tasks/test_analysis_compact_evidence.py`
- Modify: `backend/app/tasks/analysis_task.py`

**Step 1: Write the failing test**

```python
def test_compact_evidence_digest_tier_reduces_large_sections_more_aggressively():
    evidence = {
        "domain": "example.com",
        "investigation_id": "x",
        "timestamps": {"started": "2026-03-27T00:00:00Z"},
        "intel": {"related_urls": [f"https://a{i}.example.com" for i in range(120)]},
        "js_analysis": {"captured_requests": [{"url": f"https://r{i}.example.com"} for i in range(80)]},
        "signals": [{"id": str(i)} for i in range(90)],
    }

    compact = _build_analyst_input_evidence(evidence, tier="compact")
    digest = _build_analyst_input_evidence(evidence, tier="digest")

    assert len(digest["intel"]["related_urls"]) < len(compact["intel"]["related_urls"])
    assert len(digest["js_analysis"]["captured_requests"]) < len(compact["js_analysis"]["captured_requests"])
    assert len(digest["signals"]) < len(compact["signals"])
```

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k digest_tier -v`
Expected: FAIL because `_build_analyst_input_evidence` does not yet accept a `tier` argument.

**Step 3: Write minimal implementation**

Add tier support to `_build_analyst_input_evidence` with stronger trimming for `compact` and `digest`.

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k digest_tier -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/tests/unit/test_tasks/test_analysis_compact_evidence.py backend/app/tasks/analysis_task.py
git commit -m "test: cover analyst evidence compaction tiers"
```

### Task 2: Add failing tests for prompt-too-long retry handling

**Files:**
- Modify: `backend/tests/unit/test_tasks/test_analysis_compact_evidence.py`
- Modify: `backend/app/tasks/analysis_task.py`

**Step 1: Write the failing test**

```python
def test_run_analyst_with_compaction_retries_prompt_too_long(monkeypatch):
    calls = []

    def fake_run_analyst_sync(evidence_data, max_iterations, timeout_seconds):
        calls.append(evidence_data["meta"]["tier"])
        if len(calls) == 1:
            raise RuntimeError(
                "Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', 'message': 'prompt is too long: 205366 tokens > 200000 maximum'}}"
            )
        return {"classification": "benign", "primary_reasoning": "ok"}

    monkeypatch.setattr("app.tasks.analysis_task._run_analyst_sync", fake_run_analyst_sync)

    report, tier = _run_analyst_with_compaction(...)

    assert calls == ["standard", "compact"]
    assert tier == "compact"
```

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k prompt_too_long -v`
Expected: FAIL because `_run_analyst_with_compaction` does not exist yet.

**Step 3: Write minimal implementation**

Add the retry helper and prompt-overflow detector, then switch the domain/url analyst path to use it.

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k prompt_too_long -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/tests/unit/test_tasks/test_analysis_compact_evidence.py backend/app/tasks/analysis_task.py
git commit -m "feat: retry analyst with compact evidence tiers"
```

### Task 3: Add coverage for non-retry and report annotation behavior

**Files:**
- Modify: `backend/tests/unit/test_tasks/test_analysis_compact_evidence.py`
- Modify: `backend/app/tasks/analysis_task.py`

**Step 1: Write the failing test**

```python
def test_prompt_too_long_retry_annotation_is_added():
    report = {"classification": "benign", "primary_reasoning": "Reasoning", "executive_summary": "Summary"}

    annotated = _annotate_compact_analyst_report(report, used_tier="digest")

    assert annotated["primary_reasoning"].startswith("Analyst used compact evidence")
    assert annotated["executive_summary"].startswith("Analyst used compact evidence")
```

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k annotation -v`
Expected: FAIL because annotation helper does not exist yet.

**Step 3: Write minimal implementation**

Add a helper that annotates successful compact-tier reports and leaves standard-tier reports unchanged. Add a non-retry test for unrelated exceptions.

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k "annotation or non_size" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/tests/unit/test_tasks/test_analysis_compact_evidence.py backend/app/tasks/analysis_task.py
git commit -m "test: cover analyst compact retry annotations"
```

### Task 4: Verify the targeted analyst flow

**Files:**
- Modify: `backend/app/tasks/analysis_task.py`
- Test: `backend/tests/unit/test_tasks/test_analysis_compact_evidence.py`

**Step 1: Run targeted tests**

Run: `pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -v`
Expected: PASS

**Step 2: Run additional regression coverage**

Run: `pytest backend/tests/unit/test_tasks/test_investigation_task_timeout.py -v`
Expected: PASS

**Step 3: Review diffs**

Run: `git diff -- backend/app/tasks/analysis_task.py backend/tests/unit/test_tasks/test_analysis_compact_evidence.py docs/plans/2026-03-27-analyst-prompt-too-long-retry-design.md docs/plans/2026-03-27-analyst-prompt-too-long-retry.md`
Expected: Changes limited to compact retry behavior, tests, and plan docs.

**Step 4: Commit**

```bash
git add backend/app/tasks/analysis_task.py backend/tests/unit/test_tasks/test_analysis_compact_evidence.py docs/plans/2026-03-27-analyst-prompt-too-long-retry-design.md docs/plans/2026-03-27-analyst-prompt-too-long-retry.md
git commit -m "fix: retry oversized analyst prompts with compact evidence"
```
