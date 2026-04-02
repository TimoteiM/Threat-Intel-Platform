# Analyst Evidence Digest Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a compact analyst evidence digest that preserves grounded "what this domain is about" context while reducing prompt size enough to keep rich SOC reasoning.

**Architecture:** Build a deterministic digest from full collector evidence, add it to the analyst schema and prompt, and aggressively shrink heavyweight raw evidence sections for analyst input only. Keep persistence and UI paths unchanged so the full evidence is still stored and rendered outside the LLM path.

**Tech Stack:** Python, Pydantic models, pytest, OpenAI Responses API prompt builder

---

### Task 1: Add failing tests for analyst digest content

**Files:**
- Modify: `backend/tests/unit/test_tasks/test_analysis_compact_evidence.py`
- Modify: `backend/app/tasks/analysis_task.py`

**Step 1: Write the failing test**

Add a test asserting the analyst input includes `analyst_digest.associated_with` and basis clues from page title / WHOIS / Brave OSINT.

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k analyst_digest -v`
Expected: FAIL because the digest builder does not exist yet.

**Step 3: Write minimal implementation**

Add digest builder helpers and include the digest in analyst input.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k analyst_digest -v`
Expected: PASS

### Task 2: Add failing tests for heavyweight collector summaries

**Files:**
- Modify: `backend/tests/unit/test_tasks/test_analysis_compact_evidence.py`
- Modify: `backend/app/tasks/analysis_task.py`

**Step 1: Write the failing test**

Add a test asserting `hybrid_analysis`, `brave_osint`, `intel`, and `vt` are summarized much more aggressively in digest mode.

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k heavyweight_digest -v`
Expected: FAIL because the heavy sections are still mostly raw.

**Step 3: Write minimal implementation**

Implement collector-specific summary reducers.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -k heavyweight_digest -v`
Expected: PASS

### Task 3: Add prompt builder coverage for analyst digest

**Files:**
- Modify: `backend/tests/unit/test_analyst/test_system_prompt.py`
- Create or modify: prompt-builder unit coverage
- Modify: `backend/app/analyst/prompt_builder.py`
- Modify: `backend/app/models/schemas.py`

**Step 1: Write the failing test**

Add a test asserting the prompt includes an `analyst_digest` block when present.

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_analyst -k digest -v`
Expected: FAIL because the prompt does not render the new digest block yet.

**Step 3: Write minimal implementation**

Add `analyst_digest` to the schema and render it in the prompt.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_analyst -k digest -v`
Expected: PASS

### Task 4: Verify regressions

**Files:**
- Modify: `backend/app/tasks/analysis_task.py`
- Modify: `backend/app/analyst/prompt_builder.py`
- Modify: `backend/app/models/schemas.py`
- Test: `backend/tests/unit/test_tasks/test_analysis_compact_evidence.py`
- Test: `backend/tests/unit/test_tasks/test_investigation_task_timeout.py`

**Step 1: Run targeted task tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_analysis_compact_evidence.py -v`
Expected: PASS

**Step 2: Run targeted analyst tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_analyst -v`
Expected: PASS

**Step 3: Run timeout regression**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_investigation_task_timeout.py -v`
Expected: PASS
