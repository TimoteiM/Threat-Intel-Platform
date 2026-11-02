# Email AnyRun Concurrency Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Start deterministic email checks and the single email-level AnyRun submission concurrently so email investigations finish faster.

**Architecture:** Keep the same output shape, but replace the sequential await chain in `process_email_investigation(...)` with concurrent `asyncio.to_thread(...)` tasks gathered together.

**Tech Stack:** Python, asyncio, pytest

---

### Task 1: Add a failing concurrency regression test

**Files:**
- Modify: `backend/tests/unit/test_services/test_email_investigations_helpers.py`

**Step 1: Write the failing test**

Patch `run_email_indicator_checks(...)` and `_lookup_email_anyrun(...)` so each waits for the other to start. Assert `process_email_investigation(...)` completes successfully.

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_services/test_email_investigations_helpers.py -k concurrent -v`

Expected: FAIL while the flow is still sequential.

### Task 2: Implement concurrent branch startup

**Files:**
- Modify: `backend/app/services/email_investigation_processing_service.py`

**Step 1: Launch both branches together**

Use `asyncio.gather(...)` over two `asyncio.to_thread(...)` calls.

**Step 2: Preserve merge behavior**

Keep `email_anyrun`, `hybrid_analysis`, and final risk shaping unchanged after both results arrive.

### Task 3: Verify targeted regression coverage

**Files:**
- Test: `backend/tests/unit/test_services/test_email_investigations_helpers.py`

**Step 1: Run tests**

Run: `python -m pytest tests/unit/test_services/test_email_investigations_helpers.py -v`

Expected: PASS
