# Email AnyRun Single Submission Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make email investigations submit the uploaded email sample to AnyRun once and stop performing per-URL and per-attachment AnyRun submissions from the email workflow.

**Architecture:** Keep deterministic email indicator checks intact, but split AnyRun behavior into a new email-level submission path. `process_email_investigation(...)` will call a dedicated helper with the original payload and filename, while `run_email_indicator_checks(...)` will stop invoking AnyRun-backed hybrid enrichment for URLs and attachments.

**Tech Stack:** Python, FastAPI, Celery, pytest, existing AnyRun service layer

---

### Task 1: Document the approved design

**Files:**
- Create: `docs/plans/2026-04-02-email-anyrun-single-submission-design.md`
- Create: `docs/plans/2026-04-02-email-anyrun-single-submission.md`

**Step 1: Write the design summary**

Capture the approved behavior change, trade-offs, and testing expectations.

**Step 2: Save the implementation plan**

Write the minimal sequence of backend and test changes.

### Task 2: Add failing tests for email-level AnyRun behavior

**Files:**
- Modify: `backend/tests/unit/test_services/test_email_investigations_helpers.py`

**Step 1: Write the failing test**

Add a test that patches:
- `extract_email_iocs`
- `run_email_indicator_checks`
- `lookup_anyrun`

Assert that `process_email_investigation(...)`:
- calls `lookup_anyrun(...)` exactly once
- passes `indicator_type="file"`
- passes the original email bytes and filename

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/unit/test_services/test_email_investigations_helpers.py -k anyrun -v`

Expected: FAIL because the current email flow never submits the raw email payload to AnyRun.

### Task 3: Add failing regression test for indicator fan-out removal

**Files:**
- Modify: `backend/tests/unit/test_services/test_email_investigations_helpers.py`
- Modify: `backend/tests/unit/test_services/test_hybrid_analysis_service.py` if needed

**Step 1: Write the failing test**

Add a test for `run_email_indicator_checks(...)` with:
- one URL
- one attachment
- `run_anyrun=True`

Patch `lookup_hybrid_analysis(...)` to raise if called. Assert the function completes and deterministic checks still return.

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/unit/test_services/test_email_investigations_helpers.py -k indicator_checks -v`

Expected: FAIL because `_check_url(...)` and `_check_attachments(...)` still call hybrid/AnyRun today.

### Task 4: Implement the email-level AnyRun helper

**Files:**
- Modify: `backend/app/services/email_investigation_processing_service.py`
- Modify: `backend/app/services/anyrun_service.py` only if `indicator_type="file"` support needs a small extension

**Step 1: Write minimal implementation**

Add a helper that:
- accepts raw email bytes and filename
- calls `lookup_anyrun(...)` once with file submission arguments
- normalizes the returned payload into `indicator_checks["email_anyrun"]`

**Step 2: Wire it into the email flow**

Call the helper from `process_email_investigation(...)` after IOC extraction and before final response assembly.

### Task 5: Remove per-indicator AnyRun behavior from email checks

**Files:**
- Modify: `backend/app/services/email_indicator_checks_service.py`

**Step 1: Write minimal implementation**

Keep deterministic URL and attachment checks, but stop invoking `lookup_hybrid_analysis(...)` from the email investigation path.

**Step 2: Preserve response shape**

Return stable `hybrid_analysis` placeholders where needed so downstream consumers do not break.

### Task 6: Feed email-level AnyRun into risk/output shaping

**Files:**
- Modify: `backend/app/services/email_indicator_checks_service.py`
- Modify: `backend/app/services/email_investigation_processing_service.py`

**Step 1: Add email-level AnyRun result into the investigation payload**

Expose the new block under `indicator_checks`.

**Step 2: Update risk aggregation input**

Use the email-level AnyRun result as the dynamic-analysis input for final email risk.

### Task 7: Run targeted verification

**Files:**
- Test: `backend/tests/unit/test_services/test_email_investigations_helpers.py`
- Test: `backend/tests/unit/test_services/test_anyrun_service.py`
- Test: `backend/tests/unit/test_services/test_hybrid_analysis_service.py`

**Step 1: Run targeted tests**

Run:
- `pytest backend/tests/unit/test_services/test_email_investigations_helpers.py -v`
- `pytest backend/tests/unit/test_services/test_anyrun_service.py -v`
- `pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -v`

**Step 2: Run any additional narrow regression tests if needed**

Confirm the new email path is green and the standalone AnyRun service behavior still passes.
