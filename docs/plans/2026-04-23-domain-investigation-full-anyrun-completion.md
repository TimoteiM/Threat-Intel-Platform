# Domain Investigation Full AnyRun Completion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ensure domain investigations conclude and compute risk only after full Any.Run evidence is available, while keeping Any.Run lookup and sandbox work parallel internally.

**Architecture:** Adjust the investigation orchestrator so `hybrid_analysis` is a required blocking collector for domain investigations instead of a deferred background update. Keep the current Any.Run internal concurrency, and clarify the timing UI so the total is labeled as elapsed wall-clock time rather than an apparent sum.

**Tech Stack:** Python, FastAPI backend services, Celery task orchestration, React/Next.js frontend, pytest

---

### Task 1: Add Regression Coverage For Blocking Any.Run Completion

**Files:**
- Modify: `backend/tests/unit/test_tasks/test_investigation_task_timeout.py`
- Test: `backend/tests/unit/test_tasks/test_investigation_task_timeout.py`

**Step 1: Write a failing test**

Add a task-level regression showing that a domain investigation with a slow Any.Run future does not call `run_analysis(...)` until the Any.Run future resolves.

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_investigation_task_timeout.py -k anyrun -v`

Expected: FAIL because the current orchestrator allows Any.Run to remain deferred.

**Step 3: Add a scope test**

Add a second test verifying whether non-domain observable types preserve existing deferred behavior if we intentionally scope the blocking change to domains only.

**Step 4: Run tests again**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_investigation_task_timeout.py -k anyrun -v`

Expected: FAIL on the current orchestration path.

### Task 2: Remove Deferred Completion For Domain Investigations

**Files:**
- Modify: `backend/app/tasks/investigation_task.py`
- Test: `backend/tests/unit/test_tasks/test_investigation_task_timeout.py`

**Step 1: Implement the minimal orchestrator change**

Update `_run_collectors_inline(...)` and its caller so domain investigations wait for the `hybrid_analysis` future to reach a terminal result before proceeding to `run_analysis(...)`.

**Step 2: Keep Any.Run internal parallelism intact**

Do not serialize Any.Run lookup and sandbox inside the service layer; only change the outer investigation orchestration.

**Step 3: Run focused task tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_investigation_task_timeout.py -v`

Expected: PASS

### Task 3: Retire Or Narrow The Background Merge Path

**Files:**
- Modify: `backend/app/tasks/investigation_task.py`
- Inspect: `backend/app/tasks/analysis_task.py`
- Test: `backend/tests/unit/test_tasks/test_investigation_task_timeout.py`

**Step 1: Narrow background update behavior**

Ensure `_start_anyrun_background_update(...)` is no longer used for domain investigations once full Any.Run completion is required for conclusion.

**Step 2: Verify scoring now happens once with final evidence**

Confirm `run_analysis(...)` only receives complete domain Any.Run evidence in the blocking path.

**Step 3: Run focused verification**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_investigation_task_timeout.py -v`

Expected: PASS

### Task 4: Clarify Timing UI Language

**Files:**
- Modify: `frontend/src/components/investigation/CollectorTimingTable.tsx`
- Inspect: `frontend/src/app/investigations/[id]/page.tsx`

**Step 1: Rename the total label**

Change the table header text so the total is clearly presented as elapsed investigation time, not summed collector duration.

**Step 2: Keep data plumbing unchanged unless needed**

Only adjust wording unless the code requires a small prop rename for clarity.

**Step 3: Run frontend verification**

Run: `.\node_modules\.bin\tsc -p frontend/tsconfig.json --noEmit`

Expected: PASS

### Task 5: Rebuild And Smoke Test

**Files:**
- No new source files expected

**Step 1: Run focused backend and frontend checks**

Run:
- `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_investigation_task_timeout.py -v`
- `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -k "domain_intelligence or first_domain_result" -v`
- `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -v`
- `.\node_modules\.bin\tsc -p frontend/tsconfig.json --noEmit`

Expected: PASS for the scoped suites

**Step 2: Rebuild containers**

Run:
- `docker compose build api frontend`
- `docker compose up -d --force-recreate api frontend`

Expected: both containers start cleanly

**Step 3: Smoke test the user scenario**

Run a domain investigation that previously concluded before live Any.Run lookup was present.

Expected:
- the investigation remains in progress until full Any.Run evidence is ready
- final report/risk includes the Any.Run lookup-live verdict
- timing panel label no longer implies row-sum equivalence
