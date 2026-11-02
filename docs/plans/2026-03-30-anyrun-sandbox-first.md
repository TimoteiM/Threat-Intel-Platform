# Any.Run Sandbox-First Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Attempt real ANY.RUN sandbox execution by default for domain and URL investigations unless existing evidence already contains meaningful behavior details.

**Architecture:** Add a deterministic behavior-sufficiency gate and pass explicit sandbox intent into the hybrid/ANY.RUN service. Keep the existing fallback chain, but invert the preference for thin-evidence URL/domain cases so sandbox runs before lookup-only enrichment.

**Tech Stack:** Python, pytest, collector/service pipeline, ANY.RUN SDK integration

---

### Task 1: Add failing tests for the behavior sufficiency gate

**Files:**
- Modify: `backend/tests/unit/test_services/test_hybrid_analysis_service.py`
- Modify: `backend/app/services/hybrid_analysis_service.py`

**Step 1: Write the failing test**

Add tests that assert:
- rich behavior details skip sandbox-first mode
- thin URL/domain evidence enables sandbox-first mode

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -k sandbox_first -v`
Expected: FAIL because the gate and service flag do not exist yet.

**Step 3: Write minimal implementation**

Add the behavior sufficiency helper and wire it into the service call path.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -k sandbox_first -v`
Expected: PASS

### Task 2: Add failing tests for sandbox-first execution order

**Files:**
- Modify: `backend/tests/unit/test_services/test_hybrid_analysis_service.py`
- Modify: `backend/app/services/hybrid_analysis_service.py`

**Step 1: Write the failing test**

Add tests asserting that when `sandbox_first=True`:
- ANY.RUN sandbox is attempted before lookup-only result acceptance
- deferred sandbox still preserves lookup intelligence

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -k sandbox_order -v`
Expected: FAIL because the service still uses lookup-first behavior.

**Step 3: Write minimal implementation**

Reorder the ANY.RUN path for sandbox-first mode.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -k sandbox_order -v`
Expected: PASS

### Task 3: Integrate collector defaults for domain/url

**Files:**
- Modify: `backend/app/collectors/hybrid_analysis_collector.py`
- Modify: `backend/app/services/hybrid_analysis_service.py`
- Modify: `backend/tests/unit/test_services/test_hybrid_analysis_service.py`

**Step 1: Write the failing test**

Add coverage for the collector/service inputs used by `domain` and `url`.

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -k domain_url -v`
Expected: FAIL because collector defaults do not set sandbox-first behavior.

**Step 3: Write minimal implementation**

Pass sandbox-first intent for `domain` and `url`, while keeping existing file/hash behavior intact.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -k domain_url -v`
Expected: PASS

### Task 4: Verify regressions

**Files:**
- Modify: `backend/app/services/hybrid_analysis_service.py`
- Modify: `backend/app/collectors/hybrid_analysis_collector.py`
- Test: `backend/tests/unit/test_services/test_hybrid_analysis_service.py`
- Test: `backend/tests/unit/test_services/test_anyrun_service.py`
- Test: `backend/tests/unit/test_tasks/test_investigation_task_timeout.py`

**Step 1: Run hybrid-analysis tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -v`
Expected: PASS

**Step 2: Run Any.Run service tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -v`
Expected: PASS

**Step 3: Run timeout regression**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_tasks/test_investigation_task_timeout.py -v`
Expected: PASS
