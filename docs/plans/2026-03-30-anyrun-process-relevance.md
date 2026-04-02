# AnyRun Process Relevance Filter Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a backend process relevance filter so AnyRun graphs highlight attack flow instead of system noise.

**Architecture:** Score processes from normalized AnyRun process details, keep only suspicious/high-signal processes plus the required execution chain, collapse repeated low-signal system processes, and emit a simplified process-only graph from the backend. Keep detailed event payloads for drill-down outside the graph itself.

**Tech Stack:** Python, pytest, AnyRun service graph builder

---

### Task 1: Add failing tests for process relevance scoring and filtering

**Files:**
- Modify: `backend/tests/unit/test_services/test_anyrun_service.py`
- Modify: `backend/app/services/anyrun_service.py`

**Step 1: Write the failing test**

Add tests that assert:
- suspicious/high-signal processes score above threshold
- common Windows processes score lower unless needed in the chain
- root process is always kept

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -k process_relevance -v`
Expected: FAIL because the relevance helpers do not exist yet.

**Step 3: Write minimal implementation**

Add process relevance scorer and keep-set computation.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -k process_relevance -v`
Expected: PASS

### Task 2: Add failing tests for simplified execution-chain graph

**Files:**
- Modify: `backend/tests/unit/test_services/test_anyrun_service.py`
- Modify: `backend/app/services/anyrun_service.py`

**Step 1: Write the failing test**

Add a graph test that expects:
- relevant process nodes only
- execution edges only
- suspicious descendant chain preserved

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -k execution_chain -v`
Expected: FAIL because `_build_behavior_graph` still emits broad process/network graph nodes.

**Step 3: Write minimal implementation**

Refactor `_build_behavior_graph` to build the simplified process-only graph.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -k execution_chain -v`
Expected: PASS

### Task 3: Add failing tests for collapsing repeated system processes

**Files:**
- Modify: `backend/tests/unit/test_services/test_anyrun_service.py`
- Modify: `backend/app/services/anyrun_service.py`

**Step 1: Write the failing test**

Add a test asserting repeated low-signal `svchost.exe` nodes collapse into one graph node such as `svchost.exe (3 instances)`.

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -k collapse_instances -v`
Expected: FAIL because collapse logic does not exist yet.

**Step 3: Write minimal implementation**

Implement low-signal system-process collapsing after keep-set computation.

**Step 4: Run test to verify it passes**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -k collapse_instances -v`
Expected: PASS

### Task 4: Verify regressions

**Files:**
- Modify: `backend/app/services/anyrun_service.py`
- Test: `backend/tests/unit/test_services/test_anyrun_service.py`
- Test: `backend/tests/unit/test_services/test_hybrid_analysis_service.py`

**Step 1: Run AnyRun service tests**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_anyrun_service.py -v`
Expected: PASS

**Step 2: Run hybrid-analysis regression**

Run: `PYTHONPATH=backend python -m pytest backend/tests/unit/test_services/test_hybrid_analysis_service.py -v`
Expected: PASS
