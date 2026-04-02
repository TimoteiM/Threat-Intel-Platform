# AnyRun Single Suspicious Path Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the AnyRun process graph focus on the single highest-signal execution path instead of retaining multiple low-signal Windows branches.

**Architecture:** Tighten backend graph selection in `anyrun_service.py` so the graph keeps only the strongest suspicious process, its ancestor chain to root, and a compact benign context collapse where helpful. Leave DNS, HTTP, connection, threat, and IOC evidence unchanged outside the graph.

**Tech Stack:** Python, pytest

---

### Task 1: Add failing tests for single-path graph selection

**Files:**
- Modify: `backend/tests/unit/test_services/test_anyrun_service.py`

**Step 1: Add a test that drops sibling low-signal branches**

Create a graph fixture where one suspicious branch hangs off a noisy Windows parent alongside multiple benign siblings, and assert only the suspicious branch survives.

**Step 2: Add a test that prefers the strongest suspicious branch**

Create two suspicious-looking branches with different signal strengths and assert the graph keeps only the highest-signal path.

**Step 3: Run the targeted tests and verify they fail**

Run: `pytest backend/tests/unit/test_services/test_anyrun_service.py -q`

### Task 2: Implement single-path selection in the backend graph builder

**Files:**
- Modify: `backend/app/services/anyrun_service.py`

**Step 1: Add helpers to identify candidate suspicious anchors**

Use existing relevance metadata to rank suspicious nodes by strong direct signals rather than inherited context.

**Step 2: Replace broad keep logic with strongest-path keep logic**

Keep the chosen suspicious process, its ancestors to root, and avoid re-adding low-signal siblings under the same parent.

**Step 3: Preserve useful context collapse**

Allow existing low-signal chain collapse to compress benign ancestry that remains on the chosen path.

### Task 3: Verify the backend change

**Files:**
- Modify: `backend/app/services/anyrun_service.py`
- Modify: `backend/tests/unit/test_services/test_anyrun_service.py`

**Step 1: Run the targeted AnyRun service tests**

Run: `pytest backend/tests/unit/test_services/test_anyrun_service.py -q`

**Step 2: Confirm the tests pass**

Use the test result as verification that the graph selection compiles and behaves as expected.
