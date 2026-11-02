# AnyRun Domain Intelligence First Result Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make domain investigations return both the primary Any.Run result and the domain-intelligence block on the first run, without needing a manual rerun.

**Architecture:** Tighten the backend Any.Run completeness rules for domain investigations. `lookup_anyrun()` will attach explicit domain-intelligence success or failure data, and `lookup_hybrid_analysis()` will stop reusing incomplete cached Any.Run payloads for domain investigations.

**Tech Stack:** Python, FastAPI backend services, pytest unit tests, Any.Run integration helpers

---

### Task 1: Lock The Current Bug In Tests

**Files:**
- Modify: `backend/tests/unit/test_services/test_investigation_service_helpers.py`
- Modify: `backend/tests/unit/test_api/test_dashboard.py` only if shared helpers already live there
- Test: `backend/tests/unit/test_services/test_investigation_service_helpers.py`

**Step 1: Write the failing test**

Add a focused service-level test around the Any.Run lookup helpers that simulates:
- a domain investigation using URL-form input
- a primary Any.Run lookup success
- a domain-intelligence branch that also succeeds

Assert the returned payload includes `domain_intelligence` on the first result.

**Step 2: Run test to verify it fails**

Run: `python -m pytest backend/tests/unit/test_services/test_investigation_service_helpers.py -k anyrun -v`

Expected: FAIL because the current code path can return a result without attached `domain_intelligence`.

**Step 3: Add a second failing cache test**

Simulate a cached Any.Run domain payload that is otherwise valid but has no `domain_intelligence`.

Assert `lookup_hybrid_analysis()` rejects that cache entry for domain investigations and re-fetches fresh Any.Run data.

**Step 4: Run tests to verify they fail**

Run: `python -m pytest backend/tests/unit/test_services/test_investigation_service_helpers.py -k anyrun -v`

Expected: FAIL on missing completeness enforcement.

**Step 5: Commit**

```bash
git add backend/tests/unit/test_services/test_investigation_service_helpers.py
git commit -m "test: cover incomplete anyrun domain intelligence results"
```

### Task 2: Make Domain Any.Run Results Explicitly Complete

**Files:**
- Modify: `backend/app/services/anyrun_service.py`
- Test: `backend/tests/unit/test_services/test_investigation_service_helpers.py`

**Step 1: Implement minimal completion logic**

Update `lookup_anyrun()` so that for domain investigations:
- successful domain-intelligence results are always attached
- failed domain-intelligence attempts produce `domain_intelligence = {"checked": false, "error": ...}`
- silent omission is avoided

Keep the existing payload shape for the primary result and `additional_items`.

**Step 2: Run focused tests**

Run: `python -m pytest backend/tests/unit/test_services/test_investigation_service_helpers.py -k anyrun -v`

Expected: PASS for the new first-result completeness test.

**Step 3: Inspect for regressions**

Check nearby Any.Run logic for URL and hash flows to make sure only domain-investigation behavior is tightened.

**Step 4: Commit**

```bash
git add backend/app/services/anyrun_service.py backend/tests/unit/test_services/test_investigation_service_helpers.py
git commit -m "fix: require explicit domain intelligence in anyrun domain results"
```

### Task 3: Reject Incomplete Cached Domain Any.Run Payloads

**Files:**
- Modify: `backend/app/services/hybrid_analysis_service.py`
- Test: `backend/tests/unit/test_services/test_investigation_service_helpers.py`

**Step 1: Implement cache validation**

Extend the Any.Run cache acceptance checks so domain-investigation cache entries are considered incomplete when they lack a usable `domain_intelligence` object.

This should apply only to domain investigations, not generic URL/hash flows.

**Step 2: Run focused tests**

Run: `python -m pytest backend/tests/unit/test_services/test_investigation_service_helpers.py -k anyrun -v`

Expected: PASS for cache invalidation regression coverage.

**Step 3: Commit**

```bash
git add backend/app/services/hybrid_analysis_service.py backend/tests/unit/test_services/test_investigation_service_helpers.py
git commit -m "fix: ignore incomplete cached anyrun domain payloads"
```

### Task 4: Verify Collector And UI Compatibility

**Files:**
- Inspect: `backend/app/collectors/hybrid_analysis_collector.py`
- Inspect: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`
- Test: existing backend pytest target

**Step 1: Confirm collector mapping still works**

Verify `HybridAnalysisCollector` continues to map the primary row and attached `domain_intelligence` without schema changes.

**Step 2: Confirm frontend rendering contract**

Verify the frontend already renders `domain_intelligence` when present and does not require additional code changes.

**Step 3: Run verification**

Run: `python -m pytest backend/tests/unit/test_services/test_investigation_service_helpers.py -v`

Expected: PASS

**Step 4: Commit**

```bash
git add backend/app/collectors/hybrid_analysis_collector.py frontend/src/components/report/AnyRunInteractiveEvidence.tsx
git commit -m "chore: verify anyrun domain intelligence compatibility"
```

### Task 5: Rebuild And Smoke Test

**Files:**
- No source changes required unless smoke test reveals a follow-up fix

**Step 1: Rebuild API image**

Run: `docker compose build api`

Expected: successful build

**Step 2: Recreate API container**

Run: `docker compose up -d --force-recreate api`

Expected: container starts cleanly on port `8000`

**Step 3: Smoke test**

Run a domain investigation that previously showed only one Any.Run half on first load.

Expected: initial result includes both the main Any.Run block and the domain-intelligence block without manual rerun.

**Step 4: Commit**

```bash
git add .
git commit -m "feat: complete anyrun domain intelligence on first result"
```
