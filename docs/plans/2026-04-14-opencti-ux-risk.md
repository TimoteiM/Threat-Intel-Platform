# OpenCTI UX and Risk Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make OpenCTI intelligence read like a designed, analyst-friendly UI section and make strong OpenCTI evidence materially influence investigation risk scoring.

**Architecture:** Keep the existing OpenCTI collector and evidence model shape, but improve the presentation layer in the investigation report and add a dedicated OpenCTI component plus threshold-based floors in the composite risk engine. Preserve compatibility with current evidence payloads while making the OpenCTI section feel first-class and making its trust level visible in both UI and rationale.

**Tech Stack:** React, Next.js, TypeScript, existing report components, Python backend services, Pydantic schemas, pytest.

---

### Task 1: Add backend regression coverage for OpenCTI risk aggregation

**Files:**
- Create: `backend/tests/unit/test_services/test_risk_aggregator_opencti.py`
- Modify: `backend/app/services/risk_aggregator.py`

**Step 1: Write the failing test**

Add tests covering:

- no OpenCTI evidence keeps `opencti_score` at `0`
- found OpenCTI observable with moderate score contributes to overall score
- strong OpenCTI score plus rich linked intel raises risk floor to `medium`
- very strong OpenCTI evidence raises risk floor to `high`
- rationale includes OpenCTI-specific explanations when used

**Step 2: Run test to verify it fails**

Run: `docker compose exec api sh -lc "cd /app && PYTHONPATH=/app python -m pytest tests/unit/test_services/test_risk_aggregator_opencti.py -v"`

Expected: FAIL because `risk_aggregator.py` does not yet expose `opencti_score` or any OpenCTI floor behavior.

**Step 3: Write minimal implementation**

Update `backend/app/services/risk_aggregator.py` to:

- add `opencti_score` to `DEFAULT_WEIGHTS`
- calculate an OpenCTI component from:
  - `found`
  - `score`
  - linked reports / actors / malware / attack patterns / campaigns / intrusion sets
- rebalance total weights so they still sum cleanly
- add floor logic for medium / high OpenCTI outcomes
- add OpenCTI rationale strings
- include `opencti_score` in `components`

**Step 4: Run test to verify it passes**

Run: `docker compose exec api sh -lc "cd /app && PYTHONPATH=/app python -m pytest tests/unit/test_services/test_risk_aggregator_opencti.py -v"`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/services/risk_aggregator.py backend/tests/unit/test_services/test_risk_aggregator_opencti.py
git commit -m "feat: add OpenCTI risk contribution"
```

### Task 2: Refine OpenCTI evidence shaping for the frontend

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Modify: `frontend/src/components/report/TechnicalEvidenceTab.tsx`

**Step 1: Write the failing test**

If the repo has suitable frontend component tests, add a focused test around OpenCTI rendering. If not, document this as a manual verification task and add helper logic in a way that can be locally type-checked.

At minimum, define expected UI states for:

- not found
- found with moderate score and sparse intel
- found with strong score and rich intel

**Step 2: Run test or type-check to verify the current state is insufficient**

Run: `& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit`

Expected: current rendering still uses a flat table-first OpenCTI section and does not expose the new designed summary layer.

**Step 3: Write minimal implementation**

In `TechnicalEvidenceTab.tsx`:

- extract OpenCTI rendering into a clearer section layout
- add a top summary card with:
  - matched observable
  - observable type
  - score badge / severity badge
  - trust indicator
  - short summary sentence
- add a stats row with counts
- group downstream evidence into:
  - Threat Context
  - Detection Logic
  - Reports
  - ATT&CK Context
  - Notes
- improve empty and partial states

Update `frontend/src/lib/types.ts` only if the frontend needs minor helper typing additions for the redesigned section.

**Step 4: Run type-check to verify it passes**

Run: `& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit`

Expected: PASS

**Step 5: Commit**

```bash
git add frontend/src/components/report/TechnicalEvidenceTab.tsx frontend/src/lib/types.ts
git commit -m "feat: redesign OpenCTI evidence presentation"
```

### Task 3: Surface OpenCTI influence clearly in investigation rationale

**Files:**
- Modify: `backend/app/services/risk_aggregator.py`
- Modify: `frontend/src/components/report/TechnicalEvidenceTab.tsx`
- Optional: `frontend/src/lib/types.ts`

**Step 1: Write the failing test**

Extend the backend risk tests to assert that:

- rationale includes OpenCTI-specific strings when score contribution exists
- rationale includes floor language when a floor is applied

**Step 2: Run tests to verify the failure**

Run: `docker compose exec api sh -lc "cd /app && PYTHONPATH=/app python -m pytest tests/unit/test_services/test_risk_aggregator_opencti.py -v"`

Expected: FAIL until rationale details are exposed consistently.

**Step 3: Write minimal implementation**

Ensure backend output includes:

- OpenCTI component value
- OpenCTI floor metadata or rationale language

Update the UI to display the OpenCTI influence in a human-readable way where investigation risk rationale is shown.

**Step 4: Run backend tests and frontend type-check**

Run:

- `docker compose exec api sh -lc "cd /app && PYTHONPATH=/app python -m pytest tests/unit/test_services/test_risk_aggregator_opencti.py -v"`
- `& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/services/risk_aggregator.py frontend/src/components/report/TechnicalEvidenceTab.tsx frontend/src/lib/types.ts
git commit -m "feat: explain OpenCTI risk impact"
```

### Task 4: End-to-end verification with representative OpenCTI evidence

**Files:**
- No required code changes
- Review: `frontend/src/components/report/TechnicalEvidenceTab.tsx`
- Review: `backend/app/services/risk_aggregator.py`

**Step 1: Run backend verification**

Run the focused OpenCTI risk tests plus any directly relevant existing risk tests.

Suggested command:

`docker compose exec api sh -lc "cd /app && PYTHONPATH=/app python -m pytest tests/unit/test_services/test_risk_aggregator_opencti.py -v"`

**Step 2: Run frontend verification**

Run:

`& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit`

**Step 3: Verify with a live investigation**

Use a known OpenCTI-positive observable and confirm:

- OpenCTI section now reads like a designed intelligence panel
- strong OpenCTI evidence raises the investigation risk appropriately
- rationale explains the OpenCTI influence

**Step 4: Commit final integration if needed**

```bash
git add backend/app/services/risk_aggregator.py backend/tests/unit/test_services/test_risk_aggregator_opencti.py frontend/src/components/report/TechnicalEvidenceTab.tsx frontend/src/lib/types.ts
git commit -m "feat: integrate OpenCTI UX and risk scoring"
```
