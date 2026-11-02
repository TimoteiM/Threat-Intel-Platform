# Executive Summary Reasoning Enrichment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enrich `Primary Reasoning` for domain, URL, and email investigations so it explains both observable context and evidence-based security assessment.

**Architecture:** Keep the existing `primary_reasoning` field and adjust prompt/fallback behavior based on observable type. Leave `ip`, `hash`, and `file` reasoning unchanged.

**Tech Stack:** Python backend prompt/orchestration, existing analyst report schema, React/Next.js frontend rendering.

---

### Task 1: Update analyst prompt rules for richer reasoning

**Files:**
- Modify: `backend/app/analyst/system_prompt.py`
- Test: prompt-related regression via report generation path

**Step 1: Change the `primary_reasoning` instruction**
Update the prompt so `domain`, `url`, and `email` reasoning explicitly includes:
- what the observable appears to be / what the company or service appears to do
- whether it appears benign, suspicious, or malicious based on evidence

**Step 2: Preserve concise behavior for other observable types**
Do not relax the concise instruction for `ip`, `hash`, or `file`.

**Step 3: Run targeted backend tests if present**
Run: `python -m pytest backend/tests -q`
Expected: no regressions in existing parser/service tests relevant to analyst reports

**Step 4: Commit**

```bash
git add backend/app/analyst/system_prompt.py
git commit -m "feat: enrich executive summary reasoning for domains urls and email"
```

### Task 2: Adjust normalization/fallback logic

**Files:**
- Modify: `backend/app/tasks/analysis_task.py`
- Test: targeted regression for `primary_reasoning` fallback behavior

**Step 1: Inspect simplification logic**
Review `_should_simplify_primary_reasoning` and surrounding normalization so richer domain/url/email reasoning is not collapsed back into overly short fallback text.

**Step 2: Implement minimal conditional behavior**
Keep simplification protection for broken or noisy reasoning, but allow richer two-part reasoning to survive for `domain`, `url`, and `email`.

**Step 3: Run backend tests**
Run: `python -m pytest backend/tests -q`
Expected: passing relevant tests

**Step 4: Commit**

```bash
git add backend/app/tasks/analysis_task.py
git commit -m "fix: preserve richer executive reasoning for supported observables"
```

### Task 3: Light frontend validation

**Files:**
- Inspect: `frontend/src/components/report/ExecutiveSummaryTab.tsx`
- Modify only if needed

**Step 1: Verify current rendering**
Check whether the existing `Primary Reasoning` block can display the richer text cleanly.

**Step 2: If needed, make minimal UI polish**
Only add formatting support if the richer text wraps poorly. Avoid introducing new structure if plain text rendering is already clean.

**Step 3: Build frontend**
Run: `docker compose build frontend`
Expected: successful build

**Step 4: Recreate frontend container if changed**
Run: `docker compose up -d --force-recreate frontend`
Expected: frontend running normally

**Step 5: Commit if frontend changed**

```bash
git add frontend/src/components/report/ExecutiveSummaryTab.tsx
git commit -m "feat: support richer executive summary reasoning display"
```

### Task 4: End-to-end verification

**Files:**
- No new code expected

**Step 1: Run backend and frontend verification**
Run:
- `docker compose ps`
- `Invoke-WebRequest -UseBasicParsing http://localhost:3000 | Select-Object -ExpandProperty StatusCode`
- `Invoke-WebRequest -UseBasicParsing http://localhost:8000/openapi.json | Select-Object -ExpandProperty StatusCode`

Expected:
- stack healthy
- frontend `200`
- api `200`

**Step 2: Validate behavior with live investigations**
Check at least:
- one `domain` or `url` investigation
- one `email` investigation
- one `hash` or `file` investigation for control

Expected:
- `domain`/`url`/`email` show richer two-part reasoning
- `hash`/`file` remain concise

**Step 3: Final commit if needed**
Commit any remaining small adjustments with a focused message.
