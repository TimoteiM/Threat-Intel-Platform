# All Cases Filters Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a classification filter and a backend-accurate duplicate-hiding filter to the All Cases page.

**Architecture:** Extend the investigations list API to accept `classification` and `dedupe`, implement both behaviors in the repository before pagination, then wire the new query controls into the existing frontend filter surface. Keep the response shape unchanged so the page can evolve with minimal churn.

**Tech Stack:** Next.js/React, TypeScript, FastAPI, SQLAlchemy async ORM, pytest

---

### Task 1: Extend the investigations list API contract

**Files:**
- Modify: `backend/app/api/investigations.py`
- Modify: `backend/app/services/investigation_service.py`
- Modify: `frontend/src/lib/api.ts`

**Step 1: Add the new API parameters**

Update `list_investigations(...)` in `backend/app/api/investigations.py` to accept:

- `classification: str | None = None`
- `dedupe: bool = False`

and pass them into the service methods for both `list_all(...)` and `count(...)`.

**Step 2: Thread the parameters through the service**

Update `InvestigationService.list_all(...)` and `InvestigationService.count(...)` in `backend/app/services/investigation_service.py` so both methods accept:

- `classification: Optional[str] = None`
- `dedupe: bool = False`

and forward them to the repository.

**Step 3: Extend the frontend API client**

Update `listInvestigations(...)` in `frontend/src/lib/api.ts` so its params object accepts:

- `classification?: string`
- `dedupe?: boolean`

and serializes them into the query string.

**Step 4: Run focused verification**

Run:

```powershell
& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit
```

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/api/investigations.py backend/app/services/investigation_service.py frontend/src/lib/api.ts
git commit -m "feat: extend investigation list filters"
```

### Task 2: Add backend classification filtering tests

**Files:**
- Create or Modify: `backend/tests/unit/test_repository/test_investigation_repository.py`

**Step 1: Write the failing test**

Add a repository-level test covering classification filtering, for example:

```python
async def test_list_all_filters_by_classification(...):
    ...
    rows = await repo.list_all(classification="malicious")
    assert [row.classification for row in rows] == ["malicious"]
```

Also add a count assertion:

```python
count = await repo.count(classification="malicious")
assert count == 1
```

**Step 2: Run the targeted test**

Run:

```bash
pytest backend/tests/unit/test_repository/test_investigation_repository.py -k classification -v
```

Expected: FAIL because filtering is not implemented yet.

**Step 3: Commit the test once it exists**

```bash
git add backend/tests/unit/test_repository/test_investigation_repository.py
git commit -m "test: cover investigation classification filtering"
```

### Task 3: Implement backend classification filtering

**Files:**
- Modify: `backend/app/db/repository.py`

**Step 1: Add classification filtering to list queries**

Update `InvestigationRepository.list_all(...)` to accept `classification` and apply:

```python
if classification:
    query = query.where(Investigation.classification == classification)
```

**Step 2: Add classification filtering to count queries**

Update `InvestigationRepository.count(...)` with the same filter.

**Step 3: Re-run the targeted test**

Run:

```bash
pytest backend/tests/unit/test_repository/test_investigation_repository.py -k classification -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add backend/app/db/repository.py
git commit -m "feat: add classification filter to investigations"
```

### Task 4: Add failing dedupe tests

**Files:**
- Modify: `backend/tests/unit/test_repository/test_investigation_repository.py`

**Step 1: Write the failing test**

Add tests for dedupe behavior, for example:

```python
async def test_list_all_dedupe_keeps_newest_investigation(...):
    ...
    rows = await repo.list_all(dedupe=True)
    assert len(rows) == 1
    assert rows[0].id == newest.id
```

Add a matching count test:

```python
count = await repo.count(dedupe=True)
assert count == 1
```

Add a combined test:

```python
rows = await repo.list_all(classification="malicious", dedupe=True, search="findmaps")
...
```

**Step 2: Run the targeted test**

Run:

```bash
pytest backend/tests/unit/test_repository/test_investigation_repository.py -k dedupe -v
```

Expected: FAIL because dedupe is not implemented yet.

**Step 3: Commit the tests**

```bash
git add backend/tests/unit/test_repository/test_investigation_repository.py
git commit -m "test: cover deduped investigation listing"
```

### Task 5: Implement backend dedupe before pagination

**Files:**
- Modify: `backend/app/db/repository.py`

**Step 1: Extract a shared filtered base query**

Refactor repository filtering into a shared internal helper or repeated base query so `list_all(...)` and `count(...)` use identical filters for:

- `state`
- `search`
- `observable_type`
- `classification`

**Step 2: Implement dedupe selection**

When `dedupe=True`, return only the newest investigation per `domain`.

Recommended behavior:

- group by investigated value
- keep newest `created_at`
- break ties deterministically using id

Use SQLAlchemy constructs appropriate for the current database backend.

**Step 3: Apply pagination after dedupe**

Ensure `limit` and `offset` apply to the deduped query rather than the raw dataset.

**Step 4: Make `count(...)` reflect deduped totals**

Ensure `repo.count(dedupe=True, ...)` returns the size of the deduped filtered dataset.

**Step 5: Run the repository tests**

Run:

```bash
pytest backend/tests/unit/test_repository/test_investigation_repository.py -v
```

Expected: PASS

**Step 6: Commit**

```bash
git add backend/app/db/repository.py backend/tests/unit/test_repository/test_investigation_repository.py
git commit -m "feat: dedupe investigations in backend listing"
```

### Task 6: Add the new All Cases filter controls

**Files:**
- Modify: `frontend/src/app/investigations/page.tsx`

**Step 1: Add new local state**

Add page state for:

- `classificationFilter`
- `hideDuplicates`

with defaults:

- `classificationFilter = "all"`
- `hideDuplicates = false`

**Step 2: Send the new query params**

Update the `listInvestigations(...)` call so it sends:

- `classification` when not `all`
- `dedupe` when enabled

**Step 3: Reset pagination on filter change**

Whenever classification or dedupe changes:

- set page to `0`

**Step 4: Add the visible controls**

In the existing `Search and filters` module, add:

- classification selector
- hide duplicates toggle

Match the existing design language of pills, select controls, and filter summary text.

**Step 5: Update helper labels**

Update:

- page hero badges
- `MetadataGrid` labels
- helper hint text

so they reflect the new classification and dedupe state.

**Step 6: Run TypeScript verification**

Run:

```powershell
& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit
```

Expected: PASS

**Step 7: Commit**

```bash
git add frontend/src/app/investigations/page.tsx
git commit -m "feat: add all cases classification and dedupe filters"
```

### Task 7: Verify end-to-end behavior locally

**Files:**
- No code changes expected unless fixes are needed

**Step 1: Rebuild the affected services**

Run:

```powershell
docker compose build frontend api worker
docker compose up -d --force-recreate frontend api worker
```

Expected: services rebuilt and restarted successfully.

**Step 2: Verify the All Cases page manually**

Check:

- classification filter narrows results
- hide duplicates removes older repeated investigated values
- counts and page numbers match visible results
- search + state + classification + dedupe work together

**Step 3: If needed, add a small follow-up fix**

Only patch issues discovered during manual verification. Keep the fix minimal.

**Step 4: Commit any verification fixes**

```bash
git add <changed-files>
git commit -m "fix: polish all cases filtering behavior"
```

### Task 8: Final verification and branch hygiene

**Files:**
- No new files expected unless docs are updated

**Step 1: Run final backend tests**

Run:

```bash
pytest backend/tests/unit/test_repository/test_investigation_repository.py -v
```

Expected: PASS

**Step 2: Run final frontend typecheck**

Run:

```powershell
& 'C:\Program Files\nodejs\node.exe' '.\frontend\node_modules\typescript\bin\tsc' -p '.\frontend\tsconfig.json' --noEmit
```

Expected: PASS

**Step 3: Inspect git status**

Run:

```bash
git status --short
```

Expected: only intended files changed or nothing left uncommitted.

**Step 4: Final commit if needed**

```bash
git add backend/app/api/investigations.py backend/app/services/investigation_service.py backend/app/db/repository.py backend/tests/unit/test_repository/test_investigation_repository.py frontend/src/lib/api.ts frontend/src/app/investigations/page.tsx
git commit -m "feat: add classification and dedupe filters to all cases"
```
