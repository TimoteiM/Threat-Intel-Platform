# AI Assistant Session Search Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add paginated AI Assistant session browsing with a single search box that matches session titles and session log content.

**Architecture:** Extend the assistant session list API to support search and total-count pagination, then update the assistant workspace to drive a searchable session browser from that API. Keep query logic in the backend service and keep the list component presentation-focused.

**Tech Stack:** FastAPI, SQLAlchemy async ORM, Pydantic, React, Next.js, TypeScript

---

### Task 1: Add backend tests for searchable session listing

**Files:**
- Modify: `backend/tests/unit/test_services/test_assistant_service.py`

**Step 1: Write the failing tests**

Add tests that prove:
- title search returns matching sessions
- entry-content search returns matching sessions
- total count reflects all matches
- pagination returns the correct slice

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/unit/test_services/test_assistant_service.py -q`
Expected: FAIL because `list_sessions` does not support search/total pagination yet.

**Step 3: Write minimal implementation**

Update `AssistantService.list_sessions` to:
- accept `search`, `limit`, and `offset`
- filter on `AssistantSession.title` and related `AssistantEntry.raw_text`
- return paginated items plus total

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/unit/test_services/test_assistant_service.py -q`
Expected: PASS

### Task 2: Expose the new backend contract through the API

**Files:**
- Modify: `backend/app/services/assistant_service.py`
- Modify: `backend/app/api/assistant.py`

**Step 1: Write the failing test**

If needed, extend `backend/tests/unit/test_services/test_assistant_api.py` to assert the route still exists and supports the same endpoint shape after the response change.

**Step 2: Run test to verify it fails or remains red from service contract change**

Run: `pytest backend/tests/unit/test_services/test_assistant_api.py -q`

**Step 3: Write minimal implementation**

Change the API response to include:
- `items`
- `total`
- `limit`
- `offset`

Thread through the optional `search` query parameter.

**Step 4: Run tests to verify they pass**

Run: `pytest backend/tests/unit/test_services/test_assistant_api.py backend/tests/unit/test_services/test_assistant_service.py -q`
Expected: PASS

### Task 3: Update frontend API typing for paginated assistant sessions

**Files:**
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/lib/types.ts`

**Step 1: Write the failing test or compile target**

Use TypeScript compilation as the red step if no frontend unit tests exist for this path.

**Step 2: Run verification to surface type gaps**

Run: `npm run lint`
Expected: type/usage errors after the backend contract changes.

**Step 3: Write minimal implementation**

Update the assistant list API helper to accept `search` and return `total`.

**Step 4: Run verification to confirm green**

Run: `npm run lint`
Expected: no new lint/type errors from the API helper changes.

### Task 4: Add search and pagination UI to the assistant session browser

**Files:**
- Modify: `frontend/src/components/assistant/AssistantWorkspace.tsx`
- Modify: `frontend/src/components/assistant/AssistantSessionList.tsx`

**Step 1: Write the failing behavior check**

Use manual verification as the red step if no frontend tests exist:
- open AI Assistant
- confirm there is no search input and no pagination yet

**Step 2: Implement minimal UI**

Add:
- a search input
- previous/next pagination controls
- loading and empty results messaging
- page reset when search changes

Keep session detail loading behavior intact.

**Step 3: Verify behavior**

Run:
- `npm run lint`
- manual browser verification

Expected:
- searches by title work
- searches by log content work
- pagination navigates all sessions
- selecting a session still loads details

### Task 5: Final verification

**Files:**
- No additional files required

**Step 1: Run backend tests**

Run: `pytest backend/tests/unit/test_services/test_assistant_service.py backend/tests/unit/test_services/test_assistant_api.py -q`

**Step 2: Run frontend checks**

Run: `npm run lint`

**Step 3: Run end-to-end manual verification**

Check:
- empty search shows latest sessions
- title search narrows results
- content search finds sessions by entry text
- next/previous page works
- opening a result still loads the right report
