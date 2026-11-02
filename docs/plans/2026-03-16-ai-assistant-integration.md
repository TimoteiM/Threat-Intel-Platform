# AI Assistant Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a persisted GPT-5 mini powered AI Assistant with Alert Analysis and Incident Correlation modes, available both as a top-level tool and from investigation pages, with mandatory server-side sanitization.

**Architecture:** Introduce a dedicated assistant backend subsystem with new ORM models, API routes, sanitization and prompt services, then add a native Next.js assistant workspace plus investigation launch hooks. Keep it separate from the existing investigation analyst parser/orchestrator and reuse only the OpenAI configuration and shared platform UI patterns.

**Tech Stack:** FastAPI, SQLAlchemy, Alembic, Pydantic, Next.js App Router, React, TypeScript, OpenAI Responses API.

---

### Task 1: Add ORM models for assistant persistence

**Files:**
- Modify: `backend/app/models/database.py`
- Test: `backend/tests/test_assistant_models.py`

**Step 1: Write the failing model test**

Add tests that assert:

- `AssistantSession` and `AssistantEntry` tables can be created
- session has optional link to investigation
- entry belongs to session

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_models.py -v`

Expected: FAIL because models do not exist

**Step 3: Write minimal ORM implementation**

Add:

- `AssistantSession`
- `AssistantEntry`
- relationships from `Investigation` to assistant sessions

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_models.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/models/database.py backend/tests/test_assistant_models.py
git commit -m "feat: add assistant session persistence models"
```

### Task 2: Add Alembic migration for assistant tables

**Files:**
- Create: `backend/alembic/versions/009_add_ai_assistant_tables.py`
- Test: `backend/tests/test_assistant_migration_shape.py`

**Step 1: Write the failing migration-shape test**

Assert expected columns/indexes exist in migration metadata or after applying migration in test DB.

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_migration_shape.py -v`

Expected: FAIL because migration does not exist

**Step 3: Write migration**

Create tables, FK, indexes, timestamps, JSONB fields.

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_migration_shape.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/alembic/versions/009_add_ai_assistant_tables.py backend/tests/test_assistant_migration_shape.py
git commit -m "feat: add ai assistant database migration"
```

### Task 3: Add Pydantic schemas for assistant API

**Files:**
- Modify: `backend/app/models/schemas.py`
- Test: `backend/tests/test_assistant_schemas.py`

**Step 1: Write the failing schema test**

Cover:

- session create payload
- entry create payload
- run request payload
- read response shape

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_schemas.py -v`

Expected: FAIL because schemas do not exist

**Step 3: Implement schemas**

Add request/response models for:

- create session
- add/update entry
- run session
- session detail/list

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_schemas.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/models/schemas.py backend/tests/test_assistant_schemas.py
git commit -m "feat: add ai assistant api schemas"
```

### Task 4: Build deterministic sanitization service

**Files:**
- Create: `backend/app/services/assistant_sanitizer_service.py`
- Test: `backend/tests/test_assistant_sanitizer_service.py`

**Step 1: Write the failing sanitization tests**

Cover:

- IP replacement
- email replacement
- SID replacement
- username/account replacement
- deterministic token reuse within one session
- fail-closed behavior on sanitization errors

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_sanitizer_service.py -v`

Expected: FAIL because service does not exist

**Step 3: Implement the sanitization service**

Expose helpers to:

- sanitize one entry
- sanitize all session entries with shared token map
- generate sanitization summary
- restore tokens for internal display if needed

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_sanitizer_service.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/services/assistant_sanitizer_service.py backend/tests/test_assistant_sanitizer_service.py
git commit -m "feat: add assistant sanitization service"
```

### Task 5: Build assistant prompt service for both modes

**Files:**
- Create: `backend/app/services/assistant_prompt_service.py`
- Test: `backend/tests/test_assistant_prompt_service.py`

**Step 1: Write the failing prompt tests**

Cover:

- alert mode prompt contains sanitized content and required output sections
- incident mode prompt contains timeline/IoC/root-cause sections
- prompts never include raw unsanitized text

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_prompt_service.py -v`

Expected: FAIL because prompt service does not exist

**Step 3: Implement prompt builders**

Add:

- `build_alert_analysis_prompt(...)`
- `build_incident_correlation_prompt(...)`

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_prompt_service.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/services/assistant_prompt_service.py backend/tests/test_assistant_prompt_service.py
git commit -m "feat: add assistant prompt builders"
```

### Task 6: Build GPT execution service for assistant sessions

**Files:**
- Create: `backend/app/services/assistant_service.py`
- Test: `backend/tests/test_assistant_service.py`

**Step 1: Write the failing service tests**

Cover:

- alert mode run persists result
- incident mode run persists result
- raw text is not sent to prompt builder/OpenAI
- OpenAI failure sets session failed state and error

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_service.py -v`

Expected: FAIL because service does not exist

**Step 3: Implement assistant service**

Responsibilities:

- load session and entries
- sanitize server-side
- build mode prompt
- call OpenAI `gpt-5-mini`
- persist `result_json`, `report_markdown`, status, summary

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_service.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/services/assistant_service.py backend/tests/test_assistant_service.py
git commit -m "feat: add ai assistant execution service"
```

### Task 7: Add assistant API router

**Files:**
- Create: `backend/app/api/assistant.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/test_assistant_api.py`

**Step 1: Write the failing API tests**

Cover:

- create session
- add entries
- run session
- get session detail
- list sessions
- create from investigation

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_api.py -v`

Expected: FAIL because routes do not exist

**Step 3: Implement router and register it**

Add endpoints:

- `POST /api/assistant/sessions`
- `GET /api/assistant/sessions`
- `GET /api/assistant/sessions/{id}`
- `POST /api/assistant/sessions/{id}/entries`
- `POST /api/assistant/sessions/{id}/run`
- `GET /api/assistant/sessions/{id}/export`
- `POST /api/assistant/sessions/from-investigation/{investigation_id}`

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_api.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/api/assistant.py backend/app/main.py backend/tests/test_assistant_api.py
git commit -m "feat: add ai assistant api routes"
```

### Task 8: Add backend support for investigation-to-assistant preload

**Files:**
- Modify: `backend/app/services/assistant_service.py`
- Test: `backend/tests/test_assistant_investigation_link.py`

**Step 1: Write the failing preload tests**

Cover:

- linked session is created from investigation
- preloaded entry contains investigation-derived summary
- linked investigation id is persisted

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_investigation_link.py -v`

Expected: FAIL because preload logic is incomplete

**Step 3: Implement preload helpers**

Create one summarized assistant entry from:

- investigation executive summary if present
- fallback evidence summary if report absent

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_investigation_link.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/services/assistant_service.py backend/tests/test_assistant_investigation_link.py
git commit -m "feat: support assistant sessions linked to investigations"
```

### Task 9: Add frontend API client methods

**Files:**
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/lib/types.ts`
- Test: `frontend` existing typecheck

**Step 1: Add minimal failing type usage in the upcoming page/component work**

Reference missing types and methods so typecheck fails.

**Step 2: Run typecheck to verify it fails**

Run: `npm --prefix frontend run typecheck`

Expected: FAIL because assistant API types do not exist

**Step 3: Implement API client and types**

Add:

- session list/detail types
- create/run/add-entry payloads
- API functions for assistant endpoints

**Step 4: Run typecheck to verify it passes**

Run: `npm --prefix frontend run typecheck`

Expected: PASS for these additions

**Step 5: Commit**

```bash
git add frontend/src/lib/api.ts frontend/src/lib/types.ts
git commit -m "feat: add frontend ai assistant api client"
```

### Task 10: Build top-level AI Assistant page

**Files:**
- Create: `frontend/src/app/assistant/page.tsx`
- Create: `frontend/src/components/assistant/AssistantWorkspace.tsx`
- Create: `frontend/src/components/assistant/AssistantSessionList.tsx`
- Create: `frontend/src/components/assistant/AssistantEditor.tsx`
- Create: `frontend/src/components/assistant/AssistantResult.tsx`
- Modify: `frontend/src/components/layout/Header.tsx`

**Step 1: Write minimal rendering assertions if test framework exists, otherwise use typecheck-first**

At minimum verify:

- page renders
- both modes can be selected
- session list and editor compile

**Step 2: Run typecheck to verify it fails**

Run: `npm --prefix frontend run typecheck`

Expected: FAIL because page/components do not exist

**Step 3: Implement the page and components**

Requirements:

- top-level route `/assistant`
- recent sessions column
- mode switcher
- editor pane
- result pane
- export action

**Step 4: Run typecheck to verify it passes**

Run: `npm --prefix frontend run typecheck`

Expected: PASS

**Step 5: Commit**

```bash
git add frontend/src/app/assistant/page.tsx frontend/src/components/assistant frontend/src/components/layout/Header.tsx
git commit -m "feat: add top-level ai assistant workspace"
```

### Task 11: Add sanitization summary UX and mode-specific editors

**Files:**
- Modify: `frontend/src/components/assistant/AssistantEditor.tsx`
- Modify: `frontend/src/components/assistant/AssistantResult.tsx`

**Step 1: Add failing type/render expectations**

Expect:

- alert mode shows single input
- incident mode shows multiple entries
- sanitization summary appears before run

**Step 2: Run typecheck to verify it fails**

Run: `npm --prefix frontend run typecheck`

Expected: FAIL because components do not yet support these props/states

**Step 3: Implement mode-specific interaction**

Add:

- single-input alert flow
- multi-entry incident flow
- add/remove entry controls
- sanitization summary panel

**Step 4: Run typecheck to verify it passes**

Run: `npm --prefix frontend run typecheck`

Expected: PASS

**Step 5: Commit**

```bash
git add frontend/src/components/assistant/AssistantEditor.tsx frontend/src/components/assistant/AssistantResult.tsx
git commit -m "feat: add assistant mode editors and sanitization summary"
```

### Task 12: Add investigation launch integration

**Files:**
- Modify: `frontend/src/app/investigations/[id]/page.tsx`
- Modify: `frontend/src/lib/api.ts`

**Step 1: Add failing usage**

Reference an `Open in AI Assistant` action and linked session navigation.

**Step 2: Run typecheck to verify it fails**

Run: `npm --prefix frontend run typecheck`

Expected: FAIL because integration props/handlers do not exist

**Step 3: Implement investigation action**

Add:

- `Open in AI Assistant` button
- linked session creation/reuse call
- redirect to `/assistant?session=<id>`

**Step 4: Run typecheck to verify it passes**

Run: `npm --prefix frontend run typecheck`

Expected: PASS

**Step 5: Commit**

```bash
git add frontend/src/app/investigations/[id]/page.tsx frontend/src/lib/api.ts
git commit -m "feat: add investigation launch into ai assistant"
```

### Task 13: Add export support for assistant reports

**Files:**
- Modify: `backend/app/api/assistant.py`
- Modify: `frontend/src/components/assistant/AssistantResult.tsx`
- Test: `backend/tests/test_assistant_export.py`

**Step 1: Write the failing export test**

Assert export endpoint returns persisted markdown/text content for a session.

**Step 2: Run test to verify it fails**

Run: `pytest backend/tests/test_assistant_export.py -v`

Expected: FAIL because export behavior is incomplete

**Step 3: Implement export**

Return plain text or markdown response with filename.

**Step 4: Run test to verify it passes**

Run: `pytest backend/tests/test_assistant_export.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/api/assistant.py backend/tests/test_assistant_export.py frontend/src/components/assistant/AssistantResult.tsx
git commit -m "feat: add ai assistant report export"
```

### Task 14: Run full verification

**Files:**
- Verify only

**Step 1: Run backend assistant test set**

Run: `pytest backend/tests/test_assistant_* -v`

Expected: PASS

**Step 2: Run broader backend checks if needed**

Run: `pytest backend/tests -q`

Expected: PASS or known unrelated failures documented

**Step 3: Run frontend typecheck**

Run: `npm --prefix frontend run typecheck`

Expected: PASS

**Step 4: Run frontend build**

Run: `npm --prefix frontend run build`

Expected: PASS

**Step 5: Start services and smoke test**

Run:

```bash
docker compose build api frontend
docker compose up -d api worker frontend
```

Expected:

- `/assistant` loads
- creating/running a session works
- investigation-linked launch works

**Step 6: Commit final integration**

```bash
git add .
git commit -m "feat: integrate persisted ai assistant with gpt-5 mini"
```
