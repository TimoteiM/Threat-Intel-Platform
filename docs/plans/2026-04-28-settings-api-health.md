# Settings Page and API Health Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a settings page with browser-local preferences and a backend API-health endpoint that exposes normalized quota status for key external providers.

**Architecture:** Add a small backend admin route backed by a provider-normalization service with short-lived caching, then add a frontend settings route, a client-side theme/preferences layer, and a typed API client for rendering provider health safely. Keep all secrets server-side and persist UI preferences only in `localStorage`.

**Tech Stack:** FastAPI, Pydantic settings/schemas, existing backend service pattern, Next.js App Router, TypeScript, global CSS variables, localStorage.

---

### Task 1: Map the backend contract

**Files:**
- Modify: `backend/app/models/schemas.py`
- Test: `backend/tests/unit/test_api/test_dashboard.py`
- Create: `backend/tests/unit/test_api/test_admin_api_health.py`

**Step 1: Write the failing schema-level tests**

Add tests that expect a normalized response object with:

- `providers`
- `generated_at`
- provider fields including `provider`, `display_name`, `configured`, `status`, `remaining`, `limit`, `unit`, `reset_at`, `low_quota_threshold`, `last_checked_at`, `source`, `error`

**Step 2: Run the tests to verify they fail**

Run: `pytest backend/tests/unit/test_api/test_admin_api_health.py -v`

Expected: failure because the schema or route does not exist yet.

**Step 3: Add minimal response models**

Create Pydantic models in `backend/app/models/schemas.py` for:

- `APIProviderHealth`
- `APIHealthResponse`

Use optional numeric/date fields where upstream data may be absent.

**Step 4: Run the test again**

Run: `pytest backend/tests/unit/test_api/test_admin_api_health.py -v`

Expected: schema-related failures move forward to missing service/route behavior.

**Step 5: Commit**

```bash
git add backend/app/models/schemas.py backend/tests/unit/test_api/test_admin_api_health.py
git commit -m "test: define api health response contract"
```

### Task 2: Build the API health service

**Files:**
- Create: `backend/app/services/api_health_service.py`
- Modify: `backend/app/config.py`
- Test: `backend/tests/unit/test_services/test_api_health_service.py`

**Step 1: Write the failing service tests**

Add tests for:

- missing key returns `not_configured`
- provider exception returns `unavailable`
- low remaining quota returns `low_quota`
- healthy provider returns normalized values
- unsupported telemetry returns `unsupported`
- cache returns the same normalized result within the TTL window

**Step 2: Run the tests to verify they fail**

Run: `pytest backend/tests/unit/test_services/test_api_health_service.py -v`

Expected: failure because the service does not exist.

**Step 3: Implement the minimal service**

Create `backend/app/services/api_health_service.py` with:

- one orchestration function to gather provider health
- provider-specific helpers for VirusTotal, AbuseIPDB, and URLScan
- a small in-memory cache keyed by provider name
- normalization into the schema created in Task 1

Prefer lightweight read-only requests and avoid surfacing raw upstream responses.

**Step 4: Add any small config constants if needed**

If a cache TTL or low-quota threshold needs configuration, add simple defaults in `backend/app/config.py` without over-designing.

**Step 5: Run the tests to verify they pass**

Run: `pytest backend/tests/unit/test_services/test_api_health_service.py -v`

Expected: PASS

**Step 6: Commit**

```bash
git add backend/app/services/api_health_service.py backend/app/config.py backend/tests/unit/test_services/test_api_health_service.py
git commit -m "feat: add api health service"
```

### Task 3: Expose the backend admin endpoint

**Files:**
- Create: `backend/app/api/admin.py`
- Modify: `backend/app/api/router.py`
- Test: `backend/tests/unit/test_api/test_admin_api_health.py`

**Step 1: Write the failing route test**

Add a route test that:

- calls `GET /api/admin/api-health`
- expects `200`
- asserts partial provider data is returned even if one provider is unavailable

**Step 2: Run the route test to verify it fails**

Run: `pytest backend/tests/unit/test_api/test_admin_api_health.py -v`

Expected: `404` or import failure.

**Step 3: Implement the route**

Create `backend/app/api/admin.py` with an `APIRouter` and the `GET /admin/api-health` endpoint that uses the service from Task 2 and returns the normalized response.

Wire the router in `backend/app/api/router.py`.

**Step 4: Run the route test to verify it passes**

Run: `pytest backend/tests/unit/test_api/test_admin_api_health.py -v`

Expected: PASS

**Step 5: Commit**

```bash
git add backend/app/api/admin.py backend/app/api/router.py backend/tests/unit/test_api/test_admin_api_health.py
git commit -m "feat: add admin api health endpoint"
```

### Task 4: Add frontend types and client access

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Modify: `frontend/src/lib/api.ts`
- Test: `frontend/src/lib/api.ts`

**Step 1: Add the failing type-driven usage expectation**

Create or prepare a small typed usage in the settings page or a colocated helper that expects:

- `APIProviderHealth`
- `APIHealthResponse`

**Step 2: Implement the shared frontend types**

Add TypeScript interfaces for the new endpoint response to `frontend/src/lib/types.ts`.

**Step 3: Implement the API client function**

Add `getAPIHealth()` to `frontend/src/lib/api.ts` targeting `/admin/api-health`.

**Step 4: Run typecheck**

Run: `npm run typecheck`

Expected: PASS or targeted failure only where the settings page has not yet been added.

**Step 5: Commit**

```bash
git add frontend/src/lib/types.ts frontend/src/lib/api.ts
git commit -m "feat: add frontend api health client"
```

### Task 5: Add browser-local preferences and theme resolution

**Files:**
- Modify: `frontend/src/app/layout.tsx`
- Modify: `frontend/src/styles/globals.css`
- Create: `frontend/src/components/settings/ThemeScript.tsx`
- Create: `frontend/src/components/settings/SettingsPreferencesProvider.tsx`
- Create: `frontend/src/lib/settings.ts`

**Step 1: Write the failing preference behavior check**

Define the expected behavior in code:

- default theme is dark
- stored theme overrides default
- `system` follows media preference
- invalid stored values fall back safely

**Step 2: Implement shared preference helpers**

Create `frontend/src/lib/settings.ts` with:

- storage key constants
- validation helpers
- default settings object

**Step 3: Implement early theme application**

Create `ThemeScript.tsx` that applies the effective theme before the app paints, using a root attribute such as `data-theme`.

Mount it from `frontend/src/app/layout.tsx`.

**Step 4: Implement the provider**

Create `SettingsPreferencesProvider.tsx` that:

- reads localStorage on the client
- exposes current settings
- updates storage and document theme when changed

Wrap the app body content in the provider via `layout.tsx`.

**Step 5: Add light-theme token overrides**

Extend `frontend/src/styles/globals.css` so the current dark token set remains default and a `[data-theme="light"]` override remaps the shared variables.

**Step 6: Run typecheck**

Run: `npm run typecheck`

Expected: PASS or failures only in the still-missing settings page.

**Step 7: Commit**

```bash
git add frontend/src/app/layout.tsx frontend/src/styles/globals.css frontend/src/components/settings/ThemeScript.tsx frontend/src/components/settings/SettingsPreferencesProvider.tsx frontend/src/lib/settings.ts
git commit -m "feat: add browser local theme preferences"
```

### Task 6: Build the settings page and wire navigation

**Files:**
- Create: `frontend/src/app/settings/page.tsx`
- Create: `frontend/src/components/settings/SettingsPageClient.tsx`
- Modify: `frontend/src/lib/constants.ts`
- Modify: `frontend/src/components/layout/Header.tsx`

**Step 1: Write the page in a failing state**

Create the route and render placeholder sections that expect:

- appearance controls
- API health data
- workspace toggles
- system info

**Step 2: Add the navigation entry**

Update `APP_NAV_LINKS` to include `/settings`, then confirm the header renders it using the existing nav loop.

**Step 3: Implement the settings UI**

Build the page with:

- theme segmented control
- API provider cards/table
- workspace toggles for auto-refresh, duplicate warnings, and list density
- system info summary

Use the current app shell visual language and avoid one-off tokens where shared variables are enough.

**Step 4: Hook the page to the preferences provider**

Read and write settings through the provider created in Task 5.

**Step 5: Fetch live API health**

Call `getAPIHealth()` from the client component, show loading/refresh states, and handle partial failures cleanly.

**Step 6: Run typecheck**

Run: `npm run typecheck`

Expected: PASS

**Step 7: Commit**

```bash
git add frontend/src/app/settings/page.tsx frontend/src/components/settings/SettingsPageClient.tsx frontend/src/lib/constants.ts frontend/src/components/layout/Header.tsx
git commit -m "feat: add settings page"
```

### Task 7: Apply workspace preferences where they matter

**Files:**
- Modify: `frontend/src/app/investigations/[id]/page.tsx`
- Modify: `frontend/src/app/investigations/page.tsx`
- Modify: `frontend/src/app/page.tsx`
- Modify: any small shared investigation list component if one exists after inspection

**Step 1: Write a targeted failing behavior expectation**

Define minimal expected behavior in code:

- duplicate warning can be disabled from settings
- investigation detail auto-refresh respects the browser-local setting
- list density class or styling responds to the chosen preference where practical

**Step 2: Implement the smallest useful integrations**

Use the preferences provider to:

- gate duplicate warning behavior on the home page
- gate investigation auto-refresh on the detail page
- apply compact versus comfortable density on the investigation list page if the page structure supports it without a large refactor

Do not force a broad UI redesign here. Integrate only where the settings are already meaningful.

**Step 3: Run typecheck**

Run: `npm run typecheck`

Expected: PASS

**Step 4: Commit**

```bash
git add frontend/src/app/investigations/[id]/page.tsx frontend/src/app/investigations/page.tsx frontend/src/app/page.tsx
git commit -m "feat: apply workspace settings"
```

### Task 8: Verify backend and frontend together

**Files:**
- No new files required

**Step 1: Run focused backend tests**

Run: `pytest backend/tests/unit/test_api/test_admin_api_health.py backend/tests/unit/test_services/test_api_health_service.py -v`

Expected: PASS

**Step 2: Run existing nearby backend tests for confidence**

Run: `pytest backend/tests/unit/test_api/test_dashboard.py backend/tests/unit/test_services/test_investigation_service_helpers.py -v`

Expected: PASS

**Step 3: Run frontend typecheck**

Run: `npm run typecheck`

Expected: PASS

**Step 4: Run frontend lint if available**

Run: `npm run lint`

Expected: PASS or a pre-existing known failure unrelated to this work.

**Step 5: Manual verification**

Check:

- `/settings` loads
- theme changes persist across refresh
- `system` reacts correctly when no explicit theme is stored
- API cards show `healthy`, `low quota`, `not configured`, and `unavailable` states correctly with mocked or real data
- header includes the new Settings navigation link

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add settings and api health dashboard"
```
