# All Cases Filters Design

**Date:** 2026-04-17

## Goal

Add two new filters to the `All Cases` page:

- a `Classification` filter
- a `Hide duplicates` filter that removes repeated investigations for the same investigated value and keeps only the newest case

The behavior must be correct across the full dataset, not just within the currently visible page.

## Current State

The `All Cases` page currently supports:

- state filtering
- debounced search by `domain`
- pagination

The frontend page lives in `frontend/src/app/investigations/page.tsx` and calls `listInvestigations(...)` from `frontend/src/lib/api.ts`.

The backend route is `GET /api/investigations` in `backend/app/api/investigations.py`, which currently accepts:

- `limit`
- `offset`
- `state`
- `search`
- `observable_type`

Filtering and counting are implemented in:

- `backend/app/services/investigation_service.py`
- `backend/app/db/repository.py`

Today, filtering happens before pagination, but only for the existing fields. There is no classification filter and no dedupe logic.

## Requirements

### Classification Filter

Allow the user to narrow the All Cases dataset by investigation classification:

- `all`
- `benign`
- `suspicious`
- `malicious`
- `inconclusive`

This filter must combine cleanly with:

- existing state filtering
- search
- pagination

### Hide Duplicates Filter

Allow the user to hide duplicate investigations for the same investigated value.

Duplicate identity means:

- same canonical value currently surfaced by the list endpoint as `domain`

That includes domain, URL, IP, and hash investigations so long as the list endpoint continues using `domain` as the primary investigated value field.

When duplicates are hidden:

- keep the newest matching case
- suppress older cases for the same investigated value
- total count and pagination must reflect the deduped dataset

## Recommended Approach

Implement both filters in the backend list endpoint before pagination.

### Why

This gives the cleanest user experience:

- page counts stay accurate
- visible counts stay accurate
- dedupe behavior is global, not page-local
- the frontend remains simple and mostly declarative

### Why Not Client-Side Dedupe

Client-side dedupe would only operate on the currently loaded page of cases. That would create confusing behavior where:

- duplicate rows disappear on one page but still exist elsewhere
- total counts do not match visible results
- page navigation becomes inconsistent

## Data Flow

1. User changes filters on `All Cases`
2. Frontend calls `listInvestigations(...)` with:
   - `state`
   - `search`
   - `classification`
   - `dedupe`
   - `limit`
   - `offset`
3. API route forwards those values to the service
4. Service forwards to the repository
5. Repository applies:
   - state filter
   - search filter
   - observable type filter if present
   - classification filter
   - dedupe if requested
6. Repository returns paginated items and a matching filtered total
7. Frontend renders the updated list, summary chips, and pagination controls

## Backend Design

### API

Extend `GET /api/investigations` with two optional query params:

- `classification: str | None = None`
- `dedupe: bool = False`

The response shape stays the same.

### Service

Extend:

- `InvestigationService.list_all(...)`
- `InvestigationService.count(...)`

to accept and pass through:

- `classification`
- `dedupe`

### Repository

Extend:

- `InvestigationRepository.list_all(...)`
- `InvestigationRepository.count(...)`

to support:

- filtering by `Investigation.classification`
- deduping by investigated value while keeping the newest row

### Dedupe Rule

The dedupe winner is:

1. newest `created_at`
2. if timestamps tie, stable fallback on id ordering

This avoids nondeterministic results.

### Query Strategy

Preferred implementation:

- build a shared base filtered query
- if dedupe is disabled:
  - behave like the current ordered query
- if dedupe is enabled:
  - compute one newest row per `domain`
  - paginate the deduped result
  - count the deduped result set separately

Exact SQLAlchemy mechanics can be chosen during implementation, but the behavior should be backend-first and deterministic.

## Frontend Design

### UI Changes

Add to `frontend/src/app/investigations/page.tsx`:

- classification filter control
- hide duplicates toggle

These should live in the existing `Search and filters` module so the query surface stays consolidated.

### Interaction Rules

When classification changes:

- reset page to `0`

When dedupe changes:

- reset page to `0`

The summary chips and helper text should reflect:

- active state filter
- active classification filter
- whether duplicates are hidden

### API Client

Extend `listInvestigations(...)` in `frontend/src/lib/api.ts` so it can send:

- `classification`
- `dedupe`

## Edge Cases

- Unknown classification values should safely return no matches rather than crash.
- Null or unset classifications should still be supported when `classification` filter is not active.
- Dedupe should happen after search/state/classification refinement so it reflects the user’s current narrowed scope.
- If a case has an empty investigated value, implementation should either:
  - treat it as its own value, or
  - exclude it from dedupe grouping fallback logic in a deterministic way

## Testing Strategy

### Backend

Add coverage for:

- classification-only filtering
- dedupe-only behavior
- combined state + classification + search + dedupe
- count matching deduped items
- tie-break behavior for same investigated value

### Frontend

Verify:

- query params are sent correctly
- page resets on filter changes
- active filter labels update correctly
- empty state still behaves correctly under the new filters

## Success Criteria

The feature is complete when:

- users can filter All Cases by classification
- users can hide duplicate investigated values globally
- totals and pagination match what is visible
- the current visual style of the All Cases page remains intact
