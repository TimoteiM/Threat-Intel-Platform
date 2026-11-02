# AI Assistant Session Search Design

**Date:** 2026-03-22

## Goal

Add searchable, paginated session browsing to the AI Assistant so users can find sessions by title or by words contained in the session log content.

## User Experience

The current "Recent Sessions" sidebar only shows a small fixed list. We will turn it into a session browser with:

- A single search box above the session list.
- Search that matches both session titles and assistant entry `raw_text`.
- Pagination controls so the user can move through all sessions, not just the latest ones.
- Existing click-to-open behavior preserved.

The initial version uses one search input instead of separate advanced filters. This keeps the workflow fast and matches the user's request for broad lookup across title and log content. The API will still be structured so separate filters can be added later without reworking the data flow.

## Backend Design

Extend `GET /api/assistant/sessions` to accept:

- `search`: optional string
- `limit`: existing pagination size
- `offset`: existing pagination offset

The query will:

- Order by `assistant_sessions.created_at DESC`
- Filter by session title using case-insensitive partial match
- Filter by related `assistant_entries.raw_text` using case-insensitive partial match
- Use `DISTINCT` so sessions with multiple matching entries are returned once
- Return `total` alongside `items`, `limit`, and `offset`

The service layer will own this query so the route stays thin. The response format will align with the app's existing paginated APIs.

## Frontend Design

`AssistantWorkspace` will own the browser state:

- `searchTerm`
- debounced/applied query value
- `limit`
- `offset`
- `total`

It will reload sessions when the search or page changes. The list component stays presentation-focused and will receive:

- sessions
- active session id
- search box value/callback
- pagination metadata/callbacks
- loading/empty state

This keeps the fetch logic centralized and avoids mixing UI concerns into the list item rendering.

## Data Flow

1. User types into the search box.
2. Frontend requests `GET /api/assistant/sessions?search=...&limit=...&offset=...`.
3. Backend filters across titles and entry content, calculates total matches, and returns one page.
4. Frontend renders sessions plus page controls.
5. Selecting a session still loads the full detail view with `GET /api/assistant/sessions/{id}`.

## Edge Cases

- Empty search should return all sessions.
- Whitespace-only search should behave like empty search.
- Sessions without entries should still match by title.
- Content matches should work even when the matching text is not in the first entry.
- Pagination should reset to the first page when the search term changes.
- Empty results should render a clear "no sessions found" message instead of a blank panel.

## Testing

Backend:

- Service tests for title matches, entry-content matches, combined queries, and pagination totals.
- API route test updated to cover the `search` query parameter shape if needed.

Frontend:

- Component tests are optional if the repo already has a frontend test setup; otherwise verify through targeted manual checks.
- Manual verification should cover empty search, title search, content search, next/previous page behavior, and opening a result after searching.
