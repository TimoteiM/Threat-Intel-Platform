# AI Assistant Integration Design

## Goal

Integrate the existing Cyber Security Assistant concept into the Threat Investigator platform as a first-class analyst workspace that supports two modes:

- Alert Analysis
- Complex Incident Correlation

The assistant must:

- work as a standalone top-level feature
- be launchable from existing investigations
- persist sessions and outputs in the platform database
- sanitize pasted analyst data before any GPT model call
- use the platform's configured OpenAI `gpt-5-mini` model instead of Claude

## Product Shape

This feature will be implemented as a native subsystem inside the current platform rather than as a separate mini-app.

There will be two user entry points:

1. A top-level `AI Assistant` page in the main navigation.
2. An investigation-linked launch path from existing investigation detail pages.

The assistant will have two operating modes:

1. `alert_analysis`
2. `incident_correlation`

These modes share persistence, sanitization, export, and GPT invocation infrastructure, but use different prompt templates and UI layouts.

## Architecture

### Backend

Introduce a dedicated assistant subsystem in the backend with:

- ORM models for assistant sessions and session entries
- API routes for CRUD, execution, linking to investigations, and export
- a sanitization service that runs server-side before GPT calls
- an assistant prompt service with separate prompt builders per mode
- an assistant execution service that calls OpenAI `gpt-5-mini`

This must remain separate from the current investigation analyst orchestrator because the assistant is prompt-driven and analyst-authored, while investigations are evidence-driven and parsed into a strict report schema.

### Frontend

Add a top-level `AI Assistant` page using the existing platform layout and UI language. The page will support:

- recent session history
- mode switching
- entry editing
- sanitization preview/summary
- persisted outputs
- export

Investigation pages will expose an `Open in AI Assistant` action that creates or reuses a linked assistant session and preloads investigation context into the assistant workspace.

## Data Model

### `assistant_sessions`

Purpose: persist the overall assistant workflow state.

Proposed fields:

- `id`
- `title`
- `mode`
- `status`
- `linked_investigation_id` nullable FK to `investigations.id`
- `source_type` (`manual` or `from_investigation`)
- `sanitization_summary_json`
- `result_json`
- `report_markdown`
- `error`
- `created_at`
- `updated_at`
- `completed_at`

### `assistant_entries`

Purpose: persist the analyst-provided content that feeds an assistant session.

Proposed fields:

- `id`
- `session_id` FK to `assistant_sessions.id`
- `entry_index`
- `entry_label`
- `raw_text`
- `sanitized_text`
- `token_map_json`
- `created_at`

Why separate entries:

- Alert Analysis uses one primary entry.
- Incident Correlation uses multiple entries.
- Per-entry token maps are required for sanitization auditability and deterministic restoration.

## API Design

New router: `backend/app/api/assistant.py`

Primary endpoints:

- `POST /api/assistant/sessions`
- `GET /api/assistant/sessions`
- `GET /api/assistant/sessions/{id}`
- `POST /api/assistant/sessions/{id}/entries`
- `POST /api/assistant/sessions/{id}/run`
- `GET /api/assistant/sessions/{id}/export`
- `POST /api/assistant/sessions/from-investigation/{investigation_id}`

Expected behaviors:

- Session creation stores mode, title, source type, optional linked investigation.
- Entry creation persists raw and sanitized forms.
- Run endpoint rebuilds sanitization server-side, then executes the GPT prompt and persists structured output.
- Investigation-linked creation preloads relevant evidence/report summaries into one or more assistant entries.

## Sanitization Design

Sanitization is mandatory and server-side.

Rules:

- raw analyst text may be stored internally
- raw analyst text must never be sent to GPT
- sanitized text is the only model input
- token replacement must be deterministic within a session

Initial entity classes to sanitize:

- email addresses
- IPv4 and IPv6 addresses
- usernames and account names
- SIDs
- internal hostnames and workstation names
- domains where appropriate
- ports, logon IDs, process IDs, account IDs
- local and UNC file paths
- obvious tenant or org identifiers

Output handling:

- store token map per entry
- store aggregate sanitization summary per session
- render analyst-facing output with restored values where safe for internal UI display

## Prompting and GPT Integration

Use the existing platform OpenAI configuration and `gpt-5-mini`.

Create a dedicated assistant service rather than reusing the current investigation response parser.

### Alert Analysis Prompt

Target output:

- concise event summary
- what happened
- notable entities
- likely risk or severity hint
- recommended next analyst actions

### Incident Correlation Prompt

Target output:

- executive summary
- timeline reconstruction
- attack chain analysis
- indicators of compromise
- affected assets/users
- root cause analysis
- remediation recommendations

The prompt should instruct GPT to treat the input as sanitized analyst data and to preserve correlation tokens consistently.

## Investigation Integration

Add an `Open in AI Assistant` action on investigation detail pages.

Behavior:

- create or reuse a linked assistant session
- preload summarized investigation evidence and/or report content into assistant entries
- allow analysts to add more pasted logs afterward

This should not mutate the investigation workflow. It is a parallel analyst-assistance feature.

## UI / UX

### Top-Level Assistant Page

Sections:

- mode switcher
- recent sessions list
- session title and status
- entry editor
- sanitization summary
- output panel
- export controls

### Alert Analysis View

- single main input area
- sanitization preview or summary before run
- concise result rendering

### Incident Correlation View

- optional incident title
- multiple log-entry cards
- add/remove entry actions
- structured report rendering

### Investigation-Linked Experience

- CTA on investigation page
- open assistant session seeded with investigation content
- preserve a clear indication that the session is linked to that investigation

## Error Handling

The assistant must clearly distinguish:

- validation errors
- empty content
- sanitization failures
- OpenAI call failures
- persistence failures

If sanitization fails, the run must fail closed rather than sending raw text to GPT.

## Testing Strategy

Backend tests:

- sanitization unit tests
- prompt builder tests for both modes
- session CRUD tests
- run endpoint tests with mocked OpenAI
- investigation-linking tests

Frontend tests:

- mode switch behavior
- entry add/remove/update
- session load and restore
- sanitization summary rendering
- investigation launch path

## Rollout Plan

Phase 1:

- database models
- API
- top-level assistant page
- GPT integration
- persistence

Phase 2:

- investigation-linked entry point
- preload from investigation evidence/report

Phase 3:

- richer exports
- search/filter in session history
- improved structured rendering if needed

## Non-Goals

Not in first implementation:

- replacing the core investigation analyst pipeline
- real-time collaborative editing
- external SIEM connectors
- streaming model output unless already trivial to support
