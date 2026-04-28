# Settings Page and API Health Design

## Goal

Add a new `/settings` page that gives operators one place to monitor external API quota health and control browser-local product preferences, starting with theme selection. The page should make silent rate-limit exhaustion visible without exposing secrets, and it should feel like a natural extension of the existing app shell.

## Scope

This design covers:

- a backend `GET /api/admin/api-health` endpoint
- quota normalization for VirusTotal, AbuseIPDB, and URLScan
- a new frontend `/settings` page
- browser-local preferences for theme and lightweight workspace options

This design does not include:

- user accounts or server-side settings persistence
- API key editing from the browser
- secret rotation workflows
- alerting, notifications, or long-term quota history storage

## Why This Matters

The platform depends on many third-party APIs. When those providers return quota headers or rate-limit responses, the operator currently has no dedicated place to see remaining credits or determine whether a failing or degraded investigation was caused by exhausted upstream capacity. A centralized health surface reduces blind spots and gives the operator an operational cockpit for the platform itself.

## Product Shape

The new settings page should include four sections:

### 1. Appearance

- Theme options: `dark`, `light`, `system`
- Default remains dark when no preference is stored
- Preference is stored only in the browser with `localStorage`
- `system` follows `prefers-color-scheme`

### 2. API Health

- Live status cards or rows for external providers
- Primary targets: VirusTotal, AbuseIPDB, URLScan
- Secondary rows for configured providers that do not expose useful remaining-quota data can still show `configured`, `not configured`, or `unsupported quota telemetry`
- Manual refresh control
- Optional periodic refresh while the page is open

### 3. Workspace

These are browser-local convenience settings that fit the current product without needing server-side storage:

- investigation detail auto-refresh enabled/disabled
- duplicate investigation warning enabled/disabled
- list density: `comfortable` or `compact`

### 4. System Info

- app version
- backend base target used by the frontend
- environment string when available
- last API-health refresh timestamp

## Backend Design

### Endpoint

Add `GET /api/admin/api-health`.

The route should be read-only and return normalized health objects rather than raw upstream payloads. It should not fail the entire response if one provider errors.

### Response Shape

The response should be shaped for direct UI rendering:

```json
{
  "providers": [
    {
      "provider": "virustotal",
      "display_name": "VirusTotal",
      "configured": true,
      "status": "healthy",
      "remaining": 430,
      "limit": 500,
      "unit": "requests/day",
      "reset_at": "2026-04-28T21:00:00Z",
      "low_quota_threshold": 50,
      "last_checked_at": "2026-04-28T10:15:00Z",
      "source": "response_headers",
      "error": null
    }
  ],
  "generated_at": "2026-04-28T10:15:00Z"
}
```

### Provider Status Vocabulary

Use a small normalized state machine:

- `healthy`
- `low_quota`
- `rate_limited`
- `unavailable`
- `not_configured`
- `unsupported`

The API should derive these statuses from available provider data rather than pushing header-specific logic into the UI.

### Health Collection Strategy

Implement a dedicated backend service that performs lightweight requests to each provider and extracts quota metadata from headers or credits fields. The service should:

- skip providers with missing keys and report `not_configured`
- catch provider-specific exceptions and report `unavailable`
- normalize numeric fields where possible
- mask secrets entirely
- avoid high-cost or mutating upstream actions

The endpoint should be able to return partial success if one provider fails.

### Quota Parsing

The code should normalize whatever each upstream exposes into:

- `remaining`
- `limit`
- `unit`
- `reset_at`
- `source`

If a provider does not expose one of those fields, return `null` for the unknown values and keep the record usable.

### Caching

Short-lived in-memory caching is appropriate here because settings traffic is user-driven and we do not need second-by-second precision. A cache window around 30 to 60 seconds will reduce repeated upstream calls when the page is refreshed or reopened.

## Frontend Design

### Routing and Navigation

Add a new `/settings` route and surface it in the header navigation. The page should use the established shell and current visual language, but broaden it to support both light and dark theme variables.

### Theme System

Introduce a small client-side theme controller at the layout level:

- store preference in `localStorage`
- resolve effective theme from preference plus system media query
- apply a stable attribute such as `data-theme="dark"` or `data-theme="light"` on the root element
- keep existing CSS variable usage intact by remapping tokens under each theme

This avoids a large component-by-component refactor because most of the app already relies on shared CSS variables.

### Settings UX

The settings page should feel operational rather than generic. Recommended UI:

- a compact hero with page title and short explanation
- section cards with strong labels and concise help text
- API provider tiles showing configured state, remaining quota, and refresh timestamp
- clearly colored status pills for `healthy`, `low quota`, `rate limited`, and `unavailable`

The page should remain fully usable if some providers are not configured.

### Browser-Local Preferences

Store a small JSON document in `localStorage`, for example:

```json
{
  "theme": "system",
  "investigationAutoRefresh": true,
  "duplicateCheckWarning": true,
  "listDensity": "comfortable"
}
```

The frontend should validate unknown or missing values and fall back safely.

## Error Handling

### Backend

- Never return raw provider exception text that could leak secrets or request details
- Return provider-local errors as plain user-safe messages
- Preserve other providers even if one request fails

### Frontend

- Show stale or partial API health data gracefully
- Display `not configured` and `unavailable` as first-class states rather than generic failures
- Keep theme controls functional even if the API-health request fails

## Testing Strategy

### Backend

- unit tests for provider normalization
- tests for missing-key behavior
- tests ensuring partial failures do not break the full response
- API route test for response schema and generated timestamp

### Frontend

- settings page rendering test
- theme preference persistence and restore test
- effective theme resolution test for `dark`, `light`, and `system`
- API-health client mapping test

## Rollout Notes

- Backward compatible with the rest of the product
- No schema changes required for preferences
- No secret exposure in the browser
- Default experience remains dark theme unless the browser-local preference changes it

## Open Follow-Ups

Possible later extensions that are intentionally out of scope for this first pass:

- quota trend history
- notification thresholds
- per-user server-side preferences once auth exists
- API key rotation and management UI
