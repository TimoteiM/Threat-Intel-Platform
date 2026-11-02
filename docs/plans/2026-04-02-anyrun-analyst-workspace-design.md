# AnyRun Analyst Workspace Design

## Goal
Redesign the AnyRun advanced process modal into an analyst-oriented workspace that matches the structure, density, and detail level of the reference screenshots while preserving our own product branding.

## Approved Direction
- Keep our brand styling rather than copying ANY.RUN pixel-for-pixel.
- Reuse the existing `AnyRunInteractiveEvidence` modal instead of introducing a second analyst UI.
- Add a persistent process event summary rail that always shows all tracked event categories, including zero-count categories.
- Make the event summary interactive so analysts can move between event categories without losing process context.
- Keep the existing `View`, `Group`, and `Deep` modes, but make them sit inside a denser, more guided workspace.

## UX Structure

### Left rail
- Process list remains on the far left.
- Each process row still supports the current selection behavior.
- The rail should feel denser and more operational, with smaller spacing and stronger hierarchy.

### Main workspace
- Top header shows the selected process identity in a single operational line:
  - PID
  - executable name
  - image path when available
- Main content becomes a two-column analyst layout:
  - left column for process summary cards
  - right column for process timeline and detailed event content

### Summary cards
- Keep a `Threat Verdict` card with score and verdict wording.
- Split process details into compact cards:
  - process information
  - file information
  - command line
- Add an `Events` card that mirrors the reference structure:
  - `Modified files`
  - `Registry changes`
  - `Synchronization`
  - `HTTP requests`
  - `Connections`
  - `Network threats`
  - `Modules`
  - `Debug`
- Show every category even when the count is `0`.
- Clicking an event category should focus the event content area on that category.

## Behavioral Rules
- The selected process drives all summary cards, counters, timeline markings, and event details.
- `View` mode shows analyst summary information plus the event-category-driven content area.
- `Group` mode shows grouped event clusters, filtered by the selected event category when applicable.
- `Deep` mode shows event records with structured details, filtered by the selected event category when applicable.
- If a category has zero events, keep it visible in the counters and show an explicit empty-state message in the content area when selected.
- Event category selection should reset sensibly when switching to a process that does not have that event bucket populated.

## Data Mapping
- Use existing per-process `event_counts` and `events` payloads from the AnyRun backend.
- Prefer these counters for the visible event summary:
  - `modified_files`
  - `registry_changes`
  - `synchronization`
  - `http_requests`
  - `connections`
  - `network_threats`
  - `modules`
  - `debug`
- Reuse the current flattened/grouped event helpers so the redesign is mostly presentational plus category filtering.

## Non-goals
- No attempt to clone ANY.RUN branding or exact visual assets.
- No backend/schema change unless implementation reveals missing event metadata.
- No separate modal or route for analyst view.

## Verification
- The advanced process modal should visibly include the full events summary block with zero-count categories.
- Event category clicks should change the event content shown for the selected process.
- `View`, `Group`, and `Deep` should still work after the redesign.
- Frontend production build must pass.
