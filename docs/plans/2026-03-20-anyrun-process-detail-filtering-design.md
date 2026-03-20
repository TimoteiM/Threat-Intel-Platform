# AnyRun Process Detail Filtering Design

## Goal
Make the AnyRun `More info` modal feel analyst-focused instead of dumping every process entry. The process list should adapt to the selected detail mode so analysts only see processes that have meaningful data for that mode.

## Approved behavior
- `View`: show a relevant-process list instead of the full raw process dump.
- `Group`: show only processes that have grouped event data.
- `Deep`: show only processes that have deep-detail event data.
- If `Group` or `Deep` has no matching processes, show an explicit empty sidebar note instead of falling back to the full list.

## Relevant-process definition for `View`
A process is relevant if any of these are true:
- it appears in the rendered process graph
- it has a non-zero threat score or AnyRun threat level
- it has flattened process events
- it has network, file, or MITRE activity indicators

This keeps the default process list aligned with what analysts actually inspect in the graph/detail panes and removes low-value Windows background noise.

## UI behavior
- The sidebar title/count updates based on the active mode.
- Switching modes re-filters the sidebar immediately.
- If the currently selected process is not present in the new filtered list, clear selection.
- Empty states:
  - `No processes have group details.`
  - `No processes have deep details.`

## Non-goals
- No new toggle for `all processes`.
- No change to the process graph layout itself.
- No backend/schema changes.

## Verification
- Manual verification in the AnyRun modal:
  - `View` shows a shorter relevant list
  - `Group` only shows processes with grouped data
  - `Deep` only shows processes with deep details
  - empty states appear when applicable
- Frontend production build must pass.
