# AnyRun Analyst Workspace Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Redesign the AnyRun advanced process modal into a branded analyst workspace with persistent event counters and category-driven process event detail views.

**Architecture:** Keep `frontend/src/components/report/AnyRunInteractiveEvidence.tsx` as the source of truth for the advanced AnyRun modal. Add small helper functions for event-category metadata and filtering, then restructure the modal layout to present summary cards, an events rail, and mode-specific detail panes without changing the upstream payload contract.

**Tech Stack:** Next.js, React, TypeScript, React Flow

---

### Task 1: Add event-category metadata and filtering helpers

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Add a small event-category model**

Create a typed list for:
- `modified_files`
- `registry_changes`
- `synchronization`
- `http_requests`
- `connections`
- `network_threats`
- `modules`
- `debug`

**Step 2: Add helpers for counts and rows**

Add helpers that:
- read the selected process `event_counts`
- read the selected process `events`
- build filtered grouped/deep rows for the active event category

**Step 3: Verify helper integration**

Run: `npm run build`
Expected: build completes without type errors introduced by the new helper types.

### Task 2: Restructure the advanced process workspace

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Add state for active event category**

Track the selected event category in React state and reset it sensibly on process change.

**Step 2: Replace the current table-like `View` pane**

Build the branded analyst layout with:
- process header
- threat verdict card
- process information card
- file information card
- command line card
- events summary card
- timeline panel

**Step 3: Keep grouped and deep modes inside the new shell**

Place the existing grouped and deep detail content inside the redesigned main panel so analysts can switch views without losing the summary cards and event counters.

**Step 4: Add empty states for zero-count categories**

When analysts click a category with no events, show a clear empty state rather than a blank panel.

### Task 3: Verify the redesign

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`
- Add: `docs/plans/2026-04-02-anyrun-analyst-workspace-design.md`
- Add: `docs/plans/2026-04-02-anyrun-analyst-workspace.md`

**Step 1: Run frontend production build**

Run: `npm run build`

**Step 2: Review resulting modal behavior manually**

Confirm:
- all event categories are visible in the events card
- zero-count categories remain visible
- category clicks drive the content pane
- `View`, `Group`, and `Deep` still function

**Step 3: Commit**

```bash
git add docs/plans/2026-04-02-anyrun-analyst-workspace-design.md docs/plans/2026-04-02-anyrun-analyst-workspace.md frontend/src/components/report/AnyRunInteractiveEvidence.tsx
git commit -m "feat: redesign anyrun analyst workspace"
```
