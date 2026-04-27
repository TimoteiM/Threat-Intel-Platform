# Analyst Assistant New Log Analysis Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `New log analysis` action that clears the analyst assistant workspace after a completed or loaded run while keeping saved sessions in the left rail.

**Architecture:** Extend the assistant workspace component with a local reset action that clears the active session, title, and draft entries back to the initial alert-analysis state. Render the new action on the same row as `Create and Run`, aligned to the right, and only show it when a completed or loaded session is present.

**Tech Stack:** Next.js app router, React state hooks, TypeScript, inline component styles.

---

### Task 1: Reset assistant workspace state

**Files:**
- Modify: `frontend/src/components/assistant/AssistantWorkspace.tsx`

**Step 1: Define the desired reset behavior**

- Clear `activeSession`
- Clear `title`
- Reset `entries` to a single blank draft entry
- Reset `mode` to `alert_analysis`

**Step 2: Implement a small local reset helper**

- Add a `resetWorkspace()` function near the existing session handlers.
- Reuse `newEntry(0)` instead of duplicating draft-entry shape.

**Step 3: Reconnect loaded-session state to draft mode**

- Make sure clicking the reset action returns the result panel to the empty state because `activeSession` becomes `null`.

### Task 2: Add the new button to the run row

**Files:**
- Modify: `frontend/src/components/assistant/AssistantWorkspace.tsx`

**Step 1: Add the action**

- Render a `New log analysis` button in the same action row as `Create and Run`.
- Align it to the right side of the row.

**Step 2: Gate visibility**

- Show the button only when a session is loaded or a completed run exists.

**Step 3: Preserve existing run behavior**

- Keep `Create and Run` unchanged.
- Keep saved sessions visible in the left rail.

### Task 3: Verify the UI behavior

**Files:**
- Modify: `frontend/src/components/assistant/AssistantWorkspace.tsx`

**Step 1: Run frontend build**

Run: `docker compose build frontend`

Expected: successful Next.js production build.

**Step 2: Recreate the frontend container**

Run: `docker compose up -d --force-recreate frontend`

Expected: frontend restarts on the rebuilt image.

**Step 3: Smoke check**

Run: `Invoke-WebRequest http://localhost:3000`

Expected: `200`.
