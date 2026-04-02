# AnyRun Graph Backend-First Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the UI render the backend-filtered Any.Run process graph instead of rebuilding a noisy graph from raw process rows.

**Architecture:** Keep the backend `behavior_graph` as the source of truth for visible graph nodes and edges. Retain the existing frontend graph builder only as a fallback for older payloads that do not include `behavior_graph`, and make that fallback stricter so it does not refill the graph with medium-signal noise.

**Tech Stack:** Next.js, React, TypeScript, React Flow

---

### Task 1: Switch the graph component to backend-first rendering

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Add a backend graph normalizer**

Read `raw.behavior_graph.nodes` and `raw.behavior_graph.edges`, preserve the backend node `kind`, and build a `details` map only for process nodes.

**Step 2: Route graph rendering through the backend graph first**

Update `buildProcessTreeGraph` to return the normalized backend graph when available, and fall back to the legacy raw-process builder only when the backend graph is absent.

**Step 3: Tighten the legacy fallback**

Remove the fallback logic that pads the graph up to a large node cap with lower-value processes.

### Task 2: Keep UI interactions clean with backend graph nodes

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Preserve node kind in React Flow node data**

Pass the backend `kind` through to React Flow nodes so the UI can distinguish the analysis root from real process nodes.

**Step 2: Avoid opening empty details for analysis-only nodes**

Update node click handling so only process nodes populate the process details panel.

### Task 3: Verify the frontend change

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`
- Add: `docs/plans/2026-03-30-anyrun-graph-backend-first.md`

**Step 1: Run a fresh frontend build**

Run: `npm run build`

**Step 2: Restart the relevant app container if needed**

If the deployed frontend is containerized, restart the UI-serving container after the build-facing change is in place.
