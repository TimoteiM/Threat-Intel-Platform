# Dagre Process Graph Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rebuild the ANY.RUN process graph fallback using Dagre so the graph is readable, left-to-right, and focused on the relevant attack chain.

**Architecture:** Extract graph shaping into a Dagre-based transformation pipeline inside the existing AnyRun React Flow component. Keep current process selection/details behavior, but replace manual layout with a relevance-filtered, grouped, automatically positioned graph.

**Tech Stack:** Next.js, React Flow, Dagre, TypeScript

---

### Task 1: Add the graph dependency

**Files:**
- Modify: `frontend/package.json`
- Modify: `frontend/package-lock.json`

**Step 1: Add `dagre`**

Install the dependency used for automatic graph layout.

**Step 2: Verify install state**

Run an install command that updates the lockfile consistently.

### Task 2: Rebuild the graph transformation pipeline

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Keep the current source-of-truth process extraction**

Continue deriving graph rows from `behavior_details.process_details` when the backend graph is insufficient.

**Step 2: Add relevance filtering**

Hide noisy system processes unless they are part of the preserved suspicious chain or entry ancestry.

**Step 3: Add repeated-process grouping**

Collapse repeated sibling/parallel processes into one node with a count in the label.

**Step 4: Apply Dagre layout**

Create a Dagre graph, set `rankdir="LR"`, assign node dimensions, compute positions, and feed those positions into React Flow nodes.

### Task 3: Refresh node and edge styling

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Entry-point styling**

Make the entry node visually distinct with cyan emphasis.

**Step 2: Suspicious chain styling**

Apply red-border node styling and highlighted edges for suspicious processes/chains.

**Step 3: Preserve interaction**

Keep click-to-details, fitView, zoom, and pan behavior.

### Task 4: Verify the graph render

**Files:**
- Test: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Build the frontend**

Run: `npm run build`

Expected: PASS

**Step 2: Rebuild the frontend container**

Run: `docker compose up -d --build frontend`

Expected: updated UI available on `http://localhost:3000`
