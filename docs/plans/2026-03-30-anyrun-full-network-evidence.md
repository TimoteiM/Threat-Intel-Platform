# AnyRun Full Network Evidence Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Keep the AnyRun process graph noise-reduced while rendering full DNS, HTTP, connection, network threat, and IOC evidence in the UI.

**Architecture:** Leave the existing process relevance filter and backend-first graph behavior unchanged. Only remove UI-side truncation from the non-graph AnyRun evidence tables so analysts still get the filtered process graph plus complete network and IOC evidence.

**Tech Stack:** Next.js, React, TypeScript

---

### Task 1: Remove UI truncation from AnyRun evidence tables

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Inspect current AnyRun evidence mapping**

Confirm where DNS requests, connections, HTTP requests, network threats, and IOCs are sliced before rendering.

**Step 2: Remove row caps from non-graph evidence sections**

Update the evidence mappers so they use the full arrays from `behavior_details` and `raw.iocs` instead of truncating them with fixed `slice(...)` limits.

**Step 3: Keep process graph filtering unchanged**

Do not modify the graph builder or process relevance logic.

### Task 2: Verify the frontend change

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Run a fresh frontend build**

Run: `npm run build`

**Step 2: Confirm the build succeeds**

Use the build result as verification that the UI change compiles cleanly.
