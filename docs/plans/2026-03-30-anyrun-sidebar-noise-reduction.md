# AnyRun Sidebar Noise Reduction Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the AnyRun advanced process sidebar match the filtered graph more closely so common Windows processes stop dominating the "Relevant Processes" list.

**Architecture:** Keep the backend-first process graph and existing process relevance pruning intact. Tighten the sidebar's `view` mode to prefer only processes present in the rendered graph, and label low-signal ancestry/system context more clearly so analysts can distinguish context from suspicious execution.

**Tech Stack:** Next.js, React, TypeScript

---

### Task 1: Align sidebar process selection with rendered graph

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Identify the current sidebar filter**

Review the `relevantProcessListItems` logic and compare it with the graph pruning logic.

**Step 2: Tighten default sidebar membership**

Update `view` mode so it uses processes present in the rendered graph instead of broad threat/activity heuristics.

**Step 3: Preserve detail modes**

Keep `group` and `deep` modes usable, but base them on the tightened view list so they remain aligned with the graph.

### Task 2: Clarify context-only process labels

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Detect low-signal system-context processes**

Use existing process metadata such as name and relevance scores to distinguish suspicious processes from ancestry-only context.

**Step 2: Show a context label in the sidebar**

Add a short visible label for context-only processes so they no longer read as equally relevant as suspicious nodes.

### Task 3: Verify compilation

**Files:**
- Modify: `frontend/src/components/report/AnyRunInteractiveEvidence.tsx`

**Step 1: Run a fresh frontend build**

Run: `npm run build`

**Step 2: Confirm the build succeeds**

Use the build result as verification because this frontend workspace does not currently include a dedicated test harness for this component.
