# Threat Analyst Console Design

**Date:** 2026-04-15

**Objective**

Redesign the entire application around the same visual language that made the OpenCTI Intelligence module feel premium, operational, and trustworthy. The end state should feel like a unified cyber investigation workspace rather than a mix of admin screens and ad hoc feature views.

## Design Direction

The application should adopt a `Threat Analyst Console` look and feel:

- dark, layered surfaces instead of flat panel stacks
- stronger visual hierarchy through hero sections, module headers, and signal blocks
- information-dense but readable layouts
- deliberate color semantics for severity, trust, status, and source quality
- consistent treatment of labels, verdicts, markings, and metadata through pills, chips, and compact cards

This is not a neon dashboard gimmick. The mood should be disciplined, sharp, and high-trust.

## Core Principles

### 1. Intelligence-first hierarchy

Pages should lead with the most important decision-supporting information, not raw fields or generic titles.

- Hero regions summarize what matters.
- Supporting modules explain why.
- Raw metadata and low-priority details move lower in the page.

### 2. Shared visual system

The redesign must come from reusable primitives, not one-off styling per screen.

- common tokens for background, panel, module, border, accent, muted text, severity colors
- consistent spacing scale
- consistent radii and shadow language
- reusable section headers, cards, stat blocks, pills, module shells, and console tables

### 3. Different intensity by surface type

Not every screen should be equally dramatic.

- Investigation, report, evidence, and assistant views can carry the fullest console treatment.
- Lists, forms, and maintenance screens should still match the system, but remain calmer and faster to scan.

### 4. Analyst readability over decorative styling

Every visual decision must make the interface easier to parse.

- stronger grouping
- better empty states
- clearer typography hierarchy
- fewer undifferentiated tables
- better handling for long IOCs, URLs, hashes, and STIX patterns

## Visual System

### Surfaces

The application should use four main surface layers:

- `bg-root`: application shell background
- `bg-panel`: standard page panel surface
- `bg-module`: higher-emphasis content module
- `bg-elevated`: highlighted stat, badge, or inset surface

These should be visually distinct but closely related, so the app feels cohesive.

### Typography

- Section eyebrows in uppercase with wide tracking
- Strong display headings for page and module titles
- Compact but readable body copy
- Monospace reserved for technical values: URLs, hashes, STIX IDs, patterns, IDs

### Color semantics

- Red for high-confidence malicious or urgent signals
- Amber for suspicious or cautionary signals
- Green for benign, healthy, or trusted
- Blue/cyan for intelligence, source, and supporting context
- Violet for CTI relationships and linked object context

### Components

The following primitives should become standard:

- page hero
- console module
- signal strip
- stat card
- metadata grid
- intelligence table
- chip/pill
- empty state panel
- timeline/report card
- severity badge

## Page-level Application

### Dashboard

The dashboard becomes mission control.

- Replace plain stat rows with signal cards and stronger prioritization.
- Charts should live inside consistent modules with better headings and legends.
- Surface risk, malicious trends, and activity more clearly.

### Investigations list

- Improve density and hierarchy for list rows/cards
- Better status, severity, and freshness signaling
- Stronger filtering and result framing

### Investigation detail

This becomes the flagship experience.

- Hero summary
- modular findings
- analyst console sections
- stronger evidence framing
- cleaner transitions between tabs and content groups

### Assistant

- The assistant result should feel like an analyst brief, not a raw markdown dump inside a box.
- Sanitization, generated report, and output states should use the same module system as investigations.

### Email investigations

- Keep the system consistent, but preserve usability for input-heavy flows.
- Forms should be calmer than evidence views.

### Supporting pages

Alerts, clients, batches, watchlists, and maintenance pages should receive:

- token consistency
- updated cards and tables
- better empty states
- less visual noise

They do not need the full “hero + signal strip + console module” intensity unless the content warrants it.

## Technical Approach

The implementation should proceed through shared frontend foundations:

1. Define or extend theme tokens in one place.
2. Introduce reusable console primitives.
3. Update page shells and layout rules.
4. Migrate feature surfaces screen by screen.
5. Remove duplicated inline styling where practical.

We should preserve the current app architecture and avoid introducing a separate design system dependency unless clearly necessary.

## Risks

- Large visual scope can drift without shared primitives.
- Inline-style-heavy components can become hard to standardize if migrated ad hoc.
- A full-app pass can accidentally reduce usability on form-heavy pages if the console treatment is over-applied.

## Success Criteria

- The app looks and feels like one product, not mixed generations of UI.
- Investigation/report/assistant surfaces visibly inherit the OpenCTI quality bar.
- Tables, cards, and page headers feel consistent across screens.
- Technical information is easier to scan.
- No regression in responsiveness or frontend type safety.
