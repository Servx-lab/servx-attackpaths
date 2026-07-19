# Attack Paths workspace specification

This page binds to [DESIGN.md](DESIGN.md). Every screen must read as the same product if placed side by side.

## Product goal

Give an authenticated repository owner a clear way to queue one evidence-backed scan, understand the work while it runs, and prioritize the resulting findings without mistaking the output for a guarantee of security.

## Layout

Use three distinct layout families, not repeating card grids:

1. **Command strip:** repository selector, one primary `Queue scan` action, daily allowance, and a compact security scope note. This is the only primary action on the idle screen.
2. **Evidence rail:** an asymmetric two-column running view. Left is a ruled vertical stage ledger. Right is the current stage, elapsed time, queue context, and a disclosure containing scanner coverage. On mobile it becomes one vertical sequence.
3. **Results desk:** a severity strip followed by a divider-based finding table. Selecting a finding opens its inline detail drawer on desktop and a full-width detail panel on mobile. Tool coverage uses a compact row list, not a card grid.

## Flow: Queue and follow a repository scan

**Goal:** queue a deep scan for a connected repository and understand its real-time state.

**User story:** as a repository owner, I want to see what is being scanned and what is still waiting so I can make an informed decision from the result.

**Entry points:** `/attack`, a post-remediation "Run another scan" action, and a persisted active job restored on refresh.

**Prerequisites:** authenticated session, GitHub connection, a repository returned from the authorized repository endpoint, remaining daily allowance, and no active job for the same repository.

```text
[Select owned repository]
          |
          v
[Queue scan] --> [Quota/permission error] --> [Explain and recover]
          |
          v
[Waking or queued] --> [Cancel] --> [Cancelled]
          |
          v
[Evidence rail with live stages]
          |
          v
[Completed results desk] --> [Inspect / copy / run another scan]
```

### State model

| State | Main content | Primary action | Recovery |
| --- | --- | --- | --- |
| Idle, no repository | Command strip with instruction | Disabled `Queue scan` | Select an owned repository |
| Idle, repository selected | Scope and coverage summary | `Queue scan` | Show quota before request |
| Warming | Evidence rail marks "Waking executor" | `Cancel scan` | Persist job and reconnect SSE |
| Queued | Evidence rail marks queue wait and position when available | `Cancel scan` | Explain serial free queue |
| Running | Evidence rail advances through clone, secrets, code, dependency/IaC, SBOM, report | `Cancel scan` | If stream drops, poll persisted job |
| Completed | Results desk | `Review findings` focuses table | Preserve job in URL/local state |
| Partial | Results desk plus coverage row explaining failed/skipped source | `Review findings` | Suggest rerun only after issue is fixed |
| No findings | Clear evidence summary and coverage row | `Run another scan` | State that this is not proof of safety |
| Failed/cancelled | Tight error panel with safe error and retry rule | `Run another scan` | Do not expose raw worker paths or tokens |
| Rate limited | Allowance panel | Disabled until next eligible time | Show server-provided retry time |

### Edge cases

- Refresh or close: restore active job ID from `sessionStorage` and reconnect to the SSE stream. Fall back to `GET /jobs/:id` if SSE ends.
- Session expiry: show a re-authentication message and retain the selected repository and job ID.
- Offline: announce the loss of connection, keep the persisted job, and offer reconnect.
- A second tab: server conflict response becomes "This repository already has an active scan" with a link to the active job.
- Long queue: show the exact current phase and queue position only when the server has it. Never invent an ETA.

## Component briefs

### ScanCommandStrip

Purpose: make the owned-repository choice and one deliberate scan action clear.

- Native button and listbox/combobox semantics. `aria-expanded`, `aria-controls`, and keyboard Arrow/Enter/Escape behavior are required for repository selection.
- Primary button is 44px minimum height, accent fill, disabled with explicit reason in adjacent text.
- Scope copy: "Connected repositories only. Live URL scanning is off." It is not a feature chip.
- Mobile: selector and button stack. Desktop: selector takes the widest column and the allowance sits at the trailing edge.

### EvidenceRail

Purpose: make slow serial execution informative.

- Fixed ordered stages: `Queued`, `Repository`, `Secrets`, `Code`, `Dependencies & IaC`, `Inventory`, `Report`.
- Each row has a left rule, status marker, stage label, short plain-language message, and optional elapsed duration.
- Current stage gets the accent rule. Completed stages use success. Partial/failed stage uses warning/danger but no pulsing animation.
- Include `role="status" aria-live="polite"` for the current stage message; throttle repeated announcements.
- Keyboard: the coverage disclosure uses a native button and `aria-expanded`.

### FindingTable and FindingDetail

Purpose: prioritize evidence and remediation without a wall of cards.

- Columns: severity, finding, source, location. Filter controls are secondary and limited to severity and source.
- Table rows are buttons only when a detail panel exists; otherwise use an adjacent action button. Keep semantic table structure.
- Detail includes title, severity, source, location, evidence summary, suggested fix, and copy action. Never render raw secret values.
- Mobile: source and location move beneath title. Selecting a row reveals the detail below it.

### CoverageList

Purpose: make the scanner boundary visible.

- One compact row per tool: name, `ran`/`skipped`/`failed`, count, and safe reason. Use text plus icon, never color alone.
- `failed` or `skipped` changes the page result to partial coverage and explains what was not assessed.

### CancelScanDialog

Purpose: prevent accidental cancellation while keeping control with the user.

- Native dialog or Radix Dialog. Focus moves to dialog heading, Escape closes, destructive confirmation remains a separate button.
- Explain: cancellation ends the queued/running job and discards temporary worker files. Prior findings remain accessible.

## Accessibility and responsive requirements

- All text and UI contrast follows `DESIGN.md`; focus indicator is a 2px accent outline with 2px offset.
- Full keyboard path: repository selector, queue button, coverage disclosure, filters, table rows, copy button, cancel dialog.
- Screen reader announcements cover scan created, stage change, completion, partial coverage, error, and cancellation.
- Respect reduced motion by replacing stage transition animation with an immediate state change.
- Touch targets are at least 44px. No hover-only information. Use responsive reflow at `lg`, not horizontal page scrolling.

## Backend contract additions

- `POST /jobs/:id/cancel` returns persisted `cancelled` job state.
- Job detail and SSE include `queuePosition`, `queueReason`, `executionLease`, `updatedAt`, and safe coverage status.
- A recovery endpoint/job reaper re-dispatches expired leases and fails stale, undispatchable work with a user-safe message.
- Callbacks include an execution lease ID so an old executor cannot overwrite a recovered job.

## Design Pre-Flight

- [x] Only locked tokens, one accent, one radius scale, one Lucide icon family, and one type pairing.
- [x] No banned fonts, purple glow, gradient text, cream canvas, equal-card grid, fake metrics, buzzwords, or em dash copy.
- [x] Signature evidence rail is specific to the scanning workflow and passes the counterfactual test.
- [x] Loading, empty, partial, error, cancellation, rate-limit, refresh, session-expiry, and offline states are specified.
- [x] Contrast ratios, focus, keyboard behavior, ARIA/live regions, reduced motion, and mobile touch targets are specified.
- [x] Three layout families are specified and only one primary action appears per state.
- [x] Self-critique: distinctiveness 3, hierarchy 4, consistency 4, accessibility 4, state coverage 4, copy 3, restraint 4, motion 3. Total 29/32. No axis is below 3.

## Build handoff

Target: `react-vite-tailwind-engineer`.

Design system: Radix primitives + Tailwind tokens. Use existing accessible primitives where installed and native semantic controls where they are not. Theme every control with `DESIGN.md`; do not hand-recreate a component system.

Implement exactly this spec. Theme the design system with our locked tokens; do not redesign or re-implement its components.

Acceptance criteria:

- [ ] `/attack` implements command strip, evidence rail, results desk, coverage list, and cancellation dialog.
- [ ] Refresh restores an active job and reconnects to persisted progress.
- [ ] All data comes from the authenticated ServX API; no executor URL, secret, raw artifact path, or credential is rendered.
- [ ] Desktop and mobile layouts meet the state and accessibility requirements above.
- [ ] The backend supplies cancellation, safe queue state, durable lease recovery, and callback lease validation.
