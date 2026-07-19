---
project: ServX Attack Paths
register: product
aesthetic_direction: technical / utilitarian
color_strategy: restrained
design_system: Radix primitives + Tailwind tokens
design_variance: 6
motion_intensity: 3
visual_density: 7
---

## Design Read

Calm operational evidence, not a theatrical security dashboard. The bet is that a user trusts a scanner when its work is legible, bounded, and specific.

## Signature

The **evidence rail** is the signature: a ruled vertical scan ledger whose stages move from queued work to reviewed evidence. It makes waiting useful and turns a dense technical process into a comprehensible audit trail.

The chosen technical/utilitarian direction fits a tool that asks users to make security decisions. It avoids generic dark "hacker" styling, neon gradients, floating glass cards, and decorative threat visuals. The counterfactual test passes because the evidence rail, compact source labels, and scan ledger arise from this repository-scanning workflow rather than a generic SaaS dashboard.

## Identity lock

Every screen must read as the same product if placed side by side.

## Color (locked)

| Role | OKLCH | Hex | Use | Contrast |
| --- | --- | --- | --- | --- |
| canvas | `oklch(0.975 0.006 210)` | `#F4F8F9` | Page background | N/A |
| surface | `oklch(0.997 0.003 210)` | `#FCFEFE` | Panels and popovers | N/A |
| elevated | `oklch(0.955 0.010 205)` | `#EDF4F5` | Active rows and table headers | N/A |
| ink | `oklch(0.235 0.027 225)` | `#17262D` | Primary text | 15.2:1 on surface |
| muted | `oklch(0.455 0.025 225)` | `#53656D` | Secondary text | 5.5:1 on surface |
| subtle | `oklch(0.610 0.018 225)` | `#839198` | Metadata and inactive marks | 3.2:1 on surface, never body text |
| border | `oklch(0.865 0.015 210)` | `#D4E0E3` | Rules and boundaries | 3.1:1 against surface |
| accent | `oklch(0.615 0.130 193)` | `#008E9A` | Primary action, selected state, evidence rail | 4.7:1 with white text |
| success | `oklch(0.500 0.100 155)` | `#16754B` | Completed and healthy state | 5.5:1 on surface |
| warning | `oklch(0.625 0.125 75)` | `#A05B00` | Warming, partial coverage | 4.8:1 on surface |
| danger | `oklch(0.510 0.150 28)` | `#B12926` | Critical and failed state | 5.4:1 on surface |
| info | `oklch(0.500 0.095 245)` | `#2867A5` | Queued and informational state | 5.4:1 on surface |

Use the canvas and surface for 90% of visual weight. Accent is limited to the single primary action, selected repository state, and evidence-rail progress. Semantic colors communicate state only.

## Type (locked)

| Role | Family | Use | Notes |
| --- | --- | --- | --- |
| display | `IBM Plex Sans`, `ui-sans-serif`, sans-serif | Page title and major result count | 600-700 weight, tracking no tighter than `-0.02em` |
| body | `IBM Plex Sans`, `ui-sans-serif`, sans-serif | Controls, finding titles, explanatory copy | 400-600 weight, 65-75ch max reading measure |
| utility | `IBM Plex Mono`, `ui-monospace`, monospace | Scan stages, IDs, paths, source labels, status | 500-600 weight, never paragraphs |

The humanist body face is paired with a utility mono face. Do not introduce another display, body, or icon family.

## Scales (locked)

- Spacing: `0, 4, 8, 12, 16, 20, 24, 32, 40, 48, 64` px.
- Radius: `4, 8, 12, 16, 9999` px. Panels use 12, controls use 8, badges use full.
- Elevation: only a 1px border by default. Use one soft `0 12px 32px rgb(23 38 45 / 0.08)` shadow for popovers and dialogs.
- Breakpoints: `sm 640`, `md 768`, `lg 1024`, `xl 1280`.
- Motion: `120ms`, `300ms`, `500ms`, `cubic-bezier(0.16, 1, 0.3, 1)`. Stage transitions use 300ms because the change confirms scan progress. No bounce, ambient movement, or decorative looping. Respect `prefers-reduced-motion`.
- Icons: Lucide only, 16px inside controls and 20px for section labels.

## Voice

Plain, calm, and specific. Say what the service is doing and what evidence it has. Use "Queue scan", "Cancel scan", "Review findings", "Partial coverage", and "Run another scan" consistently. Do not promise that a clean scan proves safety.

