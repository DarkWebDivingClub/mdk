---
title: "Marmot Architecture — Index"
created: 2026-04-15
updated: 2026-04-21
tags: [marmot, architecture, index]
---

# Marmot Architecture — Index

A clear-eyed technical reference for the Marmot stack — where it is today, where it's going, and why.

This wiki is organized in two tiers:

1. **`overview/`** — **short, one-page docs**. Each covers one theme. Read these first; these are the docs to share with a new engineer.
2. **`further-context/`** — **deep reference material**. Longer design docs, empirical spike findings, historical decision tracking, codebase surveys. Go here when you need depth on a topic, or when you're about to update the protocol itself.

---

## Start here — overview (one page each)

Written to be readable in 5 minutes each, shareable as a package.

| Doc | What it covers |
|---|---|
| [**`overview/executive-summary.md`**](./overview/executive-summary.md) | **The one-pager.** Problem, what we're optimizing for, what we're NOT optimizing for, target state. Share this with a new engineer. |
| [`overview/protocol-boundary.md`](./overview/protocol-boundary.md) | Where the line is between protocol and application. The test for putting new features on the correct side. |
| [`overview/target-architecture.md`](./overview/target-architecture.md) | The four components (CgkaEngine, TransportPeeler, TransportAdapter, application) and their trait boundaries. |
| [`overview/capability-negotiation.md`](./overview/capability-negotiation.md) | Why the capability system is load-bearing and what every client must implement. |
| [`overview/custom-extensions.md`](./overview/custom-extensions.md) | The inherit-vs-define decision framework. The MLS Safe Extensions framework (draft-09). |
| [`overview/nostr-role.md`](./overview/nostr-role.md) | Nostr's three distinct roles — identity, app message format, transport — and which are pluggable. |
| [`overview/current-state.md`](./overview/current-state.md) | Implementations (MDK, Marmot-TS, whitenoise-rs, spike), merged MIPs, known gaps. |
| [`overview/direction.md`](./overview/direction.md) | Where we're going. Conclusions from the April 2026 spike + spec exploration. |

**Read order for a new engineer:** executive-summary → protocol-boundary → target-architecture → capability-negotiation → nostr-role → custom-extensions → current-state → direction.

---

## Deeper reference — further-context

These are longer working documents. Go here when you need depth, not orientation.

### Protocol & architecture reference

| Doc | What it covers |
|---|---|
| [`further-context/target-architecture.md`](./further-context/target-architecture.md) | The full target architecture with Rust trait sketches, data flow diagrams, migration path. |
| [`further-context/cgka-engine-design.md`](./further-context/cgka-engine-design.md) | Detailed `CgkaEngine` trait design, internal subsystems, state machine enums, storage trait design, feature registry. |
| [`further-context/capability-negotiation.md`](./further-context/capability-negotiation.md) | Full capability negotiation design. The three queries, group creation, upgrade, admin action, MIP checklist. |
| [`further-context/nostr-role-in-marmot.md`](./further-context/nostr-role-in-marmot.md) | Deep version of Nostr's three roles. What's spec-stable and what's transport-specific. |
| [`further-context/custom_extensions.md`](./further-context/custom_extensions.md) | Full decision framework + per-MIP review + MLS Extensions Safe framework teaching + `IdentityRemove` design space. |

### Spike artifacts (April 2026)

| Doc | What it covers |
|---|---|
| [`further-context/direction-and-conclusions.md`](./further-context/direction-and-conclusions.md) | The landing document for the April 2026 exploration. Conclusions, directions, open questions, next steps, durability test. |
| [`further-context/spike-findings.md`](./further-context/spike-findings.md) | Concrete cross-boundary type amendments from the implementation spike. Task list for updating the target-architecture and cgka-engine-design docs. |
| [`../learnings.md`](../learnings.md) | Raw chronological log of spike friction points. Source material for spike-findings. |

### Current state — facts and analysis

| Doc | What it covers |
|---|---|
| [`further-context/codebase-survey.md`](./further-context/codebase-survey.md) | Raw metrics — LOC counts, dependency graphs, module structures. |
| [`further-context/whitenoise-rs-deep-dive.md`](./further-context/whitenoise-rs-deep-dive.md) | Detailed analysis of the whitenoise-rs client layer — major subsystems, known complexity hotspots, refactor plan. |

### Historical context

| Doc | What it covers |
|---|---|
| [`further-context/architectural-alternatives.md`](./further-context/architectural-alternatives.md) | The six architectural alternatives considered before landing on the target. Useful for understanding *why* the target looks the way it does. |
| [`further-context/decision-points.md`](./further-context/decision-points.md) | Seven key architectural decisions with explicit recommendations. Several marked ✅ resolved. |

### Principles (lives at `docs/` top level)

| Doc | What it covers |
|---|---|
| [`../required-features.md`](../required-features.md) | Full principles statement for what Marmot the protocol defines and what it doesn't. The long-form version of `overview/protocol-boundary.md`. |

---

## Current state vs. target state, at a glance

| Layer | Today | Target |
|---|---|---|
| Presentation | Flutter (whitenoise) | Unchanged |
| FFI bridge | flutter_rust_bridge | **whitenoise-ffi** — transport-agnostic, Dart + Swift |
| Application | whitenoise-rs singleton | **whitenoise-core** — thin facade, per-account sessions |
| Transport | Nostr relay control planes, embedded | `TransportAdapter` trait, `NostrAdapter` as first impl |
| CGKA Engine | MDK — monolithic, Nostr types in API | MDK implementing `CgkaEngine` trait, Nostr types removed from storage |
| Crypto | OpenMLS direct | OpenMLS behind `CgkaEngine` trait, swappable |
| Storage | `MdkStorageProvider` (good design) | Same + `CapabilityStorage` added, `Group` type de-Nostr-ified |

---

## Key decisions already made

- **PCS is non-negotiable.** Both FS and PCS required. Sender Keys off the table.
- **MLS stays.** BeeKEM and other CGKAs interesting but immature; `CgkaEngine` trait makes them swappable in future.
- **Transport is pluggable.** FIPS mesh and others are first-class future targets.
- **whitenoise-ffi, not whitenoise-frb.** FFI bridge outputs Swift bindings too.
- **Nostr has three distinct roles** — identity (always), app message format (always), transport (pluggable).
- **One capability per feature.** Flat feature registry, no dependency graph.
- **Progressive enhancement, not hard breaks.** Create the best group possible, upgrade gracefully, never block communication.
