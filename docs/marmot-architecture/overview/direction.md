---
title: "Direction — Where We're Going"
created: 2026-04-19
tags: [marmot, overview, direction, conclusions]
status: overview
---

# Direction — Where We're Going

Consolidated conclusions from the April 2026 exploration — 7-crate spike, draft-ietf-mls-extensions-09 deep read, full MIP walk, architecture discussions on thick vs. thin protocol, reference-implementation patterns, and identity-scoped removal.

This is a snapshot of consensus. Major rework decisions are deliberately deferred until cost/benefit is clearer.

---

## What we've concluded (higher confidence)

### 1. Thick protocol with explicit interop/application boundary — embraced.
Cross-client feature parity is worth the protocol-evolution cost. Every future feature gets a conscious "protocol-level or client-level" decision at design time using the test in [`protocol-boundary.md`](./protocol-boundary.md).

### 2. Reference-implementation + multiple implementations + clients — the durable pattern.
Matches Bitcoin (Core + wallets) and Lightning (LND/LDK/Eclair/CLN + apps). Marmot is already on this path with MDK (Rust) + Marmot-TS (TypeScript). Marmot-TS has already surfaced real stress points MDK-alone missed — this principle works. Target at least one more independent implementation in the 12–24-month window.

### 3. The 7-crate target architecture — validated.
Spike exercised every boundary; each surfaced real design tension that belonged there. Cross-boundary types needed amendments (enumerated in spike-findings) but the *shape* is durable.

### 4. MLS Extensions Safe Framework as default for new customs.
Draft-09's Components + AppDataDictionary + SafeExportSecret + SafeAAD toolkit is the right architectural home for new protocol-level data going forward. Existing classical extensions don't need emergency migration. **Gated on backend library support** — OpenMLS's Safe framework status is an open question.

### 5. Custom proposal types stay outside the Safe framework.
The framework covers component data (persistent + ephemeral) but not custom proposal semantics. `IdentityRemove` (Marmot's first custom proposal type) will be a classical `ProposalType::Custom(u16)`.

### 6. `IdentityRemove` is Marmot's first needed custom proposal type.
Addresses the MIP-06 multi-device "leave all my devices" gap, admin-kicks-user-entirely races, and lost-device scenarios. Recommended shape: commit-time resolution, same-identity authorization, auto-commit by lowest-index-remaining non-target-identity member (the same race-avoidance pattern the spike developed for SelfRemove). Full design in [`../further-context/custom_extensions.md`](../further-context/custom_extensions.md) §7.

### 7. MIP-01 group image encryption stays Marmot-custom as-is.
Epoch-independent image key is a deliberate operational trade-off, not a flaw. MIP-04 per-file media encryption is different and is a Safe framework candidate.

---

## Directions we're leaning toward (needs more work)

### 1. The MIP structure itself may be wrong.
Per-feature MIPs cause scatter — landing one feature touches many MIPs. A better structure might be **reference docs for components, patterns, and primitives** with feature MIPs that reference them.

- Wire-format reference docs (per Nostr event kind, per extension, per proposal type).
- Pattern reference docs (`kind: 450` identity proof; SelfRemove auto-commit rule; gossip-inside-MLS pattern).
- Primitive reference docs (ComponentID namespace; exporter conventions; capability registry).
- Feature MIPs compose these building blocks — shorter, more focused.

**NOT a strict Bitcoin/BIP one-number-per-feature model** — overlap between features is too real. Needs a concrete pilot before committing.

### 2. `marmot_group_data` should eventually split into AppDataDictionary entries.
The monolithic 0xF2EE conflates identity, transport, admin, and message-lifecycle concerns. Each wants its own ComponentID and update frequency. Major migration; long-term.

### 3. MDK and whitenoise-rs need their own decomposition review.
Three postures worth naming — **evolution** (keep, land incremental changes from spike-findings), **refactor** (restructure around spike's crate boundaries, keep protocol as-is), **rebuild** (new protocol library built on Safe framework from day one). Honest read: phased approach. Not committed to any posture yet; deserves its own cost/benefit proposal.

---

## Open questions requiring investigation

- Does OpenMLS (or the MLS library Marmot-TS uses) support draft-09's Safe Extensions framework? If not, what's the upstream timeline?
- What does a component-based Marmot spec structure look like concretely? Which existing feature is the right pilot?
- What's the migration path for `marmot_group_data` split? How do groups transition?
- Should `IdentityRemove` be gated on multi-device being active, or available universally?
- Should the `kind: 450` identity proof pattern be elevated to a first-class Marmot primitive (a `MarmotNostrIdentityProof` reference doc) that multiple MIPs reference?

---

## Immediate next steps (concrete, near-term)

Each small enough to actually do, each produces an artifact that makes bigger decisions cheaper:

1. **Draft a spec-structure reorganization proposal.** Walk one existing feature (MIP-03 SelfRemove or MIP-06 multi-device) through a component-based structure. Decide whether to pilot.
2. **Investigate OpenMLS + Marmot-TS Safe framework support.** Gate for §1.4 above.
3. **Sketch `IdentityRemove` as a full MIP-sized design.** First concrete data point for how any new spec structure handles a new custom proposal.
4. **Start an MDK/whitenoise-rs decomposition exploration.** Categorize each item in spike-findings as evolution-compatible, refactor-required, or rebuild-only.

---

## The 10-year durability test

| Decision | Durability | Reasoning |
|---|---|---|
| Thick protocol with explicit interop/app boundary | **High** | Matches Bitcoin (15 yrs) + Lightning (7+ yrs). |
| Reference-impl + multi-impl + clients | **High** | Same pattern; already on this path. |
| 7-crate target architecture | **High** | Boundaries align with real concerns. |
| Safe framework as default for new customs | **Medium** | Contingent on MLS ecosystem and backend adoption. |
| `marmot_group_data` split | **Medium** | Architecturally clean; depends on Safe framework + migration will. |
| Component-based spec structure | **Unknown** | Novel for Marmot; needs piloting. |
| `IdentityRemove` as first custom proposal | **High** | Real gap; once shipped, stable. |

High-confidence decisions are about **shape** (thick protocol, reference-impl, crate boundaries). Lower-confidence decisions are about **ecosystem timing** (Safe framework adoption, migration windows). Commit to shape now; defer timing-dependent decisions until external work resolves.

---

## See also

- Full conclusions doc: [`../further-context/direction-and-conclusions.md`](../further-context/direction-and-conclusions.md)
- Spike empirical findings: [`../further-context/spike-findings.md`](../further-context/spike-findings.md)
- Raw spike log: [`../../learnings.md`](../../learnings.md)
