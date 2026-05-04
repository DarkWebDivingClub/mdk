---
title: "Direction & Conclusions — Landing the Spike + Custom Extensions Exploration"
created: 2026-04-19
updated: 2026-04-19
tags: [marmot, architecture, direction, conclusions]
status: reference (snapshot)
related:
  - [[spike-findings]]
  - [[custom_extensions]]
  - [[target-architecture]]
  - [[cgka-engine-design]]
---

# Direction & Conclusions

**What this doc is.** A landing artifact for the April 2026 exploration — a 7-crate implementation spike, a deep read of draft-ietf-mls-extensions-09, a full walk through all merged Marmot MIPs plus the MIP-06 PR, and a series of architecture discussions about thick vs. thin protocols, reference implementations, extension patterns, and identity-scoped removal.

This is a snapshot, not a migration plan. It captures what we've concluded, what we're leaning toward, and what's still open — with explicit honesty about the magnitude of the possible rework and the need to move slowly and carefully. The goal is a pattern that's durable for 10+ years. We're not taking that lightly.

Primary audience: the architecture team and anyone returning to this conversation after time away. Re-read this when the next major design decision comes up, before re-deriving the framing from scratch.

---

## 1. The shape of the work that got us here

- **Implementation spike** (7-crate Rust workspace, 4-terminal demo on `wss://relay.primal.net`). Built `cgka-engine`, `transport`, `mdk-spike`, `nostr-adapter`, `nostr-mls-peeler`, `whitenoise-core-spike`, `dm-cli`. Validated group creation, invite, application messages, MIP-03 SelfRemove, and MIP-03 capability rejection. Raw findings in `learnings.md`. Structured findings in `spike-findings.md`.
- **Spec deep read.** All merged MIPs (00, 01, 02, 03, 04, 05, EE), MIP-06 PR #44, and draft-ietf-mls-extensions-09 (including the new Safe Extensions framework). Exploration in `custom_extensions.md`.
- **Architecture discussions.** SelfRemove PublicMessage requirement, three-paths analysis for standard vs. custom SelfRemove, Safe framework teaching + terminology, identity-scoped removal design space, thick-vs-thin protocol framing, Bitcoin/Lightning comparison, Marmot-TS as a second independent implementation.

The collective output is what this doc consolidates.

---

## 2. What we've concluded (higher confidence)

### 2.1 Thick protocol is the right call.
Cross-client / cross-device feature parity is a stated Marmot goal (Nostr-native multi-client messaging, MIP-06 multi-device). That goal structurally forces application-level concerns down into the protocol: admin model, disappearing messages, media encryption, push-notification gossip, multi-device pairing. If only some clients implemented these, groups would break or behave inconsistently. **So we embrace it explicitly** — every future feature gets a conscious "protocol-level or client-level" decision at design time, not by reflex.

**The rule of thumb:** if inconsistent interpretation across clients would break the feature for members of the same group, it belongs in the protocol. Otherwise it can stay client-level.

### 2.2 Reference-implementation-plus-clients is the natural structure.
Matches the Bitcoin (Core + many wallets) and Lightning (LND/LDK/Eclair/CLN + client apps) pattern. Marmot's shape today — MDK as the protocol library, whitenoise-rs as the primary client — is already instance of this. **Continue in this direction**, including:

- **Multiple independent protocol implementations keep the spec honest.** MDK (Rust) and Marmot-TS (TypeScript) already demonstrate this — Marmot-TS has surfaced real stress points that MDK-alone wouldn't have caught. Continue investing in Marmot-TS parity. Target one more independent implementation (different language, different team) in the 12–24-month window.
- **Client differentiation happens above the protocol.** Custody model, UX, notification design, storage strategy, integrations — all client-level. Protocol compliance and feature semantics — protocol-level.
- **Marmot's blast radius is smaller than Bitcoin's.** A protocol mismatch in Marmot breaks one group, not the network. That gives us more room to iterate than Bitcoin/Lightning have — a real architectural advantage worth leveraging.

### 2.3 The crate-boundary decomposition from the spike holds.
The seven crates align with the target-architecture doc's component boundaries. Every cross-boundary interface surfaced real design tension that belonged there. **This shape is durable.** See `spike-findings.md` for the concrete list of data-type amendments each boundary needs.

### 2.4 Go forward with the MLS Extensions Safe Framework as Marmot's default.
Draft-ietf-mls-extensions-09 introduces the Safe Extensions framework (Components, AppDataDictionary, SafeExportSecret, SafeEncryptWithLabel, SafeSignWithLabel, SafeAAD, AppDataUpdate, AppEphemeral). **If we were starting Marmot fresh today, we would use the Safe framework as the base for most customizations.** For new subsystems going forward, it becomes the first-choice home. Existing custom extensions (`0xF2EE`, `0xF2EF`, `0xF2F0`) and existing MLS-Exporter labels don't need emergency migration, but new work should migrate toward the framework unless there's a concrete reason not to. See `custom_extensions.md` §5 for the framework in depth.

### 2.5 Custom proposal types stay outside the Safe framework.
The Safe framework covers component data (persistent and ephemeral) but does NOT cover custom proposal semantics. Any new Marmot proposal type (e.g., `IdentityRemove`) will be a classical `ProposalType::Custom(u16)` with Marmot-owned validation. Worth calling out because it's easy to conflate.

### 2.6 Marmot's first custom proposal type should be `IdentityRemove`.
The MIP-06 multi-device PR exposed a real UX gap: no way to remove all leaves of an identity atomically. Walking the full scenario space (`custom_extensions.md` §7) showed that a bundle of standard Remove proposals doesn't cover the cases cleanly — especially the race where a new leaf is added during removal. The recommended shape is a same-identity authorization carve-out on standard Remove + a new `IdentityRemove` proposal type, with the same race-avoidance pattern the spike implemented for SelfRemove.

### 2.7 MIP-01's group image encryption should NOT migrate to Safe framework.
The epoch-independence of the image key is a deliberate operational trade-off (don't re-encrypt-and-re-upload per epoch). Residual threat is former or current insiders — acceptable loss vs. the cost of re-derivation. This is correctly Marmot-custom as-is. MIP-04's per-file media encryption is different and IS a Safe-framework candidate.

---

## 3. Directions we're leaning toward (less certain, needs more work)

### 3.1 MIP structure itself may be wrong.
Per-feature MIPs (one MIP per numbered feature, Bitcoin/BIP-style) cause scattered changes: landing a new feature often requires edits across multiple MIPs, and the relationship between MIPs is implicit rather than explicit. The concrete pain point is that it's becoming hard to iterate on the spec because changes are fragmented.

**A direction worth exploring:** reorganize Marmot's spec around **reference docs for components, patterns, and primitives** — with feature MIPs that reference those. Specifically:

- Wire-format reference docs (per Nostr event kind, per MLS extension, per proposal type).
- Pattern reference docs (the `kind: 450` Nostr-identity-in-authenticated_data pattern; the SelfRemove auto-commit-by-lowest-index-remaining pattern; the gossip-inside-MLS pattern from MIP-05's 447/448/449).
- Primitive reference docs (the Marmot ComponentID namespace once we claim one; the exporter-derivation conventions; the capability registry).
- Feature MIPs that compose those building blocks — shorter, more focused, reference out rather than duplicate.

**This is NOT a strict Bitcoin/BIP one-number-per-feature model.** The overlap between features is too real — a feature often touches identity, transport, wire format, authorization, and capabilities simultaneously. One-MIP-per-feature fights that reality. A component-based spec structure matches how the work actually decomposes.

**Not decided.** Needs a concrete pilot (probably on one feature, possibly MIP-06 since it's still in PR) to see if the structure works before committing.

### 3.2 `marmot_group_data` should eventually split.
The monolithic 0xF2EE extension conflates four independent concerns:
- Display metadata (name, description, image)
- Nostr transport routing (nostr_group_id, relays)
- Admin authorization policy (admin_pubkeys)
- Message lifecycle policy (disappearing_message_secs)

Each has a different update frequency, a different stakeholder set, and different versioning needs. A clean target is splitting into multiple AppDataDictionary entries under the Safe framework, one ComponentID per concern. **But this is a major migration** requiring coordinated client rollout. Not short-term. Flagged as the long-term clean shape.

### 3.3 MDK and whitenoise-rs are large enough to warrant their own decomposition review.
Current codebases: MDK is ~66K LOC across 6 crates; whitenoise-rs is ~100K LOC in a single crate with 29 database modules. The spike demonstrated that the target architecture's 7-crate shape works at a small scale. The existing implementations have accreted beyond what the shape prescribes.

**Three postures worth naming explicitly:**

- **Evolution.** Keep MDK and whitenoise-rs. Land incremental changes from `spike-findings.md`. Adopt Safe framework for new features only. Lowest risk, slowest progress. Probably viable for 12+ months.
- **Refactor.** Restructure MDK and whitenoise-rs around the spike's crate boundaries but keep the protocol as-is. Addresses the "implementations are too large and coupled" complaint. Medium cost.
- **Rebuild.** New protocol library (possibly alongside MDK for a period) built on the Safe framework from day one, with the 7-crate shape and component-based spec structure internalized. Highest cost, cleanest outcome, longest timeline.

Honest read: a phased approach is probably right. **Evolution** for the spec reorg and incremental adoption. **Refactor** for MDK/whitenoise-rs along the spike's boundaries as we have capacity. **Rebuild** only if the refactor proves impossible — and even then, probably scoped per-subsystem rather than all-at-once.

No commitment to posture here. The user's explicit guidance was "go slowly and carefully." This is a decision that deserves its own focused exploration with clearer cost/benefit numbers than this doc can supply.

---

## 4. Major open questions

Things that need investigation before the directions above become commitments:

### Safe framework feasibility
- Does OpenMLS 0.8 (or later) support draft-09's Safe Extensions framework? If not, what does upstream adoption look like — timeline, scope, who contributes?
- Does Marmot-TS's underlying MLS library support it?
- If neither backend supports Safe Extensions yet, the "default new work to Safe framework" direction is blocked on upstream work. This is a hard gate.

### Spec reorganization
- What does a component-based Marmot spec structure actually look like? Draft proposal, not just sentiment.
- Which existing feature is the right pilot? MIP-06 is still in PR and might be malleable enough to try. Or maybe a smaller surface.
- How do we version component reference docs vs. feature MIPs? What's the coherence mechanism?

### Migration strategy
- If `marmot_group_data` splits into multiple AppDataDictionary entries, what's the migration path for existing groups? Simultaneous GroupContextExtensions update is technically possible but coordinationally expensive.
- If `IdentityRemove` ships, does it require all clients in a group to support it (and become a required capability) or can it be optional? Answer shapes the UX.

### Implementation reshape
- What's the sequencing of MDK/whitenoise-rs refactor work? Spike-findings.md has ~20 concrete amendments; which ones are load-bearing vs. cosmetic?
- Do we want a third independent implementation beyond MDK and Marmot-TS? Same language or different?

### Patterns worth formalizing
- Is the `kind: 450` Nostr-identity-in-authenticated_data pattern worth elevating to a first-class Marmot primitive (a `MarmotNostrIdentityProof` reference doc) that other MIPs can reference?
- The SelfRemove auto-commit-by-lowest-remaining pattern the spike developed — is it a Marmot protocol-level rule or a client-implementation convention?

---

## 5. Immediate next steps (concrete, near-term)

In priority order, small-enough-to-actually-do:

1. **Draft a spec-structure-reorganization proposal** as its own document. Not a migration plan — a proposal of what the shape would be. Walk through one existing feature (MIP-03 SelfRemove or MIP-06 multi-device) and show what it'd look like under a component-based structure. Then decide whether to pilot.
2. **Investigate OpenMLS + Marmot-TS Safe framework support.** Answer: "is Safe framework adoption blocked or available?" Write up findings. Gate for much of §2.4 becoming actionable.
3. **Sketch `IdentityRemove` as a full MIP-sized design.** Use §7 of `custom_extensions.md` as the starting point. Produces the first concrete data point for "what does a new MIP look like under any structure change we pilot?"
4. **Start a follow-up exploration on MDK/whitenoise-rs decomposition.** Take `spike-findings.md` §1 (the cross-boundary type amendments) and categorize each: evolution-compatible, refactor-required, rebuild-only. Produces the numerical cost/benefit for the posture-selection question in §3.3.

None of these commit to major rework. All of them produce artifacts that make the bigger decisions cheaper when they come up.

---

## 6. The 10-year durability test

The user's explicit frame: we want a pattern that lasts 10+ years. Checking the major decisions under that lens:

| Decision | Durability | Reasoning |
|---|---|---|
| Thick protocol with explicit interop/app boundary | **High** | Same pattern Bitcoin (15 years) and Lightning (7+ years) use successfully. |
| Reference implementation + multiple independent implementations + clients | **High** | Same pattern; Marmot is already on this path with MDK + Marmot-TS. |
| 7-crate target architecture | **High** | Boundaries align with genuine concerns that surfaced under implementation. |
| Safe framework as default for new customs | **Medium** | Contingent on MLS ecosystem adoption and backend library support. If the framework stalls in draft, this direction has to back off. |
| `marmot_group_data` split into components | **Medium** | Architecturally clean but depends on (a) Safe framework adoption and (b) willingness to do coordinated client migration. |
| Component-based spec structure | **Unknown** | Novel for Marmot, no direct 10-year precedent in this ecosystem. Need to pilot. |
| `IdentityRemove` as first custom proposal type | **High** | Addresses a real gap; once shipped, stable primitive. |

The highest-confidence decisions are about **shape** (thick protocol, reference-impl, crate boundaries) — these match proven patterns. The lower-confidence decisions are about **ecosystem timing** (Safe framework adoption, migration strategy) — these depend on external work we don't control.

**The correct move, given that asymmetry:** commit to the shape decisions now (they inform daily work). Defer the timing-dependent decisions until the external work resolves. Pilot the novel decisions (spec structure) on low-stakes features before committing broadly.

---

## 7. What this doc is NOT

- **Not a migration plan.** Migration decisions (whether to refactor MDK, whether to split `marmot_group_data`, whether to reorganize the spec) deserve their own focused proposals with cost/benefit analysis.
- **Not a commitment to rewrite anything.** We've explicitly identified that rework ranges from "evolve" to "refactor" to "rebuild"; no posture has been chosen.
- **Not exhaustive.** Individual topics (each MIP's per-subsystem analysis, the spike's implementation details, the full OpenMLS API pain points) live in their dedicated artifacts.
- **Not permanent.** This is a snapshot of consensus as of 2026-04-19. Re-read and update when major new information changes the framing.

---

## 8. Cross-references

Companion artifacts from this exploration:

- **[[spike-findings]]** — Concrete amendments to the target architecture driven by the implementation spike. Type-by-type, boundary-by-boundary. Use this as the punch list when working on MDK / whitenoise-rs changes.
- **[[custom_extensions]]** — The full custom-vs-inherit decision framework, per-MIP review, Safe Extensions framework teaching, and identity-scoped removal design space. Use this when designing any new Marmot primitive.
- **docs/learnings.md** — Raw chronological log of friction points from the spike. Source material for the distilled docs above.
- **[[target-architecture]]** — The pre-spike reference doc for Marmot's target component architecture. Still valid as reference; needs the updates enumerated in `spike-findings.md`.
- **[[cgka-engine-design]]** — Pre-spike reference for the CgkaEngine trait shape. Still valid as reference; needs the updates enumerated in `spike-findings.md`.

---

## 9. TL;DR

- **Thick protocol with explicit protocol-vs-application boundary per new feature** — embraced.
- **Reference-implementation + multiple independent implementations + clients** — already the pattern; keep investing (MDK, Marmot-TS, eventually a third).
- **7-crate target architecture** — validated by spike; cross-boundary types need the tightening enumerated in `spike-findings.md`.
- **MLS Extensions Safe Framework as default for new customs** — directionally committed, gated on backend support.
- **First custom proposal type: `IdentityRemove`** — addresses a real gap in the MIP-06 multi-device flow plus related identity-scoped cases.
- **MIP structure is probably wrong; component-based spec reorganization worth piloting** — not decided.
- **`marmot_group_data` eventually splits into AppDataDictionary entries** — clean target, major migration, not short-term.
- **MDK / whitenoise-rs decomposition posture (evolve / refactor / rebuild)** — not chosen; deserves a focused follow-up proposal.
- **Pattern is durable on the shape axis** (matches Bitcoin/Lightning). **Contingent on the timing axis** (Safe framework adoption, migration commitment).
- **Concrete next steps in §5** — small enough to do, each produces an artifact that makes the bigger decisions cheaper.
