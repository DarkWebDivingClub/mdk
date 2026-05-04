---
title: "Current State — Implementations & Spec"
created: 2026-04-19
tags: [marmot, overview, current-state, implementations]
status: overview
---

# Current State — Implementations & Spec

Where Marmot is today (April 2026): a merged spec, two independent protocol implementations, one client reference implementation, and a recent spike that validated the target architecture.

---

## The spec

**Merged MIPs:**
- **MIP-00** — Credentials & KeyPackages (identity binding, kind 30443)
- **MIP-01** — Group Construction & `marmot_group_data` extension
- **MIP-02** — Welcomes (kind 1059 gift-wrap of kind 444 rumor)
- **MIP-03** — Group Messages (kind 445 outer wrap, SelfRemove per MLS Extensions draft)
- **MIP-04** — Encrypted Media (per-file keys via exporter-derived HKDF, Blossom storage)
- **MIP-05** — Push Notifications (MIP-optional, kinds 447/448/449 for token gossip)

**In PR:**
- **MIP-06** — Multi-Device Support (External Commit-based pairing, `marmot_multi_device` extension 0xF2F0, `encrypted_device_name` extension 0xF2EF, `kind: 450` identity proof pattern, `join_psk` via exporter)

**Concrete spec pain point:** changes to many features scatter across multiple MIPs. This is being rethought — see [`direction.md`](./direction.md).

---

## Protocol implementations

### MDK (Rust) — ~66K LOC across 6 crates
- `mdk-core` — MLS/Nostr integration, group ops, message processing
- `mdk-sqlite-storage` — SQLCipher-backed persistent storage
- `mdk-memory-storage` — in-memory storage for testing
- `mdk-storage-traits` — storage abstraction
- `mdk-uniffi` — FFI bindings (Swift/Kotlin/Python)
- `mdk-macros` — builder/setter proc macros

OpenMLS 0.8.1 under the hood. Wrapped with Nostr-aware API today (`process_message` takes `nostr::Event`); target is a Nostr-agnostic `CgkaEngine` trait.

### Marmot-TS (TypeScript)
Independent implementation of the Marmot protocol from scratch, written by a team member. Has already surfaced real stress points and spec ambiguities that MDK-alone would have missed silently. Continues to be invested in for protocol-hygiene purposes.

---

## Client reference implementation

### whitenoise-rs (~100K LOC Rust) + whitenoise (Flutter, 66K LOC Dart)
The primary Marmot client. whitenoise-rs wraps MDK with application concerns — account management, relay control plane, event processing, chat list, push notifications, scheduled tasks, database.

**Known architecture pain points:**
- Global singleton struct with ~25 fields — testing and scope ownership are both hard.
- 29 SQLx database modules with 45 sequential migrations.
- `handle_mls_message.rs` is 2,329 LOC and touches everything.
- Relay control plane migration in progress but incomplete — legacy and new paths coexist.
- Session-projection refactor landing in ~19 phases, decomposing the singleton.

---

## The April 2026 spike

Built a 7-crate Rust workspace (`cgka-engine`, `transport`, `mdk-spike`, `nostr-adapter`, `nostr-mls-peeler`, `whitenoise-core-spike`, `dm-cli`) implementing the target architecture end-to-end. Validated across 4 terminals on `wss://relay.primal.net`:

- Group creation with capability negotiation
- Invite (post-creation add)
- Application messages (kind 9 chat inside MLS)
- MIP-03 SelfRemove (spec-compliant via `leave_group_via_self_remove`, with auto-commit-by-lowest-index-remaining)
- Capability rejection (negative test: `DM_DROP_CAPS=selfremove` correctly refuses group creation/invite)

The 4-component architecture boundaries held. Cross-boundary types needed tightening (listed in spike-findings). See [`direction.md`](./direction.md) for the full findings and forward direction.

---

## Known large items (not in the spike)

- Relay control plane details (4 specialized planes, per-plane session management)
- Push notification token management (MIP-05, 3,632 LOC)
- Multi-step login flows (NIP-55 / Amber, 3,255 LOC)
- User search (5-tier async pipeline)
- Message aggregator (reactions, edits, delivery status)
- Encrypted media (MIP-04 implementation, 2,338 LOC in MDK)

Each of these will eventually get its own decomposition review under the target architecture.

---

## Known spec/implementation gaps

- **OpenMLS Safe Extensions framework support** — draft-09's Safe framework adoption is blocked on backend library support. Investigation needed.
- **`IdentityRemove` proposal type** — identified as Marmot's first needed custom proposal but not yet specified or implemented.
- **State machines** (`EpochState`, `WelcomeState`, `MemberState`) — in the design docs but not yet implemented in MDK.
- **Fork recovery** — `EpochState::Recovering { buffered_events }` is sketched but not built.
- **`marmot_group_data` split** — the long-term target of splitting this monolithic extension into multiple AppDataDictionary entries is not yet planned.

---

## See also

- Deep reference (codebase metrics): [`../further-context/codebase-survey.md`](../further-context/codebase-survey.md)
- Deep reference (whitenoise-rs analysis): [`../further-context/whitenoise-rs-deep-dive.md`](../further-context/whitenoise-rs-deep-dive.md)
- Spike findings + amendments: [`../further-context/spike-findings.md`](../further-context/spike-findings.md)
