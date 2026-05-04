---
title: "Spike Findings — Concrete Amendments to the Target Architecture"
created: 2026-04-18
updated: 2026-04-18
tags: [marmot, architecture, spike, types, boundaries, findings]
status: reference
related:
  - [[target-architecture]]
  - [[cgka-engine-design]]
  - [[custom_extensions]]
---

# Spike Findings — Concrete Amendments to the Target Architecture

**What this doc is.** A structured record of what a 7-crate implementation spike of the target architecture revealed. The spike built `cgka-engine` / `transport` / `mdk-spike` / `nostr-adapter` / `nostr-mls-peeler` / `whitenoise-core-spike` / `dm-cli`, connected three and then four terminals on `wss://relay.primal.net`, and validated group creation, invite, send, SelfRemove (per MIP-03), and capability-negotiation rejection. The raw chronological log is in `docs/learnings.md`; this doc is the distilled version organized for doc updates.

**Verdict, up front.** The crate-boundary design is right. The *shape of components* is right. What the target-architecture doc under-specifies is the **shape of data crossing those boundaries** — every cross-boundary type needed revision during implementation. This is the dominant pattern of findings.

This doc is organized so it can be used as a task list for updating `target-architecture.md` and `cgka-engine-design.md`.

---

## 1. Types crossing crate boundaries — revisions required

Each of these types is defined in the target architecture doc. Every single one needed revision during implementation. Listed in descending order of how load-bearing the revision is.

### 1.1 `TransportMessage` is missing a routing discriminator

**Doc today** (`target-architecture.md` §"The TransportMessage Type"):
```rust
struct TransportMessage {
    id: MessageId,
    payload: Vec<u8>,
    timestamp: Timestamp,
    causal_deps: Vec<MessageId>,
    source: TransportSource,
}
```

**Problem.** The coordinator cannot route an inbound `TransportMessage` without first knowing whether it's a group message or a welcome, and for group messages it needs the target group identifier. But routing must happen **before** peeling (to pick which peel path to use and which group's context to supply). The doc's "intentionally minimal" type provides nothing to route on.

**Required shape:**
```rust
struct TransportMessage {
    id: MessageId,
    payload: Vec<u8>,
    timestamp: Timestamp,
    causal_deps: Vec<MessageId>,
    source: TransportSource,
    envelope: TransportEnvelope,           // NEW
}

enum TransportEnvelope {
    /// Group message. `transport_group_id` is the transport-visible group ID
    /// (e.g. Nostr `h`-tag value = nostr_group_id from NostrTransportData).
    GroupMessage { transport_group_id: Vec<u8> },
    /// Welcome addressed to a specific member.
    Welcome { recipient: MemberId },
}
```

**Why this is not a spike shortcut.** Any transport needs to distinguish "for the group" vs "addressed to me individually" at the outer envelope. FIPS will have the same shape. The discriminator belongs in the common type.

### 1.2 `SendResult::GroupEvolution` forgets welcomes

**Doc today:**
```rust
enum SendResult {
    ApplicationMessage { msg: TransportMessage },
    GroupEvolution {
        msg: TransportMessage,
        pending: PendingStateRef,
    },
}
```

**Problem.** Any commit that adds members produces one commit plus N welcomes, wrapped with different keys (exporter-secret for the commit, recipient-pubkey NIP-44 for the welcomes in the Nostr case). A single `msg` field is structurally insufficient. The application layer must publish all outputs before calling `confirm_published`.

**Required shape:**
```rust
GroupEvolution {
    msg: TransportMessage,
    welcomes: Vec<TransportMessage>,       // NEW
    pending: PendingStateRef,
}
```

### 1.3 `TransportPeeler` single `peel`/`wrap` pair is wrong for real transports

**Doc today** (`target-architecture.md` §"The TransportPeeler"):
```rust
trait TransportPeeler {
    fn peel(&self, msg: TransportMessage, ctx: &dyn GroupContext) -> Result<PeeledMessage>;
    fn wrap(&self, payload: EncryptedPayload, ctx: &dyn GroupContext) -> Result<TransportMessage>;
}
```

**Problem.** Nostr welcomes (kind 1059 gift-wrap, recipient pubkey, NIP-44) and Nostr group messages (kind 445, exporter secret, ChaCha20Poly1305) are **structurally different operations with different keys and different addressing**. Pretending they're one function with a branching interior made the peeler harder to test, not easier.

**Required shape:**
```rust
trait TransportPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,         // NB: value type, see 1.4
    ) -> Result<PeeledMessage, PeelerError>;

    async fn peel_welcome(
        &self,
        msg: &TransportMessage,
    ) -> Result<PeeledMessage, PeelerError>;

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError>;

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError>;
}
```

**Async is required** — `nostr-sdk` 0.44 made `EventBuilder::sign`, `EventBuilder::gift_wrap`, and `nip59::extract_rumor` async (for hardware-signer support), which forces any trait using them to be async.

### 1.4 `&dyn GroupContext` doesn't survive `#[async_trait]` + isn't needed

**Doc today.** `TransportPeeler` methods take `ctx: &dyn GroupContext`.

**Problem.** With `#[async_trait]`, passing `ctx: &dyn GroupContext` across await boundaries triggers lifetime mismatches (`E0195`): async-trait's lifetime elision clashes with trait-object default lifetimes. More importantly: **the peeler doesn't need a live callback — it just needs values.** A snapshot is more honest than a handle.

**Required shape.** Introduce a value type and make the peeler take it:
```rust
pub struct GroupContextSnapshot {
    pub exporter_secrets: HashMap<String, [u8; 32]>,
    pub epoch: EpochId,
    pub transport_group_id: Option<Vec<u8>>,
}

impl GroupContextSnapshot {
    pub fn from_context(ctx: &dyn GroupContext, labels: &[&str]) -> Self { ... }
    pub fn exporter_secret(&self, label: &str) -> Option<[u8; 32]> { ... }
}
```

The engine materialises the snapshot per peeler call. `GroupContext` (the trait) stays as the engine's **internal** abstraction — it just shouldn't cross the peeler interface.

**Free benefit.** The `labels: &[&str]` argument lets the engine decide which secrets a given peeler is allowed to see. Per-peeler secret isolation comes for free.

### 1.5 `CgkaEngine::ingest` needs a typed result — `IngestOutcome`

**Doc today:**
```rust
fn ingest(&mut self, msg: TransportMessage) -> Result<()>;
```

**Problem.** `ingest` has multiple legitimately-silent outcomes — duplicate MessageId, welcome not addressed to us, commit-echoed-by-relay-after-welcome-already-advanced-us, own-commit echo, unknown-group. In the spike these were initially all either `Ok(())` (silent but structure-less) or `Err(EngineError::Backend(String))` with stringly-typed internals. The wiring layer had no way to distinguish "dedupe-worthy" from "genuine failure" without regex.

**Required shape:**
```rust
fn ingest(&mut self, msg: TransportMessage) -> Result<IngestOutcome, EngineError>;

enum IngestOutcome {
    Processed,
    Stale { reason: StaleReason },
}

enum StaleReason {
    AlreadySeen,
    AlreadyAtEpoch { current: EpochId, msg_epoch: EpochId },
    NotForThisClient,
    UnknownGroup,
    OwnEcho,
    // Add as more classes surface
}
```

The wiring layer logs `Stale` at debug (cheap noise), `Err` at warn (real problem). `Processed` is silent.

### 1.6 `EngineError` needs typed capability-rejection variant

**Doc today.** Implicit. The spike used `EngineError::Other(String)`.

**Problem.** Capability rejection produces a structured error with named required-vs-had sets. This is exactly the kind of error the UI wants to render directly — not regex-parse.

**Required shape:**
```rust
enum EngineError {
    // ... existing
    MissingRequiredCapabilities {
        required: GroupCapabilities,
        had: GroupCapabilities,
    },
    // ... existing
}
```

### 1.7 Engine-emitted side-effect transport messages — `drain_auto_publish`

**Doc today.** Not named.

**Problem.** Sometimes processing an inbound message produces an outbound one. Concrete case: a received SelfRemove proposal triggers an auto-commit from the lowest-index remaining member (per MIP-03 §142 + race-avoidance). The engine has to emit a `TransportMessage` that wasn't triggered by a `SendIntent`. The wiring layer needs a way to pull these out and publish them.

**Required shape:**
```rust
trait CgkaEngine {
    // ... existing
    fn drain_auto_publish(&mut self) -> Vec<TransportMessage>;
}
```

Fold into `SendResult`? No — these aren't tied to a send call. They're produced mid-ingest. A separate drain method is the right factoring.

---

## 2. Behaviors not yet in the design — must be added

### 2.1 State machines (the biggest gap)

The `cgka-engine-design.md` doc specifies three explicit-enum state machines: `EpochState`, `WelcomeState`, `MemberState`. **None were implemented in the spike.** The doc calls these out as "rustls-style state-machine-as-enum" — illegal state transitions become compile errors rather than runtime `if/match` checks.

What exists today in the spike:
- A `HashMap<PendingStateRef, PendingOp>` loosely tracking outbound pending operations. Covers some of what `EpochState::PendingPublish` would, but not the invariant that `process_message` cannot be called during `PendingPublish`, and nothing for `Recovering { buffered_events }`.

What this costs us (today, in the spike):
- Commit races cannot be recovered from — forked epochs silently fail. Spike dodges this via a "lowest-index auto-committer" hack for SelfRemove.
- `WrongEpoch` on welcome-echo is caught **after the fact** in `ingest`. A state machine would make it structurally impossible to try.
- Out-of-order commits during a fork have no buffering path.

**Required work.** Implement `EpochState`, at minimum:
```rust
enum EpochState {
    Stable { epoch: EpochId },
    PendingPublish { epoch: EpochId, pending: StagedCommit, pending_ref: PendingStateRef },
    Merging { epoch: EpochId },
    Recovering { last_stable_epoch: EpochId, buffered_events: Vec<PeeledMessage> },
}
```

`WelcomeState` is low-value for Marmot in the short term (welcomes auto-accept; no "pending welcome awaiting user decision" UI case today). `MemberState` is mostly redundant with MLS's own tracking.

### 2.2 Opinionated defaults over OpenMLS

OpenMLS is unopinionated — it gives raw primitives. The CgkaEngine trait must supply the opinions that Marmot requires. The doc hints at this; concrete instances from the spike:

- `MlsGroup::leave_group()` (legacy Remove-self proposal) vs `MlsGroup::leave_group_via_self_remove()` (spec-compliant). The default is wrong for Marmot. **The engine must only expose `leave()`, mapped to the correct OpenMLS call.**
- Admin-cannot-self-remove (MIP-03 §149) — Marmot-layer check, must be enforced before the engine calls the MLS function.
- Admin-depletion-before-commit (MIP-03 §150) — Marmot-layer check before merging.
- Remove-beats-SelfRemove (MIP-03 §151) — validation rule.
- Wire-format policy that MIP-03 requires — see §3.1 below.

**Recommended doc addition.** A new section in `cgka-engine-design.md` titled "Opinionated defaults — where the engine disagrees with its backend" listing each of these and the OpenMLS behaviour they override.

### 2.3 Coordinator still a no-op

The target-arch doc describes the coordinator as doing deterministic ordering within a time window + dedupe. The spike implements only MessageId dedupe. No reordering, no time-window buffering, no fork handling. This is fine for the spike's happy path but is not the target.

---

## 3. OpenMLS constraints to surface explicitly

These are ecosystem issues, not doc issues. But they need to be documented somewhere so implementers don't hit them cold.

### 3.1 Wire-format policy has no mixed-outgoing option

MIP-03 requires `SelfRemove` proposals to be PublicMessage. OpenMLS 0.8 enforces this: `leave_group_via_self_remove` rejects groups with `OutgoingWireFormatPolicy::AlwaysCiphertext`. But OpenMLS 0.8 offers only `AlwaysPlaintext` or `AlwaysCiphertext` outgoing — **no mixed policy** that would allow PublicMessage for SelfRemove proposals and PrivateMessage for app messages.

**Spike's choice.** `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` for the entire group. The kind-445 transport wrap (ChaCha20Poly1305 keyed by exporter secret) still provides network-level encryption, so the MLS-layer PublicMessage doesn't leak anything to the relay.

**For real Marmot, three options:**
1. Accept pure-plaintext at the MLS layer (spike's choice; architecturally fine if kind-445 wrap is the trust boundary anyway).
2. Patch OpenMLS upstream to allow mixed outgoing. Well-motivated; the patch is narrow.
3. Move to a custom Marmot proposal type for leave (see `custom_extensions.md`) — sidesteps the PublicMessage requirement since its justification (external-commit interop) doesn't apply to Marmot.

This decision should be made explicitly, not stumbled into.

### 3.2 Pub(crate) surface hides things the engine wants

OpenMLS 0.8 has `pub(crate)` on exactly the APIs the architecture wants to cross:
- `MlsGroup::required_capabilities()` — the engine's `feature_status` has to walk `group.extensions()` and match `Extension::RequiredCapabilities(_)` itself.
- ~~Per-leaf `Capabilities` access — `MlsGroup::member_at(idx)` returns `Member` with credential but not leaf capabilities. Prevents a precise `feature_status` implementation that distinguishes `Upgradeable` from `Unavailable`.~~ **Corrected 2026-04-22:** this was a mis-diagnosis. `LeafNode::capabilities()` has been `pub` since OpenMLS ≥ 0.7.0. The correct access path is `group.public_group().leaf(idx)? → LeafNode::capabilities()`. `Member` is intentionally a thin summary type; go through `public_group()` for tree data. No `pub(crate)` block in reality.
- `as_member()` on `Sender` — engine must match `Sender::Member(idx)` variant manually.

**Implication.** The `CgkaEngine` trait's authors must define the API surface they need from OpenMLS, not just the surface they want to hide from application code. A companion "what we need from OpenMLS" doc, with concrete upstream PRs, would be productive.

### 3.3 Companion-crate version skew is silent

`openmls_basic_credential` 0.4 uses `openmls_traits` 0.4; OpenMLS 0.8 uses `openmls_traits` 0.5. The cross-version `Signer` trait mismatch produces confusing "trait not implemented" errors with no version hint. Real MDK needs to pin the whole OpenMLS crate family tightly.

---

## 4. Capability negotiation — validated + gaps

### What worked (validated by spike)

- **Splitting `NostrGroupDataExtension` into `BasicGroupData` (0xF2EA) + `NostrTransportData` (0xF2EB)**. `FeatureRegistry::required_for_transports(&[TransportKind::Nostr])` produced the correct union. Adding FIPS later is one registry entry + one peeler.
- **Three `RequirementLevel` shapes** — `Required`, `Optional`, `TransportRequired { transport }` — all exercised, all work.
- **Intersection-based constructable capabilities** at group creation. The negative test (`DM_DROP_CAPS=selfremove`) correctly refused to construct a group including a member with the missing capability, with a structured error naming required-vs-had.
- **RequiredCapabilities as source of truth** for `feature_status`. When a capability is in required-caps, it's `Available` by MLS guarantee — every member's KeyPackage must cover it to have been added.

### What's missing — needs design work

- ~~**Per-leaf `Capabilities` access** is not public in OpenMLS 0.8.~~ **Corrected 2026-04-22:** public access exists via `group.public_group().leaf(idx)?.capabilities()`. The spike incorrectly used `MlsGroup::member_at(idx)` (thin summary). With the correct path, `feature_status` *can* distinguish `Upgradeable` from `Unavailable` directly — no workaround needed.
- **Caching member capabilities locally** (cgka-engine-design.md §"Add a CapabilityStorage trait") was not implemented. This is the right fix for the previous bullet — each member's advertised capabilities go into a local index as KeyPackages are consumed.
- **`upgrade_group_capabilities()`** is described in the doc but not implemented in the spike.
- **`constructable_capabilities(members)` query** was implemented as a read-only check during create_group; not exposed as a standalone engine query.

---

## 5. What worked well — don't touch

Findings that **confirm** the target-architecture doc is right and don't need changes:

- **The 7-crate split.** Every crate wall corresponds to a real seam of concern. `cgka-engine` (trait + types) / `transport` (traits) / `mdk-spike` (CGKA impl) / `nostr-adapter` (TransportAdapter impl) / `nostr-mls-peeler` (TransportPeeler impl) / `whitenoise-core-spike` (wiring) / `dm-cli` (app). No layering violations surfaced.
- **`PendingStateRef` publish-before-apply contract.** Opaque handle across the trait boundary, passed back to `confirm_published` after publish succeeds. Works exactly as described. Application layer never sees what's inside.
- **`TransportAdapter::group_extension()` as the pluggability seam.** Not exercised deeply in the spike (engine constructs the extension itself to keep the boundary simple), but the shape is right.
- **Application messages as unsigned Nostr rumors inside the MLS payload** (`nostr-role-in-marmot.md`). Works cleanly; no ambiguity at the wire level.

---

## 6. Open questions — explicit asks for more work

These are the places where the spike didn't resolve the design question and more investigation is needed.

### 6.1 Do we patch OpenMLS for mixed outgoing, or adopt pure-plaintext, or move to custom SelfRemove?
A three-way decision that has architectural weight. See `custom_extensions.md` for the detailed analysis. **No action needed today**, but deferred decision should be named with the signals that would force it.

### 6.2 What shape does fork recovery take in `EpochState::Recovering`?
`cgka-engine-design.md` sketches `Recovering { last_stable_epoch, buffered_events }`. What's the buffering policy? How long do we hold events? How is re-sync triggered? Not clear from the doc; not tested by the spike.

### 6.3 How does capability upgrade actually fire?
`upgrade_group_capabilities()` is in the trait sketch. Who initiates it? Admin action? Auto-fire when all members support a newly-optional feature? UI prompt? The capability-negotiation doc has pieces of this; a full sequence diagram would help.

### 6.4 How is commit-race convergence handled?
The spike dodged this with a deterministic "lowest-index auto-committer" rule for SelfRemove. The general case (two admins issuing concurrent adds) is not addressed anywhere. Is this a coordinator-level ordering rule? A retry-with-proposal-resend loop? A "one committer wins; others resend their proposals" model?

### 6.5 Where does `CapabilityStorage` live, and what's in it?
`cgka-engine-design.md` sketches it as a new storage trait with `feature_requirement`, `save_member_capabilities`, etc. Concrete schema? When is it populated? By the engine directly on every `ingest`, or by a background job?

### 6.6 What's the exact `WelcomeState` lifecycle?
Welcomes auto-accept today. If we ever want user-controlled accept/decline, `WelcomeState::Pending` has to hold the welcome + group-preview info. What's the shape of that preview?

---

## 7. Specific doc updates this finding-set implies

A concrete task list for whoever updates the reference docs.

### `target-architecture.md`

- §"The TransportMessage Type" — add `envelope: TransportEnvelope` field and the enum.
- §"The CGKA Engine" — change `SendResult::GroupEvolution` to include `welcomes: Vec<TransportMessage>`.
- §"The TransportPeeler" — split into four methods: peel/wrap × group/welcome. Note the async requirement.
- §"The TransportPeeler" — change `ctx: &dyn GroupContext` to `ctx: &GroupContextSnapshot`. Add the snapshot type elsewhere.
- §"The CGKA Engine" — change `ingest` return to `Result<IngestOutcome, EngineError>`. Add the `IngestOutcome` / `StaleReason` types.
- §"The CGKA Engine" — add `drain_auto_publish()` method.
- New section: "Opinionated defaults — where the engine disagrees with its backend."

### `cgka-engine-design.md`

- §"State machines: what should be an enum" — add a note that spike didn't implement these; they remain as the highest-priority architectural gap.
- §"The `CgkaEngine` trait" — align error/outcome types with the revisions above.
- Add a new section: "OpenMLS constraints the engine wraps" covering §3 of this doc (wire format, pub(crate) surface, version pinning).
- Add a section: "Leave path — the spec-compliant OpenMLS call is not the default" covering the `leave_group()` / `leave_group_via_self_remove()` divergence.

### `capability-negotiation.md`

- Note that per-leaf `Capabilities` access is blocked in OpenMLS 0.8. Concrete recommendation: local caching in `CapabilityStorage` as the fix.
- Note that the `BasicGroupData` / `NostrTransportData` split was validated in the spike.

### New docs produced alongside this one

- `custom_extensions.md` — covers the "when to inherit vs define" decision framework. Starts with the SelfRemove/PublicMessage analysis and opens a spec-wide review question.
