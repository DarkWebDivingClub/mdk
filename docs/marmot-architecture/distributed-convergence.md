# Distributed Convergence — Design Draft

**Status:** draft. Captures context from a 2026-05-05 conversation between Jeff and Shaka. Not yet a spec.

**Scope:** how a Marmot client converges on the canonical group state given an arbitrary bag of received messages, in a multi-relay world. This is the broader frame the recently-landed [`CommitOrderingKey`](../../crates/traits/src/engine.rs) refactor sits inside; the digest change is a foundation for what's described here, not a complete solution.

**Out of scope (for now):** the digest mechanism itself (already landed); transport-level concerns beyond what affects engine convergence; UI / storage / key-rotation specifics.

---

## 1. Problem framing

Each Marmot client is a replica of a state machine. Messages arrive over multiple relays in arbitrary order. The state machine must converge to whatever an always-online observer would have seen, regardless of arrival order.

Two scenarios must produce the same end state:

1. **Online client.** Receives the message stream in roughly real-time. Applies each commit/proposal/app message as it arrives, resolving same-epoch races via fork-recovery.
2. **Returning client.** Has been offline for some time. Reconnects to relays and receives a *dump* — potentially hundreds of messages spanning many epochs, including commits from branches that the rest of the group eventually abandoned. Must sort the dump into the canonical sequence and reach the same final state as (1).

The hard property: **the dump may contain commits from a branch that everyone else rolled back**. The returning client has no privileged signal telling it "this branch was canonical, that one wasn't." Convergence must come from the structure of the messages themselves.

This is a distributed-systems convergence problem with a partial order over commits.

## 2. Target deployment shape

The design must work for:

- **Large groups** (500-1000 members, 20-30 admins).
- **Multiple relays** — single relay is a SPOF and defeats the purpose of Nostr-style fan-out.
- **High commit traffic** — joins, leaves, key rotations, capability upgrades.
- **Partial relay reach** — no single relay sees all messages; clients reconcile across relays.
- **Adversarial environment** — assume some clients/relays may misbehave.

Small groups on a single relay are largely a solved case. The interesting failure modes appear at scale.

## 3. What the digest change gives us

[`CommitOrderingKey`](../../crates/traits/src/engine.rs) is now `(source_epoch, SHA-256(mls_bytes))` — a content-derived total order over commits, transport-independent. Two replicas processing the same commit derive the same key by construction.

This is a strict improvement over the prior `(timestamp, message_id)` scheme:

- The engine no longer reads transport-layer fields for ordering decisions.
- An attacker can no longer manipulate transport timestamps to swing fork recovery.
- The key shape is forward-compatible with `AlwaysCiphertext` MLS framing (we hash wire bytes; no decryption needed).

It does **not** by itself solve the convergence problem. It gives us a deterministic tie-break primitive, but says nothing about *eligibility* — when a commit is still in the running for fork recovery vs. when it's stale beyond reconsideration.

## 4. The late-commit problem

Naïve content-derived ordering has a real failure mode:

> Group at epoch 1. Alice commits epoch 1→2; everyone applies it; group advances normally to epoch 5. Carol was offline, generates a different commit at source_epoch=1, comes back online and publishes it. If Carol's commit happens to have a lower digest, naïve fork-recovery would say "Carol wins, roll back to epoch 1, replay Carol's commit." That's catastrophic — epoch 2-5's work is destroyed.

This is **not** a tie-break problem. It's a *finality* problem. Tie-break asks "of two competing things, which wins"; finality asks "is this thing still in the running."

The current engine's eligibility check is `(content == Commit) AND (we_committed_from source_epoch) AND (current > msg_epoch)`. That's necessary but not sufficient — there's no upper bound on `current - msg_epoch`.

The previous `(timestamp, message_id)` scheme masked this with a social-norm assumption (Nostr clients set `created_at` honestly, so a 2-hour-late commit usually had a 2-hour-late timestamp and lost). It wasn't actually safe — a malicious client backdating `created_at` would win against any honest commit. The digest change makes the latent bug honest.

## 5. The architectural shape we think is right

### Branch extension as the primitive

> **The branch with the most observable extension wins. Tie-break by content digest.**

"Extension" means how many subsequent valid commits chain off this commit. Possibly weighted by app-message witness at descendant epochs.

This is "longest-valid-chain" applied to MLS. It works because **MLS commits already chain**: each commit's `confirmed_transcript_hash` is computed from the prior interim hash, so any pile of received commits forms a forest of trees. The "real" history is one path through this forest. The algorithm picks the path with the most extension.

Why this is the right primitive:

- **Online case:** an incumbent commit naturally accumulates extensions as time passes; a late competitor is a stub. Incumbent wins.
- **Dump case:** the returning client builds the DAG from received messages; the canonical branch has many descendants, the abandoned branch has few. Same algorithm, same answer.
- **Convergence:** every replica computes the same answer from the same input set, because the algorithm is purely a function of received messages.
- **Adversarial late commit:** the attacker's branch has zero extensions; the canonical branch has many. Attacker loses regardless of digest order.
- **Genuinely concurrent commits:** at the moment of the race, both branches are stubs of equal extension. Digest tie-break decides; the next commit settles the branch by extending it.

### Engine state model implications

The engine's data model has to grow:

- **Pending buffer.** A pool of received messages that haven't been folded into canonical state yet. App messages can sit here waiting for their epoch; commits sit here while the DAG resolves.
- **Canonical state.** The currently-applied chain. Today this is the live `MlsGroup`; the *sequence* of applied commits becomes a recordable artifact.
- **Canonicalization pass.** Given pending + canonical, decide: should canonical advance? Should it roll back and re-advance along a different branch? Replaces the current "ingest message → maybe fork-recover" loop.

The current single-rollback `fork_recovery.rs` becomes a degenerate case of branch-extension once this lands.

### What to do with the engine finality cap and witness ideas

Earlier discussion proposed a strict `current == msg_epoch + 1` cap and a forward-activity witness as primary defenses. Under branch-extension, both demote:

- **Finality cap** → **storage retention horizon.** We keep MLS state and snapshots for K epochs back; deeper rollbacks fail because storage doesn't have the snapshot. K is tunable; could be group-policy. Memory bound, not policy gate.
- **Forward-activity witness** → **branch scoring weight.** A branch with descendant app messages outranks a stub branch even if both have the same commit count. Evidence weighted into the score, not a hard lock.

## 6. Hard questions

Items the design has to actually answer.

### 6.1 How deep do we let resolution go?

A returning client could dump 500 commits across 50 epochs. Is the canonicalization pass willing to roll back 50 epochs if it discovers a deeper branch?

Probably not — at some point the cost is prohibitive and the protocol benefits from a "we're past the renegotiation horizon" rule. Open question what shape that takes:

- **Storage horizon:** keep MLS state for K epochs back. Deeper rollbacks fail because storage doesn't have the snapshot. Tunable per group.
- **Activity horizon:** snapshots evict once N forward-epoch app messages observed. Clock-free; tunable.
- **Time horizon:** snapshots expire after T (re-introduces wall-clock).

We lean toward storage + activity horizons; explicit time horizons should live at the transport layer if anywhere.

### 6.2 What counts as branch extension?

- Only commits? Most rigorous — app messages are not "branch claims," they're *use* of an epoch.
- Commits plus app messages? More inclusive — aligns with the witness idea.
- Weighted scoring (commits count more than app messages)? Probably not needed initially.

### 6.3 When does canonicalization run?

- On every ingest? Simple but does work even when nothing changed.
- On dump completion or batch end? Cheap for the dump case but needs a "batch end" signal.
- Lazily on observation? State is "the canonical history I can compute right now"; recomputed when consumer asks.

### 6.4 Pending-buffer semantics

- Lifetime: how long does a pending message hang around if no canonical chain incorporates it?
- Eviction: same horizon question as storage.
- Visibility: app messages in pending for an epoch you haven't reached — surfaced as "queued" or hidden until canonical?

### 6.5 Adversarial branch grinding

A coalition could pre-compute many commits and hold them, then dump a long branch when convenient. The dump has more extension than the canonical state's recent activity. Branch-extension says they win.

This is the analogue of selfish mining. Defenses to consider:

- **Witness-weighted scoring** — honest members' app traffic raises canonical-branch score.
- **Group-policy maximum rewind depth** — see horizons above.
- **Member-supermajority requirement** — a branch's extension only counts commits from a sufficient set of *distinct* admins.

Real consideration for the 1000-member-30-admin shape. Worth its own thread.

### 6.6 Proposal handling

Proposals reference a source epoch. A proposal at epoch N is canonical iff the commit that bundles it is canonical. Pending proposals on losing branches get dropped when their branch loses. Easy in principle; needs spelling out.

### 6.7 Re-keying and membership churn

When members leave or rotate keys, their contribution to extension stops counting at their leave epoch. An attacker can't perpetually extend their branch using a key that was rotated away. Useful natural property — confirm it actually holds.

### 6.8 Transport-side reorder buffer

Separately, the transport adapter (peeler/relay-side code, not the engine) should resort messages within a small natural-arrival window. The engine receives roughly chronological ordering; canonicalization handles the rest. This is a *sort*, not a *filter* — late messages still pass through, just unsorted relative to fresher ones.

### 6.9 Determinism of MLS commit production

OpenMLS commits include fresh HPKE path randomness. Same scenario → different bytes → different digests. This means content-derived ordering vectors aren't byte-portable between runs.

Three responses:

- **Live with it for now.** Engine-internal ordering still works (any single replica computes a consistent total order); cross-replica/cross-impl portability of fixture digests is acknowledged-broken.
- **Provide deterministic test mode.** OpenMLS may expose RNG hooks; investigate whether commits can be made byte-stable for fixture purposes.
- **Redesign the trace shape.** Express fork-recovery outcomes by scenario provenance ("alice's invite at step 5 won") rather than digest bytes. We previously decided against harness-side bookkeeping; revisit if other paths fail.

This question blocks restoration of portable fork-recovery conformance vectors.

## 7. Suggested split

- **Track A (this doc):** distributed-convergence model. Branch-extension primitive, pending buffer, horizons, adversarial defenses, proposal lifecycle, deterministic-commits investigation. Output: a spec sketch with examples, walk-throughs of the dump-replay case, and concrete rollback boundaries.
- **Track B (already partially done):** engine cleanups that are foundational but can land independently — `CommitOrderingKey` content-derivation (✓ landed), eventual `Timestamp` eviction from the engine seam, transport-side reorder buffer.

## 8. Formal verification candidate

This problem space is a strong candidate for formal verification (Tamarin, TLA+, Coq, etc.). Specifically:

- The canonicalization pass is a state-machine transition function.
- Convergence is a property: `forall replica1, replica2: same_received_set(replica1, replica2) → same_canonical_state(replica1, replica2)`.
- Branch-extension scoring is a deterministic function over a partially-ordered set of commits.
- Adversarial scenarios (late commits, branch grinding, member-collusion) can be encoded as adversary models.

Worth scoping after Track A's design stabilizes — a formal model would help nail down which axioms (e.g., "every honest commit eventually reaches every honest replica") the protocol assumes from the transport layer.

## 9. Open notes / things to fold in

Stuff from the conversation we haven't yet woven into a design but want to remember:

- `TransportMessage.causal_deps: Vec<MessageId>` is already typed but unused. It's the natural slot for partial-order tightening (a commit declares what it has seen; receivers cross-check). Defer until branch-extension is in place; revisit when honest-Byzantine tightening is needed.
- AlwaysCiphertext migration with SelfRemove plaintext carve-out is a separate near-term piece. Doesn't conflict with this design — `SHA-256(mls_bytes)` ordering survives all framing choices.
- Proposal-then-commit semantics under branch-extension: a proposal is canonical iff its committing commit is canonical. Need to decide how proposal-discard observability surfaces to apps.
- Storage cost of the pending buffer in 1000-member groups under churn — needs a bound + eviction strategy that's predictable to operators.
- Group-context extension carrying convergence-policy parameters (rewind horizon, supermajority requirement) — design the extension shape once the parameters stabilize.
