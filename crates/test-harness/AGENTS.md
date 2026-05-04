# AGENTS.md — test-harness

Read [`README.md`](README.md) for the human framing. This file is the agent-facing model.

## Pieces

| Module | Role |
|---|---|
| `src/bus.rs` | `TransportBus` — in-memory bus. Owns delivery policy, the queue, partition state, and the address book that maps `MemberId → ClientId` (for welcome routing). |
| `src/client.rs` | `HarnessClient` + `ClientBuilder`. Wraps an `Engine<MemoryStorage>` and the bus handle. `tick().await` drains pending inbound for one client. `confirm(pending).await` finishes a `GroupEvolution`. |
| `src/peeler.rs` | `MockPeeler` — pass-through. Group messages and welcomes go through distinct methods (matches the real `TransportPeeler` four-method shape from spike-findings §1.3) but the body is just length-prefixed framing, no encryption. |
| `src/proptest_support.rs` | `intent_seq(n_clients, range)` proptest strategy. Generates `HarnessIntent::Send` and `HarnessIntent::Leave`; `delivery_profile()` covers FIFO, reverse, and seeded-random delivery. |

## Bus model

The bus is **synchronous and deterministic**. Calling `client.send_app(...)` enqueues; calling `bus.deliver_all()` (or `bus.step(n)`) flushes; calling `client.tick().await` ingests on the receiver side. There is no actual async runtime cooperation — sending is `&mut self`, the engine is awaited inline.

Delivery policies (`DeliveryPolicy`):

- `ordered` — FIFO. Default for all canonical scenarios + the proptest.
- `reverse` — pop from the back. Useful for ingesting commits before their proposals.
- `seeded_random` — deterministic shuffle from a fixed `u64` seed.
- `partition` — drop messages whose recipient is in the partition set.

The bus knows about welcomes vs. group messages so welcomes can be routed to a specific recipient without requiring it to be a group member yet.

## How to add a new scripted scenario

1. New file or test fn in `tests/canonical_scenarios.rs`.
2. Build N clients with `ClientBuilder::new(pad32(b"alice")).registry(registry()).attach(&bus)`.
3. Drive the scenario with `client.send_*` / `bus.deliver_all()` / `client.tick().await`.
4. Assert on `client.epoch()`, `client.members()`, `client.drain_events()`.

Look at `three_client_happy_path_via_harness` for the canonical shape.

## How to add a new proptest invariant

1. New `proptest!` block in `tests/proptest_invariants.rs`.
2. If you need new intent kinds, extend `HarnessIntent` in `src/proptest_support.rs` and the matching strategy fn.
3. Encode the invariant as `prop_assert_unique(actual, expected, msg)` — the helper panics on mismatch so shrinking works.
4. Default `cases` is 24; the `harness-slow` feature lifts it to 1000. Don't hand-tune per-test counts.

## Coverage gaps

These are tracked in [`../../plans/2026-04-22-cgka-engine-production-refactor-v1.md`](../../plans/2026-04-22-cgka-engine-production-refactor-v1.md). If you're filling one of these in, update the plan's status row in the same change.

- **Recovery observations are not traceable yet.** The deliberate fork scenario proves final convergence, but `ScenarioTrace` should record the recovery decision path before we treat these as portable vectors.
- **`HarnessIntent` does not generate Invite / UpgradeCapabilities / UpdateGroupData.** Invite needs client minting inside a strategy; the scripted tests cover it today.
- **Partition policy is scripted, not strategy-driven.** The bus supports partitions; proptest currently drives FIFO / Reverse / SeededRandom.

## Conventions

- **Identities are `pad32(b"name")`.** MIP-01 requires 32-byte x-only pubkeys; the engine strict-fails on non-32-byte. Don't shortcut.
- **`MockPeeler` does not panic on garbage.** It returns a structured `PeelerError`. Tests can assert on `StaleReason::PeelFailed` if needed.
- **`HarnessClient` exposes only what tests need.** If you need the inner `Engine<S>`, that's a smell — extend the harness API instead and keep tests at one abstraction level.
