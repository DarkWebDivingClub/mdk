# test-harness

In-process multi-client simulator for the CGKA engine. Lets us replay scripted scenarios and run property-based invariants against `Engine<MemoryStorage>` without going anywhere near a network or real crypto.

## What this crate gives you

- `TransportBus` — an in-memory message bus with seeded scheduling, partition support, broadcast and addressed delivery (for welcomes), and replay hooks.
- `HarnessClient` — wraps `Engine<MemoryStorage>` + a `MockPeeler` (skips encryption so tests can assert on inner payloads directly).
- `proptest_support` — strategies that generate arbitrary typed `SendIntent` sequences for property-based tests.
- `MockPeeler` — a deliberately trivial `TransportPeeler` impl. Distinguishes the group-message vs welcome paths but performs no encryption.

## Run the tests

```sh
# Default: scripted scenarios + proptest with 24 cases (~1 s).
cargo test -p test-harness

# Pre-release validation: 1000 proptest cases per property.
cargo test -p test-harness --features harness-slow
```

## When to use the harness vs. integration tests

| Question | Where to put the test |
|---|---|
| "Does this single engine method behave correctly?" | `cgka-engine/tests/*.rs` |
| "Do N engines converge under FIFO delivery?" | `test-harness/tests/canonical_scenarios.rs` |
| "Does this hold for *any* sequence of N intents?" | `test-harness/tests/proptest_invariants.rs` |
| "What happens under reorder / partition / replay?" | New scripted scenario; consider extending the proptest strategies once the case is concrete |

See [`AGENTS.md`](AGENTS.md) for the agent-facing map (bus model, scheduler policies, how to add a scenario).
