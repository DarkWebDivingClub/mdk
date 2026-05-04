# spike/ — Archived April 2026 CGKA Engine Spike

This tree is the original 7-crate exploration spike that validated the target architecture. It is preserved read-only as reference material and is **not built by the main workspace**.

- Raw chronological log: [`../docs/learnings.md`](../docs/learnings.md)
- Distilled findings: [`../docs/marmot-architecture/further-context/spike-findings.md`](../docs/marmot-architecture/further-context/spike-findings.md)
- Production refactor plan: [`../plans/2026-04-22-cgka-engine-production-refactor-v1.md`](../plans/2026-04-22-cgka-engine-production-refactor-v1.md)

## Crates

| Crate | Purpose |
|---|---|
| `cgka-engine` | Trait sketch + value types |
| `transport` | Transport-adapter trait sketch |
| `mdk-spike` | OpenMLS-backed engine implementation |
| `nostr-adapter` | Nostr transport adapter |
| `nostr-mls-peeler` | Nostr kind-445 / kind-1059 peeler |
| `whitenoise-core-spike` | Wiring glue between engine + transport |
| `dm-cli` | Interactive demo binary (`dm`) used in the 3-/4-terminal smoke tests |

## Building

This directory is an **independent Cargo workspace**. Build it in isolation:

```sh
cd spike
cargo check
```

The root `Cargo.toml` excludes `spike/`, so running `cargo check` from the repo root will not touch these crates.

## Status

**Archived.** Bug fixes are not expected to land here; correctness lives in the production crates at the repo root. If something here is load-bearing, port it forward — do not modify in place.
