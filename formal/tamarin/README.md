# Tamarin Convergence Model

This directory contains the first formal model for Marmot distributed
convergence.

The v0 model is intentionally abstract. It does not model MLS internals,
transport timestamps, relay receipts, Nostr event ids, or OpenMLS serialization.
It models only the selector boundary:

- two honest clients see the same valid candidate set,
- those clients may enumerate the candidate pair in different orders,
- a deterministic policy chooses one branch,
- a branch outside policy evidence cannot be selected,
- witness quorum can only act through a bounded override rule.
- score comparison follows the same priority order as the Rust conformance
  selector.

The starting model is
[`distributed_convergence_v0.spthy`](distributed_convergence_v0.spthy).

## Targets

- `just tamarin` runs Tamarin on the model and requires `tamarin-prover` on
  `PATH`. Successful runs print only Tamarin's `summary of summaries`; failing
  runs print the full prover output.
- `just tamarin-interactive` opens the model in Tamarin's interactive UI and
  requires `tamarin-prover` on `PATH`.

## Install

Install Tamarin separately, then run:

```sh
just tamarin
```

The command-line shape follows the official Tamarin manual: a `.spthy` file can
be checked directly with `tamarin-prover`, and lemmas can be proved with
`--prove`.

References:

- [Tamarin model specification using rules](https://tamarin-prover.com/manual/master/book/005_protocol-specification-rules.html)
- [Tamarin property specification](https://tamarin-prover.com/manual/master/book/007_property-specification.html)
- [Tamarin command-line proving example](https://tamarin-prover.com/manual/master/book/003_example.html#running-tamarin-on-the-command-line)

## Modeling Notes

The first useful proof slice is not "MLS is secure." We inherit that from MLS
and OpenMLS. The useful first slice is:

```text
same valid input set + same negotiated policy => same selected branch
```

That keeps the formal model aligned with the Rust conformance model in
`crates/cgka-conformance/src/convergence.rs`.

The v0 model now uses bounded symbolic score classes instead of an opaque
`ScoreCase` fact:

```text
dN       commit-depth or effective-depth class
wN       app-witness score class
qyes/qno witness quorum class
g00/gff  digest rank class, where lower wins final ties
```

The derivation rules mirror the selector order:

1. higher effective depth,
2. quorum tie,
3. higher raw commit depth,
4. higher app-witness score,
5. lower digest rank.

Next refinements:

1. Add explicit duplicate app witnesses and prove sender-per-epoch dedupe.
2. Add a stale branch case for the rewind horizon.
3. Add three-or-more-branch delivery permutations for the same message bag.
4. Generate broader bounded scenario families from the Rust policy model.
