# AGENTS.md - crates/transport-nostr-peeler

Agent-facing map for the Nostr transport peeler crate.

## Scope

This crate owns the Nostr transport-edge peeler:

- Nostr-shaped event DTOs,
- mapping kind `445` / `1059` events into `TransportMessage`,
- kind `445` group envelope encryption and decryption,
- explicit errors for malformed or unsupported Nostr boundary input.

It must not own relay networking, relay selection, account-device sessions, app
message projection, or application storage. Keep those in adapters or the app
layer above this crate.

## Key files

| Path | Owns |
| --- | --- |
| `src/lib.rs` | Public exports and Nostr/Marmot constants. |
| `src/event.rs` | `NostrTransportEvent` DTO and `TransportMessage` conversion. |
| `src/peeler.rs` | `TransportPeeler` implementation for Nostr/MLS group messages. |
| `src/error.rs` | Nostr boundary error vocabulary. |

## Current limits

- Group messages are wrapped and peeled.
- Welcome events are classified, but full NIP-59 gift wrapping and unwrapping
  still needs signer/decrypter integration.

## Verification

```sh
cargo test -p transport-nostr-peeler
```
