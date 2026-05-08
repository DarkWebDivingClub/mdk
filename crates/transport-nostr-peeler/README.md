# transport-nostr-peeler

Nostr transport peeler for the Marmot CGKA engine.

This crate sits below `cgka-engine` and above a future relay adapter. It turns
Nostr-shaped events into `cgka_traits::TransportMessage` values, and wraps /
peels Marmot group MLS bytes for Nostr kind `445`.

## What this crate does

- Maps kind `445` events with an `h` tag into group `TransportMessage`s.
- Maps kind `1059` events with a `p` tag into welcome `TransportMessage`s.
- Preserves causal `e` tags as `TransportMessage::causal_deps`.
- Encrypts and decrypts kind `445` group envelopes with
  ChaCha20Poly1305 using the engine exporter snapshot.

## What this crate does not do

- No relay connections, subscriptions, retry policy, relay selection, or relay
  persistence.
- No application session or account-device lifecycle.
- No Nostr SDK key management.
- No full NIP-59 welcome gift-wrap signing/decryption yet. Welcome events are
  classified at the transport boundary; actual NIP-59 peeler support needs the
  signer/decrypter integration.

## Boundary shape

Inbound:

```text
real Nostr event -> NostrTransportEvent -> TransportMessage -> NostrMlsPeeler -> PeeledMessage
```

Outbound:

```text
EncryptedPayload + GroupContextSnapshot -> NostrMlsPeeler -> TransportMessage
```

The outbound `TransportMessage` carries a Nostr DTO payload and a deterministic
pre-signing id. A real Nostr adapter may replace that id after it signs and
publishes the final event.

## Run tests

```sh
cargo test -p transport-nostr-peeler
```
