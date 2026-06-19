# AGENTS.md - integrations/openclaw/marmot

OpenClaw channel plugin for Marmot through the local `dm-agent` control socket.
The OpenClaw counterpart of `integrations/hermes/marmot`. Read `README.md` first.

## Scope

- A thin, **control-plane-only** OpenClaw channel plugin. `dm-agent` owns the
  Marmot account, MLS state, Nostr transport, and QUIC previews; this plugin
  only speaks `marmot.agent-control.v1` (NDJSON over a Unix socket).
- Keep transcript hashing byte-for-byte with the authoritative Rust
  `AgentTextStreamTranscriptV1` (`crates/traits/src/agent_text_stream.rs`).
- No QUIC, crypto, relay, or MLS logic here.
- Privacy-safe logging only: no account ids, group ids, message ids, pubkeys,
  relay URLs, payloads, ciphertext, plaintext, or key material.

## Key files

- `src/transcript.ts` — transcript-hash mirror + UTF-8 chunk splitter (Rust-anchored).
- `src/client.ts` — agent-control NDJSON client (request/response + `subscribe_inbound` stream).
- `src/append-only.ts` — append-only suffix tracker for progressive updates.
- `src/live.ts` — live-preview state machine → `stream_begin`/`append`/`finalize`/`cancel`.
- `src/inbound.ts` — inbound subscription bridge (reconnect, dedupe, resync).
- `src/inbound-runtime.ts` — `registerFull` wiring + the inbound→agent dispatch seam.
- `src/outbound.ts` — `defineChannelMessageAdapter` durable send → `send_final`.
- `src/config.ts` — channel config schema + `MARMOT_*` resolution.
- `src/account.ts` — single agent-account resolution (`account_list`).
- `src/security.ts` — OpenClaw `dm.allowFrom` → `dm-agent` welcomer allowlist sync.
- `src/channel.ts` — `createChatChannelPlugin` (meta, capabilities, config, message, security, threading).
- `index.ts` / `setup-entry.ts` — plugin runtime + setup entries.
- `test/` — Vitest unit + parity tests; `test/vectors/transcript-vectors.json` is generated from the Rust impl.

## Rules

- Regenerate `test/vectors/transcript-vectors.json` from the Rust
  `AgentTextStreamTranscriptV1` if the Rust transcript hashing ever changes.
- Keep the `openclaw` dependency pinned; before bumping, verify the
  `openclaw/plugin-sdk/*` subpath exports against the new version's types.
- The inbound→agent and live-preview-pipeline seams use OpenClaw gateway runtime
  internals and are validated by the docker phone test, not the unit tests.

## Verification

```sh
cd integrations/openclaw/marmot && pnpm install && pnpm typecheck && pnpm test
# or from the repo root:
just openclaw-dev-test
```
