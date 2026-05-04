//! The `TransportPeeler` trait — crypto seam between the engine and whatever
//! transport-specific wrapping lives below it (Nostr gift-wrap + kind-445
//! exporter-secret ChaCha20, FIPS mesh frames, …).
//!
//! Per spike-findings §1.3, welcomes and group messages are **structurally
//! different operations** (different keys, different addressing) and get
//! separate methods. Fusing them into one branching `peel`/`wrap` pair made
//! the spike's implementation harder to test, not easier.
//!
//! The peeler takes a [`GroupContextSnapshot`] (value type) rather than
//! `&dyn GroupContext` to sidestep the async-trait lifetime issue documented
//! in `docs/learnings.md:44`.

use crate::error::PeelerError;
use crate::group_context::GroupContextSnapshot;
use crate::ingest::PeeledMessage;
use crate::transport::{EncryptedPayload, TransportMessage};
use crate::types::MemberId;
use async_trait::async_trait;

/// Unwrap and rewrap transport-layer envelopes. A single peeler typically
/// handles one transport (e.g. `NostrMlsPeeler`).
///
/// ### Method invariants
///
/// - `peel_group_message` MUST fail cleanly with `PeelerError::DecryptFailed`
///   on stale/wrong exporter secrets — the engine maps that to
///   `StaleReason::PeelFailed`, not a hard error.
/// - `peel_welcome` MUST fail cleanly for welcomes not addressed to the
///   local identity — the engine maps that to `StaleReason::NotForThisClient`.
/// - `wrap_group_message` MUST be deterministic given the same input
///   (same `EncryptedPayload` + same `GroupContextSnapshot.epoch` →
///   reproducible wire bytes modulo outer-layer nonces/timestamps). The
///   harness asserts on this where applicable.
/// - Implementations are `Send + Sync`; the `#[async_trait]` macro handles
///   the lifetime gymnastics.
#[async_trait]
pub trait TransportPeeler: Send + Sync {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError>;

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError>;

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
