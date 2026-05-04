use async_trait::async_trait;
use thiserror::Error;

use cgka_engine::{EncryptedPayload, GroupContextSnapshot, MemberId, PeeledMessage, TransportMessage};

#[derive(Error, Debug)]
pub enum PeelerError {
    #[error("decrypt failed: {0}")]
    Decrypt(String),
    #[error("encrypt failed: {0}")]
    Encrypt(String),
    #[error("malformed outer envelope: {0}")]
    Malformed(String),
    #[error("not for us")]
    NotForUs,
    #[error("{0}")]
    Other(String),
}

/// Per target-architecture §"The TransportPeeler". One impl per transport+CGKA pair.
///
/// Split into two paths because on the Nostr transport, group messages (kind 445) and
/// welcomes (kind 1059 gift-wrap) use different wrap schemes.
///
/// Takes `GroupContextSnapshot` by value rather than `&dyn GroupContext` because
/// async-trait method bodies cross `await` points and `&dyn Trait` references are
/// awkward there. The snapshot is small and the engine owns the original.
#[async_trait]
pub trait TransportPeeler: Send + Sync {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
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
