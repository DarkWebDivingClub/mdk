use async_trait::async_trait;
use futures::stream::BoxStream;
use thiserror::Error;

use cgka_engine::{GroupId, TransportMessage};

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("publish failed: {0}")]
    Publish(String),
    #[error("subscribe failed: {0}")]
    Subscribe(String),
    #[error("fetch failed: {0}")]
    Fetch(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Clone, Debug)]
pub struct PublishConfirmation {
    pub adapter_name: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportStatus {
    Connected,
    Connecting,
    Disconnected,
}

/// Per target-architecture §"The TransportAdapter Trait".
/// Only sees opaque blobs — never plaintext.
#[async_trait]
pub trait TransportAdapter: Send + Sync {
    fn name(&self) -> &'static str;

    async fn publish(
        &self,
        msg: &TransportMessage,
    ) -> Result<PublishConfirmation, TransportError>;

    /// Subscribe to inbound messages for a group. For the spike the group_id is
    /// the transport_group_id (Nostr `h` tag value), handed down from the engine
    /// via GroupContext::transport_group_id.
    async fn subscribe_group(
        &self,
        transport_group_id: &[u8],
    ) -> Result<BoxStream<'static, TransportMessage>, TransportError>;

    /// Subscribe to welcomes (NIP-59 giftwrap 1059) for a specific member pubkey.
    async fn subscribe_welcomes(
        &self,
    ) -> Result<BoxStream<'static, TransportMessage>, TransportError>;

    async fn fetch(
        &self,
        group_id: &GroupId,
        since: u64,
    ) -> Result<Vec<TransportMessage>, TransportError>;

    fn status(&self) -> TransportStatus;

    /// Per cgka-engine-design.md §"Transport features: extensions as first-class
    /// citizens" — returns the MLS extension this transport contributes to a
    /// newly-created group. `(extension_type, serialised_extension_bytes)`.
    fn group_extension(&self) -> Option<(u16, Vec<u8>)>;
}
