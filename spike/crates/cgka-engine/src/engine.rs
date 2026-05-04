use async_trait::async_trait;
use thiserror::Error;

use crate::capabilities::{Feature, FeatureStatus, GroupCapabilities, TransportKind};
use crate::context::GroupContext;
use crate::types::{
    EpochId, GroupEvent, GroupId, IngestOutcome, MemberId, PendingStateRef, SendIntent,
    SendResult, TransportMessage,
};

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("unknown group: {0:?}")]
    UnknownGroup(GroupId),
    #[error("unknown pending ref: {0:?}")]
    UnknownPending(PendingStateRef),
    #[error("not a member of group")]
    NotAMember,
    #[error("cgka backend error: {0}")]
    Backend(String),
    #[error("peeler error: {0}")]
    Peeler(String),
    #[error("serialization: {0}")]
    Serialize(String),
    #[error("{0}")]
    Other(String),
}

/// Target-architecture `CgkaEngine` trait — the ONLY surface the application layer
/// calls against. See target-architecture.md §"The CGKA Engine" and cgka-engine-design.md.
#[async_trait]
pub trait CgkaEngine: Send + Sync {
    // ── Inbound ─────────────────────────────────────────────────────────────────
    async fn ingest(&mut self, msg: TransportMessage) -> Result<IngestOutcome, EngineError>;

    /// Drain all pending GroupEvents. The spike uses a pull-drain model instead
    /// of a persistent Stream to keep the coordinator logic trivial.
    fn drain_events(&mut self) -> Vec<GroupEvent>;

    /// Drain any TransportMessages the engine produced as side effects of prior
    /// ingest calls (e.g. auto-committing a received SelfRemove proposal per
    /// MIP-03). The wiring layer is responsible for publishing these.
    fn drain_auto_publish(&mut self) -> Vec<TransportMessage>;

    // ── Outbound ────────────────────────────────────────────────────────────────
    async fn send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError>;
    async fn confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<GroupEvent, EngineError>;

    // ── Lifecycle ───────────────────────────────────────────────────────────────
    async fn create_group(
        &mut self,
        name: &str,
        description: &str,
        member_key_packages: &[Vec<u8>],
        transports: &[TransportKind],
    ) -> Result<(GroupId, SendResult), EngineError>;

    // ── Capability queries ──────────────────────────────────────────────────────
    fn feature_status(
        &self,
        group_id: &GroupId,
        feature: Feature,
    ) -> Result<FeatureStatus, EngineError>;

    fn constructable_capabilities(
        &self,
        member_key_packages: &[Vec<u8>],
    ) -> Result<GroupCapabilities, EngineError>;

    // ── Inspection ──────────────────────────────────────────────────────────────
    fn group_context(&self, group_id: &GroupId) -> Result<Box<dyn GroupContext>, EngineError>;
    fn members(&self, group_id: &GroupId) -> Result<Vec<MemberId>, EngineError>;
    fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError>;

    /// This client's identity as an MLS leaf/Nostr pubkey.
    fn self_id(&self) -> MemberId;

    /// Serialised KeyPackage for publishing (kind 30443).
    fn fresh_key_package(&mut self) -> Result<Vec<u8>, EngineError>;
}
