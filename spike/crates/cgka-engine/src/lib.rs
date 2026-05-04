//! Core CGKA engine trait + types. Target-architecture trait contract only —
//! no crypto, no transport. Implementations live in sibling crates.

pub mod capabilities;
pub mod context;
pub mod engine;
pub mod types;

pub use capabilities::{
    Capability, Feature, FeatureRegistry, FeatureSpec, FeatureStatus, GroupCapabilities,
    RequirementLevel, TransportKind,
};
pub use context::{GroupContext, GroupContextSnapshot};
pub use engine::{CgkaEngine, EngineError};
pub use types::{
    EncryptedPayload, EpochId, GroupEvent, GroupId, IngestOutcome, MemberId, MessageId,
    MessageType, OrderingMetadata, PeeledMessage, PendingStateRef, SendIntent, SendResult,
    StaleReason, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
