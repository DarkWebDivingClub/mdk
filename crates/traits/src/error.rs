//! Typed errors returned by the engine and the peeler.
//!
//! Every variant corresponds to a real case the spike hit. Stringly-typed
//! errors (`EngineError::Backend(String)`) are the fallback of last resort
//! and deliberately the widest variant — everything we can classify should
//! get its own variant first.

use crate::capabilities::GroupCapabilities;
use crate::types::{EpochId, GroupId};

/// Errors returned by every [`crate::engine::CgkaEngine`] method.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("unknown group: {0}")]
    UnknownGroup(GroupId),

    #[error("unknown pending send reference")]
    UnknownPending,

    #[error("local identity is not a member of group {group_id}")]
    NotAMember { group_id: GroupId },

    /// MIP-03 §149 — an admin cannot SelfRemove if doing so would leave the
    /// group with zero admins. Demote (or transfer admin status) before
    /// leaving.
    #[error(
        "admin cannot self-remove from group {group_id}: would leave the group with zero admins"
    )]
    AdminCannotSelfRemove { group_id: GroupId },

    /// MIP-03 §150 — a commit that would result in zero admins is rejected
    /// before construction. Currently fires from the auto-committer when an
    /// inbound SelfRemove from the only admin would deplete admins on
    /// commit.
    #[error("commit would deplete admins on group {group_id}")]
    AdminDepletion { group_id: GroupId },

    /// Structured replacement for the spike's stringly-typed
    /// "invitee KeyPackage missing required capabilities" error (see
    /// `docs/learnings.md:127-129`). `required` and `had` are populated so
    /// the UI can render the diff directly.
    #[error("missing required capabilities: required={required:?} had={had:?}")]
    MissingRequiredCapabilities {
        required: GroupCapabilities,
        had: GroupCapabilities,
    },

    /// Epoch fork detected that the current recovery manager could not
    /// resolve, usually because no pre-commit snapshot was available.
    /// Recoverable same-epoch commit races roll back and replay internally.
    #[error(
        "forked epoch on group {group_id}: last stable {last_stable}, conflicting {conflicting_epoch}"
    )]
    ForkedEpoch {
        group_id: GroupId,
        last_stable: EpochId,
        conflicting_epoch: EpochId,
    },

    /// Illegal state-machine transition (from
    /// [`crate::engine_state::InvalidTransition`]). Indicates an engine bug.
    #[error(transparent)]
    InvalidTransition(#[from] crate::engine_state::InvalidTransition),

    #[error(transparent)]
    Storage(#[from] crate::storage::StorageError),

    #[error(transparent)]
    Peeler(#[from] PeelerError),

    #[error("serialization failure: {0}")]
    Serialize(String),

    /// Last-resort bucket. Prefer adding a typed variant.
    #[error("backend failure: {0}")]
    Backend(String),

    /// Truly unclassified. Should be empty in practice.
    #[error("other: {0}")]
    Other(String),
}

/// Errors returned by the peeler. The split mirrors the four-method peeler
/// surface (group/welcome × peel/wrap).
#[derive(Debug, thiserror::Error)]
pub enum PeelerError {
    #[error("malformed transport payload: {0}")]
    Malformed(String),

    #[error("decrypt failed (likely stale or wrong-epoch exporter secret)")]
    DecryptFailed,

    #[error("required context secret missing: {label}")]
    MissingContext { label: String },

    /// Wrap-side failure, e.g. rumor signing failed.
    #[error("wrap failed: {0}")]
    WrapFailed(String),

    /// Last-resort bucket.
    #[error("peeler backend failure: {0}")]
    Backend(String),
}
