//! Storage traits and the `StorageProvider` aggregate.
//!
//! Four Marmot-level traits compose with `openmls_traits::storage::StorageProvider`
//! (at `CURRENT_VERSION`) to form a single type parameter `S: StorageProvider`
//! carried by the engine. No `dyn` storage dispatch; all impls are reached
//! via generics so the compiler can inline + prove consistency.
//!
//! **Invariant:** storage trait methods are **sync**. OpenMLS's storage
//! surface is sync; async concerns live above storage (on the engine). If a
//! future backend needs async I/O (e.g. a remote KV), it can wrap sync
//! methods in `tokio::task::spawn_blocking`.

use crate::capabilities::{CapabilityRequirement, GroupCapabilities};
use crate::group::{Group, Member};
use crate::message::{MessageRecord, MessageState};
use crate::types::{Backend, EpochId, GroupId, MemberId, MessageId};
use crate::welcome::PendingWelcome;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider as OpenMlsStorageProvider};

/// Marmot-level storage error. Every trait method returns
/// `Result<_, StorageError>` so the engine can pattern-match rather than
/// string-parse.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("record not found")]
    NotFound,
    #[error("record already exists")]
    AlreadyExists,
    #[error("snapshot not found: {0}")]
    SnapshotMissing(String),
    #[error("backend failure: {0}")]
    Backend(String),
    #[error("serialization failure: {0}")]
    Serialization(String),
}

pub type StorageResult<T> = Result<T, StorageError>;

// ── GroupStorage ────────────────────────────────────────────────────────────

/// CRUD for group metadata (no Nostr types; see `group.rs` invariants).
pub trait GroupStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()>;
    fn get_group(&self, id: &GroupId) -> StorageResult<Group>;
    fn delete_group(&self, id: &GroupId) -> StorageResult<()>;
    fn list_groups(&self) -> StorageResult<Vec<GroupId>>;
}

// ── MessageStorage ──────────────────────────────────────────────────────────

/// Messages + epoch-scoped snapshot/rollback hooks.
///
/// Snapshots are name-keyed per-group: the engine's `EpochManager` creates
/// one before entering a risky transition and either commits (`release_*`)
/// or rewinds (`rollback_*`). Invariant: snapshots capture every piece of
/// backend state needed to reload the group at the snapshot epoch, including
/// OpenMLS group state. `list_messages` must return a deterministic replay
/// order for a given backend; insertion order is preferred when the backend
/// can retain it.
pub trait MessageStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()>;
    fn get_message(&self, id: &MessageId) -> StorageResult<MessageRecord>;
    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()>;
    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>>;

    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;
    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;
    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()>;
}

// ── WelcomeStorage ──────────────────────────────────────────────────────────

pub trait WelcomeStorage {
    fn put_welcome(&self, welcome: &PendingWelcome) -> StorageResult<()>;
    fn take_welcome(&self, id: &MessageId) -> StorageResult<PendingWelcome>;
    fn list_welcomes(&self) -> StorageResult<Vec<PendingWelcome>>;
}

// ── CapabilityStorage ───────────────────────────────────────────────────────

/// Feature registry + per-member capability cache.
///
/// Per-member capabilities could be read live from OpenMLS via
/// `group.public_group().leaf(idx)?.capabilities()` (see Risk #1 correction
/// in the production refactor plan). This cache is an optimization: avoids
/// tree walks, retains capabilities for members who later leave, and keeps
/// `feature_status` a cheap local lookup.
pub trait CapabilityStorage {
    fn register_feature(
        &self,
        feature: crate::capabilities::Feature,
        req: CapabilityRequirement,
    ) -> StorageResult<()>;

    fn feature_requirement(
        &self,
        feature: &crate::capabilities::Feature,
    ) -> StorageResult<Option<CapabilityRequirement>>;

    fn save_member_capabilities(
        &self,
        group_id: &GroupId,
        member: &Member,
        capabilities: GroupCapabilities,
    ) -> StorageResult<()>;

    fn member_capabilities(
        &self,
        group_id: &GroupId,
        member_id: &MemberId,
    ) -> StorageResult<Option<GroupCapabilities>>;
}

// ── StorageProvider aggregate ───────────────────────────────────────────────

/// The single type parameter carried by the engine. Composes every Marmot
/// storage concern plus an **accessor** to the OpenMLS storage side.
///
/// **Design note vs. `plans/2026-04-22-cgka-engine-production-refactor-v1.md`
/// Task 2.5.** The plan originally described this as a direct-supertrait
/// composition with `openmls_traits::storage::StorageProvider<CURRENT_VERSION>`.
/// In practice that would force the Marmot storage struct to hand-forward all
/// 50+ OpenMLS trait methods — purely mechanical, zero value. An accessor
/// (`mls_storage()`) gives the engine exactly the same capability: it can
/// construct an `OpenMlsProvider` bundle (crypto + rand + this storage) when
/// invoking MLS operations, and can treat the Marmot traits as a separate
/// set. The functional contract is unchanged.
pub trait StorageProvider:
    GroupStorage + MessageStorage + WelcomeStorage + CapabilityStorage + Send + Sync
{
    /// Concrete OpenMLS storage type this provider owns.
    type Mls: OpenMlsStorageProvider<CURRENT_VERSION> + Send + Sync;

    /// Reference to the OpenMLS storage side. Used by the engine to construct
    /// `OpenMlsProvider`-shaped objects for MLS operations.
    fn mls_storage(&self) -> &Self::Mls;

    fn backend(&self) -> Backend;
}
