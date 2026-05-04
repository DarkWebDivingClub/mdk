//! Stored message records and their state machine.
//!
//! The state machine matches `cgka-engine-design.md:48-54`: messages live in
//! a typed state that the engine + coordinator walk through as processing
//! progresses. Kept here (and not inside the engine) so the storage backend
//! can query "what's retryable?" without cracking engine internals.

use crate::types::{EpochId, GroupId, MessageId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: MessageId,
    pub group_id: GroupId,
    pub epoch: EpochId,
    pub state: MessageState,
    pub payload: Vec<u8>,
}

/// Per-message state.
///
/// Transitions:
///   `Sent` → `Sent` (outbound message recorded for durable own-echo checks)
///   `Created` → `Processed` (happy path after successful ingest)
///   `Created` → `Failed` (terminal error — no retry)
///   `Created` → `Retryable` (transient error — can be re-tried later)
///   `Retryable` → `Processed` (retry succeeded)
///   any → `EpochInvalidated` (group forked past; message will never apply)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageState {
    /// Locally produced outbound message. If the transport echoes it back,
    /// the engine can classify it as `OwnEcho` even after restart.
    Sent,
    /// Stored but not yet processed.
    Created,
    /// Successfully applied to the group state.
    Processed,
    /// Terminal failure — do not retry.
    Failed,
    /// Transient failure — eligible for retry (e.g. awaiting out-of-order
    /// commit that hasn't arrived yet).
    Retryable,
    /// The epoch this message targets has been superseded by a fork recovery
    /// transition; the message will never apply. Kept for audit.
    EpochInvalidated,
}
