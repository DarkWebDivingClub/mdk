use std::time::{SystemTime, UNIX_EPOCH};

use cgka_traits::message::MessageState;
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::EpochId;
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn serialize<T: Serialize>(value: &T) -> StorageResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub(crate) fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
    serde_json::from_slice(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub(crate) trait SqliteResultExt<T> {
    fn storage(self) -> StorageResult<T>;
}

impl<T> SqliteResultExt<T> for rusqlite::Result<T> {
    fn storage(self) -> StorageResult<T> {
        self.map_err(|e| StorageError::Backend(e.to_string()))
    }
}

pub(crate) fn message_state_to_i64(state: MessageState) -> i64 {
    match state {
        MessageState::Sent => 0,
        MessageState::Created => 1,
        MessageState::Processed => 2,
        MessageState::Failed => 3,
        MessageState::Retryable => 4,
        MessageState::EpochInvalidated => 5,
        MessageState::PeelDeferred => 6,
    }
}

pub(crate) fn epoch_to_i64(epoch: EpochId) -> StorageResult<i64> {
    i64::try_from(epoch.0)
        .map_err(|_| StorageError::Serialization(format!("epoch too large: {}", epoch.0)))
}

pub(crate) fn created_at_to_i64(created_at_ms: u64) -> StorageResult<i64> {
    i64::try_from(created_at_ms).map_err(|_| {
        StorageError::Serialization(format!("created_at_ms too large: {created_at_ms}"))
    })
}

/// Encode a `bool` as the SQLite integer convention (`1`/`0`).
pub(crate) fn bool_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

/// Convert a `u64` to SQLite's signed `INTEGER`, erroring if it overflows `i64`.
pub(crate) fn u64_to_i64(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::Serialization(format!("value does not fit in sqlite INTEGER: {value}"))
    })
}

/// Convert an optional `u64` to SQLite's signed `INTEGER`, preserving `None`.
pub(crate) fn optional_u64_to_i64(value: Option<u64>) -> StorageResult<Option<i64>> {
    value.map(u64_to_i64).transpose()
}

/// Convert a `usize` to SQLite's signed `INTEGER`, erroring if it overflows `i64`.
pub(crate) fn usize_to_i64(value: usize) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::Serialization(format!("value does not fit in sqlite INTEGER: {value}"))
    })
}

/// Decode a JSON tag array as stored in projection rows.
pub(crate) fn tags_from_json(json: String) -> Result<Vec<Vec<String>>, serde_json::Error> {
    serde_json::from_str(&json)
}

/// Current wall-clock milliseconds since the Unix epoch, saturating at `i64::MAX`.
pub(crate) fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

/// Current wall-clock seconds since the Unix epoch.
pub(crate) fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Current wall-clock seconds since the Unix epoch, saturating at `i64::MAX`.
pub(crate) fn unix_now_seconds_i64() -> i64 {
    i64::try_from(unix_now_seconds()).unwrap_or(i64::MAX)
}
