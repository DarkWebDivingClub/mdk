//! # storage-memory
//!
//! Process-local, `Arc`-cloneable in-memory backend for every storage trait
//! in [`cgka_traits`]. Designed for tests, the multi-client harness, and
//! ephemeral runs. SQLite persistence is deferred.
//!
//! ## Cloneability
//!
//! [`MemoryStorage`] is cheaply cloneable. Every clone shares the same
//! underlying data — the struct just bumps `Arc` refcounts. Useful when the
//! harness needs multiple handles into one backend (rare) and mandatory for
//! scenarios where the engine hands its storage to subsystems.
//!
//! For independent per-client storage, call [`MemoryStorage::default()`] per
//! client; each gets its own `Arc`.

use cgka_traits::capabilities::{CapabilityRequirement, Feature, GroupCapabilities};
use cgka_traits::group::{Group, Member};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{
    CapabilityStorage, GroupStorage, MessageStorage, StorageError, StorageProvider, StorageResult,
    WelcomeStorage,
};
use cgka_traits::types::{Backend, EpochId, GroupId, MemberId, MessageId};
use cgka_traits::welcome::PendingWelcome;
use openmls_memory_storage::MemoryStorage as OpenMlsMemStorage;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Default)]
struct Inner {
    groups: HashMap<GroupId, Group>,
    messages: HashMap<MessageId, MessageRecord>,
    message_order: HashMap<MessageId, u64>,
    next_message_order: u64,
    welcomes: HashMap<MessageId, PendingWelcome>,
    features: HashMap<Feature, CapabilityRequirement>,
    member_caps: HashMap<(GroupId, MemberId), GroupCapabilities>,
    /// `(group_id, snapshot_name) -> GroupSnapshot` — captures CGKA metadata
    /// plus the OpenMLS memory map so fork recovery can reload the group at
    /// the snapshot epoch.
    snapshots: HashMap<(GroupId, String), GroupSnapshot>,
}

struct GroupSnapshot {
    group: Group,
    messages: HashMap<MessageId, MessageRecord>,
    message_order: HashMap<MessageId, u64>,
    member_caps: HashMap<MemberId, GroupCapabilities>,
    mls_values: HashMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct MemoryStorage {
    inner: Arc<RwLock<Inner>>,
    // `openmls_memory_storage::MemoryStorage` uses interior mutability but
    // doesn't implement `Clone`. Wrap in `Arc` so `MemoryStorage` is cheaply
    // cloneable — harness clients share access to the same inner state when
    // that's needed, and `Default` gives each fresh backend its own.
    openmls: Arc<OpenMlsMemStorage>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

fn read<T>(lock: &RwLock<T>) -> StorageResult<std::sync::RwLockReadGuard<'_, T>> {
    lock.read()
        .map_err(|e| StorageError::Backend(format!("read lock poisoned: {e}")))
}

fn write<T>(lock: &RwLock<T>) -> StorageResult<std::sync::RwLockWriteGuard<'_, T>> {
    lock.write()
        .map_err(|e| StorageError::Backend(format!("write lock poisoned: {e}")))
}

// ── GroupStorage ────────────────────────────────────────────────────────────

impl GroupStorage for MemoryStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()> {
        write(&self.inner)?
            .groups
            .insert(group.id.clone(), group.clone());
        Ok(())
    }

    fn get_group(&self, id: &GroupId) -> StorageResult<Group> {
        read(&self.inner)?
            .groups
            .get(id)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    fn delete_group(&self, id: &GroupId) -> StorageResult<()> {
        let mut inner = write(&self.inner)?;
        inner.groups.remove(id).ok_or(StorageError::NotFound)?;
        let removed_ids: Vec<MessageId> = inner
            .messages
            .iter()
            .filter(|(_, m)| m.group_id == *id)
            .map(|(id, _)| id.clone())
            .collect();
        inner.messages.retain(|_, m| m.group_id != *id);
        for msg_id in removed_ids {
            inner.message_order.remove(&msg_id);
        }
        inner.member_caps.retain(|(g, _), _| g != id);
        inner.snapshots.retain(|(g, _), _| g != id);
        Ok(())
    }

    fn list_groups(&self) -> StorageResult<Vec<GroupId>> {
        Ok(read(&self.inner)?.groups.keys().cloned().collect())
    }
}

// ── MessageStorage ──────────────────────────────────────────────────────────

impl MessageStorage for MemoryStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()> {
        let mut inner = write(&self.inner)?;
        if !inner.message_order.contains_key(&record.id) {
            let order = inner.next_message_order;
            inner.next_message_order += 1;
            inner.message_order.insert(record.id.clone(), order);
        }
        inner.messages.insert(record.id.clone(), record.clone());
        Ok(())
    }

    fn get_message(&self, id: &MessageId) -> StorageResult<MessageRecord> {
        read(&self.inner)?
            .messages
            .get(id)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()> {
        let mut inner = write(&self.inner)?;
        let rec = inner.messages.get_mut(id).ok_or(StorageError::NotFound)?;
        rec.state = new_state;
        Ok(())
    }

    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        let inner = read(&self.inner)?;
        let mut out: Vec<_> = inner
            .messages
            .values()
            .filter(|m| &m.group_id == group_id && m.epoch >= at_or_after_epoch)
            .cloned()
            .collect();
        out.sort_by_key(|m| inner.message_order.get(&m.id).copied().unwrap_or(u64::MAX));
        Ok(out)
    }

    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        let mut inner = write(&self.inner)?;
        let group = inner
            .groups
            .get(group_id)
            .cloned()
            .ok_or(StorageError::NotFound)?;
        let messages = inner
            .messages
            .iter()
            .filter(|(_, m)| m.group_id == *group_id)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let message_order = inner
            .message_order
            .iter()
            .filter(|(id, _)| {
                inner
                    .messages
                    .get(id)
                    .is_some_and(|m| m.group_id == *group_id)
            })
            .map(|(id, order)| (id.clone(), *order))
            .collect();
        let member_caps = inner
            .member_caps
            .iter()
            .filter(|((g, _), _)| g == group_id)
            .map(|((_, m), caps)| (m.clone(), caps.clone()))
            .collect();
        let mls_values = self
            .openmls
            .values
            .read()
            .map_err(|e| StorageError::Backend(format!("openmls read lock poisoned: {e}")))?
            .clone();
        inner.snapshots.insert(
            (group_id.clone(), name.to_string()),
            GroupSnapshot {
                group,
                messages,
                message_order,
                member_caps,
                mls_values,
            },
        );
        Ok(())
    }

    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        let mut inner = write(&self.inner)?;
        let snap = inner
            .snapshots
            .get(&(group_id.clone(), name.to_string()))
            .ok_or_else(|| StorageError::SnapshotMissing(name.to_string()))?;
        let group = snap.group.clone();
        let messages: Vec<(MessageId, MessageRecord)> = snap
            .messages
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let message_order: Vec<(MessageId, u64)> = snap
            .message_order
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        let member_caps: Vec<((GroupId, MemberId), GroupCapabilities)> = snap
            .member_caps
            .iter()
            .map(|(m, caps)| ((group_id.clone(), m.clone()), caps.clone()))
            .collect();
        let mls_values = snap.mls_values.clone();
        inner.groups.insert(group_id.clone(), group);
        let removed_ids: Vec<MessageId> = inner
            .messages
            .iter()
            .filter(|(_, m)| m.group_id == *group_id)
            .map(|(id, _)| id.clone())
            .collect();
        inner.messages.retain(|_, m| m.group_id != *group_id);
        for id in removed_ids {
            inner.message_order.remove(&id);
        }
        for (id, rec) in messages {
            inner.messages.insert(id, rec);
        }
        for (id, order) in message_order {
            inner.message_order.insert(id, order);
        }
        inner.member_caps.retain(|(g, _), _| g != group_id);
        for (key, caps) in member_caps {
            inner.member_caps.insert(key, caps);
        }
        *self
            .openmls
            .values
            .write()
            .map_err(|e| StorageError::Backend(format!("openmls write lock poisoned: {e}")))? =
            mls_values;
        Ok(())
    }

    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        let mut inner = write(&self.inner)?;
        inner
            .snapshots
            .remove(&(group_id.clone(), name.to_string()))
            .ok_or_else(|| StorageError::SnapshotMissing(name.to_string()))?;
        Ok(())
    }
}

// ── WelcomeStorage ──────────────────────────────────────────────────────────

impl WelcomeStorage for MemoryStorage {
    fn put_welcome(&self, welcome: &PendingWelcome) -> StorageResult<()> {
        write(&self.inner)?
            .welcomes
            .insert(welcome.message_id.clone(), welcome.clone());
        Ok(())
    }

    fn take_welcome(&self, id: &MessageId) -> StorageResult<PendingWelcome> {
        write(&self.inner)?
            .welcomes
            .remove(id)
            .ok_or(StorageError::NotFound)
    }

    fn list_welcomes(&self) -> StorageResult<Vec<PendingWelcome>> {
        Ok(read(&self.inner)?.welcomes.values().cloned().collect())
    }
}

// ── CapabilityStorage ───────────────────────────────────────────────────────

impl CapabilityStorage for MemoryStorage {
    fn register_feature(&self, feature: Feature, req: CapabilityRequirement) -> StorageResult<()> {
        write(&self.inner)?.features.insert(feature, req);
        Ok(())
    }

    fn feature_requirement(
        &self,
        feature: &Feature,
    ) -> StorageResult<Option<CapabilityRequirement>> {
        Ok(read(&self.inner)?.features.get(feature).cloned())
    }

    fn save_member_capabilities(
        &self,
        group_id: &GroupId,
        member: &Member,
        capabilities: GroupCapabilities,
    ) -> StorageResult<()> {
        write(&self.inner)?
            .member_caps
            .insert((group_id.clone(), member.id.clone()), capabilities);
        Ok(())
    }

    fn member_capabilities(
        &self,
        group_id: &GroupId,
        member_id: &MemberId,
    ) -> StorageResult<Option<GroupCapabilities>> {
        Ok(read(&self.inner)?
            .member_caps
            .get(&(group_id.clone(), member_id.clone()))
            .cloned())
    }
}

// ── StorageProvider aggregate ───────────────────────────────────────────────

impl StorageProvider for MemoryStorage {
    type Mls = OpenMlsMemStorage;

    fn mls_storage(&self) -> &Self::Mls {
        self.openmls.as_ref()
    }

    fn backend(&self) -> Backend {
        Backend::InMemory
    }
}

#[cfg(test)]
mod tests;
