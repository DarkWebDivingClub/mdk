//! Concrete [`GroupContext`] view returned by `Engine::group_context`.
//!
//! Eagerly evaluates the group's epoch and a fixed set of well-known
//! exporter secrets at construction time; subsequent queries are cheap
//! local lookups. Unknown labels return `None`.
//!
//! For peelers' use, prefer `GroupContextSnapshot::from_context(view, &[..])`
//! which materializes an isolated copy with only the labels a specific
//! peeler is permitted to see.

use cgka_traits::group_context::GroupContext;
use cgka_traits::types::EpochId;
use std::collections::HashMap;

pub struct GroupContextView {
    epoch: EpochId,
    secrets: HashMap<String, Vec<u8>>,
    transport_group_id: Option<Vec<u8>>,
}

impl GroupContextView {
    pub(crate) fn new(
        epoch: EpochId,
        secrets: HashMap<String, Vec<u8>>,
        transport_group_id: Option<Vec<u8>>,
    ) -> Self {
        Self {
            epoch,
            secrets,
            transport_group_id,
        }
    }
}

impl GroupContext for GroupContextView {
    fn epoch(&self) -> EpochId {
        self.epoch
    }

    fn exporter_secret(&self, label: &str, length: usize) -> Option<Vec<u8>> {
        self.secrets
            .get(label)
            .map(|s| s.iter().take(length).copied().collect())
    }

    fn transport_group_id(&self) -> Option<Vec<u8>> {
        self.transport_group_id.clone()
    }
}
