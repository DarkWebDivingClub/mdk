use std::collections::HashMap;

use crate::types::EpochId;

/// Abstract bundle of whatever secret material the current CGKA backend exposes
/// to its paired `TransportPeeler`. Per target-architecture §"The TransportPeeler".
///
/// MLS populates `exporter_secret` (used by the kind 445 outer wrap). A different
/// backend would populate whatever its equivalent is, or return None.
pub trait GroupContext: Send + Sync {
    fn exporter_secret(&self, label: &str) -> Option<[u8; 32]>;
    fn epoch(&self) -> EpochId;
    /// The transport-visible group identifier (e.g. Nostr `h` tag content).
    /// Returned by the transport extension that populates it.
    fn transport_group_id(&self) -> Option<Vec<u8>>;
}

/// Owned snapshot of whatever a GroupContext exposes — passed by value across
/// trait-object async boundaries where `&dyn GroupContext` runs into lifetime
/// issues with `#[async_trait]`. The engine materialises one of these for each
/// peeler call.
#[derive(Clone, Debug, Default)]
pub struct GroupContextSnapshot {
    pub exporter_secrets: HashMap<String, [u8; 32]>,
    pub epoch: EpochId,
    pub transport_group_id: Option<Vec<u8>>,
}

impl GroupContextSnapshot {
    pub fn from_context(ctx: &dyn GroupContext, labels: &[&str]) -> Self {
        let mut map = HashMap::new();
        for label in labels {
            if let Some(s) = ctx.exporter_secret(label) {
                map.insert((*label).to_string(), s);
            }
        }
        Self {
            exporter_secrets: map,
            epoch: ctx.epoch(),
            transport_group_id: ctx.transport_group_id(),
        }
    }

    pub fn exporter_secret(&self, label: &str) -> Option<[u8; 32]> {
        self.exporter_secrets.get(label).copied()
    }
}
