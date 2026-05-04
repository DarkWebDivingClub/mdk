use cgka_engine::{EpochId, GroupContext};

/// Snapshot of group context for the peeler. Built on demand by the engine when
/// wrapping/peeling a specific group's messages.
#[derive(Clone)]
pub struct MlsGroupContextSpike {
    pub exporter_secret_nostr: [u8; 32],
    pub epoch_num: u64,
    pub nostr_group_id: Option<Vec<u8>>,
}

impl GroupContext for MlsGroupContextSpike {
    fn exporter_secret(&self, label: &str) -> Option<[u8; 32]> {
        if label == "nostr" {
            Some(self.exporter_secret_nostr)
        } else {
            None
        }
    }
    fn epoch(&self) -> EpochId {
        EpochId(self.epoch_num)
    }
    fn transport_group_id(&self) -> Option<Vec<u8>> {
        self.nostr_group_id.clone()
    }
}
