//! The two MLS extension types this spike registers. The split of the current
//! monolithic NostrGroupDataExtension into a basic + nostr-specific pair is the
//! core architectural bet we are testing.

use serde::{Deserialize, Serialize};

/// Transport-agnostic group metadata. Required in every group.
pub const BASIC_GROUP_DATA_EXT_TYPE: u16 = 0xF2EA;

/// Nostr-transport-specific metadata. Required only when Nostr transport is active.
pub const NOSTR_TRANSPORT_DATA_EXT_TYPE: u16 = 0xF2EB;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicGroupData {
    pub name: String,
    pub description: String,
    pub image_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrTransportData {
    pub nostr_group_id: [u8; 32],
    pub relays: Vec<String>,
}

impl BasicGroupData {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("basicgroupdata encode")
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }
}

impl NostrTransportData {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("nostrtransportdata encode")
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }
}
