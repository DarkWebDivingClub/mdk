use crate::{
    GROUP_TAG, KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP, NOSTR_SOURCE, NostrPeelerError,
    RECIPIENT_TAG,
};
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::types::{MemberId, MessageId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const CAUSAL_DEP_TAG: &str = "e";

/// Nostr event shape consumed and produced at the peeler boundary.
///
/// This is intentionally a small DTO instead of a relay client type. A Nostr
/// adapter can map real SDK events into this value after subscription, and map
/// locally wrapped events back into SDK builders before signing/publishing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrTransportEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl NostrTransportEvent {
    /// Convert a Nostr event into the raw transport message the engine ingests.
    pub fn to_transport_message(&self) -> Result<TransportMessage, NostrPeelerError> {
        let id = MessageId::new(decode_hex_exact("event id", &self.id, 32)?);
        let causal_deps = self
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|name| name == CAUSAL_DEP_TAG))
            .filter_map(|tag| tag.get(1))
            .map(|value| decode_hex_exact("causal dependency id", value, 32).map(MessageId::new))
            .collect::<Result<Vec<_>, _>>()?;
        let envelope = match self.kind {
            KIND_MARMOT_GROUP_MESSAGE => {
                let group_id = self
                    .tag_value(GROUP_TAG)
                    .ok_or_else(|| NostrPeelerError::MissingTag(GROUP_TAG.into()))?;
                TransportEnvelope::GroupMessage {
                    transport_group_id: decode_hex("group h tag", group_id)?,
                }
            }
            KIND_NIP59_GIFT_WRAP => {
                let recipient = self
                    .tag_value(RECIPIENT_TAG)
                    .ok_or_else(|| NostrPeelerError::MissingTag(RECIPIENT_TAG.into()))?;
                TransportEnvelope::Welcome {
                    recipient: MemberId::new(decode_hex_exact("recipient p tag", recipient, 32)?),
                }
            }
            other => return Err(NostrPeelerError::UnsupportedKind(other)),
        };

        Ok(TransportMessage {
            id,
            payload: serde_json::to_vec(self)
                .map_err(|e| NostrPeelerError::Malformed(e.to_string()))?,
            timestamp: Timestamp(self.created_at),
            causal_deps,
            source: TransportSource(NOSTR_SOURCE.into()),
            envelope,
        })
    }

    /// Parse the Nostr DTO carried as a [`TransportMessage`] payload.
    pub fn from_transport_message(msg: &TransportMessage) -> Result<Self, NostrPeelerError> {
        serde_json::from_slice(&msg.payload).map_err(|e| NostrPeelerError::Malformed(e.to_string()))
    }

    /// Return the first value for a Nostr tag name.
    pub fn tag_value(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
    }

    pub(crate) fn new_local(
        pubkey: String,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Self {
        let created_at = now_unix_seconds();
        let id = pre_signing_id(&pubkey, created_at, kind, &tags, &content);
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
        }
    }
}

#[derive(Serialize)]
struct EventCore<'a> {
    pubkey: &'a str,
    created_at: u64,
    kind: u64,
    tags: &'a [Vec<String>],
    content: &'a str,
}

fn pre_signing_id(
    pubkey: &str,
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    let core = EventCore {
        pubkey,
        created_at,
        kind,
        tags,
        content,
    };
    let bytes = serde_json::to_vec(&core).expect("serializing EventCore should not fail");
    hex::encode(Sha256::digest(bytes))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>, NostrPeelerError> {
    hex::decode(value).map_err(|e| NostrPeelerError::Malformed(format!("invalid hex {label}: {e}")))
}

pub(crate) fn decode_hex_exact(
    label: &str,
    value: &str,
    expected_len: usize,
) -> Result<Vec<u8>, NostrPeelerError> {
    let bytes = decode_hex(label, value)?;
    if bytes.len() != expected_len {
        return Err(NostrPeelerError::Malformed(format!(
            "{label} must be {expected_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_445_event_maps_to_group_transport_message() {
        let event = NostrTransportEvent {
            id: "11".repeat(32),
            pubkey: "22".repeat(32),
            created_at: 1_700_000_000,
            kind: KIND_MARMOT_GROUP_MESSAGE,
            tags: vec![
                vec!["h".into(), "aa55".into()],
                vec!["e".into(), "99".repeat(32)],
            ],
            content: "encrypted body".into(),
        };

        let msg = event.to_transport_message().expect("event maps");

        assert_eq!(msg.id.as_slice(), vec![0x11; 32].as_slice());
        assert_eq!(msg.timestamp.0, 1_700_000_000);
        assert_eq!(msg.source.0, NOSTR_SOURCE);
        assert_eq!(msg.causal_deps[0].as_slice(), vec![0x99; 32].as_slice());
        assert_eq!(
            msg.envelope,
            TransportEnvelope::GroupMessage {
                transport_group_id: vec![0xaa, 0x55],
            }
        );
        assert_eq!(
            NostrTransportEvent::from_transport_message(&msg).expect("payload parses"),
            event
        );
    }

    #[test]
    fn kind_1059_event_maps_to_welcome_transport_message() {
        let event = NostrTransportEvent {
            id: "33".repeat(32),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: KIND_NIP59_GIFT_WRAP,
            tags: vec![vec!["p".into(), "55".repeat(32)]],
            content: "gift wrap body".into(),
        };

        let msg = event.to_transport_message().expect("event maps");

        assert_eq!(
            msg.envelope,
            TransportEnvelope::Welcome {
                recipient: MemberId::new(vec![0x55; 32]),
            }
        );
        assert_eq!(
            NostrTransportEvent::from_transport_message(&msg).expect("payload parses"),
            event
        );
    }
}
