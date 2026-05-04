//! NostrMlsPeeler — the explicit seam between Nostr transport and the MLS CGKA.
//!
//! Two wire formats:
//!   * Group messages: Nostr kind 445, content = ChaCha20Poly1305(exporter_secret,
//!     nonce || mls_bytes), h-tag = hex(nostr_group_id). Ephemeral signer.
//!   * Welcomes: Nostr kind 1059 gift-wrap per NIP-59. Inner rumor is kind 444
//!     whose content is base64(MLS welcome bytes).

use async_trait::async_trait;
use base64::Engine as _;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

use cgka_engine::{
    EncryptedPayload, GroupContextSnapshot, MemberId, MessageId, MessageType, OrderingMetadata,
    PeeledMessage, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use nostr::{
    event::{EventBuilder, Kind, Tag, UnsignedEvent},
    key::{Keys, PublicKey, SecretKey},
    Event, JsonUtil,
};
use transport::{PeelerError, TransportPeeler};

const EXPORTER_LABEL: &str = "nostr";
const KIND_KEY_PACKAGE: u16 = 30443;
const KIND_GROUP_MESSAGE: u16 = 445;
const KIND_WELCOME_RUMOR: u16 = 444;

pub const KIND_GROUP_MESSAGE_U16: u16 = KIND_GROUP_MESSAGE;
pub const KIND_WELCOME_GIFTWRAP_U16: u16 = 1059;
pub const KIND_KEY_PACKAGE_U16: u16 = KIND_KEY_PACKAGE;

pub struct NostrMlsPeeler {
    local_keys: Keys,
}

impl NostrMlsPeeler {
    pub fn new(local_secret: SecretKey) -> Self {
        Self {
            local_keys: Keys::new(local_secret),
        }
    }

    pub fn local_pubkey(&self) -> PublicKey {
        self.local_keys.public_key()
    }

    fn exporter_key(ctx: &GroupContextSnapshot) -> Result<chacha20poly1305::Key, PeelerError> {
        let secret = ctx
            .exporter_secret(EXPORTER_LABEL)
            .ok_or_else(|| PeelerError::Other("no exporter secret for 'nostr' label".into()))?;
        Ok(*chacha20poly1305::Key::from_slice(&secret))
    }

    fn nostr_group_id_hex(ctx: &GroupContextSnapshot) -> Result<String, PeelerError> {
        let id = ctx
            .transport_group_id
            .clone()
            .ok_or_else(|| PeelerError::Other("no transport_group_id in context".into()))?;
        Ok(hex::encode(id))
    }
}

#[async_trait]
impl TransportPeeler for NostrMlsPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        let event = Event::from_json(&msg.payload)
            .map_err(|e| PeelerError::Malformed(format!("event json: {e:?}")))?;
        if event.kind.as_u16() != KIND_GROUP_MESSAGE {
            return Err(PeelerError::Malformed(format!(
                "expected kind 445, got {}",
                event.kind.as_u16()
            )));
        }
        let ct_bundle = base64::engine::general_purpose::STANDARD
            .decode(event.content.as_bytes())
            .map_err(|e| PeelerError::Malformed(format!("b64: {e:?}")))?;
        if ct_bundle.len() < 12 {
            return Err(PeelerError::Malformed("ciphertext too short".into()));
        }
        let (nonce_bytes, ct) = ct_bundle.split_at(12);
        let cipher = ChaCha20Poly1305::new(&Self::exporter_key(ctx)?);
        let pt = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|e| PeelerError::Decrypt(format!("chacha: {e:?}")))?;

        Ok(PeeledMessage {
            id: msg.id,
            // Real type is determined by the MLS parser; the peeler can't tell without
            // a decode pass — application is a safe default hint.
            message_type: MessageType::Application,
            payload: pt,
            ordering_metadata: OrderingMetadata::default(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        let event = Event::from_json(&msg.payload)
            .map_err(|e| PeelerError::Malformed(format!("event json: {e:?}")))?;
        if event.kind != Kind::GiftWrap {
            return Err(PeelerError::Malformed(format!(
                "expected gift wrap (1059), got {}",
                event.kind.as_u16()
            )));
        }

        // NIP-59 gift wrap → seal → rumor.
        let unwrapped = nostr::nips::nip59::extract_rumor(&self.local_keys, &event)
            .await
            .map_err(|e| PeelerError::Decrypt(format!("nip59 extract: {e:?}")))?;
        let rumor: UnsignedEvent = unwrapped.rumor;
        if rumor.kind.as_u16() != KIND_WELCOME_RUMOR {
            return Err(PeelerError::Malformed(format!(
                "welcome rumor kind mismatch: {}",
                rumor.kind.as_u16()
            )));
        }

        // Inner rumor content = base64(MLS welcome bytes).
        let mls_bytes = base64::engine::general_purpose::STANDARD
            .decode(rumor.content.as_bytes())
            .map_err(|e| PeelerError::Malformed(format!("welcome b64: {e:?}")))?;

        Ok(PeeledMessage {
            id: msg.id,
            message_type: MessageType::Welcome,
            payload: mls_bytes,
            ordering_metadata: OrderingMetadata::default(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        let key = Self::exporter_key(ctx)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), payload.bytes.as_slice())
            .map_err(|e| PeelerError::Encrypt(format!("chacha: {e:?}")))?;
        let mut bundle = Vec::with_capacity(12 + ct.len());
        bundle.extend_from_slice(&nonce_bytes);
        bundle.extend_from_slice(&ct);
        let content = base64::engine::general_purpose::STANDARD.encode(&bundle);

        let group_id_hex = Self::nostr_group_id_hex(ctx)?;

        // Ephemeral signer per target-architecture §"The outer envelope is purely a
        // transport concern" — relay operators must not see the sender's identity.
        let ephemeral = Keys::generate();
        let tag = Tag::parse(vec!["h".to_string(), group_id_hex.clone()])
            .map_err(|e| PeelerError::Other(format!("tag parse: {e:?}")))?;
        let event = EventBuilder::new(Kind::Custom(KIND_GROUP_MESSAGE), content)
            .tags([tag])
            .sign(&ephemeral)
            .await
            .map_err(|e| PeelerError::Other(format!("sign: {e:?}")))?;

        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(event.id.as_bytes());

        Ok(TransportMessage {
            id: MessageId(id_bytes),
            payload: event.as_json().into_bytes(),
            timestamp: Timestamp(event.created_at.as_u64()),
            causal_deps: Vec::new(),
            source: TransportSource::Nostr,
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: hex::decode(&group_id_hex).unwrap_or_default(),
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let recipient_pk = PublicKey::from_slice(&recipient.0)
            .map_err(|e| PeelerError::Other(format!("recipient pk: {e:?}")))?;

        // Inner rumor: kind 444, content = base64(mls welcome bytes). Unsigned.
        let content_b64 = base64::engine::general_purpose::STANDARD.encode(&payload.bytes);
        let rumor = EventBuilder::new(Kind::Custom(KIND_WELCOME_RUMOR), content_b64)
            .build(self.local_keys.public_key());

        // Gift-wrap it for the recipient. Our keys are the sender side; NIP-59 uses
        // an ephemeral sender identity internally so relay operators can't attribute.
        let wrap = EventBuilder::gift_wrap(&self.local_keys, &recipient_pk, rumor, [])
            .await
            .map_err(|e| PeelerError::Encrypt(format!("gift_wrap: {e:?}")))?;

        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(wrap.id.as_bytes());

        Ok(TransportMessage {
            id: MessageId(id_bytes),
            payload: wrap.as_json().into_bytes(),
            timestamp: Timestamp(wrap.created_at.as_u64()),
            causal_deps: Vec::new(),
            source: TransportSource::Nostr,
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}
