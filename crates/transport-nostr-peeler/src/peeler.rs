use crate::error::to_peeler_error;
use crate::event::{decode_hex, decode_hex_exact};
use crate::{
    DEFAULT_EXPORTER_LABEL, GROUP_TAG, KIND_MARMOT_GROUP_MESSAGE, NOSTR_GROUP_KEY_LEN,
    NostrTransportEvent,
};
use async_trait::async_trait;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{GroupId, MemberId};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const NONCE_LEN: usize = 12;
const GROUP_CONTENT_VERSION: u8 = 1;

/// Nostr implementation of the Marmot transport peeler.
#[derive(Clone, Debug)]
pub struct NostrMlsPeeler {
    exporter_label: String,
    author_pubkey: String,
}

impl NostrMlsPeeler {
    /// Build a peeler with the current engine exporter label and an author
    /// public key. A real adapter signs the resulting event before publishing.
    pub fn new(author_pubkey: impl Into<String>) -> Self {
        Self {
            exporter_label: DEFAULT_EXPORTER_LABEL.into(),
            author_pubkey: author_pubkey.into(),
        }
    }

    /// Override the exporter label used for kind-445 group envelopes.
    pub fn with_exporter_label(mut self, label: impl Into<String>) -> Self {
        self.exporter_label = label.into();
        self
    }

    fn group_key<'a>(&self, ctx: &'a GroupContextSnapshot) -> Result<&'a [u8], PeelerError> {
        let secret = ctx.exporter_secret(&self.exporter_label).ok_or_else(|| {
            PeelerError::MissingContext {
                label: self.exporter_label.clone(),
            }
        })?;
        if secret.len() != NOSTR_GROUP_KEY_LEN {
            return Err(PeelerError::MissingContext {
                label: format!("{} (must be 32 bytes)", self.exporter_label),
            });
        }
        Ok(secret)
    }
}

impl Default for NostrMlsPeeler {
    fn default() -> Self {
        Self::new("00".repeat(32))
    }
}

#[async_trait]
impl TransportPeeler for NostrMlsPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        let event = NostrTransportEvent::from_transport_message(msg).map_err(to_peeler_error)?;
        if event.kind != KIND_MARMOT_GROUP_MESSAGE {
            return Err(PeelerError::Malformed(format!(
                "expected kind {KIND_MARMOT_GROUP_MESSAGE}, got {}",
                event.kind
            )));
        }
        ensure_group_routing_matches(&event, msg)?;

        let content: GroupEnvelopeContent = serde_json::from_str(&event.content)
            .map_err(|e| PeelerError::Malformed(e.to_string()))?;
        if content.version != GROUP_CONTENT_VERSION {
            return Err(PeelerError::Malformed(format!(
                "unsupported group envelope version {}",
                content.version
            )));
        }

        let key = self.group_key(ctx)?;
        let nonce =
            decode_hex_exact("group nonce", &content.nonce, NONCE_LEN).map_err(to_peeler_error)?;
        let ciphertext =
            decode_hex("group ciphertext", &content.ciphertext).map_err(to_peeler_error)?;
        let aad = decode_hex("group aad", &content.aad).map_err(to_peeler_error)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| PeelerError::DecryptFailed)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| PeelerError::DecryptFailed)?;
        let sender = decode_hex_exact("event pubkey", &event.pubkey, 32)
            .ok()
            .map(MemberId::new);

        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: transport_group_id(msg),
            sender,
            content: PeeledContent::MlsMessage { bytes: plaintext },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, _msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::DecryptFailed)
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        let group_id = ctx
            .transport_group_id()
            .ok_or_else(|| PeelerError::MissingContext {
                label: "transport_group_id".into(),
            })?;
        let key = self.group_key(ctx)?;
        let mut nonce = [0_u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| PeelerError::WrapFailed(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &payload.ciphertext,
                    aad: &payload.aad,
                },
            )
            .map_err(|_| PeelerError::WrapFailed("group encryption failed".into()))?;
        let content = GroupEnvelopeContent {
            version: GROUP_CONTENT_VERSION,
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
            aad: hex::encode(&payload.aad),
        };
        let event = NostrTransportEvent::new_local(
            self.author_pubkey.clone(),
            KIND_MARMOT_GROUP_MESSAGE,
            vec![vec![GROUP_TAG.into(), hex::encode(group_id)]],
            serde_json::to_string(&content).map_err(|e| PeelerError::WrapFailed(e.to_string()))?,
        );
        event.to_transport_message().map_err(to_peeler_error)
    }

    async fn wrap_welcome(
        &self,
        _payload: &EncryptedPayload,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::WrapFailed(
            "NIP-59 welcome gift wrapping requires signer/decrypter integration".into(),
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct GroupEnvelopeContent {
    version: u8,
    nonce: String,
    ciphertext: String,
    aad: String,
}

fn transport_group_id(msg: &TransportMessage) -> Option<GroupId> {
    match &msg.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => {
            Some(GroupId::new(transport_group_id.clone()))
        }
        TransportEnvelope::Welcome { .. } => None,
    }
}

fn ensure_group_routing_matches(
    event: &NostrTransportEvent,
    msg: &TransportMessage,
) -> Result<(), PeelerError> {
    let event_group_id = event
        .tag_value(GROUP_TAG)
        .ok_or_else(|| PeelerError::Malformed("missing h tag".into()))
        .and_then(|h| decode_hex("group h tag", h).map_err(to_peeler_error))?;
    match &msg.envelope {
        TransportEnvelope::GroupMessage { transport_group_id }
            if *transport_group_id == event_group_id =>
        {
            Ok(())
        }
        TransportEnvelope::GroupMessage { .. } => Err(PeelerError::Malformed(
            "event h tag does not match transport envelope".into(),
        )),
        TransportEnvelope::Welcome { .. } => Err(PeelerError::Malformed(
            "group peeler received welcome envelope".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_EXPORTER_LABEL, KIND_MARMOT_GROUP_MESSAGE};
    use cgka_traits::group_context::GroupContextSnapshot;
    use cgka_traits::ingest::PeeledContent;
    use cgka_traits::types::EpochId;
    use std::collections::HashMap;

    #[tokio::test]
    async fn group_wrap_and_peel_round_trips_mls_bytes() {
        let secret = vec![0x7a; NOSTR_GROUP_KEY_LEN];
        let group_id = vec![0x99; 32];
        let ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), secret)]),
            Some(group_id.clone()),
        );
        let peeler = NostrMlsPeeler::default();

        let wrapped = peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: b"aad".to_vec(),
                },
                &ctx,
            )
            .await
            .expect("wrap succeeds");

        assert!(matches!(
            wrapped.envelope,
            TransportEnvelope::GroupMessage {
                ref transport_group_id,
            } if *transport_group_id == group_id
        ));

        let event = NostrTransportEvent::from_transport_message(&wrapped).expect("payload parses");
        assert_eq!(event.kind, KIND_MARMOT_GROUP_MESSAGE);
        assert_eq!(event.tag_value("h"), Some(hex::encode(&group_id).as_str()));

        let peeled = peeler
            .peel_group_message(&wrapped, &ctx)
            .await
            .expect("peel succeeds");

        assert_eq!(peeled.id, wrapped.id);
        assert_eq!(
            peeled.content,
            PeeledContent::MlsMessage {
                bytes: b"inner mls bytes".to_vec(),
            }
        );
    }

    #[tokio::test]
    async fn group_peel_with_wrong_secret_fails_cleanly() {
        let group_id = vec![0x99; 32];
        let wrap_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(group_id),
        );
        let peel_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7b; 32])]),
            None,
        );
        let peeler = NostrMlsPeeler::default();
        let wrapped = peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &wrap_ctx,
            )
            .await
            .expect("wrap succeeds");

        let err = peeler
            .peel_group_message(&wrapped, &peel_ctx)
            .await
            .expect_err("wrong secret should not decrypt");

        assert!(matches!(err, PeelerError::DecryptFailed));
    }

    #[tokio::test]
    async fn group_peel_rejects_mismatched_h_tag_and_envelope() {
        let wrap_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            Some(vec![0x99; 32]),
        );
        let peel_ctx = GroupContextSnapshot::new(
            EpochId(9),
            HashMap::from([(DEFAULT_EXPORTER_LABEL.to_string(), vec![0x7a; 32])]),
            None,
        );
        let peeler = NostrMlsPeeler::default();
        let mut wrapped = peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: b"inner mls bytes".to_vec(),
                    aad: vec![],
                },
                &wrap_ctx,
            )
            .await
            .expect("wrap succeeds");
        wrapped.envelope = TransportEnvelope::GroupMessage {
            transport_group_id: vec![0x55; 32],
        };

        let err = peeler
            .peel_group_message(&wrapped, &peel_ctx)
            .await
            .expect_err("mismatched route should not peel");

        assert!(matches!(err, PeelerError::Malformed(_)));
    }
}
