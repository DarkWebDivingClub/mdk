//! NostrAdapter — a `TransportAdapter` over `wss://...` relays via nostr-sdk.
//!
//! Also exposes helpers for publishing/fetching kind 30443 KeyPackage events
//! that live above the adapter trait but below the application layer.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use futures::stream::BoxStream;
use tokio::sync::mpsc::unbounded_channel;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt;

use nostr::{
    event::{Event, EventBuilder, Kind},
    filter::Filter,
    key::{Keys, PublicKey},
    Alphabet, JsonUtil, SingleLetterTag,
};
use nostr_sdk::{Client, RelayPoolNotification};

use cgka_engine::{
    GroupId, MemberId, MessageId, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use transport::{PublishConfirmation, TransportAdapter, TransportError, TransportStatus};

const KIND_KEY_PACKAGE: u16 = 30443;
const KIND_GROUP_MESSAGE: u16 = 445;
const KIND_GIFT_WRAP: u16 = 1059;

pub struct NostrAdapter {
    client: Client,
    keys: Keys,
}

impl NostrAdapter {
    pub async fn new(keys: Keys, relays: Vec<String>) -> Result<Self, TransportError> {
        let client = Client::new(keys.clone());
        for relay in &relays {
            client
                .add_relay(relay.as_str())
                .await
                .map_err(|e| TransportError::Other(format!("add_relay: {e:?}")))?;
        }
        client.connect().await;
        Ok(Self { client, keys })
    }

    pub fn local_keys(&self) -> &Keys {
        &self.keys
    }

    pub fn local_pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Publish a serialised MLS KeyPackage as a signed kind 30443 event.
    pub async fn publish_key_package(&self, mls_bytes: &[u8]) -> Result<(), TransportError> {
        let content = base64::engine::general_purpose::STANDARD.encode(mls_bytes);
        let builder = EventBuilder::new(Kind::Custom(KIND_KEY_PACKAGE), content);
        self.client
            .send_event_builder(builder)
            .await
            .map_err(|e| TransportError::Publish(format!("kp publish: {e:?}")))?;
        Ok(())
    }

    /// Fetch the latest KeyPackage published by `pubkey`. Returns its decoded MLS bytes.
    pub async fn fetch_key_package(
        &self,
        pubkey: PublicKey,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_KEY_PACKAGE))
            .author(pubkey)
            .limit(1);
        let events = self
            .client
            .fetch_events(filter, Duration::from_secs(8))
            .await
            .map_err(|e| TransportError::Fetch(format!("fetch kp: {e:?}")))?;
        let first = events.into_iter().next();
        match first {
            None => Ok(None),
            Some(event) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(event.content.as_bytes())
                    .map_err(|e| TransportError::Fetch(format!("b64: {e:?}")))?;
                Ok(Some(bytes))
            }
        }
    }
}

fn event_to_group_tm(event: Event, transport_group_id: Vec<u8>) -> TransportMessage {
    let mut id_bytes = [0u8; 32];
    id_bytes.copy_from_slice(event.id.as_bytes());
    let ts = event.created_at.as_u64();
    let payload = event.as_json().into_bytes();
    TransportMessage {
        id: MessageId(id_bytes),
        payload,
        timestamp: Timestamp(ts),
        causal_deps: Vec::new(),
        source: TransportSource::Nostr,
        envelope: TransportEnvelope::GroupMessage { transport_group_id },
    }
}

fn event_to_welcome_tm(event: Event, recipient: MemberId) -> TransportMessage {
    let mut id_bytes = [0u8; 32];
    id_bytes.copy_from_slice(event.id.as_bytes());
    let ts = event.created_at.as_u64();
    let payload = event.as_json().into_bytes();
    TransportMessage {
        id: MessageId(id_bytes),
        payload,
        timestamp: Timestamp(ts),
        causal_deps: Vec::new(),
        source: TransportSource::Nostr,
        envelope: TransportEnvelope::Welcome { recipient },
    }
}

#[async_trait]
impl TransportAdapter for NostrAdapter {
    fn name(&self) -> &'static str {
        "nostr"
    }

    async fn publish(
        &self,
        msg: &TransportMessage,
    ) -> Result<PublishConfirmation, TransportError> {
        let event = Event::from_json(&msg.payload)
            .map_err(|e| TransportError::Publish(format!("parse: {e:?}")))?;
        self.client
            .send_event(&event)
            .await
            .map_err(|e| TransportError::Publish(format!("{e:?}")))?;
        Ok(PublishConfirmation {
            adapter_name: "nostr",
        })
    }

    async fn subscribe_group(
        &self,
        transport_group_id: &[u8],
    ) -> Result<BoxStream<'static, TransportMessage>, TransportError> {
        let group_id_hex = hex::encode(transport_group_id);
        // Only care about messages from now-onward. Without `since`, the relay can
        // deliver backlog events encrypted to epochs we don't have secrets for —
        // which produces noisy peeler decrypt errors for pre-join history.
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_GROUP_MESSAGE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::H), group_id_hex.clone())
            .since(nostr::Timestamp::now());
        let sub = self
            .client
            .subscribe(filter, None)
            .await
            .map_err(|e| TransportError::Subscribe(format!("{e:?}")))?;
        let sub_id = sub.val;

        let (tx, rx) = unbounded_channel::<TransportMessage>();
        let mut notif = self.client.notifications();
        let tgid = transport_group_id.to_vec();
        tokio::spawn(async move {
            while let Ok(n) = notif.recv().await {
                if let RelayPoolNotification::Event {
                    subscription_id,
                    event,
                    ..
                } = n
                {
                    if subscription_id == sub_id {
                        let tm = event_to_group_tm(*event, tgid.clone());
                        if tx.send(tm).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Box::pin(UnboundedReceiverStream::new(rx)))
    }

    async fn subscribe_welcomes(
        &self,
    ) -> Result<BoxStream<'static, TransportMessage>, TransportError> {
        let my_pk = self.keys.public_key();
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_GIFT_WRAP))
            .pubkey(my_pk);
        let sub = self
            .client
            .subscribe(filter, None)
            .await
            .map_err(|e| TransportError::Subscribe(format!("{e:?}")))?;
        let sub_id = sub.val;

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&my_pk.to_bytes());
        let recipient = MemberId(pk_bytes);

        let (tx, rx) = unbounded_channel::<TransportMessage>();
        let mut notif = self.client.notifications();
        tokio::spawn(async move {
            while let Ok(n) = notif.recv().await {
                if let RelayPoolNotification::Event {
                    subscription_id,
                    event,
                    ..
                } = n
                {
                    if subscription_id == sub_id {
                        let tm = event_to_welcome_tm(*event, recipient.clone());
                        if tx.send(tm).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Box::pin(UnboundedReceiverStream::new(rx)))
    }

    async fn fetch(
        &self,
        _group_id: &GroupId,
        _since: u64,
    ) -> Result<Vec<TransportMessage>, TransportError> {
        // Not implemented in spike.
        Ok(Vec::new())
    }

    fn status(&self) -> TransportStatus {
        TransportStatus::Connected
    }

    fn group_extension(&self) -> Option<(u16, Vec<u8>)> {
        // The NostrTransportData extension content requires the nostr_group_id the
        // engine is about to generate. In the target design the adapter owns it; in
        // the spike the engine constructs it to keep the spike boundary simple.
        None
    }
}

// StreamExt is unused at runtime but pulled in so the BoxStream return type works
// nicely if consumers want to map/filter. Silence unused warning.
#[allow(dead_code)]
fn _streamext_used<S: StreamExt>(_: S) {}
