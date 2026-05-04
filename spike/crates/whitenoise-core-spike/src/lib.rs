//! Thin wiring layer. Holds the engine + a NostrAdapter, runs the fan-in loop
//! from adapter subscriptions into `engine.ingest`, and exposes a small API to
//! the CLI. No persistence, no per-account projections — just enough to prove
//! the architecture end-to-end.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use futures::StreamExt;
use tokio::sync::{broadcast, mpsc, Mutex};

use cgka_engine::{
    Capability, CgkaEngine, Feature, FeatureStatus, GroupEvent, GroupId, IngestOutcome,
    SendIntent, SendResult, StaleReason, TransportKind, TransportMessage,
};
use transport::TransportAdapter;
use mdk_spike::Mdk;
use nostr::key::{Keys, PublicKey, SecretKey};
use nostr_adapter::NostrAdapter;
use nostr_mls_peeler::NostrMlsPeeler;

pub struct Session {
    engine: Arc<Mutex<Mdk>>,
    adapter: Arc<NostrAdapter>,
    keys: Keys,
    my_pk_bytes: [u8; 32],
    event_tx: broadcast::Sender<GroupEvent>,
    inbound_tx: mpsc::UnboundedSender<TransportMessage>,
}

impl Session {
    pub async fn new(secret: SecretKey, relays: Vec<String>) -> Result<Self> {
        Self::new_with_dropped_caps(secret, relays, Vec::new()).await
    }

    pub async fn new_with_dropped_caps(
        secret: SecretKey,
        relays: Vec<String>,
        dropped_caps: Vec<Capability>,
    ) -> Result<Self> {
        let keys = Keys::new(secret.clone());
        let my_pk = keys.public_key();
        let mut my_pk_bytes = [0u8; 32];
        my_pk_bytes.copy_from_slice(&my_pk.to_bytes());

        let peeler = NostrMlsPeeler::new(secret);
        let engine = Arc::new(Mutex::new(Mdk::with_dropped_caps(
            my_pk_bytes,
            Box::new(peeler),
            dropped_caps,
        )?));

        let adapter = Arc::new(NostrAdapter::new(keys.clone(), relays).await?);

        // Publish our KeyPackage (kind 30443) so others can invite us.
        let kp_bytes = {
            let mut e = engine.lock().await;
            e.fresh_key_package()?
        };
        adapter.publish_key_package(&kp_bytes).await?;

        let (event_tx, _) = broadcast::channel::<GroupEvent>(256);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<TransportMessage>();

        // Subscribe to welcomes (kind 1059 addressed to us).
        let welcome_stream = adapter.subscribe_welcomes().await?;
        spawn_forwarder(welcome_stream, inbound_tx.clone());

        // Ingest loop.
        spawn_ingest_loop(
            engine.clone(),
            adapter.clone(),
            inbound_rx,
            inbound_tx.clone(),
            event_tx.clone(),
        );

        Ok(Self {
            engine,
            adapter,
            keys,
            my_pk_bytes,
            event_tx,
            inbound_tx,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<GroupEvent> {
        self.event_tx.subscribe()
    }

    pub async fn create_group(
        &self,
        name: &str,
        description: &str,
        members: Vec<PublicKey>,
    ) -> Result<GroupId> {
        // Fetch each member's latest key package from relays.
        let mut kps = Vec::with_capacity(members.len());
        for pk in &members {
            let bytes = self
                .adapter
                .fetch_key_package(*pk)
                .await?
                .ok_or_else(|| anyhow!("no key package on relay for {pk}"))?;
            kps.push(bytes);
        }

        let (group_id, result) = {
            let mut e = self.engine.lock().await;
            e.create_group(name, description, &kps, &[TransportKind::Nostr])
                .await
                .map_err(|e| anyhow!("engine.create_group: {e:?}"))?
        };

        match result {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                self.adapter.publish(&msg).await?;
                for w in &welcomes {
                    self.adapter.publish(w).await?;
                }
                let created = {
                    let mut e = self.engine.lock().await;
                    e.confirm_published(pending).await?
                };
                let _ = self.event_tx.send(created);

                // Start group subscription for ourselves.
                let tgid = {
                    let e = self.engine.lock().await;
                    let ctx = e.group_context(&group_id)?;
                    ctx.transport_group_id()
                        .ok_or_else(|| anyhow!("no transport_group_id"))?
                };
                let stream = self.adapter.subscribe_group(&tgid).await?;
                spawn_forwarder(stream, self.inbound_tx.clone());
            }
            _ => return Err(anyhow!("unexpected SendResult from create_group")),
        }
        Ok(group_id)
    }

    pub async fn invite(&self, group_id: GroupId, member: PublicKey) -> Result<()> {
        let kp_bytes = self
            .adapter
            .fetch_key_package(member)
            .await?
            .ok_or_else(|| anyhow!("no key package on relay for {member}"))?;

        let result = {
            let mut e = self.engine.lock().await;
            e.send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![kp_bytes],
            })
            .await
            .map_err(|e| anyhow!("engine.send(Invite): {e:?}"))?
        };

        match result {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                self.adapter.publish(&msg).await?;
                for w in &welcomes {
                    self.adapter.publish(w).await?;
                }
                let ev = {
                    let mut e = self.engine.lock().await;
                    e.confirm_published(pending).await?
                };
                let _ = self.event_tx.send(ev);
                // Drain any side-effect events queued (MemberAdded etc).
                let queued = {
                    let mut e = self.engine.lock().await;
                    e.drain_events()
                };
                for q in queued {
                    let _ = self.event_tx.send(q);
                }
                Ok(())
            }
            _ => Err(anyhow!("unexpected SendResult from invite")),
        }
    }

    pub async fn leave(&self, group_id: GroupId) -> Result<()> {
        let result = {
            let mut e = self.engine.lock().await;
            e.send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .map_err(|e| anyhow!("engine.send(Leave): {e:?}"))?
        };

        match result {
            SendResult::GroupEvolution { msg, pending, .. } => {
                self.adapter.publish(&msg).await?;
                let ev = {
                    let mut e = self.engine.lock().await;
                    e.confirm_published(pending).await?
                };
                let _ = self.event_tx.send(ev);
                Ok(())
            }
            _ => Err(anyhow!("unexpected SendResult from leave")),
        }
    }

    pub async fn feature_statuses(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(Feature, FeatureStatus)>> {
        let features = [
            Feature::BasicGroupData,
            Feature::NostrTransportData,
            Feature::FipsTransportData,
            Feature::Reactions,
            Feature::SelfRemove,
        ];
        let e = self.engine.lock().await;
        let mut out = Vec::new();
        for f in features {
            let st = e
                .feature_status(group_id, f)
                .map_err(|e| anyhow!("feature_status: {e:?}"))?;
            out.push((f, st));
        }
        Ok(out)
    }

    pub async fn send_message(&self, group_id: GroupId, text: &str) -> Result<()> {
        // Build an unsigned Nostr rumor per nostr-role-in-marmot.md §"Application
        // message format". Kind 9 = chat message.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rumor = serde_json::json!({
            "pubkey": hex::encode(self.my_pk_bytes),
            "kind": 9,
            "content": text,
            "tags": [],
            "created_at": now,
        });
        let rumor_bytes = serde_json::to_vec(&rumor)?;

        let result = {
            let mut e = self.engine.lock().await;
            e.send(SendIntent::ApplicationMessage {
                group_id,
                rumor_bytes,
            })
            .await?
        };

        match result {
            SendResult::ApplicationMessage { msg } => {
                self.adapter.publish(&msg).await?;
                Ok(())
            }
            _ => Err(anyhow!("unexpected SendResult from send")),
        }
    }
}

fn spawn_forwarder<S>(mut stream: S, tx: mpsc::UnboundedSender<TransportMessage>)
where
    S: futures::Stream<Item = TransportMessage> + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(tm) = stream.next().await {
            if tx.send(tm).is_err() {
                break;
            }
        }
    });
}

fn spawn_ingest_loop(
    engine: Arc<Mutex<Mdk>>,
    adapter: Arc<NostrAdapter>,
    mut inbound_rx: mpsc::UnboundedReceiver<TransportMessage>,
    inbound_tx: mpsc::UnboundedSender<TransportMessage>,
    event_tx: broadcast::Sender<GroupEvent>,
) {
    tokio::spawn(async move {
        while let Some(tm) = inbound_rx.recv().await {
            let mut e = engine.lock().await;
            match e.ingest(tm).await {
                Ok(IngestOutcome::Processed) => {}
                Ok(IngestOutcome::Stale { reason }) => {
                    // Silently-deduped condition. Log at debug, not warn.
                    tracing::debug!("ingest stale: {:?}", stale_label(&reason));
                    continue;
                }
                Err(err) => {
                    tracing::warn!("ingest error: {err:?}");
                    continue;
                }
            }
            let events = e.drain_events();
            let auto_publish = e.drain_auto_publish();

            // For any newly-joined groups, extract transport_group_id while we still
            // hold the lock (cheap), then spawn a subscription after dropping it.
            let mut new_subs: Vec<Vec<u8>> = Vec::new();
            for ev in &events {
                if let GroupEvent::Joined { group_id, .. } = ev {
                    if let Ok(ctx) = e.group_context(group_id) {
                        if let Some(tgid) = ctx.transport_group_id() {
                            new_subs.push(tgid);
                        }
                    }
                }
            }
            drop(e);

            // Fire-and-forget publish any engine-generated transport messages
            // (e.g. auto-commits of incoming SelfRemove proposals).
            for tm in auto_publish {
                let ad = adapter.clone();
                tokio::spawn(async move {
                    if let Err(err) = ad.publish(&tm).await {
                        tracing::warn!("auto-publish failed: {err:?}");
                    }
                });
            }

            for tgid in new_subs {
                let ad = adapter.clone();
                let tx = inbound_tx.clone();
                tokio::spawn(async move {
                    match ad.subscribe_group(&tgid).await {
                        Ok(stream) => {
                            spawn_forwarder(stream, tx);
                        }
                        Err(err) => tracing::error!("subscribe_group failed: {err:?}"),
                    }
                });
            }

            for ev in events {
                let _ = event_tx.send(ev);
            }
        }
    });
}

/// Parse an npub string to a PublicKey.
pub fn parse_npub(s: &str) -> Result<PublicKey> {
    PublicKey::parse(s).map_err(|e| anyhow!("invalid npub/hex: {e:?}"))
}

fn stale_label(reason: &StaleReason) -> &'static str {
    match reason {
        StaleReason::AlreadySeen => "already-seen",
        StaleReason::AlreadyAtEpoch { .. } => "already-at-epoch (welcome-echo)",
        StaleReason::NotForThisClient => "not-for-us",
        StaleReason::UnknownGroup => "unknown-group",
        StaleReason::OwnEcho => "own-echo",
    }
}
