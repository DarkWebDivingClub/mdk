use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::{Client as NostrSdkClient, Filter, Kind, PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use transport_nostr_peeler::NostrTransportEvent;

use super::DIRECTORY_RELAY_CONNECT_WAIT;

const DIRECTORY_RELAY_FETCH_WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DirectoryEventQuery {
    pub(crate) kind: u64,
    pub(crate) authors: Vec<String>,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DirectoryRelayEventRecord {
    pub(crate) endpoints: Vec<TransportEndpoint>,
    pub(crate) event: NostrTransportEvent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryFetchRequest {
    endpoints: Vec<TransportEndpoint>,
    queries: Vec<DirectoryEventQuery>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DirectoryFetchKey {
    endpoints: Vec<TransportEndpoint>,
    queries: Vec<DirectoryEventQuery>,
}

#[derive(Clone)]
pub(crate) struct DirectoryRelayPlane {
    fetcher: Arc<dyn DirectoryRelayFetcher>,
    state: Arc<Mutex<DirectoryRelayPlaneState>>,
}

#[derive(Default)]
struct DirectoryRelayPlaneState {
    inflight: HashMap<DirectoryFetchKey, Vec<oneshot::Sender<DirectoryFetchResult>>>,
    active_subscription_ids: HashSet<String>,
    completed_fetches: usize,
    coalesced_waiters: usize,
    failed_fetches: usize,
    completed_subscription_syncs: usize,
    subscriptions_created: usize,
    subscriptions_removed: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectoryRelayStats {
    pub(crate) inflight_fetches: usize,
    pub(crate) active_subscriptions: usize,
    pub(crate) completed_fetches: usize,
    pub(crate) coalesced_waiters: usize,
    pub(crate) failed_fetches: usize,
    pub(crate) completed_subscription_syncs: usize,
    pub(crate) subscriptions_created: usize,
    pub(crate) subscriptions_removed: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectorySubscriptionSyncSummary {
    pub(crate) active_subscriptions: usize,
    pub(crate) subscriptions_created: usize,
    pub(crate) subscriptions_removed: usize,
}

type DirectoryFetchResult = Result<Vec<DirectoryRelayEventRecord>, String>;

#[async_trait]
pub(crate) trait DirectoryRelayFetcher: Send + Sync {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String>;
}

#[derive(Clone)]
pub(crate) struct NostrSdkDirectoryRelayFetcher {
    client: NostrSdkClient,
}

impl DirectoryEventQuery {
    pub(crate) fn new(kind: u64, mut authors: Vec<String>, limit: usize) -> Self {
        authors.sort();
        authors.dedup();
        Self {
            kind,
            authors,
            limit,
        }
    }
}

impl DirectoryFetchRequest {
    pub(crate) fn new(
        mut endpoints: Vec<TransportEndpoint>,
        mut queries: Vec<DirectoryEventQuery>,
    ) -> Result<Self, String> {
        endpoints.sort();
        endpoints.dedup();
        queries.sort();
        queries.dedup();
        if endpoints.is_empty() {
            return Err("directory fetch: no relay endpoints".to_owned());
        }
        if queries.is_empty() {
            return Err("directory fetch: no queries".to_owned());
        }
        for query in &queries {
            if query.authors.is_empty() {
                return Err("directory fetch: no query authors".to_owned());
            }
            if query.limit == 0 {
                return Err("directory fetch: query limit must be greater than zero".to_owned());
            }
        }
        Ok(Self { endpoints, queries })
    }

    fn key(&self) -> DirectoryFetchKey {
        DirectoryFetchKey {
            endpoints: self.endpoints.clone(),
            queries: self.queries.clone(),
        }
    }
}

impl DirectoryRelayPlane {
    pub(crate) fn new(fetcher: Arc<dyn DirectoryRelayFetcher>) -> Self {
        Self {
            fetcher,
            state: Arc::new(Mutex::new(DirectoryRelayPlaneState::default())),
        }
    }

    pub(crate) async fn fetch_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let key = request.key();
        let (rx, should_spawn) = {
            let (tx, rx) = oneshot::channel();
            let mut state = self.state.lock().await;
            if let Some(waiters) = state.inflight.get_mut(&key) {
                waiters.push(tx);
                state.coalesced_waiters += 1;
                (rx, false)
            } else {
                state.inflight.insert(key.clone(), vec![tx]);
                (rx, true)
            }
        };

        if should_spawn {
            let fetcher = self.fetcher.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                let result = fetcher.fetch_directory_events(request).await;
                let mut state = state.lock().await;
                if result.is_ok() {
                    state.completed_fetches += 1;
                } else {
                    state.failed_fetches += 1;
                }
                if let Some(waiters) = state.inflight.remove(&key) {
                    for waiter in waiters {
                        let _ = waiter.send(result.clone());
                    }
                }
            });
        }

        rx.await
            .map_err(|_| "directory fetch owner dropped before completing".to_owned())?
    }

    pub(crate) async fn stats(&self) -> DirectoryRelayStats {
        let state = self.state.lock().await;
        DirectoryRelayStats {
            inflight_fetches: state.inflight.len(),
            active_subscriptions: state.active_subscription_ids.len(),
            completed_fetches: state.completed_fetches,
            coalesced_waiters: state.coalesced_waiters,
            failed_fetches: state.failed_fetches,
            completed_subscription_syncs: state.completed_subscription_syncs,
            subscriptions_created: state.subscriptions_created,
            subscriptions_removed: state.subscriptions_removed,
        }
    }

    pub(crate) async fn subscription_diff(
        &self,
        desired_ids: &HashSet<String>,
    ) -> (HashSet<String>, HashSet<String>) {
        let state = self.state.lock().await;
        let to_add = desired_ids
            .difference(&state.active_subscription_ids)
            .cloned()
            .collect::<HashSet<_>>();
        let to_remove = state
            .active_subscription_ids
            .difference(desired_ids)
            .cloned()
            .collect::<HashSet<_>>();
        (to_add, to_remove)
    }

    pub(crate) async fn replace_subscription_ids(
        &self,
        desired_ids: HashSet<String>,
    ) -> Result<DirectorySubscriptionSyncSummary, String> {
        let mut state = self.state.lock().await;
        let created = desired_ids
            .difference(&state.active_subscription_ids)
            .count();
        let removed = state
            .active_subscription_ids
            .difference(&desired_ids)
            .count();
        state.completed_subscription_syncs += 1;
        state.subscriptions_created += created;
        state.subscriptions_removed += removed;
        state.active_subscription_ids = desired_ids;
        Ok(DirectorySubscriptionSyncSummary {
            active_subscriptions: state.active_subscription_ids.len(),
            subscriptions_created: created,
            subscriptions_removed: removed,
        })
    }
}

impl NostrSdkDirectoryRelayFetcher {
    pub(crate) fn new(client: NostrSdkClient) -> Self {
        Self { client }
    }

    pub(crate) fn standalone() -> Self {
        Self::new(NostrSdkClient::builder().build())
    }
}

#[async_trait]
impl DirectoryRelayFetcher for NostrSdkDirectoryRelayFetcher {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let relay_urls = request
            .endpoints
            .iter()
            .map(|endpoint| {
                RelayUrl::parse(endpoint.as_str())
                    .map_err(|e| format!("invalid relay URL {}: {e}", endpoint.as_str()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for relay_url in &relay_urls {
            self.client
                .add_relay(relay_url.clone())
                .await
                .map_err(|e| format!("add relay: {e}"))?;
            timeout(
                DIRECTORY_RELAY_CONNECT_WAIT,
                self.client.connect_relay(relay_url.clone()),
            )
            .await
            .map_err(|_| "connect relay timed out".to_owned())?
            .map_err(|e| format!("connect relay: {e}"))?;
        }

        let mut records = Vec::new();
        for query in request.queries {
            let public_keys = query
                .authors
                .iter()
                .map(|author| PublicKey::parse(author).map_err(|_| "invalid query author"))
                .collect::<Result<Vec<_>, _>>()?;
            let kind = u16::try_from(query.kind)
                .map(Kind::from)
                .map_err(|_| format!("unsupported Nostr kind {}", query.kind))?;
            let filter = Filter::new()
                .authors(public_keys)
                .kind(kind)
                .limit(query.limit);
            let events = self
                .client
                .fetch_events_from(relay_urls.clone(), filter, DIRECTORY_RELAY_FETCH_WAIT)
                .await
                .map_err(|e| format!("fetch directory events: {e}"))?;
            for event in events {
                let event = NostrTransportEvent::from_nostr_event(&event)
                    .map_err(|e| format!("map directory event: {e}"))?;
                records.push(DirectoryRelayEventRecord {
                    endpoints: request.endpoints.clone(),
                    event,
                });
            }
        }
        Ok(records)
    }
}
