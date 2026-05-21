//! UniFFI subscription objects.
//!
//! Each subscription wraps one of marmot-app's `Runtime*Subscription` types
//! (or a `broadcast::Receiver` for the top-level event firehose) and exposes
//! Swift-friendly methods:
//!
//! - `snapshot()` returns the initial state exactly once (subsequent calls
//!   yield the empty case).
//! - `next()` is an async fn the Swift side can drive in a `while let` loop
//!   to receive subsequent updates; it returns `None` when the underlying
//!   sender drops.
//!
//! All inner state lives behind a `tokio::sync::Mutex` because UniFFI passes
//! these objects via `Arc<Self>` and `recv()` requires `&mut`.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use marmot_app::{
    MarmotAppEvent, RuntimeChatsSubscription, RuntimeGroupStateSubscription,
    RuntimeMessagesSubscription,
};
use tokio::sync::{Mutex, broadcast};

use crate::conversions::{
    AppGroupRecordFfi, AppMessageRecordFfi, MarmotEventFfi, MessageUpdateFfi,
};

#[derive(uniffi::Object)]
pub struct ChatsSubscription {
    snapshot: StdMutex<Option<Vec<AppGroupRecordFfi>>>,
    inner: Mutex<RuntimeChatsSubscription>,
}

impl ChatsSubscription {
    pub(crate) fn new(mut inner: RuntimeChatsSubscription) -> Arc<Self> {
        let snapshot: Vec<AppGroupRecordFfi> = std::mem::take(&mut inner.snapshot)
            .into_iter()
            .map(Into::into)
            .collect();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl ChatsSubscription {
    pub fn snapshot(&self) -> Vec<AppGroupRecordFfi> {
        self.snapshot.lock().unwrap().take().unwrap_or_default()
    }

    pub async fn next(&self) -> Option<AppGroupRecordFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct MessagesSubscription {
    snapshot: StdMutex<Option<Vec<AppMessageRecordFfi>>>,
    inner: Mutex<RuntimeMessagesSubscription>,
}

impl MessagesSubscription {
    pub(crate) fn new(mut inner: RuntimeMessagesSubscription) -> Arc<Self> {
        let snapshot: Vec<AppMessageRecordFfi> = std::mem::take(&mut inner.snapshot)
            .into_iter()
            .map(Into::into)
            .collect();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl MessagesSubscription {
    pub fn snapshot(&self) -> Vec<AppMessageRecordFfi> {
        self.snapshot.lock().unwrap().take().unwrap_or_default()
    }

    pub async fn next(&self) -> Option<MessageUpdateFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct GroupStateSubscription {
    snapshot: StdMutex<Option<AppGroupRecordFfi>>,
    inner: Mutex<RuntimeGroupStateSubscription>,
}

impl GroupStateSubscription {
    pub(crate) fn new(inner: RuntimeGroupStateSubscription) -> Arc<Self> {
        let snapshot = AppGroupRecordFfi::from(inner.snapshot.clone());
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GroupStateSubscription {
    pub fn snapshot(&self) -> Option<AppGroupRecordFfi> {
        self.snapshot.lock().unwrap().take()
    }

    pub async fn next(&self) -> Option<AppGroupRecordFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

/// Top-level firehose of all events the runtime emits across every account.
/// Lags are silently skipped (broadcast channels have a bounded backlog and
/// `RecvError::Lagged` is non-fatal — the iOS side will catch back up via
/// the per-account chats/messages subscriptions).
#[derive(uniffi::Object)]
pub struct EventsSubscription {
    inner: Mutex<broadcast::Receiver<MarmotAppEvent>>,
}

impl EventsSubscription {
    pub(crate) fn new(inner: broadcast::Receiver<MarmotAppEvent>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl EventsSubscription {
    pub async fn next(&self) -> Option<MarmotEventFfi> {
        let mut inner = self.inner.lock().await;
        loop {
            match inner.recv().await {
                Ok(event) => return Some(event.into()),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}
