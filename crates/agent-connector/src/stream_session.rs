//! Active agent text-stream compose sessions, the debug final-send recorder, and idle sweeping.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agent_control::AgentControlDebugFinalSend;
use agent_stream_compose::StreamComposeCommand;
use cgka_traits::GroupId;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::error::ConnectorError;
use crate::validation::normalize_hex;

#[derive(Clone, Default)]
pub(crate) struct DebugFinalSendStore {
    sends: Arc<Mutex<Vec<AgentControlDebugFinalSend>>>,
}

impl DebugFinalSendStore {
    pub(crate) fn record(
        &self,
        mut send: AgentControlDebugFinalSend,
    ) -> AgentControlDebugFinalSend {
        let mut sends = self.sends.lock().expect("debug final send lock poisoned");
        let next_id = sends.len() + 1;
        send.message_ids_hex = vec![format!("{next_id:064x}")];
        sends.push(send.clone());
        send
    }

    pub(crate) fn list(&self) -> Vec<AgentControlDebugFinalSend> {
        self.sends
            .lock()
            .expect("debug final send lock poisoned")
            .clone()
    }
}

/// Maximum number of recent idempotency keys retained for durable-send dedup.
/// Oldest keys are evicted FIFO once the cap is reached; this bounds memory while
/// comfortably covering any plausible in-flight retry window.
const SEND_IDEMPOTENCY_CAPACITY: usize = 1024;

/// Bounded FIFO map from a client-supplied idempotency key to a server-derived
/// request fingerprint plus the durable message ids produced by the first
/// successful `send_final` for that key.
///
/// A retry that reuses the same key AND matches the recorded fingerprint returns
/// the cached ids without re-sending, so a retry after a post-write timeout cannot
/// double-post an unrecallable encrypted message. A reused key whose fingerprint
/// differs (a different request body under the same key) is treated as a cache
/// miss, so it can never return ids belonging to an unrelated send. Keys are
/// evicted oldest-first once the capacity is reached.
#[derive(Clone, Default)]
pub(crate) struct SendIdempotencyStore {
    inner: Arc<Mutex<SendIdempotencyInner>>,
}

#[derive(Default)]
struct SendIdempotencyInner {
    order: std::collections::VecDeque<String>,
    seen: HashMap<String, (u64, Vec<String>)>,
}

impl SendIdempotencyStore {
    /// The message ids recorded for `key` by an earlier successful send, but only
    /// when the recorded request `fingerprint` matches. A key hit with a different
    /// fingerprint returns `None` (treated as a cache miss).
    pub(crate) fn get(&self, key: &str, fingerprint: u64) -> Option<Vec<String>> {
        self.inner
            .lock()
            .expect("send idempotency lock poisoned")
            .seen
            .get(key)
            .filter(|(recorded, _)| *recorded == fingerprint)
            .map(|(_, ids)| ids.clone())
    }

    /// Record the request `fingerprint` and durable message ids produced for
    /// `key`. A repeat record for an existing key keeps the original entry (the
    /// first successful send wins); otherwise the key is appended and the oldest
    /// is evicted once at capacity.
    pub(crate) fn record(&self, key: String, fingerprint: u64, message_ids: Vec<String>) {
        let mut inner = self.inner.lock().expect("send idempotency lock poisoned");
        if inner.seen.contains_key(&key) {
            return;
        }
        if inner.order.len() >= SEND_IDEMPOTENCY_CAPACITY
            && let Some(evicted) = inner.order.pop_front()
        {
            inner.seen.remove(&evicted);
        }
        inner.seen.insert(key.clone(), (fingerprint, message_ids));
        inner.order.push_back(key);
    }
}

#[derive(Clone, Default)]
pub(crate) struct StreamSessionStore {
    sessions: Arc<Mutex<HashMap<String, ActiveStreamSession>>>,
}

#[derive(Clone)]
pub(crate) struct ActiveStreamSession {
    pub(crate) account_label: String,
    pub(crate) group_id: GroupId,
    pub(crate) stream_id: Vec<u8>,
    pub(crate) start_message_id_hex: String,
    pub(crate) tx: mpsc::Sender<StreamComposeCommand>,
    pub(crate) cancel_tx: mpsc::Sender<()>,
    pub(crate) abort: tokio::task::AbortHandle,
    pub(crate) last_activity: Instant,
}

impl StreamSessionStore {
    pub(crate) fn insert(&self, stream_id_hex: String, session: ActiveStreamSession) {
        let mut sessions = self.sessions.lock().expect("stream session lock poisoned");
        if let Some(previous) = sessions.insert(stream_id_hex, session) {
            // Graceful cancel over the dedicated signal: let the replaced
            // session emit its live Abort and self-terminate. The cancel signal
            // can't be starved by a full command queue, so only force-abort if
            // the cancel channel itself is gone.
            match previous.cancel_tx.try_send(()) {
                // Delivered, or a cancel is already queued (`Full`): the session
                // will still observe a cancel and emit its `Abort`, so leave it
                // to self-terminate gracefully.
                Ok(()) | Err(TrySendError::Full(())) => {}
                // The receiver is gone: the session can no longer publish an
                // `Abort`, so force-abort the task to reclaim its resources.
                Err(TrySendError::Closed(())) => previous.abort.abort(),
            }
        }
    }

    pub(crate) fn get(&self, stream_id_hex: &str) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let mut sessions = self.sessions.lock().expect("stream session lock poisoned");
        let session = sessions.get_mut(&stream_id_hex).ok_or_else(|| {
            ConnectorError::Stream(format!("no active stream session for {stream_id_hex}"))
        })?;
        // Touching the session on any command keeps it alive against the idle sweep.
        session.last_activity = Instant::now();
        Ok(session.clone())
    }

    pub(crate) fn remove(
        &self,
        stream_id_hex: &str,
    ) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        self.sessions
            .lock()
            .expect("stream session lock poisoned")
            .remove(&stream_id_hex)
            .ok_or_else(|| {
                ConnectorError::Stream(format!("no active stream session for {stream_id_hex}"))
            })
    }

    /// Abort and drop every session whose last activity is older than `max_idle`.
    ///
    /// Returns the number of sessions swept. This is what bounds the lifetime of
    /// sessions abandoned when the gateway crashes or restarts mid-stream: each such
    /// session otherwise keeps the compose task, its `mpsc::Sender`, the accumulated
    /// transcript, and (when broker connect succeeded) a dedicated quinn `Endpoint`
    /// UDP socket plus a live keep-alive'd QUIC connection alive forever.
    pub(crate) fn sweep_idle(&self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().expect("stream session lock poisoned");
        let stale: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.last_activity) >= max_idle)
            .map(|(stream_id_hex, _)| stream_id_hex.clone())
            .collect();
        for stream_id_hex in &stale {
            if let Some(session) = sessions.remove(stream_id_hex) {
                // Graceful cancel over the dedicated signal so an abandoned
                // session still emits a live `Abort`; only force-abort if the
                // cancel channel is gone. The forced abort is intentionally NOT
                // unconditional here: a successful cancel lets the session flush
                // its Abort and shut itself down.
                match session.cancel_tx.try_send(()) {
                    // Delivered, or a cancel is already queued (`Full`): the
                    // session will still drain a cancel and emit its `Abort`.
                    Ok(()) | Err(TrySendError::Full(())) => {}
                    // The receiver is gone, so no `Abort` can be published:
                    // force-abort to release the held resources.
                    Err(TrySendError::Closed(())) => session.abort.abort(),
                }
            }
        }
        stale.len()
    }
}
