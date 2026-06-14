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
