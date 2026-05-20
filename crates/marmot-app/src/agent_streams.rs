use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

const AGENT_STREAM_UPDATE_REPLAY_LIMIT: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStreamDelta {
    pub account: Option<String>,
    pub group_id: String,
    pub stream_id: String,
    pub seq: u64,
    pub record_type: u8,
    pub flags: u8,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStreamWatchReport {
    pub watch_id: String,
    pub account: Option<String>,
    pub group_id: String,
    pub stream_id: Option<String>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub status: String,
    pub text: Option<String>,
    pub transcript_hash: Option<String>,
    pub chunk_count: Option<u64>,
    pub error: Option<String>,
    pub result: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentStreamWatchStart {
    pub account: Option<String>,
    pub group_id: String,
    pub stream_id: Option<String>,
    pub started_at: u64,
    pub started_at_millis: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentStreamWatchCompletion {
    pub finished_at: u64,
    pub status: String,
    pub stream_id: Option<String>,
    pub text: Option<String>,
    pub transcript_hash: Option<String>,
    pub chunk_count: Option<u64>,
    pub error: Option<String>,
    pub result: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentStreamUpdate {
    WatchUpdated(AgentStreamWatchReport),
    Delta(AgentStreamDelta),
}

#[derive(Clone)]
pub struct AgentStreamWatchManager {
    inner: Arc<AgentStreamWatchManagerInner>,
}

struct AgentStreamWatchManagerInner {
    watches: Mutex<HashMap<String, AgentStreamWatchReport>>,
    recent_updates: Mutex<VecDeque<AgentStreamUpdate>>,
    updates: broadcast::Sender<AgentStreamUpdate>,
}

impl Default for AgentStreamWatchManager {
    fn default() -> Self {
        let (updates, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(AgentStreamWatchManagerInner {
                watches: Mutex::new(HashMap::new()),
                recent_updates: Mutex::new(VecDeque::new()),
                updates,
            }),
        }
    }
}

impl AgentStreamWatchManager {
    pub fn subscribe(&self) -> broadcast::Receiver<AgentStreamUpdate> {
        self.inner.updates.subscribe()
    }

    pub fn recent_updates(&self) -> Vec<AgentStreamUpdate> {
        self.inner
            .recent_updates
            .lock()
            .map(|updates| updates.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn start_watch(&self, start: AgentStreamWatchStart) -> AgentStreamWatchReport {
        let report = AgentStreamWatchReport {
            watch_id: stream_watch_id(
                &start.group_id,
                start.stream_id.as_deref(),
                start.started_at_millis,
            ),
            account: start.account,
            group_id: start.group_id,
            stream_id: start.stream_id,
            started_at: start.started_at,
            finished_at: None,
            status: "running".to_owned(),
            text: None,
            transcript_hash: None,
            chunk_count: None,
            error: None,
            result: None,
        };
        if let Ok(mut watches) = self.inner.watches.lock() {
            watches.insert(report.watch_id.clone(), report.clone());
        }
        self.publish_update(AgentStreamUpdate::WatchUpdated(report.clone()));
        report
    }

    pub fn finish_watch(
        &self,
        watch_id: &str,
        completion: AgentStreamWatchCompletion,
    ) -> Option<AgentStreamWatchReport> {
        let finished = {
            let mut watches = self.inner.watches.lock().ok()?;
            let report = watches.get_mut(watch_id)?;
            report.finished_at = Some(completion.finished_at);
            report.status = completion.status;
            if completion.stream_id.is_some() {
                report.stream_id = completion.stream_id;
            }
            report.text = completion.text;
            report.transcript_hash = completion.transcript_hash;
            report.chunk_count = completion.chunk_count;
            report.error = completion.error;
            report.result = completion.result;
            report.clone()
        };
        self.publish_update(AgentStreamUpdate::WatchUpdated(finished.clone()));
        Some(finished)
    }

    pub fn record_delta(&self, delta: AgentStreamDelta) {
        self.publish_update(AgentStreamUpdate::Delta(delta));
    }

    pub fn watch_exists(
        &self,
        account: Option<&str>,
        group_id: &str,
        stream_id: Option<&str>,
    ) -> bool {
        self.inner
            .watches
            .lock()
            .map(|watches| {
                watches.values().any(|watch| {
                    watch.account.as_deref() == account
                        && watch.group_id == group_id
                        && watch.stream_id.as_deref() == stream_id
                        && matches!(watch.status.as_str(), "running" | "completed")
                })
            })
            .unwrap_or(false)
    }

    pub fn reports(&self) -> Vec<AgentStreamWatchReport> {
        let mut reports = self
            .inner
            .watches
            .lock()
            .map(|watches| watches.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        sort_watch_reports(&mut reports);
        reports
    }

    pub fn previews_for_group(
        &self,
        account: Option<&str>,
        group_id: &str,
    ) -> Vec<AgentStreamWatchReport> {
        let mut reports = self
            .inner
            .watches
            .lock()
            .map(|watches| {
                watches
                    .values()
                    .filter(|watch| watch.group_id == group_id)
                    .filter(|watch| {
                        account.is_none()
                            || watch.account.as_deref().is_none()
                            || watch.account.as_deref() == account
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        sort_watch_reports(&mut reports);
        reports
    }

    fn publish_update(&self, update: AgentStreamUpdate) {
        if let Ok(mut recent) = self.inner.recent_updates.lock() {
            recent.push_back(update.clone());
            while recent.len() > AGENT_STREAM_UPDATE_REPLAY_LIMIT {
                recent.pop_front();
            }
        }
        let _ = self.inner.updates.send(update);
    }
}

fn sort_watch_reports(reports: &mut [AgentStreamWatchReport]) {
    reports.sort_by(|left, right| {
        left.started_at
            .cmp(&right.started_at)
            .then_with(|| left.watch_id.cmp(&right.watch_id))
    });
}

fn stream_watch_id(group_id: &str, stream_id: Option<&str>, started_at_ms: u128) -> String {
    let stream = stream_id.unwrap_or("latest");
    format!(
        "sw-{started_at_ms}-{}-{}",
        short_id(group_id),
        short_id(stream)
    )
}

fn short_id(value: &str) -> String {
    value.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_watch_manager_owns_preview_state_and_typed_updates() {
        let manager = AgentStreamWatchManager::default();
        let mut updates = manager.subscribe();

        let started = manager.start_watch(AgentStreamWatchStart {
            account: Some("alice".to_owned()),
            group_id: "aa".repeat(32),
            stream_id: Some("bb".repeat(32)),
            started_at: 1_700_000_000,
            started_at_millis: 1_700_000_000_123,
        });

        assert_eq!(started.status, "running");
        assert_eq!(
            started.watch_id,
            "sw-1700000000123-aaaaaaaaaaaa-bbbbbbbbbbbb"
        );
        assert!(manager.watch_exists(Some("alice"), &"aa".repeat(32), Some(&"bb".repeat(32))));
        assert!(matches!(
            updates.try_recv().expect("start update"),
            AgentStreamUpdate::WatchUpdated(report)
                if report.watch_id == started.watch_id && report.status == "running"
        ));

        manager.record_delta(AgentStreamDelta {
            account: Some("alice".to_owned()),
            group_id: "aa".repeat(32),
            stream_id: "bb".repeat(32),
            seq: 1,
            record_type: 1,
            flags: 0,
            text: "hel".to_owned(),
        });
        assert!(matches!(
            updates.try_recv().expect("delta update"),
            AgentStreamUpdate::Delta(delta) if delta.text == "hel"
        ));

        let finished = manager
            .finish_watch(
                &started.watch_id,
                AgentStreamWatchCompletion {
                    finished_at: 1_700_000_001,
                    status: "completed".to_owned(),
                    stream_id: Some("bb".repeat(32)),
                    text: Some("hello".to_owned()),
                    transcript_hash: Some("cc".repeat(32)),
                    chunk_count: Some(2),
                    error: None,
                    result: None,
                },
            )
            .expect("finished watch");

        assert_eq!(finished.text.as_deref(), Some("hello"));
        let previews = manager.previews_for_group(Some("alice"), &"aa".repeat(32));
        assert_eq!(previews, vec![finished.clone()]);
        assert!(matches!(
            updates.try_recv().expect("finish update"),
            AgentStreamUpdate::WatchUpdated(report)
                if report.watch_id == finished.watch_id && report.status == "completed"
        ));
        assert!(matches!(
            manager.recent_updates().last(),
            Some(AgentStreamUpdate::WatchUpdated(report)) if report.watch_id == finished.watch_id
        ));
    }
}
