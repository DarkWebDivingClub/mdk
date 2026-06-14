//! Runtime/debug event projection into control events, inbound replay cursor, and catch-up driver.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agent_control::{AGENT_CONTROL_STREAM_STATUS_STARTED, AgentControlEvent};
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT, STREAM_TAG,
};
use cgka_traits::{GroupId, engine::GroupEvent};
use marmot_app::{AppError, AppMessageRecord, MarmotAppEvent, MarmotAppRuntime};
use tokio::sync::{Mutex as AsyncMutex, broadcast};

use crate::INBOUND_CATCH_UP_INTERVAL;
use crate::validation::normalize_hex;

pub(crate) fn control_event_from_runtime_event(
    event: MarmotAppEvent,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    match event {
        MarmotAppEvent::MessageReceived(update) => {
            // Only kind-9 chat/media is conversational input. Edits, reactions,
            // deletes, and telemetry need explicit control semantics before they
            // can safely influence an agent prompt.
            if update.message.kind != MARMOT_APP_EVENT_KIND_CHAT {
                return None;
            }
            let group_id_hex = inbound_event_group_id_hex(
                account_filter,
                &update.account_id_hex,
                group_filter,
                &update.message.group_id,
                &update.message.sender,
            )?;
            Some(AgentControlEvent::InboundMessage {
                account_id_hex: update.account_id_hex,
                group_id_hex,
                message_id_hex: update.message.message_id_hex,
                sender_account_id_hex: update.message.sender,
                text: update.message.plaintext,
            })
        }
        MarmotAppEvent::AgentStreamStarted(update) => {
            if update.message.kind != MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
                return None;
            }
            let group_id_hex = inbound_event_group_id_hex(
                account_filter,
                &update.account_id_hex,
                group_filter,
                &update.message.group_id,
                &update.message.sender,
            )?;
            let stream_id_hex = update
                .message
                .tags
                .iter()
                .find(|tag| tag.first().is_some_and(|name| name == STREAM_TAG))
                .and_then(|tag| tag.get(1))
                .and_then(|stream_id_hex| normalize_hex(stream_id_hex).ok())?;
            Some(AgentControlEvent::StreamUpdate {
                account_id_hex: update.account_id_hex,
                group_id_hex,
                stream_id_hex,
                status: AGENT_CONTROL_STREAM_STATUS_STARTED.to_owned(),
            })
        }
        MarmotAppEvent::GroupEvent(group_event) => match group_event.event {
            GroupEvent::GroupJoined {
                group_id,
                via_welcome,
                welcomer,
            } => {
                let group_id_hex = hex::encode(group_id.as_slice());
                if !inbound_filter_matches(
                    account_filter,
                    &group_event.account_id_hex,
                    group_filter,
                    &group_id_hex,
                ) {
                    return None;
                }
                Some(AgentControlEvent::GroupInvite {
                    account_id_hex: group_event.account_id_hex,
                    group_id_hex,
                    via_welcome_message_id_hex: hex::encode(via_welcome.as_slice()),
                    welcomer_account_id_hex: welcomer.map(|member| hex::encode(member.as_slice())),
                })
            }
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn control_event_from_debug_event(
    event: AgentControlEvent,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    let (account_id_hex, group_id_hex) = match &event {
        AgentControlEvent::InboundMessage {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::GroupInvite {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::StreamUpdate {
            account_id_hex,
            group_id_hex,
            ..
        } => (account_id_hex, group_id_hex),
        // ResyncRequired carries optional account/group scope and is never produced by the
        // debug-inject path; apply the subscription filters against whatever scope it carries.
        AgentControlEvent::ResyncRequired {
            account_id_hex,
            group_id_hex,
            ..
        } => {
            let account_ok = match (account_filter, account_id_hex.as_deref()) {
                (Some(filter), Some(value)) => filter == value,
                _ => true,
            };
            let group_ok = match (group_filter, group_id_hex.as_deref()) {
                (Some(filter), Some(value)) => filter == value,
                _ => true,
            };
            return (account_ok && group_ok).then_some(event);
        }
    };
    inbound_filter_matches(account_filter, account_id_hex, group_filter, group_id_hex)
        .then_some(event)
}

fn inbound_event_group_id_hex(
    account_filter: Option<&str>,
    account_id_hex: &str,
    group_filter: Option<&str>,
    group_id: &GroupId,
    sender_account_id_hex: &str,
) -> Option<String> {
    let group_id_hex = hex::encode(group_id.as_slice());
    if inbound_filter_matches(account_filter, account_id_hex, group_filter, &group_id_hex)
        && sender_account_id_hex != account_id_hex
    {
        Some(group_id_hex)
    } else {
        None
    }
}

fn inbound_filter_matches(
    account_filter: Option<&str>,
    account_id_hex: &str,
    group_filter: Option<&str>,
    group_id_hex: &str,
) -> bool {
    account_filter.is_none_or(|filter| filter == account_id_hex)
        && group_filter.is_none_or(|filter| filter == group_id_hex)
}

/// Build a `ResyncRequired` control event scoped to this subscription's filters. Emitted when the
/// inbound broadcast channel lags and drops events: the dropped inbound messages are gone for good
/// (catch-up never re-emits already-broadcast messages), so the agent must re-query its own state.
pub(crate) fn resync_required_event(
    account_filter: Option<&str>,
    group_filter: Option<&str>,
    dropped_events: u64,
) -> AgentControlEvent {
    AgentControlEvent::ResyncRequired {
        account_id_hex: account_filter.map(str::to_owned),
        group_id_hex: group_filter.map(str::to_owned),
        dropped_events,
    }
}

/// Project a stored app-message record into the same `InboundMessage` event the live
/// `MessageReceived` path emits, or `None` if it is not an inbound user message for this
/// subscription. This keeps storage-backed replay byte-for-byte consistent with live delivery:
/// only inbound (`direction == "received"`) chat messages from a different sender are surfaced,
/// agent text-stream starts are skipped (the live path diverts them to a separate signal), and
/// the subscription's account/group filters are honored.
pub(crate) fn inbound_message_event_from_record(
    account_id_hex: &str,
    record: AppMessageRecord,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    // Only genuine inbound chat messages are user messages to the agent. Outbound (own) sends,
    // reactions/system events, and kind-1200 agent stream starts (which the live path diverts to
    // a separate signal) are not re-delivered as inbound. Filtering to the chat kind covers all
    // of those non-chat kinds, including the stream-start kind.
    debug_assert_ne!(
        MARMOT_APP_EVENT_KIND_CHAT,
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
    );
    if record.direction != "received" {
        return None;
    }
    if record.kind != MARMOT_APP_EVENT_KIND_CHAT {
        return None;
    }
    // The live path drops messages whose sender is the subscribed account itself.
    if record.sender == account_id_hex {
        return None;
    }
    if !inbound_filter_matches(
        account_filter,
        account_id_hex,
        group_filter,
        &record.group_id_hex,
    ) {
        return None;
    }
    Some(AgentControlEvent::InboundMessage {
        account_id_hex: account_id_hex.to_owned(),
        group_id_hex: record.group_id_hex,
        message_id_hex: record.message_id_hex,
        sender_account_id_hex: record.sender,
        text: record.plaintext,
    })
}

/// Bounded set of inbound message ids already delivered on a subscription, used to dedup
/// storage-backed replay against live delivery (and against itself) after broadcast lag. Keeps a
/// FIFO of recent ids so a long-lived subscription cannot grow memory without bound; once the
/// capacity is reached the oldest id is evicted. The capacity comfortably exceeds the broadcast
/// channel depth, so every message that could plausibly be re-queried after a single overflow is
/// still tracked.
pub(crate) struct DeliveredInboundCursor {
    capacity: usize,
    order: VecDeque<String>,
    seen: HashSet<String>,
}

impl DeliveredInboundCursor {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    pub(crate) fn contains(&self, message_id_hex: &str) -> bool {
        self.seen.contains(message_id_hex)
    }

    pub(crate) fn record(&mut self, message_id_hex: String) {
        if self.seen.contains(&message_id_hex) {
            return;
        }
        if self.order.len() >= self.capacity
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        self.seen.insert(message_id_hex.clone());
        self.order.push_back(message_id_hex);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum InboundCatchUpEvent {
    Completed,
}

#[derive(Clone)]
pub(crate) struct InboundCatchUpDriver {
    runtime: MarmotAppRuntime,
    lock: Arc<AsyncMutex<()>>,
    events: broadcast::Sender<InboundCatchUpEvent>,
    pub(crate) started: Arc<AtomicBool>,
    pub(crate) active: Arc<AtomicU64>,
}

impl InboundCatchUpDriver {
    pub(crate) fn new(runtime: MarmotAppRuntime) -> Self {
        let (events, _) = broadcast::channel(16);
        Self {
            runtime,
            lock: Arc::new(AsyncMutex::new(())),
            events,
            started: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicU64::new(0)),
        }
    }

    fn spawn(&self) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + INBOUND_CATCH_UP_INTERVAL,
                INBOUND_CATCH_UP_INTERVAL,
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if driver.active.load(Ordering::Acquire) == 0 {
                    driver.started.store(false, Ordering::Release);
                    if driver.active.load(Ordering::Acquire) == 0 {
                        break;
                    }
                    if driver
                        .started
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = driver.request().await;
            }
        });
    }

    pub(crate) fn subscribe(
        &self,
    ) -> (
        broadcast::Receiver<InboundCatchUpEvent>,
        InboundCatchUpSubscription,
    ) {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.spawn();
        (
            self.events.subscribe(),
            InboundCatchUpSubscription {
                active: self.active.clone(),
            },
        )
    }

    pub(crate) async fn request(&self) -> Result<(), AppError> {
        let _guard = self.lock.lock().await;
        let result = self.runtime.catch_up_accounts().await;
        if result.is_ok() {
            let _ = self.events.send(InboundCatchUpEvent::Completed);
        } else {
            tracing::warn!(
                target: "agent_connector",
                method = "inbound_catch_up_request",
                error_code = "catch_up_failed",
                "inbound catch-up request failed"
            );
        }
        result
    }
}

pub(crate) struct InboundCatchUpSubscription {
    active: Arc<AtomicU64>,
}

impl Drop for InboundCatchUpSubscription {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}
