//! Top-level event firehose FFI conversion.

use marmot_app::MarmotAppEvent;

use super::message::RuntimeMessageReceivedFfi;
use super::timeline::RuntimeProjectionUpdateFfi;

/// Top-level event firehose, FFI-shaped. Agent streams collapse to a single
/// "agent stream activity" variant — host apps do not differentiate them at
/// the surface level for v1.
// FFI enum: see `TimelineSubscriptionUpdateFfi` — UniFFI lowers each variant
// by value, so boxing wouldn't change the wire size.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, uniffi::Enum)]
pub enum MarmotEventFfi {
    GroupJoined {
        account_id_hex: String,
        account_label: String,
        group_id_hex: String,
    },
    GroupStateUpdated {
        account_id_hex: String,
        account_label: String,
        group_id_hex: String,
    },
    MessageReceived {
        received: RuntimeMessageReceivedFfi,
    },
    ProjectionUpdated {
        update: RuntimeProjectionUpdateFfi,
    },
    GroupEvent {
        account_id_hex: String,
        account_label: String,
    },
    AccountError {
        account_id_hex: String,
        account_label: String,
        message: String,
    },
    AgentStreamActivity {
        account_id_hex: String,
        account_label: String,
    },
}

impl From<MarmotAppEvent> for MarmotEventFfi {
    fn from(value: MarmotAppEvent) -> Self {
        match value {
            MarmotAppEvent::GroupJoined {
                account_id_hex,
                account_label,
                group_id,
            } => Self::GroupJoined {
                account_id_hex,
                account_label,
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            MarmotAppEvent::GroupStateUpdated {
                account_id_hex,
                account_label,
                group_id,
            } => Self::GroupStateUpdated {
                account_id_hex,
                account_label,
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            MarmotAppEvent::MessageReceived(m) => Self::MessageReceived { received: m.into() },
            MarmotAppEvent::ProjectionUpdated(update) => Self::ProjectionUpdated {
                update: update.into(),
            },
            MarmotAppEvent::GroupEvent(e) => Self::GroupEvent {
                account_id_hex: e.account_id_hex,
                account_label: e.account_label,
            },
            MarmotAppEvent::AccountError(e) => Self::AccountError {
                account_id_hex: e.account_id_hex,
                account_label: e.account_label,
                message: e.message,
            },
            MarmotAppEvent::AgentStreamStarted(m) => Self::AgentStreamActivity {
                account_id_hex: m.account_id_hex,
                account_label: m.account_label,
            },
        }
    }
}
