//! Final-message sends, agent activity/operation/group-system events, and debug send recording.

use agent_control::{AgentControlDebugFinalSend, AgentControlEvent, AgentControlResponse};
use cgka_traits::GroupId;
use marmot_app::AgentOperationEventRequest;

use crate::AgentConnector;
use crate::error::ConnectorError;
use crate::validation::normalize_hex;

impl AgentConnector {
    pub(crate) async fn send_final_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        text: String,
        reply_to_message_id_hex: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        if self.debug_controls {
            return self.debug_record_final_send_response(
                account_id_hex,
                group_id_hex,
                text,
                reply_to_message_id_hex,
            );
        }

        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let summary = if let Some(target_message_id) = reply_to_message_id_hex {
            self.runtime
                .reply_to_message(&account.label, &group_id, &target_message_id, &text)
                .await?
        } else {
            self.runtime
                .send_message(&account.label, &group_id, text.into_bytes())
                .await?
        };
        Ok(AgentControlResponse::FinalSent {
            message_ids_hex: summary.message_ids,
        })
    }

    pub(crate) fn debug_inject_inbound_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        message_id_hex: &str,
        sender_account_id_hex: &str,
        text: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        let event = AgentControlEvent::InboundMessage {
            account_id_hex: normalize_hex(account_id_hex)?,
            group_id_hex: normalize_hex(group_id_hex)?,
            message_id_hex: normalize_hex(message_id_hex)?,
            sender_account_id_hex: normalize_hex(sender_account_id_hex)?,
            text,
        };
        let _ = self.debug_events.send(event);
        Ok(AgentControlResponse::Ack)
    }

    pub(crate) fn debug_recorded_finals_response(
        &self,
    ) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        Ok(AgentControlResponse::DebugRecordedFinals {
            sends: self.debug_final_sends.list(),
        })
    }

    fn debug_record_final_send_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        text: String,
        reply_to_message_id_hex: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        let record = self.debug_final_sends.record(AgentControlDebugFinalSend {
            account_id_hex: normalize_hex(account_id_hex)?,
            group_id_hex: normalize_hex(group_id_hex)?,
            text,
            reply_to_message_id_hex: reply_to_message_id_hex
                .map(|value| normalize_hex(&value))
                .transpose()?,
            message_ids_hex: Vec::new(),
        });
        Ok(AgentControlResponse::FinalSent {
            message_ids_hex: record.message_ids_hex,
        })
    }

    fn ensure_debug_controls(&self) -> Result<(), ConnectorError> {
        if self.debug_controls {
            Ok(())
        } else {
            Err(ConnectorError::DebugControlsDisabled)
        }
    }

    pub(crate) async fn send_agent_activity_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        status: String,
        text: String,
        reply_to_message_id_hex: Option<String>,
        extra: Option<serde_json::Value>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let reply_to_message_id_hex = reply_to_message_id_hex
            .map(|value| normalize_hex(&value))
            .transpose()?;
        let summary = self
            .runtime
            .send_agent_activity(
                &account.label,
                &group_id,
                status,
                text,
                reply_to_message_id_hex,
                extra,
            )
            .await?;
        Ok(AgentControlResponse::AppEventSent {
            message_ids_hex: summary.message_ids,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_agent_operation_event_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        event_type: String,
        status: String,
        operation_id: Option<String>,
        run_id: Option<String>,
        turn_id: Option<String>,
        name: Option<String>,
        text: String,
        preview: Option<String>,
        details: Option<serde_json::Value>,
        sequence: Option<u64>,
        ok: Option<bool>,
        duration_ms: Option<u64>,
        reply_to_message_id_hex: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let reply_to_message_id_hex = reply_to_message_id_hex
            .map(|value| normalize_hex(&value))
            .transpose()?;
        let summary = self
            .runtime
            .send_agent_operation_event(
                &account.label,
                &group_id,
                AgentOperationEventRequest {
                    event_type,
                    status,
                    operation_id,
                    run_id,
                    turn_id,
                    name,
                    text,
                    preview,
                    details,
                    sequence,
                    ok,
                    duration_ms,
                    reply_to_message_id: reply_to_message_id_hex,
                },
            )
            .await?;
        Ok(AgentControlResponse::AppEventSent {
            message_ids_hex: summary.message_ids,
        })
    }

    pub(crate) async fn send_group_system_event_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        system_type: String,
        text: String,
        data: Option<serde_json::Value>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let summary = self
            .runtime
            .send_group_system_event(&account.label, &group_id, system_type, text, data)
            .await?;
        Ok(AgentControlResponse::AppEventSent {
            message_ids_hex: summary.message_ids,
        })
    }
}
