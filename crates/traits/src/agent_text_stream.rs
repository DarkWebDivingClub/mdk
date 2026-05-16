//! Shared agent text stream protocol values.
//!
//! This module intentionally stops below the QUIC transport binding. It gives
//! upper layers stable names for the Marmot component/capabilities and small
//! helpers for the component state, key context, and final transcript
//! hash.

use crate::app_components::AppComponentData;
pub use crate::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT, AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
};
use crate::capabilities::Feature;
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AGENT_TEXT_STREAM_QUIC_RECEIVE_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.receive.v1");
pub const AGENT_TEXT_STREAM_QUIC_SEND_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.send.v1");
pub const AGENT_TEXT_STREAM_QUIC_FANOUT_FEATURE: Feature =
    Feature("marmot.feature.agent_text_stream_quic.fanout.v1");

pub const AGENT_TEXT_STREAM_KEY_CONTEXT_VERSION: &[u8] = b"v1";
pub const AGENT_TEXT_STREAM_TRANSCRIPT_HASH_CONTEXT: &[u8] =
    b"marmot agent text stream transcript v1";

pub const AGENT_TEXT_STREAM_ROLE_RECEIVE: u8 = 0x01;
pub const AGENT_TEXT_STREAM_ROLE_SEND: u8 = 0x02;
pub const AGENT_TEXT_STREAM_ROLE_FANOUT: u8 = 0x04;
pub const AGENT_TEXT_STREAM_ROLE_MASK: u8 =
    AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND | AGENT_TEXT_STREAM_ROLE_FANOUT;

pub const AGENT_TEXT_STREAM_RECORD_TEXT_DELTA: u8 = 0x01;
pub const AGENT_TEXT_STREAM_RECORD_TOOL_DELTA: u8 = 0x02;
pub const AGENT_TEXT_STREAM_RECORD_STATUS: u8 = 0x03;
pub const AGENT_TEXT_STREAM_RECORD_CHECKPOINT: u8 = 0x04;
pub const AGENT_TEXT_STREAM_RECORD_ABORT: u8 = 0x05;
pub const AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE: u8 = 0x06;

pub const AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN: u32 = 64 * 1024;
pub const AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS: u32 = 5 * 60;
pub const AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES: u16 = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTextStreamQuicPolicyV1 {
    pub required_member_roles: u8,
    pub allowed_member_roles: u8,
    pub max_plaintext_frame_len: u32,
    pub replay_ttl_secs: u32,
    pub padding_bucket_bytes: u16,
}

impl AgentTextStreamQuicPolicyV1 {
    pub fn user_to_agent_default() -> Self {
        Self {
            required_member_roles: AGENT_TEXT_STREAM_ROLE_RECEIVE,
            allowed_member_roles: AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND,
            max_plaintext_frame_len: 4096,
            replay_ttl_secs: 0,
            padding_bucket_bytes: 0,
        }
    }

    pub fn encode_component_state(&self) -> Result<Vec<u8>, AgentTextStreamPolicyError> {
        self.validate()?;
        let mut out = Vec::with_capacity(12);
        out.push(self.required_member_roles);
        out.push(self.allowed_member_roles);
        out.extend_from_slice(&self.max_plaintext_frame_len.to_be_bytes());
        out.extend_from_slice(&self.replay_ttl_secs.to_be_bytes());
        out.extend_from_slice(&self.padding_bucket_bytes.to_be_bytes());
        Ok(out)
    }

    pub fn decode_component_state(bytes: &[u8]) -> Result<Self, AgentTextStreamPolicyError> {
        if bytes.len() != 12 {
            return Err(AgentTextStreamPolicyError::InvalidComponentStateLength(
                bytes.len(),
            ));
        }
        let policy = Self {
            required_member_roles: bytes[0],
            allowed_member_roles: bytes[1],
            max_plaintext_frame_len: u32::from_be_bytes(
                bytes[2..6]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
            replay_ttl_secs: u32::from_be_bytes(
                bytes[6..10]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
            padding_bucket_bytes: u16::from_be_bytes(
                bytes[10..12]
                    .try_into()
                    .expect("slice length checked by component state length"),
            ),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_app_component_data(&self) -> Result<AppComponentData, AgentTextStreamPolicyError> {
        Ok(AppComponentData {
            component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
            data: self.encode_component_state()?,
        })
    }

    pub fn validate(&self) -> Result<(), AgentTextStreamPolicyError> {
        if self.required_member_roles == 0 {
            return Err(AgentTextStreamPolicyError::EmptyRequiredRoles);
        }
        if self.required_member_roles & !AGENT_TEXT_STREAM_ROLE_MASK != 0 {
            return Err(AgentTextStreamPolicyError::UnknownRequiredRoleBits(
                self.required_member_roles,
            ));
        }
        if self.allowed_member_roles & !AGENT_TEXT_STREAM_ROLE_MASK != 0 {
            return Err(AgentTextStreamPolicyError::UnknownAllowedRoleBits(
                self.allowed_member_roles,
            ));
        }
        if self.required_member_roles & !self.allowed_member_roles != 0 {
            return Err(AgentTextStreamPolicyError::RequiredRolesNotAllowed);
        }
        if self.max_plaintext_frame_len == 0 {
            return Err(AgentTextStreamPolicyError::EmptyFrameLimit);
        }
        if self.max_plaintext_frame_len > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN {
            return Err(AgentTextStreamPolicyError::FrameLimitTooLarge(
                self.max_plaintext_frame_len,
            ));
        }
        if self.replay_ttl_secs > AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS {
            return Err(AgentTextStreamPolicyError::ReplayTtlTooLarge(
                self.replay_ttl_secs,
            ));
        }
        if self.padding_bucket_bytes > AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES {
            return Err(AgentTextStreamPolicyError::PaddingBucketTooLarge(
                self.padding_bucket_bytes,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentTextStreamPolicyError {
    #[error("required agent text stream roles cannot be empty")]
    EmptyRequiredRoles,
    #[error("required agent text stream role mask contains unknown bits: {0:#04x}")]
    UnknownRequiredRoleBits(u8),
    #[error("allowed agent text stream role mask contains unknown bits: {0:#04x}")]
    UnknownAllowedRoleBits(u8),
    #[error("required agent text stream roles must be a subset of allowed roles")]
    RequiredRolesNotAllowed,
    #[error("agent text stream plaintext frame limit cannot be zero")]
    EmptyFrameLimit,
    #[error("agent text stream component state must be 12 bytes, got {0}")]
    InvalidComponentStateLength(usize),
    #[error("agent text stream plaintext frame limit exceeds app profile max: {0}")]
    FrameLimitTooLarge(u32),
    #[error("agent text stream replay ttl exceeds app profile max: {0}")]
    ReplayTtlTooLarge(u32),
    #[error("agent text stream padding bucket exceeds app profile max: {0}")]
    PaddingBucketTooLarge(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTextStreamKeyContextV1 {
    pub group_id: GroupId,
    pub stream_id: Vec<u8>,
    pub mls_epoch: EpochId,
    pub sender_id: MemberId,
    pub start_event_id: MessageId,
}

impl AgentTextStreamKeyContextV1 {
    pub fn new(
        group_id: GroupId,
        stream_id: impl Into<Vec<u8>>,
        mls_epoch: EpochId,
        sender_id: MemberId,
        start_event_id: MessageId,
    ) -> Self {
        Self {
            group_id,
            stream_id: stream_id.into(),
            mls_epoch,
            sender_id,
            start_event_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_len_prefixed(&mut out, AGENT_TEXT_STREAM_KEY_CONTEXT_VERSION);
        push_len_prefixed(&mut out, self.group_id.as_slice());
        push_len_prefixed(&mut out, &self.stream_id);
        out.extend_from_slice(&self.mls_epoch.0.to_be_bytes());
        push_len_prefixed(&mut out, self.sender_id.as_slice());
        push_len_prefixed(&mut out, self.start_event_id.as_slice());
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTextStreamFinalV1 {
    pub stream_id: Vec<u8>,
    pub final_text_or_reference: String,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
    pub finished_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTextStreamTranscriptV1 {
    stream_id: Vec<u8>,
    start_event_id: MessageId,
    hash: [u8; 32],
    chunk_count: u64,
}

impl AgentTextStreamTranscriptV1 {
    pub fn new(stream_id: impl Into<Vec<u8>>, start_event_id: MessageId) -> Self {
        let stream_id = stream_id.into();
        let mut hasher = Sha256::new();
        hasher.update(AGENT_TEXT_STREAM_TRANSCRIPT_HASH_CONTEXT);
        hash_len_prefixed(&mut hasher, &stream_id);
        hash_len_prefixed(&mut hasher, start_event_id.as_slice());
        Self {
            stream_id,
            start_event_id,
            hash: hasher.finalize().into(),
            chunk_count: 0,
        }
    }

    pub fn append(&mut self, seq: u64, record_type: u8, plaintext_frame: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(seq.to_be_bytes());
        hasher.update([record_type]);
        hasher.update(plaintext_frame);
        self.hash = hasher.finalize().into();
        self.chunk_count += 1;
    }

    pub fn stream_id(&self) -> &[u8] {
        &self.stream_id
    }

    pub fn start_event_id(&self) -> &MessageId {
        &self.start_event_id
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_to_agent_policy_encodes_component_state() {
        let bytes = AgentTextStreamQuicPolicyV1::user_to_agent_default()
            .encode_component_state()
            .unwrap();
        assert_eq!(
            bytes,
            vec![
                AGENT_TEXT_STREAM_ROLE_RECEIVE,
                AGENT_TEXT_STREAM_ROLE_RECEIVE | AGENT_TEXT_STREAM_ROLE_SEND,
                0x00,
                0x00,
                0x10,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        );
        assert_eq!(
            AgentTextStreamQuicPolicyV1::decode_component_state(&bytes).unwrap(),
            AgentTextStreamQuicPolicyV1::user_to_agent_default()
        );
    }

    #[test]
    fn policy_validation_enforces_app_profile_caps() {
        let too_large_frame = AgentTextStreamQuicPolicyV1 {
            max_plaintext_frame_len: AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_frame.validate(),
            Err(AgentTextStreamPolicyError::FrameLimitTooLarge(_))
        ));

        let too_large_replay = AgentTextStreamQuicPolicyV1 {
            replay_ttl_secs: AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_replay.validate(),
            Err(AgentTextStreamPolicyError::ReplayTtlTooLarge(_))
        ));

        let too_large_padding = AgentTextStreamQuicPolicyV1 {
            padding_bucket_bytes: AGENT_TEXT_STREAM_MAX_PADDING_BUCKET_BYTES + 1,
            ..AgentTextStreamQuicPolicyV1::user_to_agent_default()
        };
        assert!(matches!(
            too_large_padding.validate(),
            Err(AgentTextStreamPolicyError::PaddingBucketTooLarge(_))
        ));
    }

    #[test]
    fn key_context_is_versioned_and_length_delimited() {
        let context = AgentTextStreamKeyContextV1::new(
            GroupId::new(vec![0x01, 0x02]),
            vec![0x03, 0x04],
            EpochId(9),
            MemberId::new(vec![0x05]),
            MessageId::new(vec![0x06; 32]),
        )
        .encode();
        assert_eq!(&context[..10], &[0, 0, 0, 0, 0, 0, 0, 2, b'v', b'1']);
        assert!(
            context
                .windows(8)
                .any(|window| window == 9_u64.to_be_bytes())
        );
    }

    #[test]
    fn transcript_hash_commits_to_order_and_type() {
        let start = MessageId::new(vec![0x22; 32]);
        let mut first = AgentTextStreamTranscriptV1::new(vec![0x11; 32], start.clone());
        first.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"hel");
        first.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"lo");

        let mut different_order = AgentTextStreamTranscriptV1::new(vec![0x11; 32], start.clone());
        different_order.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"lo");
        different_order.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"hel");

        let mut different_type = AgentTextStreamTranscriptV1::new(vec![0x11; 32], start);
        different_type.append(1, AGENT_TEXT_STREAM_RECORD_STATUS, b"hel");
        different_type.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"lo");

        assert_eq!(first.chunk_count(), 2);
        assert_ne!(first.hash(), different_order.hash());
        assert_ne!(first.hash(), different_type.hash());
    }
}
