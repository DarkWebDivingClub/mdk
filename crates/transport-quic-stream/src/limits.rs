//! Receive-side bounds on record count and accumulated plaintext, with the
//! accumulator that enforces them and the limit-breach error type.

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_DEFAULT_MAX_PLAINTEXT_BYTES, AGENT_TEXT_STREAM_DEFAULT_MAX_RECORDS,
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AgentTextStreamRecordV1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentTextStreamReceiveLimits {
    pub max_records: u64,
    pub max_plaintext_bytes: usize,
    /// Group policy `max_plaintext_frame_len` when available. Receive paths
    /// reject wire frames above this value plus the spec-pinned 1024-byte
    /// allowance; the app-profile constant is the ceiling and default.
    pub max_plaintext_frame_len: u32,
}

impl Default for AgentTextStreamReceiveLimits {
    fn default() -> Self {
        Self {
            max_records: AGENT_TEXT_STREAM_DEFAULT_MAX_RECORDS,
            max_plaintext_bytes: AGENT_TEXT_STREAM_DEFAULT_MAX_PLAINTEXT_BYTES,
            max_plaintext_frame_len: AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentTextStreamReceiveAccumulator {
    limits: AgentTextStreamReceiveLimits,
    records: u64,
    plaintext_bytes: usize,
}

impl AgentTextStreamReceiveAccumulator {
    pub fn new(limits: AgentTextStreamReceiveLimits) -> Self {
        Self {
            limits,
            records: 0,
            plaintext_bytes: 0,
        }
    }

    pub fn observe(
        &mut self,
        record: &AgentTextStreamRecordV1,
    ) -> Result<(), AgentTextStreamReceiveLimitError> {
        let records = self.records.checked_add(1).ok_or(
            AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: u64::MAX,
                limit: self.limits.max_records,
            },
        )?;
        if records > self.limits.max_records {
            return Err(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: records,
                limit: self.limits.max_records,
            });
        }

        let plaintext_bytes = self
            .plaintext_bytes
            .checked_add(record.plaintext_frame.len())
            .ok_or(
                AgentTextStreamReceiveLimitError::PlaintextByteLimitExceeded {
                    attempted: usize::MAX,
                    limit: self.limits.max_plaintext_bytes,
                },
            )?;
        if plaintext_bytes > self.limits.max_plaintext_bytes {
            return Err(
                AgentTextStreamReceiveLimitError::PlaintextByteLimitExceeded {
                    attempted: plaintext_bytes,
                    limit: self.limits.max_plaintext_bytes,
                },
            );
        }

        self.records = records;
        self.plaintext_bytes = plaintext_bytes;
        Ok(())
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    pub fn plaintext_bytes(&self) -> usize {
        self.plaintext_bytes
    }
}

impl Default for AgentTextStreamReceiveAccumulator {
    fn default() -> Self {
        Self::new(AgentTextStreamReceiveLimits::default())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentTextStreamReceiveLimitError {
    #[error("agent text stream record limit exceeded: {attempted} > {limit}")]
    RecordLimitExceeded { attempted: u64, limit: u64 },
    #[error("agent text stream plaintext byte limit exceeded: {attempted} > {limit}")]
    PlaintextByteLimitExceeded { attempted: usize, limit: usize },
}
