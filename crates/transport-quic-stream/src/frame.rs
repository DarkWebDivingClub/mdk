//! Length-prefixed wire framing: write/read a single record and validate the
//! `frame_len` against the policy and absolute caps before allocating.

use cgka_traits::agent_text_stream::AgentTextStreamRecordV1;

use crate::error::QuicTextStreamError;
use crate::protocol::{FRAME_LEN_BYTES, MAX_FRAME_SIZE};

pub(crate) async fn write_record(
    send: &mut quinn::SendStream,
    record: &AgentTextStreamRecordV1,
) -> Result<(), QuicTextStreamError> {
    let bytes = record.encode()?;
    let len =
        u32::try_from(bytes.len()).map_err(|_| QuicTextStreamError::FrameTooLarge(bytes.len()))?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub(crate) async fn read_record(
    recv: &mut quinn::RecvStream,
    max_frame_len: usize,
) -> Result<Option<AgentTextStreamRecordV1>, QuicTextStreamError> {
    let mut len_bytes = [0_u8; FRAME_LEN_BYTES];
    let mut read = 0;
    while read < FRAME_LEN_BYTES {
        match recv.read(&mut len_bytes[read..]).await? {
            Some(0) => return Err(QuicTextStreamError::TruncatedFrameLength),
            Some(n) => read += n,
            None if read == 0 => return Ok(None),
            None => return Err(QuicTextStreamError::TruncatedFrameLength),
        }
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    validate_frame_len(len, max_frame_len)?;
    let mut bytes = vec![0_u8; len];
    recv.read_exact(&mut bytes).await?;
    Ok(Some(AgentTextStreamRecordV1::decode(&bytes)?))
}

pub(crate) fn validate_frame_len(
    len: usize,
    max_frame_len: usize,
) -> Result<(), QuicTextStreamError> {
    if len == 0 {
        return Err(QuicTextStreamError::EmptyFrame);
    }
    if len > max_frame_len.min(MAX_FRAME_SIZE) {
        return Err(QuicTextStreamError::FrameTooLarge(len));
    }
    Ok(())
}
