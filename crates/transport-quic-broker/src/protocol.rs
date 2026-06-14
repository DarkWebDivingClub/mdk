//! Broker wire protocol constants: public ALPN/control/limit values plus the
//! private frame, room-retention, and timeout tunables shared across modules.

use std::time::Duration;

#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS,
};
use transport_quic_stream::AGENT_TEXT_STREAM_FRAME_ALLOWANCE;

/// Broker control protocol string. Carried in every control envelope and also
/// negotiated as the TLS ALPN value on broker connections.
pub const QUIC_BROKER_PROTOCOL_V1: &str = "marmot.quic_broker.v1";
/// ALPN protocol negotiated by broker connections (`marmot.quic_broker.v1`).
pub const QUIC_BROKER_ALPN_V1: &[u8] = QUIC_BROKER_PROTOCOL_V1.as_bytes();
pub const QUIC_BROKER_CONTROL_PUBLISH: u8 = 1;
pub const QUIC_BROKER_CONTROL_SUBSCRIBE: u8 = 2;
pub const DEFAULT_SUBSCRIBER_QUEUE_DEPTH: usize = 32;
pub const DEFAULT_BROKER_BACKLOG_DEPTH: usize = 1024;
pub const DEFAULT_BROKER_MAX_ROOMS: usize = 512;
pub const DEFAULT_BROKER_MAX_BACKLOG_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_BROKER_MAX_CONNECTIONS: usize = 256;
pub const DEFAULT_BROKER_MAX_STREAMS_PER_CONNECTION: usize = 64;
pub const DEFAULT_BROKER_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_BROKER_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_BROKER_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Default broker replay window: `0` retains no replay backlog, matching the
/// first-profile `replay_ttl_secs` default of `0` (no retained replay).
pub const DEFAULT_BROKER_REPLAY_TTL: Duration = Duration::ZERO;
/// Hard cap on the broker replay window, matching the first application
/// profile's `replay_ttl_secs <= 300`.
pub const MAX_BROKER_REPLAY_TTL: Duration =
    Duration::from_secs(AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS as u64);

pub(crate) const FRAME_LEN_BYTES: usize = 4;
#[cfg(test)]
pub(crate) const LOCAL_SERVER_BIND: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
pub(crate) const MAX_FRAME_SIZE: usize =
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize + AGENT_TEXT_STREAM_FRAME_ALLOWANCE;
pub(crate) const PUBLISH_SUBSCRIBER_GRACE: Duration = Duration::from_secs(5);
pub(crate) const FINISHED_ROOM_TTL: Duration = Duration::from_secs(60);
// Stale unfinished rooms are a defense-in-depth cleanup path for task
// cancellation, so keep the same retention window as finished backlog rooms.
pub(crate) const UNFINISHED_ROOM_TTL: Duration = FINISHED_ROOM_TTL;
pub(crate) const SEND_STOP_WAIT: Duration = Duration::from_secs(5);
