use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_MAX_REPLAY_TTL_SECS,
    AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN, AGENT_TEXT_STREAM_RECORD_ABORT,
    AGENT_TEXT_STREAM_RECORD_CHECKPOINT, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AgentTextStreamRecordError, AgentTextStreamRecordV1, AgentTextStreamTranscriptV1,
};
use cgka_traits::app_components::{decode_quic_varint, encode_quic_varint};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, Semaphore, mpsc};
use tokio::time::{sleep, timeout};
use transport_quic_stream::{
    AGENT_TEXT_STREAM_FRAME_ALLOWANCE, AgentTextStreamCrypto, AgentTextStreamReceiveAccumulator,
    AgentTextStreamReceiveLimitError, AgentTextStreamReceiveLimits, ReceivedTextChunk,
    ReceivedTextStream, SentTextStream, decrypt_record, effective_plaintext_cap, encrypt_record,
    frame_len_cap,
};

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

const FRAME_LEN_BYTES: usize = 4;
#[cfg(test)]
const LOCAL_SERVER_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const MAX_FRAME_SIZE: usize =
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize + AGENT_TEXT_STREAM_FRAME_ALLOWANCE;
const PUBLISH_SUBSCRIBER_GRACE: Duration = Duration::from_secs(5);
const FINISHED_ROOM_TTL: Duration = Duration::from_secs(60);
// Stale unfinished rooms are a defense-in-depth cleanup path for task
// cancellation, so keep the same retention window as finished backlog rooms.
const UNFINISHED_ROOM_TTL: Duration = FINISHED_ROOM_TTL;
const SEND_STOP_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct QuicBrokerConfig {
    pub bind_addr: SocketAddr,
    pub per_subscriber_queue: usize,
    pub max_backlog: usize,
    pub max_rooms: usize,
    pub max_backlog_bytes: usize,
    pub max_connections: usize,
    pub max_streams_per_connection: usize,
    pub read_timeout: Duration,
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    /// Replay window for serving retained backlog to late subscribers. The
    /// broker timestamps backlog records on append and purges entries older
    /// than this window before serving them. `0` (the default) retains no
    /// replay backlog; the hard cap is [`MAX_BROKER_REPLAY_TTL`] (300s). The
    /// group policy `replay_ttl_secs` is the interop-visible bound; this
    /// broker is policy-blind, so the operator-configured value applies to
    /// every room.
    pub replay_ttl: Duration,
    pub tls: QuicBrokerTlsConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuicBrokerTlsConfig {
    GenerateSelfSigned {
        subject_alt_names: Vec<String>,
    },
    PemFiles {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

impl Default for QuicBrokerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4450),
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
            max_rooms: DEFAULT_BROKER_MAX_ROOMS,
            max_backlog_bytes: DEFAULT_BROKER_MAX_BACKLOG_BYTES,
            max_connections: DEFAULT_BROKER_MAX_CONNECTIONS,
            max_streams_per_connection: DEFAULT_BROKER_MAX_STREAMS_PER_CONNECTION,
            read_timeout: DEFAULT_BROKER_READ_TIMEOUT,
            max_idle_timeout: DEFAULT_BROKER_MAX_IDLE_TIMEOUT,
            keep_alive_interval: DEFAULT_BROKER_KEEP_ALIVE_INTERVAL,
            replay_ttl: DEFAULT_BROKER_REPLAY_TTL,
            tls: QuicBrokerTlsConfig::GenerateSelfSigned {
                subject_alt_names: vec!["localhost".to_owned()],
            },
        }
    }
}

pub struct QuicBrokerServer {
    endpoint: Endpoint,
    server_cert_der: Vec<u8>,
    state: Arc<BrokerState>,
    connection_limiter: Arc<Semaphore>,
    max_streams_per_connection: usize,
    read_timeout: Duration,
}

impl QuicBrokerServer {
    pub fn bind(config: QuicBrokerConfig) -> Result<Self, QuicBrokerError> {
        if config.per_subscriber_queue == 0 {
            return Err(QuicBrokerError::EmptySubscriberQueue);
        }
        if config.max_backlog == 0 {
            return Err(QuicBrokerError::EmptyBacklog);
        }
        if config.max_rooms == 0 {
            return Err(QuicBrokerError::EmptyRoomLimit);
        }
        if config.max_backlog_bytes == 0 {
            return Err(QuicBrokerError::EmptyBacklogByteLimit);
        }
        if config.max_connections == 0 {
            return Err(QuicBrokerError::EmptyConnectionLimit);
        }
        if config.max_streams_per_connection == 0 {
            return Err(QuicBrokerError::EmptyStreamLimit);
        }
        if config.read_timeout.is_zero() {
            return Err(QuicBrokerError::EmptyReadTimeout);
        }
        if config.max_idle_timeout.is_zero() {
            return Err(QuicBrokerError::EmptyIdleTimeout);
        }
        if config.keep_alive_interval.is_zero() {
            return Err(QuicBrokerError::EmptyKeepAliveInterval);
        }
        if config.replay_ttl > MAX_BROKER_REPLAY_TTL {
            return Err(QuicBrokerError::ReplayTtlTooLarge {
                requested_secs: config.replay_ttl.as_secs(),
                cap_secs: MAX_BROKER_REPLAY_TTL.as_secs(),
            });
        }
        let (mut server_config, server_cert_der) = configure_server(&config.tls)?;
        server_config.transport_config(Arc::new(broker_transport_config(&config)?));
        let endpoint = Endpoint::server(server_config, config.bind_addr)?;
        Ok(Self {
            endpoint,
            server_cert_der,
            state: Arc::new(BrokerState::new(
                config.per_subscriber_queue,
                config.max_backlog,
                config.max_rooms,
                config.max_backlog_bytes,
                config.replay_ttl,
            )),
            connection_limiter: Arc::new(Semaphore::new(config.max_connections)),
            max_streams_per_connection: config.max_streams_per_connection,
            read_timeout: config.read_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicBrokerError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn server_cert_der(&self) -> &[u8] {
        &self.server_cert_der
    }

    pub fn server_cert_sha256_fingerprint(&self) -> String {
        certificate_sha256_fingerprint_hex(&self.server_cert_der)
    }

    pub async fn run_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), QuicBrokerError> {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    self.endpoint.close(0_u32.into(), b"shutdown");
                    self.endpoint.wait_idle().await;
                    return Ok(());
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };
                    let Ok(permit) = Arc::clone(&self.connection_limiter).try_acquire_owned() else {
                        incoming.refuse();
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    let max_streams_per_connection = self.max_streams_per_connection;
                    let read_timeout = self.read_timeout;
                    tokio::spawn(async move {
                        let _permit = permit;
                        let Ok(connection) = incoming.await else {
                            return;
                        };
                        let _ = handle_connection(
                            state,
                            connection,
                            max_streams_per_connection,
                            read_timeout,
                        ).await;
                    });
                }
            }
        }
    }
}

fn certificate_sha256_fingerprint_hex(certificate_der: &[u8]) -> String {
    hex::encode(Sha256::digest(certificate_der))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BrokerStreamKey {
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
}

impl BrokerStreamKey {
    pub fn new(stream_id: impl Into<Vec<u8>>, start_event_id: MessageId) -> Self {
        Self {
            stream_id: stream_id.into(),
            start_event_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicBrokerControlTypeV1 {
    Publish,
    Subscribe,
}

impl QuicBrokerControlTypeV1 {
    fn wire(self) -> u8 {
        match self {
            Self::Publish => QUIC_BROKER_CONTROL_PUBLISH,
            Self::Subscribe => QUIC_BROKER_CONTROL_SUBSCRIBE,
        }
    }

    fn from_wire(value: u8) -> Result<Self, QuicBrokerError> {
        match value {
            QUIC_BROKER_CONTROL_PUBLISH => Ok(Self::Publish),
            QUIC_BROKER_CONTROL_SUBSCRIBE => Ok(Self::Subscribe),
            other => Err(QuicBrokerError::UnknownControlType(other)),
        }
    }
}

/// Binary broker control envelope, Marmot binary profile:
///
/// ```text
/// struct {
///   opaque marmot_broker<1..255>;     // ASCII "marmot.quic_broker.v1"
///   BrokerControlType control_type;   // uint8: publish(1), subscribe(2)
///   opaque stream_id<1..64>;          // raw stream id bytes
///   opaque start_event_id<1..64>;     // raw event id bytes (32 bytes today)
/// } QuicBrokerControlEnvelopeV1;
/// ```
///
/// Each `opaque name<min..max>` field uses the QUIC variable-length length
/// prefix. On the wire the envelope is framed exactly like a record frame: a
/// 4-byte big-endian `frame_len` followed by that many envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicBrokerControlEnvelopeV1 {
    pub control_type: QuicBrokerControlTypeV1,
    pub stream_id: Vec<u8>,
    pub start_event_id: Vec<u8>,
}

impl QuicBrokerControlEnvelopeV1 {
    pub fn publish(stream_id: impl Into<Vec<u8>>, start_event_id: &MessageId) -> Self {
        Self {
            control_type: QuicBrokerControlTypeV1::Publish,
            stream_id: stream_id.into(),
            start_event_id: start_event_id.as_slice().to_vec(),
        }
    }

    pub fn subscribe(stream_id: impl Into<Vec<u8>>, start_event_id: &MessageId) -> Self {
        Self {
            control_type: QuicBrokerControlTypeV1::Subscribe,
            stream_id: stream_id.into(),
            start_event_id: start_event_id.as_slice().to_vec(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, QuicBrokerError> {
        self.validate_bounds()?;
        let mut out = Vec::new();
        encode_quic_varint(QUIC_BROKER_PROTOCOL_V1.len() as u64, &mut out);
        out.extend_from_slice(QUIC_BROKER_PROTOCOL_V1.as_bytes());
        out.push(self.control_type.wire());
        encode_quic_varint(self.stream_id.len() as u64, &mut out);
        out.extend_from_slice(&self.stream_id);
        encode_quic_varint(self.start_event_id.len() as u64, &mut out);
        out.extend_from_slice(&self.start_event_id);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QuicBrokerError> {
        let (marmot_broker, rest) = take_control_len_prefixed(bytes, "marmot_broker")?;
        if marmot_broker.is_empty() || marmot_broker.len() > 255 {
            return Err(QuicBrokerError::WrongControlProtocol(
                String::from_utf8_lossy(marmot_broker).into_owned(),
            ));
        }
        if marmot_broker != QUIC_BROKER_PROTOCOL_V1.as_bytes() {
            return Err(QuicBrokerError::WrongControlProtocol(
                String::from_utf8_lossy(marmot_broker).into_owned(),
            ));
        }
        let (control_type, rest) = rest
            .split_first()
            .ok_or(QuicBrokerError::ControlTruncated("control_type"))?;
        let control_type = QuicBrokerControlTypeV1::from_wire(*control_type)?;
        let (stream_id, rest) = take_control_len_prefixed(rest, "stream_id")?;
        let (start_event_id, rest) = take_control_len_prefixed(rest, "start_event_id")?;
        if !rest.is_empty() {
            return Err(QuicBrokerError::ControlTrailingBytes(rest.len()));
        }
        let envelope = Self {
            control_type,
            stream_id: stream_id.to_vec(),
            start_event_id: start_event_id.to_vec(),
        };
        envelope.validate_bounds()?;
        Ok(envelope)
    }

    fn validate_bounds(&self) -> Result<(), QuicBrokerError> {
        if self.stream_id.is_empty() {
            return Err(QuicBrokerError::EmptyStreamId);
        }
        if self.stream_id.len() > AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN {
            return Err(QuicBrokerError::StreamIdTooLong(self.stream_id.len()));
        }
        if self.start_event_id.is_empty() {
            return Err(QuicBrokerError::EmptyStartEventId);
        }
        if self.start_event_id.len() > AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN {
            return Err(QuicBrokerError::StartEventIdTooLong(
                self.start_event_id.len(),
            ));
        }
        Ok(())
    }

    pub fn key(&self) -> BrokerStreamKey {
        BrokerStreamKey::new(
            self.stream_id.clone(),
            MessageId::new(self.start_event_id.clone()),
        )
    }
}

fn take_control_len_prefixed<'a>(
    bytes: &'a [u8],
    field: &'static str,
) -> Result<(&'a [u8], &'a [u8]), QuicBrokerError> {
    let (len, prefix_len) =
        decode_quic_varint(bytes).map_err(|_| QuicBrokerError::ControlTruncated(field))?;
    let len = usize::try_from(len).map_err(|_| QuicBrokerError::ControlTruncated(field))?;
    let rest = bytes
        .get(prefix_len..)
        .ok_or(QuicBrokerError::ControlTruncated(field))?;
    if rest.len() < len {
        return Err(QuicBrokerError::ControlTruncated(field));
    }
    Ok(rest.split_at(len))
}

#[derive(Clone, Debug)]
pub enum BrokerServerTrust {
    Platform,
    CertificateDer(Vec<u8>),
    InsecureLocal,
}

#[derive(Clone, Debug)]
pub struct PublishTextToBroker {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub text: String,
    pub max_chunk_bytes: usize,
    pub chunk_delay: Duration,
    pub crypto: Option<AgentTextStreamCrypto>,
    /// Group policy `max_plaintext_frame_len` when the caller has the decoded
    /// `AgentTextStreamQuicPolicyV1` available. Chunk size is clamped to it;
    /// the app-profile constant is the ceiling and the fallback when `None`.
    pub max_plaintext_frame_len: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct OpenBrokerTextPublisher {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub crypto: Option<AgentTextStreamCrypto>,
    /// Group policy `max_plaintext_frame_len` when the caller has the decoded
    /// `AgentTextStreamQuicPolicyV1` available. Chunk size is clamped to it;
    /// the app-profile constant is the ceiling and the fallback when `None`.
    pub max_plaintext_frame_len: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct SubscribeTextFromBroker {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub crypto: Option<AgentTextStreamCrypto>,
}

pub struct BrokerTextPublisher {
    endpoint: Endpoint,
    connection: quinn::Connection,
    send: quinn::SendStream,
    transcript: AgentTextStreamTranscriptV1,
    next_seq: u64,
    crypto: Option<AgentTextStreamCrypto>,
    max_plaintext_frame_len: Option<u32>,
}

impl BrokerTextPublisher {
    pub async fn connect(config: OpenBrokerTextPublisher) -> Result<Self, QuicBrokerError> {
        let endpoint = client_endpoint(config.trust, config.broker_addr)?;
        let connection = endpoint
            .connect(config.broker_addr, &config.server_name)?
            .await?;
        let mut send = connection.open_uni().await?;
        write_control_frame(
            &mut send,
            &QuicBrokerControlEnvelopeV1::publish(config.stream_id.clone(), &config.start_event_id),
        )
        .await?;

        Ok(Self {
            endpoint,
            connection,
            send,
            transcript: AgentTextStreamTranscriptV1::new(config.stream_id, config.start_event_id),
            next_seq: 1,
            crypto: config.crypto,
            max_plaintext_frame_len: config.max_plaintext_frame_len,
        })
    }

    pub async fn append_text(
        &mut self,
        text: &str,
        max_chunk_bytes: usize,
        chunk_delay: Duration,
    ) -> Result<u64, QuicBrokerError> {
        self.append_record_text(
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
            text,
            max_chunk_bytes,
            chunk_delay,
        )
        .await
    }

    pub async fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        max_chunk_bytes: usize,
        chunk_delay: Duration,
    ) -> Result<u64, QuicBrokerError> {
        if max_chunk_bytes == 0 {
            return Err(QuicBrokerError::EmptyChunkSize);
        }
        if max_chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
            return Err(QuicBrokerError::ChunkSizeTooLarge(max_chunk_bytes));
        }
        // Clamp the chunk size to the group policy cap when the publisher was
        // opened with one; the app-profile constant remains the ceiling.
        let max_chunk_bytes =
            max_chunk_bytes.min(effective_plaintext_cap(self.max_plaintext_frame_len));

        let mut appended = 0_u64;
        for chunk in transport_quic_stream::split_text_deltas(text, max_chunk_bytes) {
            let record = AgentTextStreamRecordV1::new(
                self.transcript.stream_id().to_vec(),
                self.next_seq,
                record_type,
                chunk,
            );
            record.validate()?;
            self.next_seq += 1;
            let wire_record = if let Some(crypto) = &self.crypto {
                encrypt_record(crypto, &record)?
            } else {
                record.clone()
            };
            write_record_frame(&mut self.send, &wire_record).await?;
            self.transcript
                .append(record.seq, record.record_type, &record.plaintext_frame);
            appended += 1;
            if !chunk_delay.is_zero() {
                sleep(chunk_delay).await;
            }
        }
        Ok(appended)
    }

    /// Emit a single zero-length `Abort` (`0x05`) record so live subscribers
    /// observe the terminal cancellation of a preview and remove or mark it as
    /// cancelled. `Abort` carries no durable text; it consumes one `seq` and
    /// contributes to the transcript like any other record.
    pub async fn append_abort(&mut self) -> Result<(), QuicBrokerError> {
        let record = AgentTextStreamRecordV1::new(
            self.transcript.stream_id().to_vec(),
            self.next_seq,
            AGENT_TEXT_STREAM_RECORD_ABORT,
            Vec::new(),
        );
        record.validate()?;
        self.next_seq += 1;
        let wire_record = if let Some(crypto) = &self.crypto {
            encrypt_record(crypto, &record)?
        } else {
            record.clone()
        };
        write_record_frame(&mut self.send, &wire_record).await?;
        self.transcript
            .append(record.seq, record.record_type, &record.plaintext_frame);
        Ok(())
    }

    pub async fn finish(mut self) -> Result<SentTextStream, QuicBrokerError> {
        self.send.finish()?;
        let stopped = timeout(SEND_STOP_WAIT, self.send.stopped()).await;
        self.connection.close(0_u32.into(), b"done");
        self.endpoint.wait_idle().await;
        match stopped {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {}
        }
        Ok(SentTextStream {
            stream_id: self.transcript.stream_id().to_vec(),
            transcript_hash: self.transcript.hash(),
            chunk_count: self.transcript.chunk_count(),
        })
    }
}

pub async fn publish_text_to_broker(
    config: PublishTextToBroker,
) -> Result<SentTextStream, QuicBrokerError> {
    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr: config.broker_addr,
        server_name: config.server_name,
        trust: config.trust,
        stream_id: config.stream_id,
        start_event_id: config.start_event_id,
        crypto: config.crypto,
        max_plaintext_frame_len: config.max_plaintext_frame_len,
    })
    .await?;
    publisher
        .append_text(&config.text, config.max_chunk_bytes, config.chunk_delay)
        .await?;
    publisher.finish().await
}

pub async fn subscribe_text_from_broker(
    config: SubscribeTextFromBroker,
) -> Result<ReceivedTextStream, QuicBrokerError> {
    subscribe_text_from_broker_with_updates(config, |_| {}).await
}

pub async fn subscribe_text_from_broker_with_updates<F>(
    config: SubscribeTextFromBroker,
    mut on_chunk: F,
) -> Result<ReceivedTextStream, QuicBrokerError>
where
    F: FnMut(&ReceivedTextChunk),
{
    subscribe_text_from_broker_with_limits(
        config,
        AgentTextStreamReceiveLimits::default(),
        &mut on_chunk,
    )
    .await
}

pub async fn subscribe_text_from_broker_with_limits<F>(
    config: SubscribeTextFromBroker,
    limits: AgentTextStreamReceiveLimits,
    mut on_chunk: F,
) -> Result<ReceivedTextStream, QuicBrokerError>
where
    F: FnMut(&ReceivedTextChunk),
{
    let endpoint = client_endpoint(config.trust, config.broker_addr)?;
    let connection = endpoint
        .connect(config.broker_addr, &config.server_name)?
        .await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::subscribe(config.stream_id.clone(), &config.start_event_id),
    )
    .await?;
    send.finish()?;

    // Last-accepted seq high-water mark per the QUIC transport binding:
    // records at or below it (duplicates, broker backlog replayed on
    // reconnect) are discarded silently and are never stream-fatal; the next
    // accepted record is high_water + 1; a record further ahead is a gap.
    let mut high_water = 0_u64;
    let mut chunks = Vec::new();
    let mut text = String::new();
    let mut transcript =
        AgentTextStreamTranscriptV1::new(config.stream_id.clone(), config.start_event_id);
    let mut limit_state = AgentTextStreamReceiveAccumulator::new(limits);
    let max_frame_len = frame_len_cap(Some(limits.max_plaintext_frame_len));

    while let Some(record) = read_record_frame(&mut recv, None, max_frame_len).await? {
        if record.seq <= high_water {
            continue;
        }
        if record.seq != high_water + 1 {
            return Err(QuicBrokerError::UnexpectedSequence {
                expected: high_water + 1,
                actual: record.seq,
            });
        }
        let record = if let Some(crypto) = &config.crypto {
            decrypt_record(crypto, &record)?
        } else {
            record
        };
        limit_state.observe(&record)?;
        if record.stream_id != config.stream_id {
            return Err(QuicBrokerError::MixedStreamIds);
        }
        high_water = record.seq;

        let frame_text = stream_record_text(&record)?;
        if record.record_type == AGENT_TEXT_STREAM_RECORD_TEXT_DELTA {
            text.push_str(&frame_text);
        }
        transcript.append(record.seq, record.record_type, &record.plaintext_frame);
        let chunk = ReceivedTextChunk {
            seq: record.seq,
            record_type: record.record_type,
            flags: record.flags,
            text: frame_text,
        };
        on_chunk(&chunk);
        chunks.push(chunk);
    }

    connection.close(0_u32.into(), b"done");
    if chunks.is_empty() {
        return Err(QuicBrokerError::EmptyStream);
    }
    Ok(ReceivedTextStream {
        stream_id: transcript.stream_id().to_vec(),
        chunks,
        text,
        transcript_hash: transcript.hash(),
        chunk_count: transcript.chunk_count(),
    })
}

/// Decode the per-record text a subscriber can surface for a single stream record.
///
/// `TextDelta`, `Status`, `ProgressDelta`, and `Checkpoint` carry UTF-8 the
/// consumer renders: deltas build the provisional preview, status/progress feed
/// non-chat agent chrome, and a `Checkpoint` is a full preview snapshot the
/// consumer swaps in for its live preview. `Abort` and `FinalNotice` are
/// advisory (the consumer acts on the record type, not its bytes), as is any
/// unknown future type, so they decode to an empty string. Note this only
/// decodes one record's frame; accumulation into the provisional answer text is
/// the caller's job and stays `TextDelta`-only.
fn stream_record_text(record: &AgentTextStreamRecordV1) -> Result<String, QuicBrokerError> {
    match record.record_type {
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
        | AGENT_TEXT_STREAM_RECORD_STATUS
        | AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA
        | AGENT_TEXT_STREAM_RECORD_CHECKPOINT => {
            Ok(str::from_utf8(&record.plaintext_frame)?.to_owned())
        }
        _ => Ok(String::new()),
    }
}

#[derive(Debug)]
struct BrokerState {
    per_subscriber_queue: usize,
    max_backlog: usize,
    max_rooms: usize,
    max_backlog_bytes: usize,
    replay_ttl: Duration,
    inner: Mutex<BrokerStateInner>,
}

#[derive(Debug, Default)]
struct BrokerStateInner {
    rooms: HashMap<BrokerStreamKey, BrokerRoom>,
    next_subscriber_id: u64,
    total_backlog_bytes: usize,
}

#[derive(Debug)]
struct BrokerRoom {
    subscribers: Vec<Subscriber>,
    backlog: VecDeque<BacklogRecord>,
    backlog_bytes: usize,
    subscriber_notify: Arc<Notify>,
    finished_at: Option<Instant>,
    last_activity_at: Instant,
}

impl Default for BrokerRoom {
    fn default() -> Self {
        Self {
            subscribers: Vec::new(),
            backlog: VecDeque::new(),
            backlog_bytes: 0,
            subscriber_notify: Arc::new(Notify::new()),
            finished_at: None,
            last_activity_at: Instant::now(),
        }
    }
}

#[derive(Debug)]
struct BacklogRecord {
    record: AgentTextStreamRecordV1,
    bytes: usize,
    /// Append timestamp used to purge entries older than the broker replay
    /// TTL before serving backlog to a new subscriber.
    appended_at: Instant,
}

/// Drop backlog entries older than the replay TTL from the front of the
/// (append-ordered) backlog. Returns the freed byte count so the caller can
/// adjust the global backlog budget. A zero TTL purges everything.
fn purge_expired_backlog(room: &mut BrokerRoom, replay_ttl: Duration) -> usize {
    let mut freed = 0;
    while let Some(front) = room.backlog.front() {
        if front.appended_at.elapsed() < replay_ttl {
            break;
        }
        let dropped = room.backlog.pop_front().expect("front entry checked above");
        room.backlog_bytes = room.backlog_bytes.saturating_sub(dropped.bytes);
        freed += dropped.bytes;
    }
    freed
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    tx: mpsc::Sender<AgentTextStreamRecordV1>,
}

impl BrokerState {
    fn new(
        per_subscriber_queue: usize,
        max_backlog: usize,
        max_rooms: usize,
        max_backlog_bytes: usize,
        replay_ttl: Duration,
    ) -> Self {
        Self {
            per_subscriber_queue,
            max_backlog,
            max_rooms,
            max_backlog_bytes,
            replay_ttl,
            inner: Mutex::new(BrokerStateInner::default()),
        }
    }

    async fn subscribe(
        &self,
        key: BrokerStreamKey,
    ) -> Result<
        (
            u64,
            Vec<AgentTextStreamRecordV1>,
            mpsc::Receiver<AgentTextStreamRecordV1>,
        ),
        QuicBrokerError,
    > {
        let (tx, rx) = mpsc::channel(self.per_subscriber_queue);
        let mut inner = self.inner.lock().await;
        self.purge_expired_rooms(&mut inner);
        if !inner.rooms.contains_key(&key) && inner.rooms.len() >= self.max_rooms {
            return Err(QuicBrokerError::RoomLimitExceeded {
                limit: self.max_rooms,
            });
        }
        let id = inner.next_subscriber_id;
        inner.next_subscriber_id += 1;
        let (freed, backlog) = {
            let room = inner.rooms.entry(key).or_default();
            if room.finished_at.is_none() {
                room.last_activity_at = Instant::now();
            }
            // Purge entries past the replay window before serving backlog: a
            // late subscriber only sees records the replay TTL still covers,
            // and the default TTL of zero serves no backlog at all.
            let freed = purge_expired_backlog(room, self.replay_ttl);
            let backlog: Vec<_> = room
                .backlog
                .iter()
                .map(|entry| entry.record.clone())
                .collect();
            if room.finished_at.is_none() {
                room.subscribers.push(Subscriber { id, tx });
                room.subscriber_notify.notify_waiters();
                room.subscriber_notify.notify_one();
            }
            (freed, backlog)
        };
        inner.total_backlog_bytes = inner.total_backlog_bytes.saturating_sub(freed);
        Ok((id, backlog, rx))
    }

    async fn unsubscribe(&self, key: &BrokerStreamKey, id: u64) {
        let mut inner = self.inner.lock().await;
        self.purge_expired_rooms(&mut inner);
        let mut should_remove = false;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.subscribers.retain(|subscriber| subscriber.id != id);
            if room.finished_at.is_none() {
                room.last_activity_at = Instant::now();
            }
            should_remove = room.subscribers.is_empty()
                && room.backlog.is_empty()
                && room.finished_at.is_none();
        }
        if should_remove {
            remove_room(&mut inner, key);
        }
    }

    async fn publish(
        &self,
        key: &BrokerStreamKey,
        record: AgentTextStreamRecordV1,
    ) -> Result<usize, QuicBrokerError> {
        // The replay window bounds backlog retention: with the default TTL of
        // zero the broker retains nothing and records reach live subscribers
        // only.
        let retain_backlog = !self.replay_ttl.is_zero();
        let record_bytes = record.encode()?.len();
        if retain_backlog && record_bytes > self.max_backlog_bytes {
            return Err(QuicBrokerError::BacklogRecordTooLarge {
                record_bytes,
                limit: self.max_backlog_bytes,
            });
        }
        let mut inner = self.inner.lock().await;
        self.purge_expired_rooms(&mut inner);
        if inner
            .rooms
            .get(key)
            .is_some_and(|room| room.finished_at.is_some())
        {
            remove_room(&mut inner, key);
        }
        if !inner.rooms.contains_key(key) && inner.rooms.len() >= self.max_rooms {
            return Err(QuicBrokerError::RoomLimitExceeded {
                limit: self.max_rooms,
            });
        }
        let mut delivered = 0;
        let mut total_backlog_bytes = inner.total_backlog_bytes;
        let room = inner.rooms.entry(key.clone()).or_default();
        room.last_activity_at = Instant::now();
        if retain_backlog {
            let freed = purge_expired_backlog(room, self.replay_ttl);
            total_backlog_bytes = total_backlog_bytes.saturating_sub(freed);
            room.backlog.push_back(BacklogRecord {
                record: record.clone(),
                bytes: record_bytes,
                appended_at: Instant::now(),
            });
            room.backlog_bytes += record_bytes;
            total_backlog_bytes += record_bytes;
            while room.backlog.len() > self.max_backlog
                || total_backlog_bytes > self.max_backlog_bytes
            {
                let Some(dropped) = room.backlog.pop_front() else {
                    break;
                };
                room.backlog_bytes = room.backlog_bytes.saturating_sub(dropped.bytes);
                total_backlog_bytes = total_backlog_bytes.saturating_sub(dropped.bytes);
            }
        }
        room.subscribers.retain(|subscriber| {
            if subscriber.tx.try_send(record.clone()).is_ok() {
                delivered += 1;
                true
            } else {
                false
            }
        });
        let should_remove =
            room.subscribers.is_empty() && room.backlog.is_empty() && room.finished_at.is_none();
        inner.total_backlog_bytes = total_backlog_bytes;
        if should_remove {
            remove_room(&mut inner, key);
        }
        Ok(delivered)
    }

    async fn wait_for_subscriber(&self, key: &BrokerStreamKey) -> Result<(), QuicBrokerError> {
        let result = timeout(PUBLISH_SUBSCRIBER_GRACE, async {
            loop {
                let notify = {
                    let mut inner = self.inner.lock().await;
                    self.purge_expired_rooms(&mut inner);
                    if !inner.rooms.contains_key(key) && inner.rooms.len() >= self.max_rooms {
                        return Err(QuicBrokerError::RoomLimitExceeded {
                            limit: self.max_rooms,
                        });
                    }
                    let room = inner.rooms.entry(key.clone()).or_default();
                    if room.finished_at.is_some() {
                        *room = BrokerRoom::default();
                    }
                    if !room.subscribers.is_empty() {
                        return Ok(());
                    }
                    room.subscriber_notify.clone()
                };
                notify.notified().await;
            }
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.drop_empty_unfinished_room(key).await;
                Ok(())
            }
        }
    }

    async fn drop_room(&self, key: &BrokerStreamKey) {
        let mut inner = self.inner.lock().await;
        remove_room(&mut inner, key);
    }

    async fn drop_empty_unfinished_room(&self, key: &BrokerStreamKey) {
        let mut inner = self.inner.lock().await;
        let should_remove = inner.rooms.get(key).is_some_and(|room| {
            room.subscribers.is_empty() && room.backlog.is_empty() && room.finished_at.is_none()
        });
        if should_remove {
            remove_room(&mut inner, key);
        }
    }

    async fn finish_room(self: &Arc<Self>, key: &BrokerStreamKey) {
        if !self.mark_room_finished(key).await {
            return;
        }
        let state = Arc::clone(self);
        let key = key.clone();
        tokio::spawn(async move {
            sleep(FINISHED_ROOM_TTL).await;
            state.drop_expired_finished_room(&key).await;
        });
    }

    async fn mark_room_finished(&self, key: &BrokerStreamKey) -> bool {
        let mut inner = self.inner.lock().await;
        self.purge_expired_rooms(&mut inner);
        let mut should_remove = false;
        let mut should_retain = false;
        let mut freed = 0;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.subscribers.clear();
            freed = purge_expired_backlog(room, self.replay_ttl);
            should_remove = room.backlog.is_empty();
            if !should_remove {
                let now = Instant::now();
                room.finished_at = Some(now);
                room.last_activity_at = now;
                should_retain = true;
            }
        }
        inner.total_backlog_bytes = inner.total_backlog_bytes.saturating_sub(freed);
        if should_remove {
            remove_room(&mut inner, key);
        }
        should_retain
    }

    async fn drop_expired_finished_room(&self, key: &BrokerStreamKey) {
        let mut inner = self.inner.lock().await;
        let Some(room) = inner.rooms.get(key) else {
            return;
        };
        if room
            .finished_at
            .is_some_and(|finished_at| finished_at.elapsed() >= FINISHED_ROOM_TTL)
        {
            remove_room(&mut inner, key);
        }
    }

    fn purge_expired_rooms(&self, inner: &mut BrokerStateInner) {
        // Finished rooms get a one-shot timer in `finish_room`; unfinished-room
        // cleanup is activity-driven and runs when the broker state is touched.
        // Retained rooms also drop backlog entries past the replay window so
        // the broker never holds replay data beyond `replay_ttl`.
        let replay_ttl = self.replay_ttl;
        let mut total_backlog_bytes = 0;
        inner.rooms.retain(|_, room| {
            let retain = if let Some(finished_at) = room.finished_at {
                finished_at.elapsed() < FINISHED_ROOM_TTL
            } else {
                !room.subscribers.is_empty()
                    || room.last_activity_at.elapsed() < UNFINISHED_ROOM_TTL
            };
            if retain {
                purge_expired_backlog(room, replay_ttl);
                total_backlog_bytes += room.backlog_bytes;
            }
            retain
        });
        inner.total_backlog_bytes = total_backlog_bytes;
    }

    #[cfg(test)]
    async fn room_count(&self) -> usize {
        self.inner.lock().await.rooms.len()
    }

    #[cfg(test)]
    async fn backlog_bytes_for_test(&self) -> usize {
        self.inner.lock().await.total_backlog_bytes
    }

    #[cfg(test)]
    async fn age_finished_room_for_test(&self, key: &BrokerStreamKey, age: Duration) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.finished_at = Some(Instant::now().checked_sub(age).unwrap());
        }
    }

    #[cfg(test)]
    async fn age_unfinished_room_for_test(&self, key: &BrokerStreamKey, age: Duration) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key)
            && room.finished_at.is_none()
        {
            room.last_activity_at = Instant::now().checked_sub(age).unwrap();
        }
    }

    #[cfg(test)]
    async fn age_oldest_backlog_for_test(
        &self,
        key: &BrokerStreamKey,
        count: usize,
        age: Duration,
    ) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key) {
            for entry in room.backlog.iter_mut().take(count) {
                entry.appended_at = Instant::now().checked_sub(age).unwrap();
            }
        }
    }
}

fn remove_room(inner: &mut BrokerStateInner, key: &BrokerStreamKey) {
    if let Some(room) = inner.rooms.remove(key) {
        inner.total_backlog_bytes = inner.total_backlog_bytes.saturating_sub(room.backlog_bytes);
    }
}

async fn handle_connection(
    state: Arc<BrokerState>,
    connection: quinn::Connection,
    max_streams_per_connection: usize,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let stream_limiter = Arc::new(Semaphore::new(max_streams_per_connection));
    loop {
        tokio::select! {
            uni = connection.accept_uni() => {
                let Ok(mut recv) = uni else {
                    return Ok(());
                };
                let Ok(permit) = Arc::clone(&stream_limiter).try_acquire_owned() else {
                    let _ = recv.stop(0_u32.into());
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_publish_stream(state, recv, read_timeout).await;
                });
            }
            bi = connection.accept_bi() => {
                let Ok((mut send, mut recv)) = bi else {
                    return Ok(());
                };
                let Ok(permit) = Arc::clone(&stream_limiter).try_acquire_owned() else {
                    let _ = send.reset(0_u32.into());
                    let _ = recv.stop(0_u32.into());
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_subscribe_stream(state, send, recv, read_timeout).await;
                });
            }
        }
    }
}

async fn handle_publish_stream(
    state: Arc<BrokerState>,
    mut recv: quinn::RecvStream,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let control = read_control_frame(&mut recv, read_timeout).await?;
    // Spec-mandated directionality: a subscribe envelope on a client-opened
    // unidirectional stream is rejected.
    if control.control_type != QuicBrokerControlTypeV1::Publish {
        let _ = recv.stop(0_u32.into());
        return Err(QuicBrokerError::SubscribeRequiresBidirectionalStream);
    }
    let key = control.key();
    state.wait_for_subscriber(&key).await?;
    let mut limit_state = AgentTextStreamReceiveAccumulator::default();

    // The `read_timeout` is a handshake deadline only: it bounds how long an
    // unauthenticated peer may stall before sending its publish control frame.
    // Once a publisher has authenticated a room we must NOT apply a per-record
    // deadline. Agents legitimately go quiet between records (e.g. a long tool
    // call with no progress events); a per-frame deadline would error the
    // publish stream on that silence, which latches the composer's `live_error`
    // and kills the live preview for the rest of the response with no recovery.
    // QUIC liveness (max_idle_timeout + keep_alive_interval) still reaps a
    // genuinely dead publisher, and the resource caps (max_connections /
    // max_rooms / backlog budgets) still bound an idle-but-alive one, so reads
    // here are intentionally unbounded by the application-level deadline.
    let result = async {
        while let Some(record) = read_record_frame(&mut recv, None, MAX_FRAME_SIZE).await? {
            if record.stream_id != key.stream_id {
                return Err(QuicBrokerError::MixedStreamIds);
            }
            limit_state.observe(&record)?;
            state.publish(&key, record).await?;
        }
        Ok::<_, QuicBrokerError>(())
    }
    .await;

    if matches!(&result, Err(QuicBrokerError::MixedStreamIds)) {
        state.drop_room(&key).await;
    } else {
        state.finish_room(&key).await;
    }
    result
}

async fn handle_subscribe_stream(
    state: Arc<BrokerState>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let control = match read_control_frame(&mut recv, read_timeout).await {
        Ok(control) => control,
        Err(err) => {
            // Reset the return direction so the client observes the rejection
            // instead of a clean zero-record end of stream.
            let _ = send.reset(0_u32.into());
            return Err(err);
        }
    };
    // Spec-mandated directionality: a publish envelope on a bidirectional
    // stream is rejected.
    if control.control_type != QuicBrokerControlTypeV1::Subscribe {
        let _ = send.reset(0_u32.into());
        let _ = recv.stop(0_u32.into());
        return Err(QuicBrokerError::PublishRequiresUnidirectionalStream);
    }
    let key = control.key();
    let (subscriber_id, backlog, mut rx) = state.subscribe(key.clone()).await?;
    let result = async {
        for record in backlog {
            write_record_frame(&mut send, &record).await?;
        }
        while let Some(record) = rx.recv().await {
            write_record_frame(&mut send, &record).await?;
        }
        send.finish()?;
        Ok::<_, QuicBrokerError>(())
    }
    .await;
    state.unsubscribe(&key, subscriber_id).await;
    result
}

async fn write_control_frame(
    send: &mut quinn::SendStream,
    control: &QuicBrokerControlEnvelopeV1,
) -> Result<(), QuicBrokerError> {
    let bytes = control.encode()?;
    write_bytes_frame(send, &bytes).await
}

async fn read_control_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
) -> Result<QuicBrokerControlEnvelopeV1, QuicBrokerError> {
    let bytes = read_bytes_frame(recv, Some(read_timeout), MAX_FRAME_SIZE)
        .await?
        .ok_or(QuicBrokerError::MissingControlFrame)?;
    QuicBrokerControlEnvelopeV1::decode(&bytes)
}

async fn write_record_frame(
    send: &mut quinn::SendStream,
    record: &AgentTextStreamRecordV1,
) -> Result<(), QuicBrokerError> {
    let bytes = record.encode()?;
    write_bytes_frame(send, &bytes).await
}

async fn read_record_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Option<Duration>,
    max_frame_len: usize,
) -> Result<Option<AgentTextStreamRecordV1>, QuicBrokerError> {
    let Some(bytes) = read_bytes_frame(recv, read_timeout, max_frame_len).await? else {
        return Ok(None);
    };
    Ok(Some(AgentTextStreamRecordV1::decode(&bytes)?))
}

async fn write_bytes_frame(
    send: &mut quinn::SendStream,
    bytes: &[u8],
) -> Result<(), QuicBrokerError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| QuicBrokerError::FrameTooLarge(bytes.len()))?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

async fn read_bytes_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Option<Duration>,
    max_frame_len: usize,
) -> Result<Option<Vec<u8>>, QuicBrokerError> {
    let mut len_bytes = [0_u8; FRAME_LEN_BYTES];
    let mut read = 0;
    while read < FRAME_LEN_BYTES {
        let chunk = match read_timeout {
            Some(read_timeout) => {
                broker_read_deadline(read_timeout, recv.read(&mut len_bytes[read..])).await?
            }
            None => recv.read(&mut len_bytes[read..]).await?,
        };
        match chunk {
            Some(0) => return Err(QuicBrokerError::TruncatedFrameLength),
            Some(n) => read += n,
            None if read == 0 => return Ok(None),
            None => return Err(QuicBrokerError::TruncatedFrameLength),
        }
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    validate_frame_len(len, max_frame_len)?;
    let mut bytes = vec![0_u8; len];
    match read_timeout {
        Some(read_timeout) => {
            broker_read_deadline(read_timeout, recv.read_exact(&mut bytes)).await?;
        }
        None => recv.read_exact(&mut bytes).await?,
    }
    Ok(Some(bytes))
}

async fn broker_read_deadline<T, E>(
    read_timeout: Duration,
    read: impl Future<Output = Result<T, E>>,
) -> Result<T, QuicBrokerError>
where
    QuicBrokerError: From<E>,
{
    timeout(read_timeout, read)
        .await
        .map_err(|_| QuicBrokerError::ReadTimeout)?
        .map_err(Into::into)
}

fn validate_frame_len(len: usize, max_frame_len: usize) -> Result<(), QuicBrokerError> {
    if len == 0 {
        return Err(QuicBrokerError::EmptyFrame);
    }
    if len > max_frame_len.min(MAX_FRAME_SIZE) {
        return Err(QuicBrokerError::FrameTooLarge(len));
    }
    Ok(())
}

fn broker_transport_config(config: &QuicBrokerConfig) -> Result<TransportConfig, QuicBrokerError> {
    let mut transport = TransportConfig::default();
    let streams = VarInt::try_from(config.max_streams_per_connection as u64)?;
    transport
        .max_concurrent_bidi_streams(streams)
        .max_concurrent_uni_streams(streams)
        .max_idle_timeout(Some(config.max_idle_timeout.try_into()?))
        .keep_alive_interval(Some(config.keep_alive_interval));
    Ok(transport)
}

fn configure_server(tls: &QuicBrokerTlsConfig) -> Result<(ServerConfig, Vec<u8>), QuicBrokerError> {
    match tls {
        QuicBrokerTlsConfig::GenerateSelfSigned { subject_alt_names } => {
            let subject_alt_names = if subject_alt_names.is_empty() {
                vec!["localhost".to_owned()]
            } else {
                subject_alt_names.clone()
            };
            let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
                .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?;
            let cert_der = CertificateDer::from(certified_key.cert);
            let key_der = PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der());
            let server_config = broker_server_config(vec![cert_der.clone()], key_der.into())?;
            Ok((server_config, cert_der.as_ref().to_vec()))
        }
        QuicBrokerTlsConfig::PemFiles {
            cert_path,
            key_path,
        } => {
            let certs = load_certificate_chain(cert_path)?;
            let leaf_cert_der = certs
                .first()
                .ok_or(QuicBrokerError::EmptyCertificateChain)?
                .as_ref()
                .to_vec();
            let key = load_private_key(key_path)?;
            let server_config = broker_server_config(certs, key)?;
            Ok((server_config, leaf_cert_der))
        }
    }
}

/// Build the broker QUIC server config with the spec-mandated ALPN
/// `marmot.quic_broker.v1` so broker connections negotiate the broker control
/// protocol during the TLS handshake.
fn broker_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, QuicBrokerError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?;
    crypto.alpn_protocols = vec![QUIC_BROKER_ALPN_V1.to_vec()];
    crypto.max_early_data_size = u32::MAX;
    Ok(ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto)
            .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?,
    )))
}

fn load_certificate_chain(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>, QuicBrokerError> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(QuicBrokerError::Io)?;
    if certs.is_empty() {
        return Err(QuicBrokerError::EmptyCertificateChain);
    }
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, QuicBrokerError> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)
        .map_err(QuicBrokerError::Io)?
        .ok_or(QuicBrokerError::MissingPrivateKey)
}

fn client_endpoint(
    trust: BrokerServerTrust,
    broker_addr: SocketAddr,
) -> Result<Endpoint, QuicBrokerError> {
    // Every broker-path client config negotiates the spec-mandated ALPN
    // `marmot.quic_broker.v1`, so the rustls config is built here instead of
    // through the quinn convenience constructors (which set no ALPN).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| QuicBrokerError::ClientConfig(err.to_string()))?;
    let mut crypto = match trust {
        BrokerServerTrust::Platform => builder
            .with_platform_verifier()
            .map_err(|err| QuicBrokerError::ClientConfig(err.to_string()))?
            .with_no_client_auth(),
        BrokerServerTrust::CertificateDer(cert_der) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(cert_der))?;
            builder
                .with_root_certificates(Arc::new(roots))
                .with_no_client_auth()
        }
        BrokerServerTrust::InsecureLocal => {
            if !broker_addr.ip().is_loopback() {
                return Err(QuicBrokerError::InsecureLocalRequiresLoopback(broker_addr));
            }
            builder
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new(provider))
                .with_no_client_auth()
        }
    };
    crypto.alpn_protocols = vec![QUIC_BROKER_ALPN_V1.to_vec()];
    crypto.enable_early_data = true;
    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|err| QuicBrokerError::ClientConfig(err.to_string()))?,
    ));
    let mut endpoint = Endpoint::client(client_bind_addr_for_broker(broker_addr))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn client_bind_addr_for_broker(broker_addr: SocketAddr) -> SocketAddr {
    match broker_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuicBrokerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    QuinnConfig(#[from] quinn::ConfigError),
    #[error("broker QUIC transport value exceeds varint bounds")]
    TransportValueTooLarge(#[from] quinn::VarIntBoundsExceeded),
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error(transparent)]
    Write(#[from] quinn::WriteError),
    #[error(transparent)]
    Read(#[from] quinn::ReadError),
    #[error(transparent)]
    ReadExact(#[from] quinn::ReadExactError),
    #[error(transparent)]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error(transparent)]
    Stopped(#[from] quinn::StoppedError),
    #[error(transparent)]
    Record(#[from] AgentTextStreamRecordError),
    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),
    #[error(transparent)]
    StreamCrypto(#[from] transport_quic_stream::QuicTextStreamError),
    #[error(transparent)]
    ReceiveLimit(#[from] AgentTextStreamReceiveLimitError),
    #[error("certificate setup failed: {0}")]
    Certificate(String),
    #[error("certificate PEM file did not contain any certificates")]
    EmptyCertificateChain,
    #[error("private key PEM file did not contain a usable private key")]
    MissingPrivateKey,
    #[error("QUIC client config failed: {0}")]
    ClientConfig(String),
    #[error("--insecure-local is only allowed for loopback QUIC broker endpoints, got {0}")]
    InsecureLocalRequiresLoopback(SocketAddr),
    #[error("broker subscriber queue depth cannot be zero")]
    EmptySubscriberQueue,
    #[error("broker backlog depth cannot be zero")]
    EmptyBacklog,
    #[error("broker room limit cannot be zero")]
    EmptyRoomLimit,
    #[error("broker backlog byte limit cannot be zero")]
    EmptyBacklogByteLimit,
    #[error("broker connection limit cannot be zero")]
    EmptyConnectionLimit,
    #[error("broker per-connection stream limit cannot be zero")]
    EmptyStreamLimit,
    #[error("broker read timeout cannot be zero")]
    EmptyReadTimeout,
    #[error("broker idle timeout cannot be zero")]
    EmptyIdleTimeout,
    #[error("broker keep-alive interval cannot be zero")]
    EmptyKeepAliveInterval,
    #[error(
        "broker replay ttl exceeds the application profile cap: {requested_secs}s > {cap_secs}s"
    )]
    ReplayTtlTooLarge { requested_secs: u64, cap_secs: u64 },
    #[error("broker room limit exceeded: {limit}")]
    RoomLimitExceeded { limit: usize },
    #[error("broker backlog record is larger than the byte budget: {record_bytes} > {limit}")]
    BacklogRecordTooLarge { record_bytes: usize, limit: usize },
    #[error("broker frame read timed out")]
    ReadTimeout,
    #[error("broker control frame is missing")]
    MissingControlFrame,
    #[error("wrong broker control protocol: {0}")]
    WrongControlProtocol(String),
    #[error("unknown broker control type: {0}")]
    UnknownControlType(u8),
    #[error("broker control envelope is truncated while reading {0}")]
    ControlTruncated(&'static str),
    #[error("broker control envelope carries trailing bytes: {0}")]
    ControlTrailingBytes(usize),
    #[error("publish streams must be unidirectional")]
    PublishRequiresUnidirectionalStream,
    #[error("subscribe streams must be bidirectional")]
    SubscribeRequiresBidirectionalStream,
    #[error("agent text stream id cannot be empty")]
    EmptyStreamId,
    #[error("agent text stream id is too long: {0}")]
    StreamIdTooLong(usize),
    #[error("agent text stream start event id cannot be empty")]
    EmptyStartEventId,
    #[error("agent text stream start event id is too long: {0}")]
    StartEventIdTooLong(usize),
    #[error("agent text stream did not contain any records")]
    EmptyStream,
    #[error("agent text stream frame length was truncated")]
    TruncatedFrameLength,
    #[error("agent text stream frame cannot be empty")]
    EmptyFrame,
    #[error("agent text stream frame is too large: {0}")]
    FrameTooLarge(usize),
    #[error("agent text stream chunk size cannot be zero")]
    EmptyChunkSize,
    #[error("agent text stream chunk size exceeds app profile max: {0}")]
    ChunkSizeTooLarge(usize),
    #[error("agent text stream mixed stream ids")]
    MixedStreamIds,
    /// A record arrived ahead of the high-water mark (`actual > expected`),
    /// signalling a gap the receiver cannot fill without a replay source.
    /// Records at or below the high-water mark are discarded silently and
    /// never raise this error.
    #[error("agent text stream sequence gap: expected {expected}, got {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_RECORD_STATUS;
    use tokio::sync::oneshot;

    /// State helper with replay retention enabled (the profile cap) so the
    /// pre-existing backlog tests keep exercising retention; replay-TTL
    /// behavior itself is covered by the dedicated tests below.
    fn test_state(max_backlog: usize) -> BrokerState {
        BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog,
            DEFAULT_BROKER_MAX_ROOMS,
            DEFAULT_BROKER_MAX_BACKLOG_BYTES,
            MAX_BROKER_REPLAY_TTL,
        )
    }

    #[tokio::test]
    async fn broker_forwards_live_records_to_subscriber_with_same_transcript() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xaa; 32];
        let start_event_id = MessageId::new(vec![0x11; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let sent = publish_text_to_broker(PublishTextToBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            text: "hello broker stream".to_owned(),
            max_chunk_bytes: 6,
            chunk_delay: Duration::ZERO,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "hello broker stream");
        assert_eq!(received.chunk_count, 4);
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_does_not_apply_per_record_deadline_to_authenticated_publisher() {
        // Regression for the live-preview latch: an agent that goes quiet between
        // records (e.g. a long tool call with no progress events) must not have
        // its publish stream errored by a per-record read deadline. Before the
        // fix, `read_timeout` was enforced on every record-frame read after the
        // handshake, so an idle gap longer than the deadline killed the stream;
        // the composer then latched `live_error` and the preview was dead for the
        // rest of the response. Here we use a tiny read_timeout and idle well past
        // it between two records, and assert both records still arrive. The QUIC
        // idle timeout (kept long here) is what reaps a genuinely dead publisher.
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            read_timeout: Duration::from_millis(100),
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xa9; 32];
        let start_event_id = MessageId::new(vec![0x19; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();
        publisher
            .append_text("before", 32, Duration::ZERO)
            .await
            .unwrap();
        // Idle far longer than the per-record read_timeout (100ms).
        sleep(Duration::from_millis(500)).await;
        // This write would have failed before the fix, because the broker would
        // have already errored the publish stream on the idle gap.
        publisher
            .append_text("after", 32, Duration::ZERO)
            .await
            .unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "beforeafter");
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_closes_subscribers_when_publish_stream_errors_after_backlog() {
        let stream_id = vec![0xac; 32];
        let start_event_id = MessageId::new(vec![0x21; 32]);
        let small_record =
            AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"ok".to_vec());
        let large_record = AgentTextStreamRecordV1::text_delta(
            stream_id.clone(),
            2,
            b"this record is too large".to_vec(),
        );
        let max_backlog_bytes = small_record.encode().unwrap().len();
        assert!(large_record.encode().unwrap().len() > max_backlog_bytes);

        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog_bytes,
            // Backlog byte budgets only apply when replay retention is on.
            replay_ttl: MAX_BROKER_REPLAY_TTL,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();
        publisher
            .append_text("ok", 32, Duration::ZERO)
            .await
            .unwrap();
        publisher
            .append_text("this record is too large", 32, Duration::ZERO)
            .await
            .unwrap();
        let _ = publisher.finish().await;

        let received = tokio::time::timeout(Duration::from_secs(2), subscriber)
            .await
            .expect("subscriber should not park forever after publish loop error")
            .unwrap()
            .unwrap();

        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "ok");
        assert_eq!(received.chunk_count, 1);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_forwards_status_records_without_adding_to_text() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xcc; 32];
        let start_event_id = MessageId::new(vec![0x33; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();
        publisher
            .append_text("hello", 32, Duration::ZERO)
            .await
            .unwrap();
        publisher
            .append_record_text(
                AGENT_TEXT_STREAM_RECORD_STATUS,
                "thinking",
                32,
                Duration::ZERO,
            )
            .await
            .unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "hello");
        assert_eq!(received.chunk_count, 2);
        assert_eq!(received.chunks.len(), 2);
        assert_eq!(
            received.chunks[0].record_type,
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
        );
        assert_eq!(received.chunks[0].text, "hello");
        assert_eq!(
            received.chunks[1].record_type,
            AGENT_TEXT_STREAM_RECORD_STATUS
        );
        assert_eq!(received.chunks[1].text, "thinking");
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_forwards_abort_record_to_subscriber() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0x5a; 32];
        let start_event_id = MessageId::new(vec![0x5b; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();
        publisher
            .append_text("partial answer", 32, Duration::ZERO)
            .await
            .unwrap();
        publisher.append_abort().await.unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // The provisional text is the TextDelta only; the Abort carries no text
        // but is delivered as a terminal record the receiver acts on.
        assert_eq!(received.text, "partial answer");
        assert_eq!(received.chunk_count, 2);
        assert_eq!(received.chunks.len(), 2);
        assert_eq!(
            received.chunks[0].record_type,
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
        );
        assert_eq!(
            received.chunks[1].record_type,
            AGENT_TEXT_STREAM_RECORD_ABORT
        );
        assert_eq!(received.chunks[1].text, "");
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_forwards_checkpoint_snapshot_without_merging_into_final_text() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xc4; 32];
        let start_event_id = MessageId::new(vec![0x44; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();
        // A delta builds the provisional answer; the checkpoint is a full preview
        // snapshot the receiver forwards for the consumer to swap in.
        publisher
            .append_text("hello", 32, Duration::ZERO)
            .await
            .unwrap();
        publisher
            .append_record_text(
                AGENT_TEXT_STREAM_RECORD_CHECKPOINT,
                "hello world",
                32,
                Duration::ZERO,
            )
            .await
            .unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // Checkpoint plaintext reaches the subscriber as the record's text...
        assert_eq!(received.chunks.len(), 2);
        assert_eq!(
            received.chunks[1].record_type,
            AGENT_TEXT_STREAM_RECORD_CHECKPOINT
        );
        assert_eq!(received.chunks[1].text, "hello world");
        // ...but it is not merged into the provisional final text, which stays the
        // concatenation of TextDelta frames only.
        assert_eq!(received.text, "hello");
        assert_eq!(received.chunk_count, 2);
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_progress_and_status_only_stream_yields_empty_final_text() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0x9c; 32];
        let start_event_id = MessageId::new(vec![0x55; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();
        publisher
            .append_record_text(
                AGENT_TEXT_STREAM_RECORD_STATUS,
                "thinking",
                32,
                Duration::ZERO,
            )
            .await
            .unwrap();
        publisher
            .append_record_text(
                AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
                "searching",
                32,
                Duration::ZERO,
            )
            .await
            .unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // A stream that never sends a TextDelta has no chat answer: the final text
        // is legitimately empty, so consumers can tell "no answer" apart from a
        // real preview instead of rendering a blank chat bubble.
        assert_eq!(received.text, "");
        // The status/progress content is still delivered per-record for live
        // non-chat chrome.
        assert_eq!(received.chunks.len(), 2);
        assert_eq!(
            received.chunks[0].record_type,
            AGENT_TEXT_STREAM_RECORD_STATUS
        );
        assert_eq!(received.chunks[0].text, "thinking");
        assert_eq!(
            received.chunks[1].record_type,
            AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA
        );
        assert_eq!(received.chunks[1].text, "searching");
        assert_eq!(received.chunk_count, 2);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_subscriber_rejects_streams_past_receive_limits() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xdd; 32];
        let start_event_id = MessageId::new(vec![0x44; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker_with_limits(
            SubscribeTextFromBroker {
                broker_addr,
                server_name: "localhost".to_owned(),
                trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
                stream_id: stream_id.clone(),
                start_event_id: start_event_id.clone(),
                crypto: None,
            },
            AgentTextStreamReceiveLimits {
                max_records: 1,
                max_plaintext_bytes: 1024,
                ..AgentTextStreamReceiveLimits::default()
            },
            |_| {},
        ));
        sleep(Duration::from_millis(100)).await;

        let _ = publish_text_to_broker(PublishTextToBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id,
            start_event_id,
            text: "two records".to_owned(),
            max_chunk_bytes: 3,
            chunk_delay: Duration::ZERO,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await;

        let err = timeout(Duration::from_secs(5), subscriber)
            .await
            .expect("subscriber should hit receive limit")
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            err,
            QuicBrokerError::ReceiveLimit(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: 2,
                limit: 1
            })
        ));

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_replays_full_backlog_to_late_subscriber() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: 2,
            max_backlog: 16,
            // Late-subscriber backlog replay requires an explicit replay
            // window; the default TTL of zero retains nothing.
            replay_ttl: MAX_BROKER_REPLAY_TTL,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xbb; 32];
        let start_event_id = MessageId::new(vec![0x22; 32]);
        let early_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();

        publisher
            .append_text("abcdefghij", 1, Duration::ZERO)
            .await
            .unwrap();
        let late_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let sent = publisher.finish().await.unwrap();
        let _ = early_subscriber.await;
        let late_received = late_subscriber.await.unwrap().unwrap();

        assert_eq!(late_received.text, "abcdefghij");
        assert_eq!(late_received.chunk_count, 10);
        assert_eq!(sent.transcript_hash, late_received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_replays_finished_backlog_to_late_subscriber() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
            // Late-subscriber backlog replay requires an explicit replay
            // window; the default TTL of zero retains nothing.
            replay_ttl: MAX_BROKER_REPLAY_TTL,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xcc; 32];
        let start_event_id = MessageId::new(vec![0x33; 32]);
        let early_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let sent = publish_text_to_broker(PublishTextToBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            text: "finished transcript".to_owned(),
            max_chunk_bytes: 4,
            crypto: None,
            chunk_delay: Duration::ZERO,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();
        let early_received = early_subscriber.await.unwrap().unwrap();
        assert_eq!(early_received.transcript_hash, sent.transcript_hash);

        let late_received = timeout(
            Duration::from_secs(5),
            subscribe_text_from_broker(SubscribeTextFromBroker {
                broker_addr,
                server_name: "localhost".to_owned(),
                trust: BrokerServerTrust::CertificateDer(server_cert),
                stream_id,
                start_event_id,
                crypto: None,
            }),
        )
        .await
        .expect("late subscriber should receive retained finished backlog")
        .unwrap();

        assert_eq!(late_received.text, "finished transcript");
        assert_eq!(late_received.transcript_hash, sent.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_retains_finished_rooms_and_closes_live_subscribers() {
        let state = Arc::new(test_state(DEFAULT_BROKER_BACKLOG_DEPTH));
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());
        let (_subscriber_id, _backlog, mut rx) = state.subscribe(key.clone()).await.unwrap();
        assert_eq!(state.room_count().await, 1);

        state.publish(&key, record.clone()).await.unwrap();
        state.finish_room(&key).await;

        assert_eq!(state.room_count().await, 1);
        assert_eq!(rx.recv().await.expect("queued live record").seq, record.seq);
        assert!(rx.recv().await.is_none());

        let (_late_id, backlog, mut finished_rx) = state.subscribe(key).await.unwrap();
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].seq, record.seq);
        assert!(finished_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn broker_drops_finished_rooms_after_ttl() {
        let state = Arc::new(test_state(DEFAULT_BROKER_BACKLOG_DEPTH));
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

        state.publish(&key, record).await.unwrap();
        state.finish_room(&key).await;

        assert_eq!(state.room_count().await, 1);
        state
            .age_finished_room_for_test(&key, FINISHED_ROOM_TTL + Duration::from_secs(1))
            .await;
        state.drop_expired_finished_room(&key).await;
        assert_eq!(state.room_count().await, 0);
    }

    #[tokio::test]
    async fn broker_purges_stale_unfinished_rooms_without_live_subscribers() {
        let state = test_state(DEFAULT_BROKER_BACKLOG_DEPTH);
        let stale_key = BrokerStreamKey::new(vec![0xab; 32], MessageId::new(vec![0x12; 32]));
        let live_key = BrokerStreamKey::new(vec![0xcd; 32], MessageId::new(vec![0x34; 32]));

        state
            .publish(
                &stale_key,
                AgentTextStreamRecordV1::text_delta(vec![0xab; 32], 1, b"stale".to_vec()),
            )
            .await
            .unwrap();
        state
            .publish(
                &live_key,
                AgentTextStreamRecordV1::text_delta(vec![0xcd; 32], 1, b"live".to_vec()),
            )
            .await
            .unwrap();
        let (_subscriber_id, _backlog, _rx) = state.subscribe(live_key.clone()).await.unwrap();
        state
            .age_unfinished_room_for_test(&stale_key, UNFINISHED_ROOM_TTL + Duration::from_secs(1))
            .await;
        state
            .age_unfinished_room_for_test(&live_key, UNFINISHED_ROOM_TTL + Duration::from_secs(1))
            .await;

        state
            .publish(
                &BrokerStreamKey::new(vec![0xef; 32], MessageId::new(vec![0x56; 32])),
                AgentTextStreamRecordV1::text_delta(vec![0xef; 32], 1, b"trigger".to_vec()),
            )
            .await
            .unwrap();

        assert_eq!(state.room_count().await, 2);
        let (_late_id, stale_backlog, _stale_rx) = state.subscribe(stale_key).await.unwrap();
        assert!(stale_backlog.is_empty());
        let (_live_id, live_backlog, _live_rx) = state.subscribe(live_key).await.unwrap();
        assert_eq!(live_backlog.len(), 1);
    }

    #[tokio::test]
    async fn broker_buffers_records_until_subscriber_arrives() {
        let state = test_state(DEFAULT_BROKER_BACKLOG_DEPTH);
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

        assert_eq!(state.publish(&key, record.clone()).await.unwrap(), 0);
        let (_subscriber_id, backlog, _rx) = state.subscribe(key).await.unwrap();
        let received = backlog.first().expect("subscriber should receive backlog");

        assert_eq!(received.seq, record.seq);
        assert_eq!(received.plaintext_frame, record.plaintext_frame);
    }

    #[tokio::test]
    async fn broker_backlog_drops_oldest_records_when_bound_reached() {
        let state = test_state(2);
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        for seq in 1..=3 {
            let record = AgentTextStreamRecordV1::text_delta(
                vec![0xaa; 32],
                seq,
                format!("chunk-{seq}").into_bytes(),
            );
            assert_eq!(state.publish(&key, record).await.unwrap(), 0);
        }

        let (_subscriber_id, backlog, mut rx) = state.subscribe(key).await.unwrap();
        let first = backlog.first().expect("subscriber should receive backlog");
        let second = backlog.get(1).expect("subscriber should receive backlog");
        assert_eq!(first.seq, 2);
        assert_eq!(second.seq, 3);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn broker_state_rejects_new_rooms_past_limit() {
        let state = BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
            1,
            usize::MAX,
            MAX_BROKER_REPLAY_TTL,
        );
        let first_key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let second_key = BrokerStreamKey::new(vec![0xbb; 32], MessageId::new(vec![0x22; 32]));

        state
            .publish(
                &first_key,
                AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"first".to_vec()),
            )
            .await
            .unwrap();
        let err = state
            .publish(
                &second_key,
                AgentTextStreamRecordV1::text_delta(vec![0xbb; 32], 1, b"second".to_vec()),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            QuicBrokerError::RoomLimitExceeded { limit: 1 }
        ));
        assert_eq!(state.room_count().await, 1);
    }

    #[tokio::test]
    async fn broker_state_enforces_global_backlog_byte_budget() {
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let sample = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());
        let state = BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
            4,
            sample.encode().unwrap().len() * 2,
            MAX_BROKER_REPLAY_TTL,
        );

        for seq in 1..=3 {
            state
                .publish(
                    &key,
                    AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], seq, b"hello".to_vec()),
                )
                .await
                .unwrap();
        }

        let (_subscriber_id, backlog, _rx) = state.subscribe(key).await.unwrap();
        assert_eq!(
            backlog.iter().map(|record| record.seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(state.backlog_bytes_for_test().await <= sample.encode().unwrap().len() * 2);
    }

    #[tokio::test]
    async fn broker_read_deadline_times_out_stalled_reads() {
        let err = broker_read_deadline(Duration::from_millis(5), async {
            sleep(Duration::from_millis(50)).await;
            Ok::<_, std::io::Error>(())
        })
        .await
        .unwrap_err();

        assert!(matches!(err, QuicBrokerError::ReadTimeout));
    }

    #[test]
    fn broker_config_rejects_zero_resource_limits() {
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                max_rooms: 0,
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::EmptyRoomLimit)
        ));
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                max_connections: 0,
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::EmptyConnectionLimit)
        ));
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                max_streams_per_connection: 0,
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::EmptyStreamLimit)
        ));
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                read_timeout: Duration::ZERO,
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::EmptyReadTimeout)
        ));
    }

    #[test]
    fn oversized_frames_are_rejected_before_allocation() {
        assert!(matches!(
            validate_frame_len(MAX_FRAME_SIZE + 1, MAX_FRAME_SIZE),
            Err(QuicBrokerError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn stream_record_text_decodes_renderable_frames_and_leaves_advisory_records_empty() {
        use cgka_traits::agent_text_stream::{
            AGENT_TEXT_STREAM_RECORD_ABORT, AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
        };

        let stream_id = vec![0x11; 32];
        let record = |record_type, plaintext: &str| {
            AgentTextStreamRecordV1::new(stream_id.clone(), 1, record_type, plaintext.as_bytes())
        };

        // Renderable frames decode to their UTF-8 plaintext. Checkpoint is a full
        // preview snapshot the consumer swaps in, so it must not stay blank.
        for (record_type, plaintext) in [
            (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello"),
            (AGENT_TEXT_STREAM_RECORD_STATUS, "thinking"),
            (AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, "search: glp-1"),
            (AGENT_TEXT_STREAM_RECORD_CHECKPOINT, "hello world"),
        ] {
            assert_eq!(
                stream_record_text(&record(record_type, plaintext)).unwrap(),
                plaintext
            );
        }

        // Abort and FinalNotice are advisory: the consumer reacts to the record
        // type, so they decode to "" even when the sender attached bytes.
        for record_type in [
            AGENT_TEXT_STREAM_RECORD_ABORT,
            AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
        ] {
            assert_eq!(
                stream_record_text(&record(record_type, "ignored")).unwrap(),
                ""
            );
        }
    }

    #[test]
    fn client_bind_addr_matches_broker_address_family() {
        assert_eq!(
            client_bind_addr_for_broker(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4450)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );
        assert_eq!(
            client_bind_addr_for_broker(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4450)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        );
    }

    #[tokio::test]
    async fn insecure_local_rejects_remote_broker_addr() {
        let err = publish_text_to_broker(PublishTextToBroker {
            broker_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 4450),
            server_name: "example.com".to_owned(),
            trust: BrokerServerTrust::InsecureLocal,
            stream_id: vec![0xaa; 32],
            start_event_id: MessageId::new(vec![0x11; 32]),
            text: "hello".to_owned(),
            max_chunk_bytes: 5,
            chunk_delay: Duration::ZERO,
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            QuicBrokerError::InsecureLocalRequiresLoopback(_)
        ));
    }

    #[tokio::test]
    async fn broker_can_bind_with_pem_certificate_files() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let certified_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        std::fs::write(&cert_path, certified_key.cert.pem()).unwrap();
        std::fs::write(&key_path, certified_key.signing_key.serialize_pem()).unwrap();

        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
            tls: QuicBrokerTlsConfig::PemFiles {
                cert_path,
                key_path,
            },
            ..QuicBrokerConfig::default()
        })
        .unwrap();

        assert_eq!(server.server_cert_der(), certified_key.cert.der().as_ref());
    }

    #[test]
    fn certificate_fingerprint_is_sha256_hex() {
        assert_eq!(
            certificate_sha256_fingerprint_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn broker_control_envelope_round_trips_binary_encoding() {
        let stream_id = vec![0xaa; 32];
        let start_event_id = MessageId::new(vec![0x11; 32]);

        let publish = QuicBrokerControlEnvelopeV1::publish(stream_id.clone(), &start_event_id);
        let bytes = publish.encode().unwrap();
        // opaque marmot_broker<1..255>: single-byte varint prefix (21) + ASCII.
        assert_eq!(bytes[0], 21);
        assert_eq!(&bytes[1..22], QUIC_BROKER_PROTOCOL_V1.as_bytes());
        assert_eq!(bytes[22], QUIC_BROKER_CONTROL_PUBLISH);
        // opaque stream_id<1..64>: raw bytes, not hex text.
        assert_eq!(bytes[23], 32);
        assert_eq!(&bytes[24..56], stream_id.as_slice());
        assert_eq!(bytes[56], 32);
        assert_eq!(&bytes[57..89], start_event_id.as_slice());
        assert_eq!(bytes.len(), 89);
        assert_eq!(
            QuicBrokerControlEnvelopeV1::decode(&bytes).unwrap(),
            publish
        );

        let subscribe = QuicBrokerControlEnvelopeV1::subscribe(stream_id, &start_event_id);
        let bytes = subscribe.encode().unwrap();
        assert_eq!(bytes[22], QUIC_BROKER_CONTROL_SUBSCRIBE);
        assert_eq!(
            QuicBrokerControlEnvelopeV1::decode(&bytes).unwrap(),
            subscribe
        );
    }

    #[test]
    fn broker_control_envelope_rejects_malformed_envelopes() {
        let valid =
            QuicBrokerControlEnvelopeV1::publish(vec![0xaa; 32], &MessageId::new(vec![0x11; 32]))
                .encode()
                .unwrap();

        let mut wrong_protocol = valid.clone();
        wrong_protocol[1] = b'x';
        assert!(matches!(
            QuicBrokerControlEnvelopeV1::decode(&wrong_protocol),
            Err(QuicBrokerError::WrongControlProtocol(_))
        ));

        let mut unknown_type = valid.clone();
        unknown_type[22] = 3;
        assert!(matches!(
            QuicBrokerControlEnvelopeV1::decode(&unknown_type),
            Err(QuicBrokerError::UnknownControlType(3))
        ));

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(matches!(
            QuicBrokerControlEnvelopeV1::decode(&trailing),
            Err(QuicBrokerError::ControlTrailingBytes(1))
        ));

        assert!(matches!(
            QuicBrokerControlEnvelopeV1::decode(&valid[..10]),
            Err(QuicBrokerError::ControlTruncated(_))
        ));

        let empty_stream_id = QuicBrokerControlEnvelopeV1 {
            control_type: QuicBrokerControlTypeV1::Publish,
            stream_id: Vec::new(),
            start_event_id: vec![0x11; 32],
        };
        assert!(matches!(
            empty_stream_id.encode(),
            Err(QuicBrokerError::EmptyStreamId)
        ));

        let oversized_stream_id = QuicBrokerControlEnvelopeV1 {
            control_type: QuicBrokerControlTypeV1::Publish,
            stream_id: vec![0xaa; AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN + 1],
            start_event_id: vec![0x11; 32],
        };
        assert!(matches!(
            oversized_stream_id.encode(),
            Err(QuicBrokerError::StreamIdTooLong(len))
                if len == AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN + 1
        ));

        let oversized_start_event_id = QuicBrokerControlEnvelopeV1 {
            control_type: QuicBrokerControlTypeV1::Publish,
            stream_id: vec![0xaa; 32],
            start_event_id: vec![0x11; AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN + 1],
        };
        assert!(matches!(
            oversized_start_event_id.encode(),
            Err(QuicBrokerError::StartEventIdTooLong(len))
                if len == AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN + 1
        ));
    }

    #[test]
    fn broker_rejects_replay_ttl_above_profile_cap() {
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                replay_ttl: MAX_BROKER_REPLAY_TTL + Duration::from_secs(1),
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::ReplayTtlTooLarge {
                requested_secs: 301,
                cap_secs: 300
            })
        ));
    }

    #[tokio::test]
    async fn broker_purges_expired_backlog_before_serving_late_subscriber() {
        let state = BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
            DEFAULT_BROKER_MAX_ROOMS,
            DEFAULT_BROKER_MAX_BACKLOG_BYTES,
            Duration::from_secs(30),
        );
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        for seq in 1..=2 {
            state
                .publish(
                    &key,
                    AgentTextStreamRecordV1::text_delta(
                        vec![0xaa; 32],
                        seq,
                        format!("chunk-{seq}").into_bytes(),
                    ),
                )
                .await
                .unwrap();
        }
        // Age the oldest entry past the replay window; the newer one stays.
        state
            .age_oldest_backlog_for_test(&key, 1, Duration::from_secs(31))
            .await;

        let (_subscriber_id, backlog, _rx) = state.subscribe(key).await.unwrap();
        assert_eq!(
            backlog.iter().map(|record| record.seq).collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[tokio::test]
    async fn broker_state_retains_no_backlog_with_default_zero_replay_ttl() {
        let state = BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
            DEFAULT_BROKER_MAX_ROOMS,
            DEFAULT_BROKER_MAX_BACKLOG_BYTES,
            DEFAULT_BROKER_REPLAY_TTL,
        );
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        // Keep the room alive with a live subscriber, then publish.
        let (_subscriber_id, _backlog, mut rx) = state.subscribe(key.clone()).await.unwrap();
        state
            .publish(
                &key,
                AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"live".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(rx.recv().await.expect("live record").seq, 1);
        assert_eq!(state.backlog_bytes_for_test().await, 0);

        let (_late_id, backlog, _late_rx) = state.subscribe(key).await.unwrap();
        assert!(backlog.is_empty(), "zero replay ttl must serve no backlog");
    }

    #[tokio::test]
    async fn broker_serves_no_backlog_to_late_subscriber_by_default() {
        // Default config: replay_ttl is zero, so a late subscriber sees only
        // live records. Its first record is ahead of seq 1, which it must
        // report as a gap instead of silently producing a wrong transcript.
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xe1; 32];
        let start_event_id = MessageId::new(vec![0x71; 32]);
        let early_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
            max_plaintext_frame_len: None,
        })
        .await
        .unwrap();
        publisher
            .append_text("ab", 1, Duration::ZERO)
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;

        let late_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        publisher.append_text("c", 1, Duration::ZERO).await.unwrap();
        let _ = publisher.finish().await.unwrap();

        let early_received = timeout(Duration::from_secs(5), early_subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(early_received.text, "abc");

        let late_err = timeout(Duration::from_secs(5), late_subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            late_err,
            QuicBrokerError::UnexpectedSequence {
                expected: 1,
                actual: 3
            }
        ));

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn subscriber_discards_duplicate_records_replayed_through_broker() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xe2; 32];
        let start_event_id = MessageId::new(vec![0x72; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        // Raw publisher that re-sends an already-delivered record, like a
        // broker replaying retained backlog on reconnect. The duplicate must
        // be discarded silently by the subscriber, never stream-fatal.
        let endpoint =
            client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
        let connection = endpoint
            .connect(broker_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut send = connection.open_uni().await.unwrap();
        write_control_frame(
            &mut send,
            &QuicBrokerControlEnvelopeV1::publish(stream_id.clone(), &start_event_id),
        )
        .await
        .unwrap();
        let first = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"he".to_vec());
        let second = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 2, b"ll".to_vec());
        let third = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 3, b"o".to_vec());
        for record in [&first, &second, &first, &second, &third] {
            write_record_frame(&mut send, record).await.unwrap();
        }
        send.finish().unwrap();
        let _ = timeout(SEND_STOP_WAIT, send.stopped()).await;
        connection.close(0_u32.into(), b"done");
        endpoint.wait_idle().await;

        let received = timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(received.text, "hello");
        assert_eq!(received.chunk_count, 3);
        assert_eq!(
            received
                .chunks
                .iter()
                .map(|chunk| chunk.seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        let mut transcript = AgentTextStreamTranscriptV1::new(stream_id, start_event_id);
        transcript.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"he");
        transcript.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"ll");
        transcript.append(3, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"o");
        assert_eq!(received.transcript_hash, transcript.hash());

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_negotiates_v1_alpn_and_rejects_clients_without_it() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        // The broker-path client endpoint negotiates marmot.quic_broker.v1.
        let endpoint = client_endpoint(
            BrokerServerTrust::CertificateDer(server_cert.clone()),
            broker_addr,
        )
        .unwrap();
        let connection = endpoint
            .connect(broker_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let handshake = connection
            .handshake_data()
            .expect("handshake data available")
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .expect("rustls handshake data");
        assert_eq!(handshake.protocol.as_deref(), Some(QUIC_BROKER_ALPN_V1));
        connection.close(0_u32.into(), b"done");
        endpoint.wait_idle().await;

        // A client that offers no ALPN fails the TLS handshake.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new(provider))
            .with_no_client_auth();
        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).expect("quic client config"),
        ));
        let mut no_alpn_endpoint = Endpoint::client(LOCAL_SERVER_BIND).unwrap();
        no_alpn_endpoint.set_default_client_config(client_config);
        let result = no_alpn_endpoint
            .connect(broker_addr, "localhost")
            .unwrap()
            .await;
        assert!(
            result.is_err(),
            "broker must reject clients without the broker ALPN"
        );
        no_alpn_endpoint.wait_idle().await;

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_rejects_publish_envelope_on_bidirectional_stream() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let endpoint =
            client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
        let connection = endpoint
            .connect(broker_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_control_frame(
            &mut send,
            &QuicBrokerControlEnvelopeV1::publish(vec![0xe3; 32], &MessageId::new(vec![0x73; 32])),
        )
        .await
        .unwrap();
        send.finish().unwrap();

        // The broker rejects the stream without serving any records: the
        // return direction errors instead of delivering a record frame.
        let read = timeout(
            Duration::from_secs(5),
            read_record_frame(&mut recv, None, MAX_FRAME_SIZE),
        )
        .await
        .expect("broker should answer the rejected stream promptly");
        assert!(
            read.is_err(),
            "publish envelope on a bidirectional stream must be rejected"
        );

        connection.close(0_u32.into(), b"done");
        endpoint.wait_idle().await;
        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_rejects_subscribe_envelope_on_unidirectional_stream() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        // The broker task is intentionally not joined: the test returns while
        // the legit subscriber is still parked waiting for a publisher.
        let _broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xe4; 32];
        let start_event_id = MessageId::new(vec![0x74; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        // A rogue client that sends a subscribe envelope on a unidirectional
        // stream and then writes record frames must not be treated as the
        // room's publisher.
        let endpoint =
            client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
        let connection = endpoint
            .connect(broker_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut send = connection.open_uni().await.unwrap();
        write_control_frame(
            &mut send,
            &QuicBrokerControlEnvelopeV1::subscribe(stream_id.clone(), &start_event_id),
        )
        .await
        .unwrap();
        let _ = write_record_frame(
            &mut send,
            &AgentTextStreamRecordV1::text_delta(stream_id, 1, b"rogue".to_vec()),
        )
        .await;
        let _ = send.finish();

        // The legit subscriber must not receive the rogue record; it stays
        // blocked waiting for a real publisher.
        let subscriber = match timeout(Duration::from_millis(500), subscriber).await {
            Err(_) => {
                connection.close(0_u32.into(), b"done");
                endpoint.wait_idle().await;
                let _ = shutdown_tx.send(());
                return;
            }
            Ok(joined) => joined,
        };
        panic!("subscriber should still be waiting, got {subscriber:?}");
    }
}
