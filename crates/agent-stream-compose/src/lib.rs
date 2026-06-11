//! Reusable live-preview stream composition for Marmot agent integrations.

use std::collections::VecDeque;
use std::future::Future;
use std::time::Duration;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AgentTextStreamTranscriptV1,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use transport_quic_broker::{BrokerTextPublisher, OpenBrokerTextPublisher};

const DEFAULT_LIVE_BROKER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamComposeReport {
    pub account: Option<String>,
    pub group_id: String,
    pub stream_id: String,
    pub start_message_id: String,
    pub candidate: String,
    pub status: String,
    pub text: String,
    pub transcript_hash: Option<String>,
    pub chunk_count: u64,
    pub error: Option<String>,
}

pub enum StreamComposeCommand {
    Append {
        text: String,
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
    Status {
        status: String,
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
    Progress {
        text: String,
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
    Finish {
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
    Cancel,
}

trait LiveBrokerPublisher: Sized + Send + 'static {
    async fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        chunk_bytes: usize,
    ) -> Result<(), String>;

    async fn finish(self) -> Result<(), String>;
}

impl LiveBrokerPublisher for BrokerTextPublisher {
    async fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        chunk_bytes: usize,
    ) -> Result<(), String> {
        BrokerTextPublisher::append_record_text(
            self,
            record_type,
            text,
            chunk_bytes,
            Duration::ZERO,
        )
        .await
        .map(|_| ())
        .map_err(|err| err.to_string())
    }

    async fn finish(self) -> Result<(), String> {
        BrokerTextPublisher::finish(self)
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    }
}

pub async fn run_stream_compose_session(
    open: OpenBrokerTextPublisher,
    chunk_bytes: usize,
    rx: mpsc::Receiver<StreamComposeCommand>,
    report: StreamComposeReport,
) {
    let connect = BrokerTextPublisher::connect(open.clone());
    run_stream_compose_session_with_connector(
        open,
        connect,
        chunk_bytes,
        rx,
        report,
        DEFAULT_LIVE_BROKER_WRITE_TIMEOUT,
    )
    .await;
}

async fn run_stream_compose_session_with_connector<P, C, E>(
    open: OpenBrokerTextPublisher,
    connect: C,
    chunk_bytes: usize,
    mut rx: mpsc::Receiver<StreamComposeCommand>,
    mut report: StreamComposeReport,
    live_write_timeout: Duration,
) where
    P: LiveBrokerPublisher,
    C: Future<Output = Result<P, E>> + Send + 'static,
    E: ToString + Send + 'static,
{
    let mut transcript = LocalComposeTranscript::new(&open);
    let mut pending_live_records = VecDeque::new();
    let mut publisher = None;
    let mut connect_task = Some(tokio::spawn(async move {
        connect.await.map_err(|err| err.to_string())
    }));
    let mut live_error = None;

    loop {
        let command = if let Some(task) = connect_task.as_mut() {
            tokio::select! {
                connect_result = task => {
                    connect_task = None;
                    match connect_result {
                        Ok(Ok(mut connected)) => {
                            if let Err(err) = live_broker_deadline(
                                live_write_timeout,
                                flush_pending_live_records(
                                    &mut connected,
                                    &mut pending_live_records,
                                    chunk_bytes,
                                ),
                            )
                            .await
                            {
                                live_error = Some(err);
                                pending_live_records.clear();
                            } else {
                                publisher = Some(connected);
                            }
                        }
                        Ok(Err(err)) => {
                            live_error = Some(err);
                            pending_live_records.clear();
                        }
                        Err(err) => {
                            live_error = Some(err.to_string());
                            pending_live_records.clear();
                        }
                    }
                    continue;
                }
                command = rx.recv() => command,
            }
        } else {
            rx.recv().await
        };
        let Some(command) = command else {
            if let Some(task) = connect_task {
                task.abort();
            }
            return;
        };

        match command {
            StreamComposeCommand::Append { text, respond } => {
                let result = append_stream_compose_text(
                    &mut report,
                    &mut transcript,
                    ComposeLiveSink {
                        publisher: &mut publisher,
                        pending_live_records: &mut pending_live_records,
                        live_error: &mut live_error,
                        live_write_timeout,
                    },
                    text,
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
            }
            StreamComposeCommand::Status { status, respond } => {
                let result = append_stream_compose_status(
                    &mut report,
                    &mut transcript,
                    ComposeLiveSink {
                        publisher: &mut publisher,
                        pending_live_records: &mut pending_live_records,
                        live_error: &mut live_error,
                        live_write_timeout,
                    },
                    status,
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
            }
            StreamComposeCommand::Progress { text, respond } => {
                let result = append_stream_compose_progress(
                    &mut report,
                    &mut transcript,
                    ComposeLiveSink {
                        publisher: &mut publisher,
                        pending_live_records: &mut pending_live_records,
                        live_error: &mut live_error,
                        live_write_timeout,
                    },
                    text,
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
            }
            StreamComposeCommand::Finish { respond } => {
                if let Some(task) = connect_task.take() {
                    task.abort();
                }
                let result = finish_stream_compose_report(
                    &mut report,
                    &transcript,
                    ComposeLiveSink {
                        publisher: &mut publisher,
                        pending_live_records: &mut pending_live_records,
                        live_error: &mut live_error,
                        live_write_timeout,
                    },
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
                return;
            }
            StreamComposeCommand::Cancel => {
                if let Some(task) = connect_task {
                    task.abort();
                }
                return;
            }
        }
    }
}

struct LocalComposeTranscript {
    transcript: AgentTextStreamTranscriptV1,
    next_seq: u64,
}

struct PendingComposeRecord {
    record_type: u8,
    text: String,
}

impl LocalComposeTranscript {
    fn new(open: &OpenBrokerTextPublisher) -> Self {
        Self {
            transcript: AgentTextStreamTranscriptV1::new(
                open.stream_id.clone(),
                open.start_event_id.clone(),
            ),
            next_seq: 1,
        }
    }

    fn append_text(&mut self, text: &str, chunk_bytes: usize) -> Result<u64, String> {
        self.append_record_text(AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, text, chunk_bytes)
    }

    fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        chunk_bytes: usize,
    ) -> Result<u64, String> {
        validate_stream_chunk_bytes(chunk_bytes)?;
        let mut appended = 0_u64;
        for chunk in transport_quic_stream::split_text_deltas(text, chunk_bytes) {
            self.transcript.append(self.next_seq, record_type, &chunk);
            self.next_seq += 1;
            appended += 1;
        }
        Ok(appended)
    }

    fn transcript_hash(&self) -> String {
        hex::encode(self.transcript.hash())
    }

    fn chunk_count(&self) -> u64 {
        self.transcript.chunk_count()
    }
}

fn validate_stream_chunk_bytes(chunk_bytes: usize) -> Result<(), String> {
    if chunk_bytes == 0 {
        return Err("agent text stream chunk size cannot be zero".to_owned());
    }
    if chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
        return Err(format!(
            "agent text stream chunk size exceeds app profile max: {chunk_bytes}"
        ));
    }
    Ok(())
}

async fn append_stream_compose_text<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    mut live: ComposeLiveSink<'_, P>,
    text: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    transcript.append_text(&text, chunk_bytes)?;
    report.text.push_str(&text);
    report.chunk_count = transcript.chunk_count();
    report.transcript_hash = Some(transcript.transcript_hash());

    append_live_record(
        &mut live,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        text,
        chunk_bytes,
    )
    .await;
    if let Some(err) = live.live_error.as_deref() {
        report.error = Some(format!("live stream failed: {err}"));
    }

    Ok(report.clone())
}

async fn append_stream_compose_status<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    live: ComposeLiveSink<'_, P>,
    status: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    report.status.clone_from(&status);
    append_stream_compose_non_text_record(
        report,
        transcript,
        live,
        AGENT_TEXT_STREAM_RECORD_STATUS,
        status,
        chunk_bytes,
    )
    .await
}

async fn append_stream_compose_progress<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    live: ComposeLiveSink<'_, P>,
    text: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    append_stream_compose_non_text_record(
        report,
        transcript,
        live,
        AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
        text,
        chunk_bytes,
    )
    .await
}

struct ComposeLiveSink<'a, P> {
    publisher: &'a mut Option<P>,
    pending_live_records: &'a mut VecDeque<PendingComposeRecord>,
    live_error: &'a mut Option<String>,
    live_write_timeout: Duration,
}

async fn append_stream_compose_non_text_record<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    mut live: ComposeLiveSink<'_, P>,
    record_type: u8,
    text: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    transcript.append_record_text(record_type, &text, chunk_bytes)?;
    report.chunk_count = transcript.chunk_count();
    report.transcript_hash = Some(transcript.transcript_hash());

    append_live_record(&mut live, record_type, text, chunk_bytes).await;
    if let Some(err) = live.live_error.as_deref() {
        report.error = Some(format!("live stream failed: {err}"));
    }

    Ok(report.clone())
}

async fn append_live_record<P: LiveBrokerPublisher>(
    live: &mut ComposeLiveSink<'_, P>,
    record_type: u8,
    text: String,
    chunk_bytes: usize,
) {
    if live.live_error.is_none() {
        if let Some(connected) = live.publisher.as_mut() {
            if let Err(err) = live_broker_deadline(
                live.live_write_timeout,
                connected.append_record_text(record_type, &text, chunk_bytes),
            )
            .await
            {
                *live.live_error = Some(err);
                *live.publisher = None;
                live.pending_live_records.clear();
            }
        } else {
            live.pending_live_records
                .push_back(PendingComposeRecord { record_type, text });
        }
    }
}

async fn finish_stream_compose_report<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &LocalComposeTranscript,
    live: ComposeLiveSink<'_, P>,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    let flush_result = if live.live_error.is_none() {
        if let Some(connected) = live.publisher.as_mut() {
            Some(
                live_broker_deadline(
                    live.live_write_timeout,
                    flush_pending_live_records(connected, live.pending_live_records, chunk_bytes),
                )
                .await,
            )
        } else {
            None
        }
    } else {
        None
    };
    if let Some(Err(err)) = flush_result {
        *live.live_error = Some(err);
        *live.publisher = None;
        live.pending_live_records.clear();
    }

    if live.live_error.is_none()
        && let Some(connected) = live.publisher.take()
        && let Err(err) = live_broker_deadline(live.live_write_timeout, connected.finish()).await
    {
        *live.live_error = Some(err);
    }

    report.status = "finished".to_owned();
    report.transcript_hash = Some(transcript.transcript_hash());
    report.chunk_count = transcript.chunk_count();
    if let Some(err) = live.live_error.as_deref() {
        report.error = Some(format!("live stream failed: {err}"));
    }
    Ok(report.clone())
}

async fn flush_pending_live_records<P: LiveBrokerPublisher>(
    publisher: &mut P,
    pending_live_records: &mut VecDeque<PendingComposeRecord>,
    chunk_bytes: usize,
) -> Result<(), String> {
    while let Some(record) = pending_live_records.pop_front() {
        if let Err(err) = publisher
            .append_record_text(record.record_type, &record.text, chunk_bytes)
            .await
        {
            pending_live_records.clear();
            return Err(err);
        }
    }
    Ok(())
}

async fn live_broker_deadline<T>(
    live_write_timeout: Duration,
    operation: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    if live_write_timeout.is_zero() {
        return operation.await;
    }
    // Dropping the timed-out operation cancels the in-flight QUIC write; callers
    // then drop the publisher so future live records fall back to the local transcript.
    tokio::time::timeout(live_write_timeout, operation)
        .await
        .map_err(|_| format!("live broker write timed out after {live_write_timeout:?}"))?
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use cgka_traits::MessageId;
    use cgka_traits::agent_text_stream::{
        AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, AGENT_TEXT_STREAM_RECORD_STATUS,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamTranscriptV1,
    };
    use tokio::sync::{mpsc, oneshot};
    use transport_quic_broker::{BrokerServerTrust, OpenBrokerTextPublisher};

    use crate::{StreamComposeCommand, StreamComposeReport, run_stream_compose_session};

    fn test_stream_compose_open(
        stream_id: Vec<u8>,
        start_event_id: MessageId,
    ) -> OpenBrokerTextPublisher {
        OpenBrokerTextPublisher {
            broker_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::InsecureLocal,
            stream_id,
            start_event_id,
            crypto: None,
        }
    }

    fn test_stream_compose_report(stream_id: &[u8]) -> StreamComposeReport {
        StreamComposeReport {
            account: Some("account".to_owned()),
            group_id: hex::encode([0x11; 32]),
            stream_id: hex::encode(stream_id),
            start_message_id: hex::encode([0x22; 32]),
            candidate: "quic://127.0.0.1:9".to_owned(),
            status: "streaming".to_owned(),
            text: String::new(),
            transcript_hash: None,
            chunk_count: 0,
            error: None,
        }
    }

    fn expected_stream_transcript_hash_for_appends(
        stream_id: &[u8],
        start_event_id: &MessageId,
        appends: &[&str],
        chunk_bytes: usize,
    ) -> String {
        let mut transcript =
            AgentTextStreamTranscriptV1::new(stream_id.to_vec(), start_event_id.clone());
        let mut seq = 1_u64;
        for text in appends {
            for chunk in transport_quic_stream::split_text_deltas(text, chunk_bytes) {
                transcript.append(seq, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, &chunk);
                seq += 1;
            }
        }
        hex::encode(transcript.hash())
    }

    fn expected_stream_transcript_hash_for_records(
        stream_id: &[u8],
        start_event_id: &MessageId,
        records: &[(u8, &str)],
        chunk_bytes: usize,
    ) -> String {
        let mut transcript =
            AgentTextStreamTranscriptV1::new(stream_id.to_vec(), start_event_id.clone());
        let mut seq = 1_u64;
        for (record_type, text) in records {
            for chunk in transport_quic_stream::split_text_deltas(text, chunk_bytes) {
                transcript.append(seq, *record_type, &chunk);
                seq += 1;
            }
        }
        hex::encode(transcript.hash())
    }

    #[tokio::test]
    async fn compose_session_finalizes_local_transcript_when_broker_connect_is_pending() {
        let stream_id = vec![0xaa; 32];
        let start_event_id = MessageId::new(vec![0xbb; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let report = test_stream_compose_report(&stream_id);
        let (tx, rx) = mpsc::channel(4);
        let session = tokio::spawn(run_stream_compose_session(open, 8, rx, report));

        let (append_tx, append_rx) = oneshot::channel();
        tx.send(StreamComposeCommand::Append {
            text: "hello ".to_owned(),
            respond: append_tx,
        })
        .await
        .unwrap();
        let appended = tokio::time::timeout(Duration::from_millis(250), append_rx)
            .await
            .expect("append should not wait for broker connect")
            .unwrap()
            .unwrap();
        assert_eq!(appended.text, "hello ");
        assert_eq!(appended.chunk_count, 1);

        let (finish_tx, finish_rx) = oneshot::channel();
        tx.send(StreamComposeCommand::Finish { respond: finish_tx })
            .await
            .unwrap();
        let finished = tokio::time::timeout(Duration::from_millis(250), finish_rx)
            .await
            .expect("finish should use local transcript fallback")
            .unwrap()
            .unwrap();

        assert_eq!(finished.status, "finished");
        assert_eq!(finished.text, "hello ");
        assert_eq!(finished.chunk_count, 1);
        assert_eq!(
            finished.transcript_hash.as_deref(),
            Some(
                expected_stream_transcript_hash_for_appends(
                    &stream_id,
                    &start_event_id,
                    &["hello "],
                    8,
                )
                .as_str()
            )
        );

        session.await.unwrap();
    }

    #[tokio::test]
    async fn compose_session_final_report_contains_full_transcript_text() {
        let stream_id = vec![0xcc; 32];
        let start_event_id = MessageId::new(vec![0xdd; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let report = test_stream_compose_report(&stream_id);
        let (tx, rx) = mpsc::channel(4);
        let session = tokio::spawn(run_stream_compose_session(open, 5, rx, report));

        for text in ["hello ", "world"] {
            let (respond, response) = oneshot::channel();
            tx.send(StreamComposeCommand::Append {
                text: text.to_owned(),
                respond,
            })
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_millis(250), response)
                .await
                .expect("append should complete")
                .unwrap()
                .unwrap();
        }

        let (respond, response) = oneshot::channel();
        tx.send(StreamComposeCommand::Finish { respond })
            .await
            .unwrap();
        let finished = tokio::time::timeout(Duration::from_millis(250), response)
            .await
            .expect("finish should complete")
            .unwrap()
            .unwrap();

        assert_eq!(finished.text, "hello world");
        assert_eq!(finished.chunk_count, 3);
        assert_eq!(
            finished.transcript_hash.as_deref(),
            Some(
                expected_stream_transcript_hash_for_appends(
                    &stream_id,
                    &start_event_id,
                    &["hello ", "world"],
                    5,
                )
                .as_str()
            )
        );

        session.await.unwrap();
    }

    #[tokio::test]
    async fn compose_session_status_updates_transcript_without_changing_text() {
        let stream_id = vec![0xee; 32];
        let start_event_id = MessageId::new(vec![0xff; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let report = test_stream_compose_report(&stream_id);
        let (tx, rx) = mpsc::channel(4);
        let session = tokio::spawn(run_stream_compose_session(open, 16, rx, report));

        let (append_respond, append_response) = oneshot::channel();
        tx.send(StreamComposeCommand::Append {
            text: "hello".to_owned(),
            respond: append_respond,
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_millis(250), append_response)
            .await
            .expect("append should complete")
            .unwrap()
            .unwrap();

        let (status_respond, status_response) = oneshot::channel();
        tx.send(StreamComposeCommand::Status {
            status: "thinking".to_owned(),
            respond: status_respond,
        })
        .await
        .unwrap();
        let status_report = tokio::time::timeout(Duration::from_millis(250), status_response)
            .await
            .expect("status should complete")
            .unwrap()
            .unwrap();

        let expected_hash = expected_stream_transcript_hash_for_records(
            &stream_id,
            &start_event_id,
            &[
                (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello"),
                (AGENT_TEXT_STREAM_RECORD_STATUS, "thinking"),
            ],
            16,
        );
        assert_eq!(status_report.status, "thinking");
        assert_eq!(status_report.text, "hello");
        assert_eq!(status_report.chunk_count, 2);
        assert_eq!(
            status_report.transcript_hash.as_deref(),
            Some(expected_hash.as_str())
        );

        let (finish_respond, finish_response) = oneshot::channel();
        tx.send(StreamComposeCommand::Finish {
            respond: finish_respond,
        })
        .await
        .unwrap();
        let finished = tokio::time::timeout(Duration::from_millis(250), finish_response)
            .await
            .expect("finish should complete")
            .unwrap()
            .unwrap();

        assert_eq!(finished.status, "finished");
        assert_eq!(finished.text, "hello");
        assert_eq!(finished.chunk_count, 2);
        assert_eq!(
            finished.transcript_hash.as_deref(),
            Some(expected_hash.as_str())
        );

        session.await.unwrap();
    }

    #[tokio::test]
    async fn compose_session_progress_updates_transcript_without_changing_text() {
        let stream_id = vec![0x9a; 32];
        let start_event_id = MessageId::new(vec![0x9b; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let report = test_stream_compose_report(&stream_id);
        let (tx, rx) = mpsc::channel(4);
        let session = tokio::spawn(run_stream_compose_session(open, 16, rx, report));

        let (append_respond, append_response) = oneshot::channel();
        tx.send(StreamComposeCommand::Append {
            text: "answer".to_owned(),
            respond: append_respond,
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_millis(250), append_response)
            .await
            .expect("append should complete")
            .unwrap()
            .unwrap();

        let (progress_respond, progress_response) = oneshot::channel();
        tx.send(StreamComposeCommand::Progress {
            text: "search: glp-1".to_owned(),
            respond: progress_respond,
        })
        .await
        .unwrap();
        let progress_report = tokio::time::timeout(Duration::from_millis(250), progress_response)
            .await
            .expect("progress should complete")
            .unwrap()
            .unwrap();

        let expected_hash = expected_stream_transcript_hash_for_records(
            &stream_id,
            &start_event_id,
            &[
                (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "answer"),
                (AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, "search: glp-1"),
            ],
            16,
        );
        assert_eq!(progress_report.text, "answer");
        assert_eq!(progress_report.chunk_count, 2);
        assert_eq!(
            progress_report.transcript_hash.as_deref(),
            Some(expected_hash.as_str())
        );

        let (finish_respond, finish_response) = oneshot::channel();
        tx.send(StreamComposeCommand::Finish {
            respond: finish_respond,
        })
        .await
        .unwrap();
        let finished = tokio::time::timeout(Duration::from_millis(250), finish_response)
            .await
            .expect("finish should complete")
            .unwrap()
            .unwrap();

        assert_eq!(finished.status, "finished");
        assert_eq!(finished.text, "answer");
        assert_eq!(finished.chunk_count, 2);
        assert_eq!(
            finished.transcript_hash.as_deref(),
            Some(expected_hash.as_str())
        );

        session.await.unwrap();
    }

    struct StalledPublisher {
        append_started: Option<oneshot::Sender<()>>,
    }

    impl super::LiveBrokerPublisher for StalledPublisher {
        async fn append_record_text(
            &mut self,
            _record_type: u8,
            _text: &str,
            _chunk_bytes: usize,
        ) -> Result<(), String> {
            if let Some(append_started) = self.append_started.take() {
                let _ = append_started.send(());
            }
            future::pending().await
        }

        async fn finish(self) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn append_live_record_times_out_stalled_publisher_and_drops_it() {
        let mut publisher = Some(StalledPublisher {
            append_started: None,
        });
        let mut pending_live_records = std::collections::VecDeque::new();
        let mut live_error = None;

        super::append_live_record(
            &mut super::ComposeLiveSink {
                publisher: &mut publisher,
                pending_live_records: &mut pending_live_records,
                live_error: &mut live_error,
                live_write_timeout: Duration::from_millis(10),
            },
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
            "hello".to_owned(),
            8,
        )
        .await;

        assert!(publisher.is_none(), "stalled publisher should be dropped");
        assert!(pending_live_records.is_empty());
        assert!(
            live_error
                .as_deref()
                .is_some_and(|err| err.contains("timed out")),
            "append should record live timeout: {live_error:?}"
        );
    }

    struct StalledFinishPublisher;

    impl super::LiveBrokerPublisher for StalledFinishPublisher {
        async fn append_record_text(
            &mut self,
            _record_type: u8,
            _text: &str,
            _chunk_bytes: usize,
        ) -> Result<(), String> {
            Ok(())
        }

        async fn finish(self) -> Result<(), String> {
            future::pending().await
        }
    }

    #[tokio::test]
    async fn finish_report_times_out_stalled_live_finish_and_uses_local_transcript() {
        let stream_id = vec![0x5a; 32];
        let start_event_id = MessageId::new(vec![0x5b; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let mut report = test_stream_compose_report(&stream_id);
        let transcript = super::LocalComposeTranscript::new(&open);
        let mut publisher = Some(StalledFinishPublisher);
        let mut pending_live_records = std::collections::VecDeque::new();
        let mut live_error = None;

        let finished = super::finish_stream_compose_report(
            &mut report,
            &transcript,
            super::ComposeLiveSink {
                publisher: &mut publisher,
                pending_live_records: &mut pending_live_records,
                live_error: &mut live_error,
                live_write_timeout: Duration::from_millis(10),
            },
            8,
        )
        .await
        .unwrap();

        assert!(
            publisher.is_none(),
            "publisher should be consumed on finish"
        );
        assert_eq!(finished.status, "finished");
        assert_eq!(finished.chunk_count, 0);
        assert!(
            finished
                .error
                .as_deref()
                .is_some_and(|err| err.contains("timed out")),
            "finish should report live timeout: {:?}",
            finished.error
        );
    }

    #[tokio::test]
    async fn compose_session_times_out_stalled_live_flush_and_still_finishes() {
        let stream_id = vec![0x4a; 32];
        let start_event_id = MessageId::new(vec![0x4b; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let report = test_stream_compose_report(&stream_id);
        let (tx, rx) = mpsc::channel(4);
        let (connect_tx, connect_rx) = oneshot::channel();
        let (append_started_tx, append_started_rx) = oneshot::channel();
        let session = tokio::spawn(super::run_stream_compose_session_with_connector(
            open,
            async move {
                connect_rx.await.map_err(|err| err.to_string())?;
                Ok::<_, String>(StalledPublisher {
                    append_started: Some(append_started_tx),
                })
            },
            8,
            rx,
            report,
            Duration::from_millis(10),
        ));

        let (append_tx, append_rx) = oneshot::channel();
        tx.send(StreamComposeCommand::Append {
            text: "hello".to_owned(),
            respond: append_tx,
        })
        .await
        .unwrap();
        let appended = tokio::time::timeout(Duration::from_millis(250), append_rx)
            .await
            .expect("append should use local transcript while broker connect is pending")
            .unwrap()
            .unwrap();
        assert_eq!(appended.text, "hello");
        assert_eq!(appended.chunk_count, 1);
        assert_eq!(appended.error, None);

        connect_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_millis(250), append_started_rx)
            .await
            .expect("pending live flush should start")
            .unwrap();

        let (finish_tx, finish_rx) = oneshot::channel();
        tx.send(StreamComposeCommand::Finish { respond: finish_tx })
            .await
            .unwrap();
        let finished = tokio::time::timeout(Duration::from_millis(250), finish_rx)
            .await
            .expect("finish should not wait indefinitely behind the stalled live flush")
            .unwrap()
            .unwrap();

        assert_eq!(finished.status, "finished");
        assert_eq!(finished.text, "hello");
        assert_eq!(finished.chunk_count, 1);
        assert!(
            finished
                .error
                .as_deref()
                .is_some_and(|err| err.contains("timed out")),
            "finish should report live timeout: {:?}",
            finished.error
        );
        assert_eq!(
            finished.transcript_hash.as_deref(),
            Some(
                expected_stream_transcript_hash_for_appends(
                    &stream_id,
                    &start_event_id,
                    &["hello"],
                    8,
                )
                .as_str()
            )
        );

        session.await.unwrap();
    }
}
