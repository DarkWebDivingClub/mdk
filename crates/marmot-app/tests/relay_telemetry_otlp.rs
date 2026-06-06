//! End-to-end push test for the opt-in OTLP exporter.
//!
//! Runs only with the `otlp-export` feature. It stands up a minimal local HTTP
//! server (no real collector needed), opts the exporter in against it, and
//! asserts the push lands as an `application/x-protobuf` POST to `/v1/metrics`
//! with a non-empty OTLP body. The protobuf *contents* are unit-tested in the
//! crate; this test covers the wire transport.
#![cfg(feature = "otlp-export")]

use std::time::Duration;

use marmot_app::{MarmotRelayPlane, RelayTelemetryExportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct CapturedRequest {
    method: String,
    path: String,
    content_type: Option<String>,
    body_len: usize,
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn capture_one_request(listener: TcpListener, tx: oneshot::Sender<CapturedRequest>) {
    let Ok((mut stream, _)) = listener.accept().await else {
        return;
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        buf.extend_from_slice(&chunk[..read]);

        let Some(header_end) = find_subsequence(&buf, b"\r\n\r\n").map(|pos| pos + 4) else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while buf.len() < header_end + content_length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => buf.extend_from_slice(&chunk[..read]),
            }
        }

        let request_line = headers.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let content_type = headers.lines().find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-type:")
                .map(|value| value.trim().to_owned())
        });

        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = stream.shutdown().await;
        let _ = tx.send(CapturedRequest {
            method,
            path,
            content_type,
            body_len: buf.len().saturating_sub(header_end),
        });
        return;
    }
}

#[tokio::test]
async fn export_once_pushes_otlp_metrics_over_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let server = tokio::spawn(capture_one_request(listener, tx));

    let relay_plane = MarmotRelayPlane::full_history();
    let exporter = relay_plane
        .telemetry_exporter(RelayTelemetryExportConfig::enabled(format!(
            "http://{addr}"
        )))
        .expect("opted-in exporter is constructed");

    let count = exporter
        .export_once(None)
        .await
        .expect("export push succeeds");
    assert!(count > 0, "population metrics are always present");

    let captured = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("server responded in time")
        .expect("captured request");
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/v1/metrics");
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/x-protobuf")
    );
    assert!(captured.body_len > 0, "OTLP protobuf body is non-empty");

    server.await.unwrap();
}
