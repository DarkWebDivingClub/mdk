//! Opt-in relay-telemetry exporter.
//!
//! This is the final stage of the export pipeline in
//! `docs/marmot-architecture/relay-observability.md`: only when the user has
//! opted in, it polls the relay-plane [`RelayTelemetryRollup`], resolves opaque
//! relay indices to relay-URL labels at the export boundary, maps the result to
//! a privacy-safe OTLP metric batch, and pushes it to a first-party
//! Marmot-operated collector over TLS.
//!
//! ## Privacy contract, enforced structurally here
//!
//! - **Opt-in, off by default (req. 1).** [`MarmotRelayPlane::telemetry_exporter`]
//!   is the single construction gate: it returns `None` unless export is
//!   enabled and an endpoint is configured. No exporter, no resolution, no push.
//! - **Relay identity is the only label (req. 3).** The export batch is a flat
//!   list of [`ExportMetricPoint`]s, each of which can carry at most a single
//!   `relay` label and nothing else — there is deliberately no field for an
//!   account, member, device, group, subscription, pubkey, message, event, or
//!   IP value, so a forbidden label cannot be attached.
//! - **Aggregate only (req. 4).** Point values are monotonic counters, gauges,
//!   or fixed-bucket cumulative histograms — never per-event or per-timestamp
//!   rows.
//!
//! The OTLP wire encoding and HTTP push live behind the `otlp-export` cargo
//! feature so the heavy `opentelemetry-proto`/`prost` dependencies stay out of
//! the default build. The privacy-critical mapping ([`build_export_batch`]) and
//! the opt-in gate are in the default build and fully tested.

use transport_nostr_adapter::{DurationHistogramSnapshot, RelayIndex, RelayLabelResolution};

use crate::config::RelayTelemetryExportConfig;
use crate::relay_plane::{EngineReorgMetrics, MarmotRelayPlane, RelayTelemetryRollup};

/// Metric names, matching the catalogue in `relay-observability.md`.
pub mod metric_names {
    /// Per-relay first-event latency histogram.
    pub const FIRST_EVENT_LATENCY: &str = "relay_first_event_latency";
    /// Per-relay EOSE latency histogram.
    pub const EOSE_LATENCY: &str = "relay_eose_latency";
    /// Per-relay total delivered copies (monotonic).
    pub const DELIVERY_COUNT: &str = "relay_delivery_count";
    /// Per-relay corroborating (non-first) copies (monotonic).
    pub const REDUNDANT_COUNT: &str = "relay_redundant_count";
    /// Per-relay fraction of copies that arrived first (gauge).
    pub const FIRST_DELIVERER_RATE: &str = "relay_first_deliverer_rate";
    /// Population-level cross-relay arrival spread histogram (no relay label).
    pub const CROSS_RELAY_SPREAD: &str = "cross_relay_spread";
    /// Device-wide relay connection attempts (monotonic).
    pub const CONNECTION_ATTEMPTS: &str = "relay_connection_attempts";
    /// Device-wide successful relay connections (monotonic).
    pub const CONNECTION_SUCCESSES: &str = "relay_connection_successes";
    /// Device-wide publish attempts (monotonic).
    pub const PUBLISH_ATTEMPTS: &str = "relay_publish_attempts";
    /// Device-wide accepted publishes (monotonic).
    pub const PUBLISH_SUCCESSES: &str = "relay_publish_successes";
    /// Device-wide failed publishes (monotonic).
    pub const PUBLISH_FAILURES: &str = "relay_publish_failures";
    /// Engine settle episodes (monotonic).
    pub const SETTLES: &str = "relay_settles";
    /// Engine post-settle reorgs (monotonic).
    pub const POST_SETTLE_REORGS: &str = "relay_post_settle_reorgs";
    /// Engine derived reorg rate (gauge).
    pub const OBSERVED_REORG_RATE: &str = "relay_observed_reorg_rate";
    /// Engine reorg-lateness histogram (ms).
    pub const REORG_LATENESS: &str = "relay_reorg_lateness_ms";
}

/// A fixed-bucket cumulative histogram in the export batch.
///
/// Mirrors the device-local [`DurationHistogramSnapshot`] bucket edges, which
/// the exporter forwards unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportHistogram {
    /// Inclusive upper bounds of each bucket, ascending (milliseconds).
    pub bounds_ms: Vec<u64>,
    /// Count per bucket; same length as `bounds_ms`.
    pub bucket_counts: Vec<u64>,
    /// Samples above the largest bound.
    pub overflow_count: u64,
}

impl ExportHistogram {
    fn from_snapshot(snapshot: &DurationHistogramSnapshot) -> Self {
        Self {
            bounds_ms: snapshot
                .buckets
                .iter()
                .map(|bucket| bucket.upper_bound_ms)
                .collect(),
            bucket_counts: snapshot.buckets.iter().map(|bucket| bucket.count).collect(),
            overflow_count: snapshot.overflow_count,
        }
    }

    /// Total samples across all buckets and the overflow.
    pub fn total(&self) -> u64 {
        self.bucket_counts.iter().sum::<u64>() + self.overflow_count
    }
}

/// The value of one export metric point.
#[derive(Clone, Debug, PartialEq)]
pub enum ExportMetricValue {
    /// Monotonic, cumulative-since-process-start counter.
    Counter(u64),
    /// Point-in-time ratio or rate.
    Gauge(f64),
    /// Cumulative fixed-bucket histogram.
    Histogram(ExportHistogram),
}

/// One exported metric point.
///
/// The `relay` field is the **only** label any export point may carry. There is
/// deliberately no field for any client-, account-, group-, or
/// subscription-derived value, so the "relay identity is the sole label" rule of
/// the privacy contract is structural, not conventional.
#[derive(Clone, Debug, PartialEq)]
pub struct ExportMetricPoint {
    /// Metric name from [`metric_names`].
    pub name: &'static str,
    /// Relay-identity label (a relay URL), or `None` for population-level
    /// metrics. The sole label permitted to leave the device.
    pub relay: Option<String>,
    /// The aggregate value.
    pub value: ExportMetricValue,
}

/// A privacy-safe batch of export metric points, ready for OTLP encoding.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RelayTelemetryExportBatch {
    /// Flat list of metric points.
    pub points: Vec<ExportMetricPoint>,
}

impl RelayTelemetryExportBatch {
    /// Number of metric points in the batch.
    pub fn len(&self) -> usize {
        self.points.len()
    }

    /// Whether the batch carries no points.
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// Distinct relay labels present in the batch (for inspection and tests).
    pub fn relay_labels(&self) -> Vec<&str> {
        let mut labels: Vec<&str> = self
            .points
            .iter()
            .filter_map(|point| point.relay.as_deref())
            .collect();
        labels.sort_unstable();
        labels.dedup();
        labels
    }
}

/// Map a rollup plus resolved relay labels into the privacy-safe export batch.
///
/// Per-relay points are emitted only for relays whose opaque index resolves to
/// a relay URL; an unresolved index is skipped rather than exported with an
/// opaque or empty label, so nothing but a real relay identity ever appears.
/// Population-level points carry no label.
pub fn build_export_batch(
    rollup: &RelayTelemetryRollup,
    resolution: &RelayLabelResolution,
) -> RelayTelemetryExportBatch {
    let mut points = Vec::new();

    for entry in &rollup.relays {
        let Some(label) = resolution.label_for(RelayIndex(entry.relay_index)) else {
            continue;
        };
        let relay = label.as_str().to_owned();
        points.push(ExportMetricPoint {
            name: metric_names::FIRST_EVENT_LATENCY,
            relay: Some(relay.clone()),
            value: ExportMetricValue::Histogram(ExportHistogram::from_snapshot(
                &entry.first_event_latency,
            )),
        });
        points.push(ExportMetricPoint {
            name: metric_names::EOSE_LATENCY,
            relay: Some(relay.clone()),
            value: ExportMetricValue::Histogram(ExportHistogram::from_snapshot(
                &entry.eose_latency,
            )),
        });
        points.push(ExportMetricPoint {
            name: metric_names::DELIVERY_COUNT,
            relay: Some(relay.clone()),
            value: ExportMetricValue::Counter(entry.delivery_count()),
        });
        points.push(ExportMetricPoint {
            name: metric_names::REDUNDANT_COUNT,
            relay: Some(relay.clone()),
            value: ExportMetricValue::Counter(entry.redundant_count()),
        });
        if let Some(rate) = entry.first_deliverer_rate() {
            points.push(ExportMetricPoint {
                name: metric_names::FIRST_DELIVERER_RATE,
                relay: Some(relay),
                value: ExportMetricValue::Gauge(rate),
            });
        }
    }

    // Population-level points carry no relay label.
    points.push(ExportMetricPoint {
        name: metric_names::CROSS_RELAY_SPREAD,
        relay: None,
        value: ExportMetricValue::Histogram(ExportHistogram::from_snapshot(
            &rollup.cross_relay_spread,
        )),
    });
    for (name, value) in [
        (
            metric_names::CONNECTION_ATTEMPTS,
            rollup.connection_attempts,
        ),
        (
            metric_names::CONNECTION_SUCCESSES,
            rollup.connection_successes,
        ),
        (metric_names::PUBLISH_ATTEMPTS, rollup.publish_attempts),
        (metric_names::PUBLISH_SUCCESSES, rollup.publish_successes),
        (metric_names::PUBLISH_FAILURES, rollup.publish_failures),
    ] {
        points.push(ExportMetricPoint {
            name,
            relay: None,
            value: ExportMetricValue::Counter(value),
        });
    }

    if let Some(engine) = &rollup.engine {
        points.push(ExportMetricPoint {
            name: metric_names::SETTLES,
            relay: None,
            value: ExportMetricValue::Counter(engine.settles),
        });
        points.push(ExportMetricPoint {
            name: metric_names::POST_SETTLE_REORGS,
            relay: None,
            value: ExportMetricValue::Counter(engine.post_settle_reorgs),
        });
        if let Some(rate) = rollup.observed_reorg_rate() {
            points.push(ExportMetricPoint {
                name: metric_names::OBSERVED_REORG_RATE,
                relay: None,
                value: ExportMetricValue::Gauge(rate),
            });
        }
        points.push(ExportMetricPoint {
            name: metric_names::REORG_LATENESS,
            relay: None,
            value: ExportMetricValue::Histogram(ExportHistogram::from_snapshot(
                &engine.reorg_lateness_ms,
            )),
        });
    }

    RelayTelemetryExportBatch { points }
}

/// Error surfaced by the opt-in OTLP exporter.
///
/// Messages are deliberately free of the endpoint URL and any relay identity so
/// they remain safe to log.
#[derive(Debug, thiserror::Error)]
pub enum RelayExportError {
    /// Export is enabled but no endpoint is configured.
    #[error("relay telemetry export endpoint is not configured")]
    MissingEndpoint,
    /// The OTLP push could not be sent.
    #[cfg(feature = "otlp-export")]
    #[error("relay telemetry export request failed to send")]
    Request,
    /// The collector returned a non-success status.
    #[cfg(feature = "otlp-export")]
    #[error("relay telemetry export endpoint returned status {0}")]
    Status(u16),
}

impl MarmotRelayPlane {
    /// Build an opt-in relay-telemetry exporter — the single construction gate.
    ///
    /// Returns `None` unless [`RelayTelemetryExportConfig::export_allowed`]
    /// holds — opted in, an endpoint is configured, and that endpoint is TLS
    /// (`https`, or loopback `http` for local testing). Off-by-default opt-in is
    /// structurally enforced: with no exporter there is no resolution and no
    /// push, and relay identities are never sent over a non-TLS transport.
    pub fn telemetry_exporter(
        &self,
        config: RelayTelemetryExportConfig,
    ) -> Option<RelayTelemetryExporter> {
        if !config.export_allowed() {
            if config.enabled {
                // Opted in but the endpoint is missing or not TLS: fail closed
                // (no exporter) rather than push relay identities in the clear.
                tracing::warn!(
                    target: "marmot_app::relay_telemetry_export",
                    method = "telemetry_exporter",
                    "relay telemetry export disabled: endpoint missing or not https",
                );
            }
            return None;
        }
        Some(RelayTelemetryExporter {
            relay_plane: self.clone(),
            config,
            started_at: std::time::SystemTime::now(),
        })
    }
}

/// Opt-in exporter that pushes relay telemetry to a first-party OTLP collector.
///
/// Only constructed by [`MarmotRelayPlane::telemetry_exporter`] when opted in.
#[derive(Clone)]
pub struct RelayTelemetryExporter {
    relay_plane: MarmotRelayPlane,
    config: RelayTelemetryExportConfig,
    /// Collection start, used as the cumulative `start_time` for OTLP points.
    /// Only read by the feature-gated OTLP push.
    #[cfg_attr(not(feature = "otlp-export"), allow(dead_code))]
    started_at: std::time::SystemTime,
}

impl RelayTelemetryExporter {
    /// The configured poll/push interval.
    pub fn interval(&self) -> std::time::Duration {
        self.config.interval
    }

    /// Build the privacy-safe export batch from the current rollup and the
    /// opt-in-resolved relay labels.
    ///
    /// `engine` folds in the optional engine reorg metrics once that workstream
    /// lands; pass `None` until then.
    pub async fn build_batch(
        &self,
        engine: Option<EngineReorgMetrics>,
    ) -> RelayTelemetryExportBatch {
        let rollup = self.relay_plane.telemetry_rollup(engine).await;
        // The exporter only exists when opted in, so resolution is always
        // available here; default to an empty resolution defensively.
        let resolution = self
            .relay_plane
            .resolve_relay_labels(&self.config)
            .await
            .unwrap_or_default();
        build_export_batch(&rollup, &resolution)
    }
}

#[cfg(feature = "otlp-export")]
mod otlp {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, InstrumentationScope, KeyValue, any_value,
    };
    use opentelemetry_proto::tonic::metrics::v1::{
        AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
        ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use prost::Message;

    use super::{ExportMetricValue, RelayExportError, RelayTelemetryExportBatch};

    const SCOPE_NAME: &str = "marmot.relay_telemetry";

    fn unix_nano(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as u64)
            .unwrap_or_default()
    }

    fn relay_attributes(relay: &Option<String>) -> Vec<KeyValue> {
        match relay {
            Some(relay) => vec![KeyValue {
                key: "relay".to_owned(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue(relay.clone())),
                }),
                ..Default::default()
            }],
            None => Vec::new(),
        }
    }

    /// Encode the batch into an OTLP/HTTP `ExportMetricsServiceRequest`.
    ///
    /// Counters become monotonic cumulative sums, gauges become gauges, and
    /// histograms become cumulative OTLP histograms carrying the same bucket
    /// edges as the device-local snapshots (cumulative since `start_ns`).
    pub(super) fn to_request(
        batch: &RelayTelemetryExportBatch,
        start_ns: u64,
        now_ns: u64,
    ) -> ExportMetricsServiceRequest {
        let metrics = batch
            .points
            .iter()
            .map(|point| {
                let attributes = relay_attributes(&point.relay);
                let data = match &point.value {
                    ExportMetricValue::Counter(value) => metric::Data::Sum(Sum {
                        data_points: vec![NumberDataPoint {
                            attributes,
                            start_time_unix_nano: start_ns,
                            time_unix_nano: now_ns,
                            value: Some(number_data_point::Value::AsInt(*value as i64)),
                            ..Default::default()
                        }],
                        aggregation_temporality: AggregationTemporality::Cumulative as i32,
                        is_monotonic: true,
                    }),
                    ExportMetricValue::Gauge(value) => metric::Data::Gauge(Gauge {
                        data_points: vec![NumberDataPoint {
                            attributes,
                            start_time_unix_nano: start_ns,
                            time_unix_nano: now_ns,
                            value: Some(number_data_point::Value::AsDouble(*value)),
                            ..Default::default()
                        }],
                    }),
                    ExportMetricValue::Histogram(histogram) => {
                        let mut bucket_counts = histogram.bucket_counts.clone();
                        // OTLP histograms carry one more bucket than bounds: the
                        // final bucket counts samples above the largest bound.
                        bucket_counts.push(histogram.overflow_count);
                        let count = bucket_counts.iter().sum();
                        metric::Data::Histogram(Histogram {
                            data_points: vec![HistogramDataPoint {
                                attributes,
                                start_time_unix_nano: start_ns,
                                time_unix_nano: now_ns,
                                count,
                                bucket_counts,
                                explicit_bounds: histogram
                                    .bounds_ms
                                    .iter()
                                    .map(|bound| *bound as f64)
                                    .collect(),
                                ..Default::default()
                            }],
                            aggregation_temporality: AggregationTemporality::Cumulative as i32,
                        })
                    }
                };
                Metric {
                    name: point.name.to_owned(),
                    data: Some(data),
                    ..Default::default()
                }
            })
            .collect();

        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource::default()),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(InstrumentationScope {
                        name: SCOPE_NAME.to_owned(),
                        ..Default::default()
                    }),
                    metrics,
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        }
    }

    /// POST an OTLP metrics request to `{endpoint}/v1/metrics` over TLS.
    pub(super) async fn push(
        batch: &RelayTelemetryExportBatch,
        endpoint: &str,
        started_at: SystemTime,
    ) -> Result<(), RelayExportError> {
        let request = to_request(batch, unix_nano(started_at), unix_nano(SystemTime::now()));
        let body = request.encode_to_vec();
        let url = format!("{}/v1/metrics", endpoint.trim_end_matches('/'));
        // Bound both connect and overall request time so a stuck collector
        // cannot hang an export indefinitely (both stay well under the default
        // poll interval).
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| RelayExportError::Request)?;
        let response = client
            .post(url)
            .header("content-type", "application/x-protobuf")
            .body(body)
            .send()
            .await
            .map_err(|_| RelayExportError::Request)?;
        if !response.status().is_success() {
            return Err(RelayExportError::Status(response.status().as_u16()));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::relay_telemetry_export::{
            ExportHistogram, ExportMetricPoint, ExportMetricValue, RelayTelemetryExportBatch,
            metric_names,
        };

        #[test]
        fn to_request_maps_points_to_otlp_metrics() {
            let batch = RelayTelemetryExportBatch {
                points: vec![
                    ExportMetricPoint {
                        name: metric_names::DELIVERY_COUNT,
                        relay: Some("wss://a.example".into()),
                        value: ExportMetricValue::Counter(7),
                    },
                    ExportMetricPoint {
                        name: metric_names::FIRST_DELIVERER_RATE,
                        relay: Some("wss://a.example".into()),
                        value: ExportMetricValue::Gauge(0.5),
                    },
                    ExportMetricPoint {
                        name: metric_names::CROSS_RELAY_SPREAD,
                        relay: None,
                        value: ExportMetricValue::Histogram(ExportHistogram {
                            bounds_ms: vec![10, 50],
                            bucket_counts: vec![1, 2],
                            overflow_count: 3,
                        }),
                    },
                ],
            };

            let request = to_request(&batch, 100, 200);
            let scope_metrics = &request.resource_metrics[0].scope_metrics[0];
            assert_eq!(scope_metrics.scope.as_ref().unwrap().name, SCOPE_NAME);
            assert_eq!(scope_metrics.metrics.len(), 3);

            // Counter -> monotonic cumulative Sum, carrying the relay label.
            let sum = match &scope_metrics.metrics[0].data {
                Some(metric::Data::Sum(sum)) => sum,
                other => panic!("expected sum, got {other:?}"),
            };
            assert!(sum.is_monotonic);
            assert_eq!(
                sum.aggregation_temporality,
                AggregationTemporality::Cumulative as i32
            );
            let point = &sum.data_points[0];
            assert_eq!(point.value, Some(number_data_point::Value::AsInt(7)));
            assert_eq!(point.start_time_unix_nano, 100);
            assert_eq!(point.time_unix_nano, 200);
            assert_eq!(point.attributes[0].key, "relay");

            // Histogram -> bucket_counts = per-bucket + overflow, same bounds, no label.
            let histogram = match &scope_metrics.metrics[2].data {
                Some(metric::Data::Histogram(histogram)) => histogram,
                other => panic!("expected histogram, got {other:?}"),
            };
            let point = &histogram.data_points[0];
            assert!(
                point.attributes.is_empty(),
                "population metric carries no label"
            );
            assert_eq!(point.bucket_counts, vec![1, 2, 3]);
            assert_eq!(point.explicit_bounds, vec![10.0, 50.0]);
            assert_eq!(point.count, 6);
        }
    }
}

#[cfg(feature = "otlp-export")]
impl RelayTelemetryExporter {
    /// Build the batch and push it once to the configured collector.
    ///
    /// Returns the number of metric points pushed.
    pub async fn export_once(
        &self,
        engine: Option<EngineReorgMetrics>,
    ) -> Result<usize, RelayExportError> {
        let endpoint = self
            .config
            .endpoint
            .clone()
            .ok_or(RelayExportError::MissingEndpoint)?;
        let batch = self.build_batch(engine).await;
        let count = batch.len();
        otlp::push(&batch, &endpoint, self.started_at).await?;
        tracing::debug!(
            target: "marmot_app::relay_telemetry_export",
            method = "export_once",
            point_count = count,
            "pushed relay telemetry export batch"
        );
        Ok(count)
    }

    /// Poll-and-push on the configured interval until `shutdown` flips to `true`.
    ///
    /// Engine reorg metrics are not yet folded into the periodic loop; it
    /// reports adapter and relay-plane metrics until the engine snapshot is
    /// wired in at this seam.
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(self.config.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if self.export_once(None).await.is_err() {
                        tracing::warn!(
                            target: "marmot_app::relay_telemetry_export",
                            method = "run",
                            "relay telemetry export push failed"
                        );
                    }
                }
                result = shutdown.changed() => {
                    // `changed()` errors when the sender is dropped; treat that
                    // as a shutdown too, otherwise the branch would resolve
                    // immediately every iteration and spin the loop.
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use cgka_traits::TransportEndpoint;
    use transport_nostr_adapter::HistogramBucket;

    use crate::relay_plane::{EngineReorgMetrics, RelayRollupEntry, RelayTelemetryRollup};

    use super::*;

    fn hist(count: u64) -> DurationHistogramSnapshot {
        DurationHistogramSnapshot {
            buckets: vec![HistogramBucket {
                upper_bound_ms: 50,
                count,
            }],
            overflow_count: 0,
        }
    }

    #[test]
    fn build_export_batch_labels_only_resolved_relays() {
        let rollup = RelayTelemetryRollup {
            relays: vec![
                RelayRollupEntry {
                    relay_index: 0,
                    first_event_latency: hist(2),
                    eose_latency: hist(1),
                    delivered_first: 3,
                    delivered_later: 1,
                },
                // Index 1 has no resolved label, so it must be skipped entirely.
                RelayRollupEntry {
                    relay_index: 1,
                    delivered_first: 9,
                    ..Default::default()
                },
            ],
            cross_relay_spread: hist(5),
            messages_observed: 5,
            connection_attempts: 4,
            connection_successes: 3,
            publish_attempts: 2,
            publish_successes: 2,
            ..Default::default()
        };
        let resolution = RelayLabelResolution::from_pairs([(
            RelayIndex(0),
            TransportEndpoint("wss://a.example".into()),
        )]);

        let batch = build_export_batch(&rollup, &resolution);

        // Only the resolved relay appears, and only as a `relay` label.
        assert_eq!(batch.relay_labels(), vec!["wss://a.example"]);

        let relay_points: Vec<_> = batch
            .points
            .iter()
            .filter(|point| point.relay.is_some())
            .collect();
        assert!(
            relay_points
                .iter()
                .all(|point| point.relay.as_deref() == Some("wss://a.example")),
            "every per-relay point carries the single resolved relay label",
        );
        assert!(
            relay_points
                .iter()
                .any(|point| point.name == metric_names::FIRST_EVENT_LATENCY)
        );
        assert!(relay_points.iter().any(|point| {
            point.name == metric_names::DELIVERY_COUNT
                && point.value == ExportMetricValue::Counter(4)
        }));
        assert!(relay_points.iter().any(|point| {
            point.name == metric_names::FIRST_DELIVERER_RATE
                && point.value == ExportMetricValue::Gauge(0.75)
        }));

        // Population points carry no label, and the cross-relay spread is one.
        assert!(batch.points.iter().any(|point| {
            point.name == metric_names::CROSS_RELAY_SPREAD && point.relay.is_none()
        }));
        // No publish/connection/population point ever carries a relay label.
        assert!(
            batch
                .points
                .iter()
                .filter(|point| point.name != metric_names::FIRST_EVENT_LATENCY
                    && point.name != metric_names::EOSE_LATENCY
                    && point.name != metric_names::DELIVERY_COUNT
                    && point.name != metric_names::REDUNDANT_COUNT
                    && point.name != metric_names::FIRST_DELIVERER_RATE)
                .all(|point| point.relay.is_none())
        );
    }

    #[test]
    fn build_export_batch_forwards_histogram_bucket_edges() {
        let rollup = RelayTelemetryRollup {
            cross_relay_spread: DurationHistogramSnapshot {
                buckets: vec![
                    HistogramBucket {
                        upper_bound_ms: 10,
                        count: 1,
                    },
                    HistogramBucket {
                        upper_bound_ms: 50,
                        count: 2,
                    },
                ],
                overflow_count: 4,
            },
            ..Default::default()
        };
        let batch = build_export_batch(&rollup, &RelayLabelResolution::default());
        let spread = batch
            .points
            .iter()
            .find(|point| point.name == metric_names::CROSS_RELAY_SPREAD)
            .expect("cross relay spread point");
        match &spread.value {
            ExportMetricValue::Histogram(histogram) => {
                assert_eq!(histogram.bounds_ms, vec![10, 50]);
                assert_eq!(histogram.bucket_counts, vec![1, 2]);
                assert_eq!(histogram.overflow_count, 4);
                assert_eq!(histogram.total(), 7);
            }
            other => panic!("expected histogram, got {other:?}"),
        }
    }

    #[test]
    fn build_export_batch_folds_in_engine_metrics_when_present() {
        let rollup = RelayTelemetryRollup {
            engine: Some(EngineReorgMetrics {
                settles: 4,
                post_settle_reorgs: 1,
                reorg_lateness_ms: hist(1),
            }),
            ..Default::default()
        };
        let batch = build_export_batch(&rollup, &RelayLabelResolution::default());
        assert!(batch.points.iter().any(|point| {
            point.name == metric_names::OBSERVED_REORG_RATE
                && point.value == ExportMetricValue::Gauge(0.25)
        }));
        assert!(
            batch
                .points
                .iter()
                .any(|point| point.name == metric_names::REORG_LATENESS)
        );
        // Engine metrics are population-level: no relay label.
        assert!(
            batch
                .points
                .iter()
                .filter(|point| point.name == metric_names::SETTLES
                    || point.name == metric_names::POST_SETTLE_REORGS
                    || point.name == metric_names::OBSERVED_REORG_RATE
                    || point.name == metric_names::REORG_LATENESS)
                .all(|point| point.relay.is_none())
        );
    }

    #[tokio::test]
    async fn telemetry_exporter_is_gated_and_builds_population_only_batch() {
        let relay_plane = MarmotRelayPlane::full_history();

        // Off by default, and enabled-without-endpoint is still inert.
        assert!(
            relay_plane
                .telemetry_exporter(RelayTelemetryExportConfig::disabled())
                .is_none()
        );
        assert!(
            relay_plane
                .telemetry_exporter(RelayTelemetryExportConfig {
                    enabled: true,
                    endpoint: None,
                    ..Default::default()
                })
                .is_none()
        );

        let exporter = relay_plane
            .telemetry_exporter(RelayTelemetryExportConfig::enabled("https://otlp.example"))
            .expect("opted-in exporter is constructed");
        let batch = exporter.build_batch(None).await;

        // No relay traffic yet: population points only, no relay labels leak.
        assert!(batch.relay_labels().is_empty());
        assert!(
            batch
                .points
                .iter()
                .any(|point| point.name == metric_names::CROSS_RELAY_SPREAD)
        );
        assert!(batch.points.iter().all(|point| point.relay.is_none()));
    }
}
