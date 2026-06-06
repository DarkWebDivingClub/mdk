use std::time::Duration;

const DEFAULT_DIRECTORY_MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarmotAppConfig {
    pub directory_max_future_skew: Duration,
}

impl Default for MarmotAppConfig {
    fn default() -> Self {
        Self {
            directory_max_future_skew: DEFAULT_DIRECTORY_MAX_FUTURE_SKEW,
        }
    }
}

impl MarmotAppConfig {
    pub fn with_directory_max_future_skew(mut self, skew: Duration) -> Self {
        self.directory_max_future_skew = skew;
        self
    }
}

/// Default export poll/push interval. Coarse on purpose: the data is
/// aggregate and cumulative, so a coarse window respects battery and metered
/// networks without losing resolution.
const DEFAULT_EXPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Opt-in configuration for relay-telemetry export.
///
/// Off by default. While `enabled` is `false` nothing is resolved or exported
/// and the app behaves exactly as today. This is the single opt-in switch that
/// gates relay-identity resolution and the OTLP exporter — see the privacy
/// contract in `docs/marmot-architecture/relay-observability.md`.
///
/// The `endpoint` must be a first-party Marmot-operated OTLP/HTTP collector
/// reached over TLS (`https`); the exporter POSTs to `{endpoint}/v1/metrics`.
/// Plain `http` is accepted only for loopback collectors used in local testing,
/// so anything that actually leaves the device stays on TLS. Export is inert
/// without an endpoint, and the exporter is not constructed for a non-TLS,
/// non-loopback endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayTelemetryExportConfig {
    /// Whether the user has opted in to relay-telemetry export. Off by default.
    pub enabled: bool,
    /// First-party OTLP/HTTP collector base URL. Must be `https`, except a
    /// loopback `http` collector for local testing. `None` keeps export inert
    /// even when `enabled`.
    pub endpoint: Option<String>,
    /// How often to poll the rollup and push.
    pub interval: Duration,
}

impl Default for RelayTelemetryExportConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl RelayTelemetryExportConfig {
    /// A disabled (opt-out) configuration. This is also [`Default`].
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            interval: DEFAULT_EXPORT_INTERVAL,
        }
    }

    /// An opted-in configuration pushing to `endpoint` at the default interval.
    pub fn enabled(endpoint: impl Into<String>) -> Self {
        Self {
            enabled: true,
            endpoint: Some(endpoint.into()),
            interval: DEFAULT_EXPORT_INTERVAL,
        }
    }

    /// Override the poll/push interval.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Whether export may actually run: opted in, an endpoint is configured, and
    /// that endpoint is reachable over TLS (`https`). Plain `http` is allowed
    /// only for loopback collectors used in local testing, so the privacy
    /// contract's TLS requirement holds for anything that leaves the device.
    ///
    /// This is the single gate condition shared by `telemetry_exporter` and
    /// relay-identity resolution.
    pub(crate) fn export_allowed(&self) -> bool {
        self.enabled
            && self
                .endpoint
                .as_deref()
                .is_some_and(endpoint_transport_allowed)
    }
}

/// Accept `https` for any host; accept `http` only for a loopback host (a local
/// test collector). Reject anything else, including unparseable endpoints.
fn endpoint_transport_allowed(endpoint: &str) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => url.host().is_some_and(host_is_loopback),
        _ => false,
    }
}

fn host_is_loopback(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(addr) => addr.is_loopback(),
        url::Host::Ipv6(addr) => addr.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_allowed_requires_opt_in_endpoint_and_tls() {
        // Off by default, and an endpoint alone does not enable export.
        assert!(!RelayTelemetryExportConfig::disabled().export_allowed());
        assert!(
            !RelayTelemetryExportConfig {
                enabled: true,
                endpoint: None,
                ..Default::default()
            }
            .export_allowed()
        );

        // https is accepted; plain http to a remote host is rejected.
        assert!(RelayTelemetryExportConfig::enabled("https://otlp.example.org").export_allowed());
        assert!(!RelayTelemetryExportConfig::enabled("http://otlp.example.org").export_allowed());
        assert!(!RelayTelemetryExportConfig::enabled("ftp://otlp.example.org").export_allowed());
        assert!(!RelayTelemetryExportConfig::enabled("not a url").export_allowed());

        // http is allowed only for loopback collectors (local testing).
        assert!(RelayTelemetryExportConfig::enabled("http://127.0.0.1:4318").export_allowed());
        assert!(RelayTelemetryExportConfig::enabled("http://[::1]:4318").export_allowed());
        assert!(RelayTelemetryExportConfig::enabled("http://localhost:4318").export_allowed());
    }
}
