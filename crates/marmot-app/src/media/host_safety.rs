use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cgka_traits::app_components::{BLOSSOM_LOCATOR_KIND_V1, ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN};
use url::{Host, Url};

use super::MediaLocator;
use crate::AppError;

/// Structurally validate one locator. Per encrypted-media.md Validation a
/// receiver MUST reject a media reference ONLY for structural reasons: an empty
/// locator kind or value, or a value that does not parse as a URL. Whether a
/// well-formed locator is in the group policy or supported by this client is a
/// FETCHABILITY question, decided at fetch time (see `fetch_encrypted_media_blob`)
/// and before emitting an outbound reference (see `validate_outbound`); it MUST
/// NOT invalidate the reference or drop the containing message here.
pub(crate) fn validate_locator(
    locator: &MediaLocator,
    allow_loopback_http: bool,
) -> Result<(), AppError> {
    if locator.kind.trim().is_empty() || locator.value.trim().is_empty() {
        return Err(AppError::InvalidAppMessagePayload(
            "media locator kind and value cannot be empty".into(),
        ));
    }
    // The locator KIND is a fetchability concern, not a validity condition: an
    // out-of-policy or client-unsupported kind (e.g. a non-Blossom `ipfs://`
    // locator) is kept and handled at fetch time, never dropped here, because
    // media is authenticated by its hashes + AEAD independent of the locator.
    let url = Url::parse(&locator.value)
        .map_err(|_| AppError::InvalidAppMessagePayload("media locator URL is invalid".into()))?;
    // Host safety is the exception that DOES drop: a Blossom locator is one this
    // client will fetch over HTTP, so an unsafe host (loopback / non-public /
    // IPv6-transition) or cleartext scheme is a hostile request vector that
    // hash-authentication does not neutralize. Only Blossom locators are ever
    // fetched (`fetch_encrypted_media_blob` filters to them), so a non-Blossom
    // locator skips this check — it is unfetchable-by-this-client, not unsafe.
    if locator.kind == BLOSSOM_LOCATOR_KIND_V1 {
        validate_blossom_fetch_url(&url, allow_loopback_http).map_err(|err| {
            AppError::InvalidAppMessagePayload(format!("media locator URL is unsafe: {err}"))
        })?;
    }
    Ok(())
}

pub(crate) fn validate_blossom_fetch_url(
    url: &Url,
    allow_loopback_http: bool,
) -> Result<(), String> {
    if url.as_str().len() > ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN {
        return Err(format!(
            "URL exceeds {ENCRYPTED_MEDIA_ENDPOINT_URL_MAX_LEN} bytes"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not include credentials".into());
    }
    if url.fragment().is_some() {
        return Err("URL must not include a fragment".into());
    }
    let host = url.host().ok_or("URL must include a host")?;
    match url.scheme() {
        "https" => validate_public_or_allowed_loopback_host(host, false),
        "http" if allow_loopback_http && is_loopback_host(host) => Ok(()),
        "http" => Err("URL scheme must be https".into()),
        _ => Err("URL scheme must be https".into()),
    }
}

fn validate_public_or_allowed_loopback_host(
    host: Host<&str>,
    allow_loopback: bool,
) -> Result<(), String> {
    match host {
        Host::Domain(domain) => {
            let lowered = domain.to_ascii_lowercase();
            if lowered == "localhost" || lowered.ends_with(".localhost") {
                return if allow_loopback {
                    Ok(())
                } else {
                    Err("URL must not point at localhost".into())
                };
            }
            Ok(())
        }
        Host::Ipv4(addr) => reject_non_public_ip(IpAddr::V4(addr), allow_loopback),
        Host::Ipv6(addr) => reject_non_public_ip(IpAddr::V6(addr), allow_loopback),
    }
}

pub(crate) fn is_loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let lowered = domain.to_ascii_lowercase();
            lowered == "localhost" || lowered.ends_with(".localhost")
        }
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
}

pub(crate) fn reject_non_public_ip(addr: IpAddr, allow_loopback: bool) -> Result<(), String> {
    match addr {
        IpAddr::V4(addr) if allow_loopback && addr.is_loopback() => Ok(()),
        IpAddr::V6(addr) if allow_loopback && addr.is_loopback() => Ok(()),
        IpAddr::V4(addr) if is_public_ipv4(addr) => Ok(()),
        IpAddr::V6(addr) if is_public_ipv6(addr) => Ok(()),
        _ => Err("URL must not point at a non-public address".into()),
    }
}

fn is_public_ipv4(addr: Ipv4Addr) -> bool {
    let [a, b, c, d] = addr.octets();
    !matches!(
        (a, b, c, d),
        (0, _, _, _)
            | (10, _, _, _)
            | (100, 64..=127, _, _)
            | (127, _, _, _)
            | (169, 254, _, _)
            | (172, 16..=31, _, _)
            | (192, 0, 0, _)
            | (192, 0, 2, _)
            | (192, 88, 99, _)
            | (192, 168, _, _)
            | (198, 18..=19, _, _)
            | (198, 51, 100, _)
            | (203, 0, 113, _)
            | (224..=255, _, _, _)
    )
}

fn is_public_ipv6(addr: Ipv6Addr) -> bool {
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    let segments = addr.segments();
    let first = segments[0];
    let second = segments[1];
    if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
        return false;
    }
    // Reject IPv6 transition mechanisms that can route to an embedded IPv4
    // endpoint through host-local tunnel configuration, bypassing the IPv4
    // non-public-address checks above.
    if first == 0x2002 || (first == 0x2001 && second == 0x0000) {
        return false;
    }
    if first == 0x2001 && second == 0x0db8 {
        return false;
    }
    // Documentation 3fff::/20 (RFC 9637). It falls inside global-unicast 2000::/3,
    // so the terminal rule below would otherwise accept it. Reject to match the
    // canonical unsafe-host set (spec/foundation/host-safety.md) and the avatar/
    // endpoint validator in cgka_traits, which already rejects 3fff::/20.
    if (first & 0xfff0) == 0x3ff0 {
        return false;
    }
    (first & 0xe000) == 0x2000
}

/// Whether `url` is a loopback-HTTP blob endpoint: scheme `http` (cleartext)
/// AND a loopback host (`localhost`/`*.localhost`, 127.0.0.0/8, or `::1`). Such
/// endpoints are valid component state but must not be acted on outside dev/test
/// (see `MarmotAppConfig::allow_loopback_blob_endpoints`). A URL that does not
/// parse, uses HTTPS, or targets a routable host is not a loopback-HTTP endpoint.
pub(crate) fn is_loopback_http_endpoint(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Domain(domain)) => {
            let lowered = domain.to_ascii_lowercase();
            lowered == "localhost" || lowered.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}
