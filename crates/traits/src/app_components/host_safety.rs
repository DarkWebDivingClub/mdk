//! Public-IP / loopback host classifiers shared by the avatar-url and
//! encrypted-media endpoint validators.
//!
//! These are reimplemented elsewhere (the media-locator validator in
//! `marmot-app`); this copy is the engine-side, spec-aligned set per
//! `spec/foundation/host-safety.md`.

use std::net::{Ipv4Addr, Ipv6Addr};
use url::Host;

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

pub(crate) fn reject_non_routable_ipv4(addr: Ipv4Addr) -> Result<(), String> {
    let o = addr.octets();
    // Canonical unsafe-host set (spec/foundation/host-safety.md). std classifies
    // some ranges; the rest are matched explicitly so this validator stays in
    // lockstep with the media-locator validator in marmot-app and with the spec.
    let unsafe_host = addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_documentation()
        || addr.is_unspecified()
        || addr.is_multicast()
        || o[0] == 0 // this host 0.0.0.0/8
        || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
        || matches!(o, [192, 0, 0, _]) // IETF protocol assignments 192.0.0.0/24
        || matches!(o, [192, 88, 99, _]) // 6to4 relay anycast 192.88.99.0/24
        || (o[0] == 198 && (18..=19).contains(&o[1])) // benchmarking 198.18.0.0/15
        || o[0] >= 240; // reserved 240.0.0.0/4 (incl. 255.255.255.255 broadcast)
    if unsafe_host {
        return Err("group avatar URL must not point at a non-routable address".into());
    }
    Ok(())
}

pub(crate) fn reject_non_routable_ipv6(addr: Ipv6Addr) -> Result<(), String> {
    if let Some(mapped) = addr.to_ipv4_mapped() {
        return reject_non_routable_ipv4(mapped);
    }
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return Err("group avatar URL must not point at a non-routable address".into());
    }
    // Ranges the stable std API does not classify, per the canonical unsafe-host
    // set (spec/foundation/host-safety.md), kept in lockstep with the media-locator
    // validator in marmot-app:
    //   - unique-local  fc00::/7       (first & 0xfe00 == 0xfc00)
    //   - link-local    fe80::/10      (first & 0xffc0 == 0xfe80)
    //   - 6to4          2002::/16      (first == 0x2002)              transition prefix
    //   - Teredo        2001:0000::/32 (first == 0x2001 && second == 0)  transition prefix
    //   - documentation 2001:db8::/32  (first == 0x2001 && second == 0x0db8)
    //   - documentation 3fff::/20      (first & 0xfff0 == 0x3ff0), per RFC 9637
    let [first, second, ..] = addr.segments();
    if (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || first == 0x2002
        || (first == 0x2001 && second == 0x0000)
        || (first == 0x2001 && second == 0x0db8)
        || (first & 0xfff0) == 0x3ff0
        // Only global unicast 2000::/3 is routable today; reject anything else
        // not already caught above (loopback/unspecified/multicast handled earlier).
        || (first & 0xe000) != 0x2000
    {
        return Err("group avatar URL must not point at a non-routable address".into());
    }
    Ok(())
}
