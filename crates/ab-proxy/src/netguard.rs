//! Post-resolution destination validation (SSRF / DNS-rebinding guard).
//!
//! Policy is evaluated per *hostname*, but the proxy connects to whatever IP
//! DNS returns. An allowlisted name that resolves to loopback, link-local,
//! RFC1918 or ULA space would otherwise open a host-side tunnel from the
//! proxy's network namespace to that destination — exactly what a DNS
//! rebinding attack or an internal-DNS metadata record needs. Every resolved
//! address therefore passes through [`is_protected_destination`] before any
//! connect attempt.
//!
//! Escape hatches (both deliberate configuration):
//! - explicit **IP-literal** allow rules (`--allow 10.0.2.2:443`) bypass this
//!   check entirely — the operator named the exact address;
//! - `--allow-private-dns` / `ProxyConfig::allow_private_dns` disables the
//!   check for hostnames (needed when a sandbox legitimately must reach
//!   private infrastructure by name).

use std::net::IpAddr;

/// True for addresses that must never be reached on behalf of an *allowlisted
/// hostname*: unspecified, loopback, link-local (v4 + v6), RFC1918, CGNAT
/// 100.64/10, reserved class E, multicast/broadcast, and the IPv4-mapped IPv6
/// forms of all of these (`::ffff:127.0.0.1` et al).
pub fn is_protected_destination(ip: IpAddr) -> bool {
    // Unwrap IPv4-mapped IPv6 so v4-in-v6 cannot smuggle a private range
    // past the v4 checks below.
    let ip = match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let is_rfc1918 = o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168);
            let is_cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
            v4.is_unspecified() // 0.0.0.0
                || v4.is_loopback() // 127.0.0.0/8
                || v4.is_link_local() // 169.254.0.0/16 (cloud metadata lives here)
                || v4.is_broadcast() // 255.255.255.255
                || v4.is_multicast() // 224.0.0.0/4
                || is_rfc1918
                || is_cgnat
                || o[0] >= 240 // reserved 240/4
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || v6.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
    }

    #[test]
    fn protected_ranges_are_rejected() {
        assert!(is_protected_destination(v4([0, 0, 0, 0])));
        assert!(is_protected_destination(v4([127, 0, 0, 1])));
        assert!(is_protected_destination(v4([169, 254, 169, 254])));
        assert!(is_protected_destination(v4([10, 1, 2, 3])));
        assert!(is_protected_destination(v4([172, 16, 0, 1])));
        assert!(is_protected_destination(v4([172, 31, 255, 254])));
        assert!(is_protected_destination(v4([192, 168, 1, 1])));
        assert!(is_protected_destination(v4([100, 64, 7, 9])));
        assert!(is_protected_destination(v4([240, 0, 0, 1])));
        assert!(is_protected_destination(v4([255, 255, 255, 255])));
        assert!(is_protected_destination(v4([224, 0, 0, 22])));

        assert!(is_protected_destination("::".parse().unwrap()));
        assert!(is_protected_destination("::1".parse().unwrap()));
        assert!(is_protected_destination("fe80::1".parse().unwrap()));
        assert!(is_protected_destination("fc00::1".parse().unwrap()));
        assert!(is_protected_destination("fd12:3456::1".parse().unwrap()));
        assert!(is_protected_destination("ff02::1".parse().unwrap()));
        // v4-mapped forms must not bypass the v4 checks.
        assert!(is_protected_destination(
            "::ffff:127.0.0.1".parse().unwrap()
        ));
        assert!(is_protected_destination("::ffff:10.0.0.7".parse().unwrap()));
        assert!(is_protected_destination(
            "::ffff:169.254.169.254".parse().unwrap()
        ));
    }

    #[test]
    fn public_addresses_pass() {
        for s in [
            "1.2.3.4",
            "8.8.8.8",
            "52.84.1.2",
            "172.32.0.1",
            "100.128.0.1",
            "9.9.9.9",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_protected_destination(ip), "{s} must not be protected");
        }
        for s in ["2606:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_protected_destination(ip), "{s} must not be protected");
        }
    }
}
