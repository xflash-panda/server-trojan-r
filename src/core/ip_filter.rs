//! IP address filtering utilities for SSRF protection.
//!
//! Provides functions to detect private, loopback, and link-local addresses.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Check if an IPv4 address is private/loopback/link-local/reserved
pub fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()                   // 127.0.0.0/8
        || ip.is_private()             // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()          // 169.254.0.0/16
        || octets[0] == 0             // 0.0.0.0/8 ("this network")
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)  // 100.64.0.0/10 (CGN, RFC 6598)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)  // 192.0.0.0/24 (IETF protocol)
        || ip.is_broadcast()           // 255.255.255.255
        || ip.is_multicast() // 224.0.0.0/4
}

/// Check if an IPv6 address is private/loopback/link-local/ULA
pub fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback()           // ::1
        || is_ipv6_ula(ip)     // fc00::/7 (Unique Local Address)
        || is_ipv6_link_local(ip) // fe80::/10
}

/// Check if IPv6 is Unique Local Address (fc00::/7)
fn is_ipv6_ula(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Check if IPv6 is link-local (fe80::/10)
fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ipv4_loopback() {
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_class_a() {
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_class_b() {
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 32, 0, 1))); // Outside range
    }

    #[test]
    fn test_is_private_ipv4_class_c() {
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_link_local() {
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_public() {
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(142, 250, 80, 14)));
    }

    #[test]
    fn test_is_private_ipv6_loopback() {
        assert!(is_private_ipv6(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_is_private_ipv6_ula() {
        assert!(is_private_ipv6(&"fc00::1".parse().unwrap()));
        assert!(is_private_ipv6(&"fd00::1".parse().unwrap()));
        assert!(is_private_ipv6(
            &"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ipv6_link_local() {
        assert!(is_private_ipv6(&"fe80::1".parse().unwrap()));
        assert!(is_private_ipv6(
            &"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ipv6_public() {
        assert!(!is_private_ipv6(&"2001:4860:4860::8888".parse().unwrap())); // Google DNS
        assert!(!is_private_ipv6(&"2606:4700:4700::1111".parse().unwrap())); // Cloudflare
    }

    #[test]
    fn test_is_private_ipv4_this_network() {
        assert!(is_private_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(0, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_cgn() {
        assert!(is_private_ipv4(&Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(100, 128, 0, 1))); // Outside CGN range
    }

    #[test]
    fn test_is_private_ipv4_ietf_protocol() {
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 0, 0, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(192, 0, 1, 1))); // Outside range
    }

    #[test]
    fn test_is_private_ipv4_broadcast() {
        assert!(is_private_ipv4(&Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_is_private_ipv4_multicast() {
        assert!(is_private_ipv4(&Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(239, 255, 255, 255)));
    }
}
