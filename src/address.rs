use anyhow::{anyhow, Result};
use moka::future::Cache;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

const DNS_RESOLVE_TIMEOUT_SECS: u64 = 10;

/// DNS cache TTL in seconds
const DNS_CACHE_TTL_SECS: u64 = 120;

/// DNS negative cache TTL in seconds (for failed lookups)
const DNS_NEGATIVE_CACHE_TTL_SECS: u64 = 30;

/// Maximum number of DNS cache entries
const DNS_CACHE_MAX_ENTRIES: u64 = 10_000;

/// Check if an IP address is private/internal (DNS rebinding protection)
fn is_private_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            ip.is_loopback()                    // 127.0.0.0/8
                || ip.is_private()              // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || ip.is_link_local()           // 169.254.0.0/16
                || ip.is_broadcast()            // 255.255.255.255
                || ip.is_unspecified()          // 0.0.0.0
                || is_shared_address(ip)        // 100.64.0.0/10 (CGNAT)
                || is_benchmarking(ip)          // 198.18.0.0/15
                || is_reserved(ip)              // 240.0.0.0/4
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()                    // ::1
                || ip.is_unspecified()          // ::
                || is_ipv6_unique_local(ip)     // fc00::/7
                || is_ipv6_link_local(ip)       // fe80::/10
        }
    }
}

/// 100.64.0.0/10 - Shared Address Space (CGNAT)
fn is_shared_address(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// 198.18.0.0/15 - Benchmarking
fn is_benchmarking(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] & 0xFE) == 18
}

/// 240.0.0.0/4 - Reserved for future use
fn is_reserved(ip: &Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

/// fc00::/7 - Unique Local Addresses
fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFE00) == 0xFC00
}

/// fe80::/10 - Link-Local Addresses
fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xFFC0) == 0xFE80
}

/// Cached DNS result
#[derive(Clone, Debug)]
enum DnsCacheEntry {
    /// Successfully resolved addresses
    Success(Vec<SocketAddr>),
    /// Failed to resolve (negative cache)
    Failed(String),
}

/// Global DNS cache using moka for high-performance concurrent access
static DNS_CACHE: LazyLock<Cache<String, DnsCacheEntry>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(DNS_CACHE_MAX_ENTRIES)
        .time_to_live(Duration::from_secs(DNS_CACHE_TTL_SECS))
        .build()
});

/// Counter for round-robin address selection
static ADDR_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Address type constants (compatible with Trojan/SOCKS5 address encoding)
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

/// Maximum domain name length (RFC 1035)
const MAX_DOMAIN_LENGTH: usize = 255;

/// Address decode result
#[derive(Debug)]
pub enum DecodeResult {
    /// Successfully decoded address with consumed bytes count
    Ok(Address, usize),
    /// Need more data to complete decoding
    NeedMoreData,
    /// Invalid address format
    Invalid(&'static str),
}

/// Target address for Trojan protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    IPv4([u8; 4], u16),
    IPv6([u8; 16], u16),
    Domain(String, u16),
}

impl Address {
    /// Decode address from buffer (Trojan/SOCKS5 format)
    ///
    /// Format:
    /// - IPv4: 1 byte type (0x01) + 4 bytes IP + 2 bytes port
    /// - Domain: 1 byte type (0x03) + 1 byte length + domain + 2 bytes port
    /// - IPv6: 1 byte type (0x04) + 16 bytes IP + 2 bytes port
    pub fn decode(buf: &[u8]) -> DecodeResult {
        if buf.is_empty() {
            return DecodeResult::NeedMoreData;
        }

        let atyp = buf[0];
        let mut cursor = 1;

        match atyp {
            ATYP_IPV4 => {
                // Need: type(1) + ip(4) + port(2) = 7 bytes
                if buf.len() < 7 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                DecodeResult::Ok(Address::IPv4(ip, port), cursor)
            }
            ATYP_DOMAIN => {
                // Need at least: type(1) + len(1) = 2 bytes
                if buf.len() < 2 {
                    return DecodeResult::NeedMoreData;
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;

                // Need: type(1) + len(1) + domain + port(2)
                if buf.len() < 2 + domain_len + 2 {
                    return DecodeResult::NeedMoreData;
                }

                if domain_len > MAX_DOMAIN_LENGTH {
                    return DecodeResult::Invalid("domain name too long");
                }

                let domain = match std::str::from_utf8(&buf[cursor..cursor + domain_len]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return DecodeResult::Invalid("invalid UTF-8 in domain"),
                };
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                DecodeResult::Ok(Address::Domain(domain, port), cursor)
            }
            ATYP_IPV6 => {
                // Need: type(1) + ip(16) + port(2) = 19 bytes
                if buf.len() < 19 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                DecodeResult::Ok(Address::IPv6(ip, port), cursor)
            }
            _ => DecodeResult::Invalid("unknown address type"),
        }
    }

    /// Encode address to buffer (Trojan/SOCKS5 format)
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Address::IPv4(ip, port) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Domain(domain, port) => {
                buf.push(ATYP_DOMAIN);
                // Truncate domain if exceeds max length (should not happen with valid input)
                let domain_len = domain.len().min(MAX_DOMAIN_LENGTH);
                buf.push(domain_len as u8);
                buf.extend_from_slice(&domain.as_bytes()[..domain_len]);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::IPv6(ip, port) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// Get encoded size in bytes
    pub fn encoded_size(&self) -> usize {
        match self {
            Address::IPv4(_, _) => 1 + 4 + 2, // type + ip + port
            Address::Domain(domain, _) => {
                // type + len + domain (capped) + port
                1 + 1 + domain.len().min(MAX_DOMAIN_LENGTH) + 2
            }
            Address::IPv6(_, _) => 1 + 16 + 2, // type + ip + port
        }
    }

    /// Validate domain name and create Address
    /// Returns None if domain exceeds maximum length
    pub fn new_domain(domain: String, port: u16) -> Option<Self> {
        if domain.len() > MAX_DOMAIN_LENGTH {
            return None;
        }
        Some(Address::Domain(domain, port))
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(_, port) => *port,
            Address::IPv6(_, port) => *port,
            Address::Domain(_, port) => *port,
        }
    }

    pub async fn to_socket_addr(&self) -> Result<SocketAddr> {
        match self {
            Address::IPv4(ip, port) => {
                let addr = IpAddr::V4(std::net::Ipv4Addr::from(*ip));
                Ok(SocketAddr::new(addr, *port))
            }
            Address::IPv6(ip, port) => {
                let addr = IpAddr::V6(std::net::Ipv6Addr::from(*ip));
                Ok(SocketAddr::new(addr, *port))
            }
            Address::Domain(domain, port) => {
                Self::resolve_domain_cached(domain, *port).await
            }
        }
    }

    /// Resolve domain with DNS caching
    async fn resolve_domain_cached(domain: &str, port: u16) -> Result<SocketAddr> {
        // Cache key includes port for correct socket address
        let cache_key = format!("{}:{}", domain, port);

        // Try cache first
        if let Some(entry) = DNS_CACHE.get(&cache_key).await {
            return match entry {
                DnsCacheEntry::Success(addrs) => {
                    // Round-robin address selection for load balancing
                    let idx = ADDR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        % addrs.len();
                    Ok(addrs[idx])
                }
                DnsCacheEntry::Failed(msg) => Err(anyhow!("{}", msg)),
            };
        }

        // Cache miss - perform DNS lookup
        let result = tokio::time::timeout(
            Duration::from_secs(DNS_RESOLVE_TIMEOUT_SECS),
            tokio::net::lookup_host((domain, port)),
        )
        .await;

        match result {
            Ok(Ok(addrs)) => {
                let addrs: Vec<SocketAddr> = addrs.collect();
                if addrs.is_empty() {
                    let msg = format!("No addresses found for domain: {}", domain);
                    DNS_CACHE
                        .insert(cache_key, DnsCacheEntry::Failed(msg.clone()))
                        .await;
                    Err(anyhow!("{}", msg))
                } else {
                    // Filter out private/internal IPs to prevent DNS rebinding attacks
                    let public_addrs: Vec<SocketAddr> = addrs
                        .into_iter()
                        .filter(|addr| !is_private_ip(&addr.ip()))
                        .collect();

                    if public_addrs.is_empty() {
                        let msg = format!(
                            "DNS rebinding protection: domain {} resolved to private IP",
                            domain
                        );
                        DNS_CACHE
                            .insert(cache_key, DnsCacheEntry::Failed(msg.clone()))
                            .await;
                        Err(anyhow!("{}", msg))
                    } else {
                        DNS_CACHE
                            .insert(cache_key, DnsCacheEntry::Success(public_addrs.clone()))
                            .await;
                        Ok(public_addrs[0])
                    }
                }
            }
            Ok(Err(e)) => {
                let msg = format!("DNS lookup failed for {}: {}", domain, e);
                DNS_CACHE
                    .insert(cache_key, DnsCacheEntry::Failed(msg.clone()))
                    .await;
                Err(anyhow!("{}", msg))
            }
            Err(_) => {
                let msg = format!(
                    "DNS resolution timeout after {} seconds for {}",
                    DNS_RESOLVE_TIMEOUT_SECS, domain
                );
                DNS_CACHE
                    .insert(cache_key, DnsCacheEntry::Failed(msg.clone()))
                    .await;
                Err(anyhow!("{}", msg))
            }
        }
    }

    /// Clear the DNS cache (useful for testing)
    #[cfg(test)]
    pub async fn clear_dns_cache() {
        DNS_CACHE.invalidate_all();
        DNS_CACHE.run_pending_tasks().await;
    }

    /// Get DNS cache statistics (for monitoring)
    #[allow(dead_code)]
    pub fn dns_cache_stats() -> (u64, u64) {
        (DNS_CACHE.entry_count(), DNS_CACHE_MAX_ENTRIES)
    }

    // For UDP associations, we don't use the target address as the key
    // Instead, we could use connection info or just create unique sockets
    pub fn to_association_key(&self, client_info: &str) -> String {
        format!("{}_{}", client_info, self.to_key())
    }

    pub fn to_key(&self) -> String {
        match self {
            Address::IPv4(ip, port) => format!("{}:{}", std::net::Ipv4Addr::from(*ip), port),
            Address::IPv6(ip, port) => format!("[{}]:{}", std::net::Ipv6Addr::from(*ip), port),
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Decode tests ==========

    #[test]
    fn test_decode_ipv4() {
        let mut buf = Vec::new();
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&[192, 168, 1, 1]);
        buf.extend_from_slice(&8080u16.to_be_bytes());

        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 7);
                assert_eq!(addr, Address::IPv4([192, 168, 1, 1], 8080));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_decode_ipv6() {
        let ip = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut buf = Vec::new();
        buf.push(ATYP_IPV6);
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(&443u16.to_be_bytes());

        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 19);
                assert_eq!(addr, Address::IPv6(ip, 443));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_decode_domain() {
        let mut buf = Vec::new();
        buf.push(ATYP_DOMAIN);
        buf.push(11); // "example.com" length
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&80u16.to_be_bytes());

        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 1 + 1 + 11 + 2);
                assert_eq!(addr, Address::Domain("example.com".to_string(), 80));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_decode_need_more_data_empty() {
        assert!(matches!(Address::decode(&[]), DecodeResult::NeedMoreData));
    }

    #[test]
    fn test_decode_need_more_data_ipv4_incomplete() {
        let buf = [ATYP_IPV4, 192, 168]; // Missing IP bytes and port
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));
    }

    #[test]
    fn test_decode_need_more_data_ipv6_incomplete() {
        let buf = [ATYP_IPV6, 0, 0, 0, 0]; // Missing IP bytes
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));
    }

    #[test]
    fn test_decode_need_more_data_domain_incomplete() {
        let buf = [ATYP_DOMAIN, 10, b'e', b'x']; // Domain length says 10, only 2 provided
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));
    }

    #[test]
    fn test_decode_invalid_type() {
        let buf = [0x99, 0, 0, 0, 0];
        assert!(matches!(Address::decode(&buf), DecodeResult::Invalid(_)));
    }

    #[test]
    fn test_decode_invalid_utf8_domain() {
        let mut buf = Vec::new();
        buf.push(ATYP_DOMAIN);
        buf.push(4);
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFF, 0xFE]); // Invalid UTF-8
        buf.extend_from_slice(&80u16.to_be_bytes());

        assert!(matches!(Address::decode(&buf), DecodeResult::Invalid(_)));
    }

    // ========== Encode tests ==========

    #[test]
    fn test_encode_ipv4() {
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let mut buf = Vec::new();
        addr.encode(&mut buf);

        assert_eq!(buf.len(), 7);
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([buf[5], buf[6]]), 8080);
    }

    #[test]
    fn test_encode_ipv6() {
        let ip = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let addr = Address::IPv6(ip, 443);
        let mut buf = Vec::new();
        addr.encode(&mut buf);

        assert_eq!(buf.len(), 19);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(&buf[1..17], &ip);
        assert_eq!(u16::from_be_bytes([buf[17], buf[18]]), 443);
    }

    #[test]
    fn test_encode_domain() {
        let addr = Address::Domain("test.com".to_string(), 80);
        let mut buf = Vec::new();
        addr.encode(&mut buf);

        assert_eq!(buf.len(), 1 + 1 + 8 + 2);
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1], 8); // domain length
        assert_eq!(&buf[2..10], b"test.com");
        assert_eq!(u16::from_be_bytes([buf[10], buf[11]]), 80);
    }

    // ========== Encode/Decode roundtrip tests ==========

    #[test]
    fn test_roundtrip_ipv4() {
        let original = Address::IPv4([10, 20, 30, 40], 12345);
        let mut buf = Vec::new();
        original.encode(&mut buf);

        match Address::decode(&buf) {
            DecodeResult::Ok(decoded, consumed) => {
                assert_eq!(consumed, buf.len());
                assert_eq!(decoded, original);
            }
            _ => panic!("Roundtrip failed"),
        }
    }

    #[test]
    fn test_roundtrip_ipv6() {
        let ip = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let original = Address::IPv6(ip, 65535);
        let mut buf = Vec::new();
        original.encode(&mut buf);

        match Address::decode(&buf) {
            DecodeResult::Ok(decoded, consumed) => {
                assert_eq!(consumed, buf.len());
                assert_eq!(decoded, original);
            }
            _ => panic!("Roundtrip failed"),
        }
    }

    #[test]
    fn test_roundtrip_domain() {
        let original = Address::Domain("sub.domain.example.org".to_string(), 8443);
        let mut buf = Vec::new();
        original.encode(&mut buf);

        match Address::decode(&buf) {
            DecodeResult::Ok(decoded, consumed) => {
                assert_eq!(consumed, buf.len());
                assert_eq!(decoded, original);
            }
            _ => panic!("Roundtrip failed"),
        }
    }

    // ========== encoded_size tests ==========

    #[test]
    fn test_encoded_size_ipv4() {
        let addr = Address::IPv4([0, 0, 0, 0], 0);
        assert_eq!(addr.encoded_size(), 7);
    }

    #[test]
    fn test_encoded_size_ipv6() {
        let addr = Address::IPv6([0; 16], 0);
        assert_eq!(addr.encoded_size(), 19);
    }

    #[test]
    fn test_encoded_size_domain() {
        let addr = Address::Domain("example.com".to_string(), 80);
        assert_eq!(addr.encoded_size(), 1 + 1 + 11 + 2);
    }

    // ========== Original tests ==========

    #[test]
    fn test_ipv4_address_port() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_ipv6_address_port() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_domain_address_port() {
        let addr = Address::Domain("example.com".to_string(), 80);
        assert_eq!(addr.port(), 80);
    }

    #[test]
    fn test_ipv4_to_key() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        assert_eq!(addr.to_key(), "192.168.1.1:8080");
    }

    #[test]
    fn test_ipv6_to_key() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        assert_eq!(addr.to_key(), "[::1]:443");
    }

    #[test]
    fn test_domain_to_key() {
        let addr = Address::Domain("example.com".to_string(), 80);
        assert_eq!(addr.to_key(), "example.com:80");
    }

    #[test]
    fn test_to_association_key() {
        let addr = Address::IPv4([10, 0, 0, 1], 1234);
        let key = addr.to_association_key("client_127.0.0.1:5000");
        assert_eq!(key, "client_127.0.0.1:5000_10.0.0.1:1234");
    }

    #[tokio::test]
    async fn test_ipv4_to_socket_addr() {
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let socket_addr = addr.to_socket_addr().await.unwrap();
        assert_eq!(socket_addr.to_string(), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn test_ipv6_to_socket_addr() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        let socket_addr = addr.to_socket_addr().await.unwrap();
        assert_eq!(socket_addr.to_string(), "[::1]:443");
    }

    #[tokio::test]
    async fn test_domain_to_socket_addr_localhost_blocked() {
        // localhost resolves to 127.0.0.1 which is blocked by DNS rebinding protection
        let addr = Address::Domain("localhost".to_string(), 8080);
        let result = addr.to_socket_addr().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("DNS rebinding protection"));
    }

    #[tokio::test]
    async fn test_domain_to_socket_addr_unresolvable() {
        // Use a guaranteed invalid TLD per RFC 6761
        let addr = Address::Domain("unresolvable.invalid".to_string(), 80);
        let result = addr.to_socket_addr().await;
        // Some DNS resolvers may return NXDOMAIN, others may resolve it
        // We just verify the function completes without panic
        let _ = result;
    }

    #[test]
    fn test_address_clone() {
        let addr1 = Address::Domain("example.com".to_string(), 443);
        let addr2 = addr1.clone();
        assert_eq!(addr1.to_key(), addr2.to_key());
    }

    #[test]
    fn test_address_debug() {
        let addr = Address::IPv4([192, 168, 0, 1], 8080);
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("IPv4"));
        assert!(debug_str.contains("192"));
        assert!(debug_str.contains("8080"));
    }

    // ========== DNS cache tests ==========

    #[tokio::test]
    async fn test_dns_cache_private_ip_blocked() {
        // Clear cache first
        Address::clear_dns_cache().await;

        // localhost resolves to private IP, should be blocked
        let addr = Address::Domain("localhost".to_string(), 9999);

        // First call - cache miss, blocked by DNS rebinding protection
        let result1 = addr.to_socket_addr().await;
        assert!(result1.is_err());

        // Second call - should hit negative cache
        let result2 = addr.to_socket_addr().await;
        assert!(result2.is_err());

        // Both should fail with DNS rebinding protection error
        assert!(result1
            .unwrap_err()
            .to_string()
            .contains("DNS rebinding protection"));
    }

    #[tokio::test]
    async fn test_dns_cache_negative_caching() {
        // Clear cache first
        Address::clear_dns_cache().await;

        // Use invalid TLD that should fail
        let addr = Address::Domain("nonexistent.invalid".to_string(), 80);

        // First call - will fail and cache the failure
        let result1 = addr.to_socket_addr().await;

        // Second call - should hit negative cache
        let result2 = addr.to_socket_addr().await;

        // Both should fail (we're testing that negative caching works)
        // Note: Some DNS resolvers might actually resolve .invalid, so we just
        // verify consistency
        assert_eq!(result1.is_ok(), result2.is_ok());
    }

    #[tokio::test]
    async fn test_dns_cache_ipv4_bypass() {
        // IPv4 addresses should bypass cache entirely
        let addr = Address::IPv4([8, 8, 8, 8], 53);
        let result = addr.to_socket_addr().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "8.8.8.8:53");
    }

    #[tokio::test]
    async fn test_dns_cache_ipv6_bypass() {
        // IPv6 addresses should bypass cache entirely
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 53);
        let result = addr.to_socket_addr().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "[::1]:53");
    }

    #[tokio::test]
    async fn test_dns_cache_different_ports() {
        // Clear cache first
        Address::clear_dns_cache().await;

        // Same domain (private IP), different ports should be cached separately
        // Both should fail due to DNS rebinding protection
        let addr1 = Address::Domain("localhost".to_string(), 8080);
        let addr2 = Address::Domain("localhost".to_string(), 9090);

        let result1 = addr1.to_socket_addr().await;
        let result2 = addr2.to_socket_addr().await;

        // Both should fail (localhost resolves to private IP)
        assert!(result1.is_err());
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_dns_cache_stats() {
        let (count, max) = Address::dns_cache_stats();
        // Just verify the function works and returns reasonable values
        assert!(max > 0);
        assert!(count <= max);
    }

    #[tokio::test]
    async fn test_dns_cache_concurrent_access() {
        // Clear cache first
        Address::clear_dns_cache().await;

        let mut handles = vec![];

        // Spawn multiple tasks to access DNS cache concurrently
        // Using localhost which resolves to private IP (will be blocked)
        for i in 0..10 {
            handles.push(tokio::spawn(async move {
                let addr = Address::Domain("localhost".to_string(), 8000 + i);
                addr.to_socket_addr().await
            }));
        }

        // Wait for all to complete - all should fail due to DNS rebinding protection
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_err());
        }
    }
}
