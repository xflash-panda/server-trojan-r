use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};

const DNS_RESOLVE_TIMEOUT_SECS: u64 = 10;

/// Address type constants (compatible with Trojan/SOCKS5 address encoding)
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

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
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
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
            Address::IPv4(_, _) => 1 + 4 + 2,              // type + ip + port
            Address::Domain(domain, _) => 1 + 1 + domain.len() + 2, // type + len + domain + port
            Address::IPv6(_, _) => 1 + 16 + 2,            // type + ip + port
        }
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
                let addrs = tokio::time::timeout(
                    tokio::time::Duration::from_secs(DNS_RESOLVE_TIMEOUT_SECS),
                    tokio::net::lookup_host((domain.as_str(), *port)),
                )
                .await
                .map_err(|_| {
                    anyhow!(
                        "DNS resolution timeout after {} seconds",
                        DNS_RESOLVE_TIMEOUT_SECS
                    )
                })??;
                addrs
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("Failed to resolve domain: {}", domain))
            }
        }
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
    async fn test_domain_to_socket_addr_localhost() {
        let addr = Address::Domain("localhost".to_string(), 8080);
        let result = addr.to_socket_addr().await;
        assert!(result.is_ok());
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
}
