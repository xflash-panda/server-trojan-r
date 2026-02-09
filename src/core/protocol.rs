//! Trojan protocol parsing
//!
//! Implements the Trojan protocol format:
//! - 56-byte password (SHA224 hex encoded)
//! - CRLF
//! - Command (1 byte: CONNECT=1, UDP_ASSOCIATE=3)
//! - Address (ATYP + address + port)
//! - CRLF
//! - Payload

use bytes::{Bytes, BytesMut};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::lookup_host;

use crate::logger::log;

/// Address type constants
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Trojan command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCmd {
    /// TCP connect
    Connect = 1,
    /// UDP associate
    UdpAssociate = 3,
}

impl TryFrom<u8> for TrojanCmd {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TrojanCmd::Connect),
            3 => Ok(TrojanCmd::UdpAssociate),
            _ => Err("invalid trojan command"),
        }
    }
}

/// Address types supported by Trojan
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// IPv4 address
    IPv4([u8; 4], u16),
    /// IPv6 address
    IPv6([u8; 16], u16),
    /// Domain name
    Domain(String, u16),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::IPv4(ip, port) => write!(f, "{}:{}", Ipv4Addr::from(*ip), port),
            Address::IPv6(ip, port) => write!(f, "[{}]:{}", Ipv6Addr::from(*ip), port),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

/// Address decode result
#[derive(Debug)]
pub enum DecodeResult<T> {
    /// Successfully decoded
    Ok(T, usize),
    /// Need more data
    NeedMoreData,
    /// Invalid data
    Invalid(&'static str),
}

impl Address {
    /// Encode address to buffer
    pub fn encode(&self, buf: &mut Vec<u8>) -> usize {
        match self {
            Address::IPv4(ip, port) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
                7
            }
            Address::IPv6(ip, port) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
                19
            }
            Address::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                buf.push(ATYP_DOMAIN);
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
                1 + 1 + domain_bytes.len() + 2
            }
        }
    }

    /// Get the port number
    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(_, port) | Address::IPv6(_, port) | Address::Domain(_, port) => *port,
        }
    }

    /// Get the host as a borrowed or owned string.
    ///
    /// Returns `Cow::Borrowed` for domains (zero allocation) and
    /// `Cow::Owned` for IP addresses (requires formatting).
    pub fn host(&self) -> Cow<'_, str> {
        match self {
            Address::IPv4(ip, _) => Cow::Owned(Ipv4Addr::from(*ip).to_string()),
            Address::IPv6(ip, _) => Cow::Owned(Ipv6Addr::from(*ip).to_string()),
            Address::Domain(domain, _) => Cow::Borrowed(domain),
        }
    }

    /// Decode address from buffer
    pub fn decode(buf: &[u8]) -> DecodeResult<Self> {
        if buf.is_empty() {
            return DecodeResult::NeedMoreData;
        }

        let atyp = buf[0];
        match atyp {
            ATYP_IPV4 => {
                // 1 (type) + 4 (ip) + 2 (port) = 7 bytes
                if buf.len() < 7 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[1..5]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                DecodeResult::Ok(Address::IPv4(ip, port), 7)
            }
            ATYP_IPV6 => {
                // 1 (type) + 16 (ip) + 2 (port) = 19 bytes
                if buf.len() < 19 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                DecodeResult::Ok(Address::IPv6(ip, port), 19)
            }
            ATYP_DOMAIN => {
                // 1 (type) + 1 (len) + len (domain) + 2 (port)
                if buf.len() < 2 {
                    return DecodeResult::NeedMoreData;
                }
                let domain_len = buf[1] as usize;
                let total_len = 1 + 1 + domain_len + 2;
                if buf.len() < total_len {
                    return DecodeResult::NeedMoreData;
                }
                let domain = match std::str::from_utf8(&buf[2..2 + domain_len]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return DecodeResult::Invalid("invalid domain encoding"),
                };
                let port = u16::from_be_bytes([buf[2 + domain_len], buf[3 + domain_len]]);
                DecodeResult::Ok(Address::Domain(domain, port), total_len)
            }
            _ => DecodeResult::Invalid("invalid address type"),
        }
    }

    /// Resolve to socket address
    pub async fn to_socket_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            Address::IPv4(ip, port) => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), *port)),
            Address::IPv6(ip, port) => Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), *port)),
            Address::Domain(domain, port) => {
                let addr_str = format!("{}:{}", domain, port);
                let mut addrs = lookup_host(&addr_str).await?;
                addrs.next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no addresses found for {}", domain),
                    )
                })
            }
        }
    }
}

/// Trojan protocol request
#[derive(Debug)]
pub struct TrojanRequest {
    /// Password (56 bytes, SHA224 hex encoded)
    pub password: [u8; 56],
    /// Command type
    pub cmd: TrojanCmd,
    /// Target address
    pub addr: Address,
    /// Initial payload (zero-copy)
    pub payload: Bytes,
}

impl TrojanRequest {
    /// Minimum request size: 56 (password) + 2 (CRLF) + 1 (cmd) + 7 (min addr) + 2 (CRLF) = 68
    pub const MIN_SIZE: usize = 68;

    /// Check if buffer contains a complete request without consuming it
    /// Returns Ok(header_len) if complete, Err for need more data or invalid
    pub fn check_complete(buf: &[u8]) -> Result<usize, Option<&'static str>> {
        if buf.len() < Self::MIN_SIZE {
            return Err(None); // Need more data
        }

        // Check first CRLF
        if buf[56] != b'\r' || buf[57] != b'\n' {
            return Err(Some("missing CRLF after password"));
        }

        // Validate command
        if TrojanCmd::try_from(buf[58]).is_err() {
            return Err(Some("invalid trojan command"));
        }

        // Check address length
        let addr_result = Address::decode(&buf[59..]);
        let addr_consumed = match addr_result {
            DecodeResult::Ok(_, consumed) => consumed,
            DecodeResult::NeedMoreData => return Err(None),
            DecodeResult::Invalid(msg) => return Err(Some(msg)),
        };

        let crlf_pos = 59 + addr_consumed;

        // Check second CRLF
        if buf.len() < crlf_pos + 2 {
            return Err(None);
        }
        if buf[crlf_pos] != b'\r' || buf[crlf_pos + 1] != b'\n' {
            return Err(Some("missing CRLF after address"));
        }

        Ok(crlf_pos + 2)
    }

    /// Decode trojan request from buffer (zero-copy for payload)
    ///
    /// Format: password(56) + CRLF + cmd(1) + address + CRLF + payload
    pub fn decode_zerocopy(buf: &mut BytesMut) -> DecodeResult<Self> {
        // Need at least minimum size
        if buf.len() < Self::MIN_SIZE {
            return DecodeResult::NeedMoreData;
        }

        // Parse password (56 bytes)
        let mut password = [0u8; 56];
        password.copy_from_slice(&buf[..56]);

        // Check first CRLF
        if buf[56] != b'\r' || buf[57] != b'\n' {
            log::debug!("Invalid CRLF after password");
            return DecodeResult::Invalid("missing CRLF after password");
        }

        // Parse command
        let cmd = match TrojanCmd::try_from(buf[58]) {
            Ok(cmd) => cmd,
            Err(msg) => return DecodeResult::Invalid(msg),
        };

        // Parse address
        let (addr, addr_consumed) = match Address::decode(&buf[59..]) {
            DecodeResult::Ok(addr, consumed) => (addr, consumed),
            DecodeResult::NeedMoreData => return DecodeResult::NeedMoreData,
            DecodeResult::Invalid(msg) => return DecodeResult::Invalid(msg),
        };

        let crlf_pos = 59 + addr_consumed;

        // Check second CRLF
        if buf.len() < crlf_pos + 2 {
            return DecodeResult::NeedMoreData;
        }
        if buf[crlf_pos] != b'\r' || buf[crlf_pos + 1] != b'\n' {
            return DecodeResult::Invalid("missing CRLF after address");
        }

        let header_len = crlf_pos + 2;

        // Split off the header, remaining is payload
        let _ = buf.split_to(header_len);
        let payload = buf.split().freeze();

        DecodeResult::Ok(
            TrojanRequest {
                password,
                cmd,
                addr,
                payload,
            },
            header_len,
        )
    }
}

/// Trojan UDP packet format (within TCP stream)
///
/// Format: ATYP + DST.ADDR + DST.PORT + Length(2 bytes) + CRLF + Payload
#[derive(Debug)]
pub struct TrojanUdpPacket {
    /// Target address
    pub addr: Address,
    /// UDP payload
    pub payload: Bytes,
}

impl TrojanUdpPacket {
    /// Minimum packet size: 1 (ATYP) + 4 (min addr) + 2 (port) + 2 (length) + 2 (CRLF) = 11
    pub const MIN_SIZE: usize = 11;

    /// Decode a single UDP packet from buffer
    ///
    /// Returns the decoded packet and consumed bytes count
    pub fn decode(buf: &[u8]) -> DecodeResult<Self> {
        if buf.len() < Self::MIN_SIZE {
            return DecodeResult::NeedMoreData;
        }

        // Parse address
        let (addr, addr_consumed) = match Address::decode(buf) {
            DecodeResult::Ok(addr, consumed) => (addr, consumed),
            DecodeResult::NeedMoreData => return DecodeResult::NeedMoreData,
            DecodeResult::Invalid(msg) => return DecodeResult::Invalid(msg),
        };

        let length_pos = addr_consumed;

        // Check if we have enough data for length + CRLF
        if buf.len() < length_pos + 4 {
            return DecodeResult::NeedMoreData;
        }

        // Parse payload length (2 bytes, big-endian)
        let payload_len = u16::from_be_bytes([buf[length_pos], buf[length_pos + 1]]) as usize;

        // Check CRLF after length
        if buf[length_pos + 2] != b'\r' || buf[length_pos + 3] != b'\n' {
            return DecodeResult::Invalid("missing CRLF after length");
        }

        let payload_start = length_pos + 4;
        let total_len = payload_start + payload_len;

        // Check if we have the complete payload
        if buf.len() < total_len {
            return DecodeResult::NeedMoreData;
        }

        let payload = Bytes::copy_from_slice(&buf[payload_start..total_len]);

        DecodeResult::Ok(TrojanUdpPacket { addr, payload }, total_len)
    }

    /// Encode a UDP packet to bytes
    pub fn encode(addr: &Address, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + payload.len());

        // Encode address
        addr.encode(&mut buf);

        // Add length (2 bytes, big-endian)
        let payload_len = payload.len() as u16;
        buf.extend_from_slice(&payload_len.to_be_bytes());

        // Add CRLF
        buf.extend_from_slice(b"\r\n");

        // Add payload
        buf.extend_from_slice(payload);

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn test_trojan_cmd_try_from() {
        assert_eq!(TrojanCmd::try_from(1), Ok(TrojanCmd::Connect));
        assert_eq!(TrojanCmd::try_from(3), Ok(TrojanCmd::UdpAssociate));
        assert!(TrojanCmd::try_from(0).is_err());
        assert!(TrojanCmd::try_from(2).is_err());
        assert!(TrojanCmd::try_from(4).is_err());
    }

    #[test]
    fn test_address_decode_ipv4() {
        let buf = [1, 192, 168, 1, 1, 0x1F, 0x90]; // 192.168.1.1:8080
        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 7);
                assert!(matches!(addr, Address::IPv4([192, 168, 1, 1], 8080)));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_address_decode_ipv6() {
        let mut buf = vec![4]; // ATYP_IPV6
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        buf.extend_from_slice(&[0x01, 0xBB]); // port 443

        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 19);
                assert!(matches!(addr, Address::IPv6(_, 443)));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_address_decode_domain() {
        let mut buf = vec![3, 11]; // ATYP_DOMAIN, length
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&[0x00, 0x50]); // port 80

        match Address::decode(&buf) {
            DecodeResult::Ok(addr, consumed) => {
                assert_eq!(consumed, 15);
                assert!(matches!(addr, Address::Domain(ref d, 80) if d == "example.com"));
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_address_decode_need_more_data() {
        let buf = [1, 192, 168]; // Incomplete IPv4
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));

        let buf = [4, 0, 0, 0]; // Incomplete IPv6
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));

        let buf = [3, 11, b'e', b'x']; // Incomplete domain
        assert!(matches!(Address::decode(&buf), DecodeResult::NeedMoreData));
    }

    #[test]
    fn test_address_decode_invalid() {
        let buf = [99, 0, 0, 0, 0, 0, 0]; // Invalid ATYP
        assert!(matches!(Address::decode(&buf), DecodeResult::Invalid(_)));
    }

    #[test]
    fn test_address_display() {
        let ipv4 = Address::IPv4([192, 168, 1, 1], 8080);
        assert_eq!(format!("{}", ipv4), "192.168.1.1:8080");

        let ipv6 = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        assert_eq!(format!("{}", ipv6), "[::1]:443");

        let domain = Address::Domain("example.com".to_string(), 80);
        assert_eq!(format!("{}", domain), "example.com:80");
    }

    #[test]
    fn test_trojan_request_decode_connect() {
        let mut buf = BytesMut::new();

        // Password (56 bytes)
        buf.extend_from_slice(&[b'a'; 56]);
        // CRLF
        buf.extend_from_slice(b"\r\n");
        // Command (CONNECT)
        buf.put_u8(1);
        // Address (IPv4)
        buf.extend_from_slice(&[1, 127, 0, 0, 1, 0x1F, 0x90]); // 127.0.0.1:8080
                                                               // CRLF
        buf.extend_from_slice(b"\r\n");
        // Payload
        buf.extend_from_slice(b"hello");

        match TrojanRequest::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(req, _) => {
                assert_eq!(req.password, [b'a'; 56]);
                assert_eq!(req.cmd, TrojanCmd::Connect);
                assert!(matches!(req.addr, Address::IPv4([127, 0, 0, 1], 8080)));
                assert_eq!(req.payload.as_ref(), b"hello");
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_trojan_request_decode_udp_associate() {
        let mut buf = BytesMut::new();

        // Password
        buf.extend_from_slice(&[b'x'; 56]);
        // CRLF
        buf.extend_from_slice(b"\r\n");
        // Command (UDP_ASSOCIATE)
        buf.put_u8(3);
        // Address (domain)
        buf.extend_from_slice(&[3, 7]); // ATYP_DOMAIN, length
        buf.extend_from_slice(b"udp.com");
        buf.extend_from_slice(&[0x00, 0x35]); // port 53
                                              // CRLF
        buf.extend_from_slice(b"\r\n");

        match TrojanRequest::decode_zerocopy(&mut buf) {
            DecodeResult::Ok(req, _) => {
                assert_eq!(req.cmd, TrojanCmd::UdpAssociate);
                assert!(matches!(req.addr, Address::Domain(ref d, 53) if d == "udp.com"));
                assert!(req.payload.is_empty());
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_trojan_request_decode_need_more_data() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[b'a'; 50]); // Incomplete password

        assert!(matches!(
            TrojanRequest::decode_zerocopy(&mut buf),
            DecodeResult::NeedMoreData
        ));
    }

    #[test]
    fn test_trojan_request_decode_invalid_crlf() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[b'a'; 56]);
        buf.extend_from_slice(b"\n\r"); // Wrong order
                                        // Add padding to meet MIN_SIZE
        buf.extend_from_slice(&[0u8; 20]);

        assert!(matches!(
            TrojanRequest::decode_zerocopy(&mut buf),
            DecodeResult::Invalid(_)
        ));
    }

    #[test]
    fn test_trojan_request_decode_invalid_command() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[b'a'; 56]);
        buf.extend_from_slice(b"\r\n");
        buf.put_u8(99); // Invalid command
                        // Add padding to meet MIN_SIZE (need at least 68 bytes total)
        buf.extend_from_slice(&[0u8; 20]);

        assert!(matches!(
            TrojanRequest::decode_zerocopy(&mut buf),
            DecodeResult::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn test_address_to_socket_addr_ipv4() {
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let socket_addr = addr.to_socket_addr().await.unwrap();
        assert_eq!(socket_addr.to_string(), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn test_address_to_socket_addr_ipv6() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        let socket_addr = addr.to_socket_addr().await.unwrap();
        assert_eq!(socket_addr.to_string(), "[::1]:443");
    }

    #[tokio::test]
    async fn test_address_to_socket_addr_domain() {
        let addr = Address::Domain("localhost".to_string(), 80);
        let result = addr.to_socket_addr().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_address_to_socket_addr_domain_resolution() {
        // Test with an empty domain which should fail
        let addr = Address::Domain("".to_string(), 80);
        let result = addr.to_socket_addr().await;
        // Empty domain should fail to resolve
        assert!(result.is_err());
    }

    // Tests for Address helper methods

    #[test]
    fn test_address_host_ipv4() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        assert_eq!(addr.host(), "192.168.1.1");
    }

    #[test]
    fn test_address_host_ipv6() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        assert_eq!(addr.host(), "::1");
    }

    #[test]
    fn test_address_host_domain() {
        let addr = Address::Domain("example.com".to_string(), 80);
        assert_eq!(addr.host(), "example.com");
    }

    #[test]
    fn test_address_port() {
        let ipv4 = Address::IPv4([127, 0, 0, 1], 8080);
        assert_eq!(ipv4.port(), 8080);

        let ipv6 = Address::IPv6([0; 16], 443);
        assert_eq!(ipv6.port(), 443);

        let domain = Address::Domain("test.com".to_string(), 53);
        assert_eq!(domain.port(), 53);
    }

    #[test]
    fn test_address_encode_ipv4() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        let mut buf = Vec::new();
        let len = addr.encode(&mut buf);
        assert_eq!(len, 7);
        assert_eq!(buf, vec![1, 192, 168, 1, 1, 0x1F, 0x90]);
    }

    #[test]
    fn test_address_encode_ipv6() {
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443);
        let mut buf = Vec::new();
        let len = addr.encode(&mut buf);
        assert_eq!(len, 19);
        assert_eq!(buf[0], 4); // ATYP_IPV6
        assert_eq!(
            &buf[1..17],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(&buf[17..19], &[0x01, 0xBB]); // port 443
    }

    #[test]
    fn test_address_encode_domain() {
        let addr = Address::Domain("test.com".to_string(), 80);
        let mut buf = Vec::new();
        let len = addr.encode(&mut buf);
        assert_eq!(len, 1 + 1 + 8 + 2); // ATYP + len + domain + port
        assert_eq!(buf[0], 3); // ATYP_DOMAIN
        assert_eq!(buf[1], 8); // domain length
        assert_eq!(&buf[2..10], b"test.com");
        assert_eq!(&buf[10..12], &[0x00, 0x50]); // port 80
    }

    /// Verify that host() returns Cow::Borrowed for domains (zero allocation)
    /// and Cow::Owned for IP addresses.
    #[test]
    fn test_address_host_cow_borrowing() {
        use std::borrow::Cow;

        // Domain: should be Cow::Borrowed (no heap allocation)
        let domain = Address::Domain("example.com".to_string(), 80);
        let host = domain.host();
        assert!(
            matches!(host, Cow::Borrowed(_)),
            "Domain host should be Cow::Borrowed"
        );

        // IPv4: must be Cow::Owned (requires formatting)
        let ipv4 = Address::IPv4([10, 0, 0, 1], 80);
        let host = ipv4.host();
        assert!(
            matches!(host, Cow::Owned(_)),
            "IPv4 host should be Cow::Owned"
        );

        // IPv6: must be Cow::Owned (requires formatting)
        let ipv6 = Address::IPv6([0; 16], 443);
        let host = ipv6.host();
        assert!(
            matches!(host, Cow::Owned(_)),
            "IPv6 host should be Cow::Owned"
        );
    }

    /// Verify that host().into_owned() works for AclAddr construction
    #[test]
    fn test_address_host_into_owned() {
        let domain = Address::Domain("test.com".to_string(), 443);
        let owned: String = domain.host().into_owned();
        assert_eq!(owned, "test.com");

        let ipv4 = Address::IPv4([8, 8, 8, 8], 53);
        let owned: String = ipv4.host().into_owned();
        assert_eq!(owned, "8.8.8.8");
    }

    #[test]
    fn test_address_encode_decode_roundtrip() {
        let original = Address::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        original.encode(&mut buf);

        match Address::decode(&buf) {
            DecodeResult::Ok(decoded, _) => {
                assert_eq!(decoded, original);
            }
            _ => panic!("Failed to decode"),
        }
    }

    // Tests for TrojanUdpPacket

    #[test]
    fn test_trojan_udp_packet_decode_ipv4() {
        let mut buf = Vec::new();
        // IPv4 address: 8.8.8.8:53
        buf.push(1); // ATYP_IPV4
        buf.extend_from_slice(&[8, 8, 8, 8]);
        buf.extend_from_slice(&[0x00, 0x35]); // port 53
        buf.extend_from_slice(&[0x00, 0x05]); // length: 5 bytes
        buf.extend_from_slice(b"\r\n"); // CRLF
        buf.extend_from_slice(b"hello"); // Payload

        match TrojanUdpPacket::decode(&buf) {
            DecodeResult::Ok(packet, consumed) => {
                assert_eq!(consumed, 7 + 2 + 2 + 5); // addr + length + crlf + payload
                assert!(matches!(packet.addr, Address::IPv4([8, 8, 8, 8], 53)));
                assert_eq!(packet.payload.as_ref(), b"hello");
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_trojan_udp_packet_decode_domain() {
        let mut buf = Vec::new();
        // Domain address: dns.google:53
        buf.push(3); // ATYP_DOMAIN
        buf.push(10); // domain length
        buf.extend_from_slice(b"dns.google");
        buf.extend_from_slice(&[0x00, 0x35]); // port 53
        buf.extend_from_slice(&[0x00, 0x04]); // length: 4 bytes
        buf.extend_from_slice(b"\r\n"); // CRLF
        buf.extend_from_slice(b"test"); // Payload

        match TrojanUdpPacket::decode(&buf) {
            DecodeResult::Ok(packet, consumed) => {
                assert_eq!(consumed, 1 + 1 + 10 + 2 + 2 + 2 + 4);
                assert!(matches!(packet.addr, Address::Domain(ref d, 53) if d == "dns.google"));
                assert_eq!(packet.payload.as_ref(), b"test");
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_trojan_udp_packet_decode_need_more_data() {
        // Too short
        let buf = vec![1, 8, 8, 8, 8];
        assert!(matches!(
            TrojanUdpPacket::decode(&buf),
            DecodeResult::NeedMoreData
        ));

        // Missing payload
        let mut buf = Vec::new();
        buf.push(1);
        buf.extend_from_slice(&[8, 8, 8, 8]);
        buf.extend_from_slice(&[0x00, 0x35]);
        buf.extend_from_slice(&[0x00, 0x10]); // claims 16 bytes payload
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(b"short"); // only 5 bytes

        assert!(matches!(
            TrojanUdpPacket::decode(&buf),
            DecodeResult::NeedMoreData
        ));
    }

    #[test]
    fn test_trojan_udp_packet_decode_invalid_crlf() {
        let mut buf = Vec::new();
        buf.push(1);
        buf.extend_from_slice(&[8, 8, 8, 8]);
        buf.extend_from_slice(&[0x00, 0x35]);
        buf.extend_from_slice(&[0x00, 0x05]);
        buf.extend_from_slice(b"\n\r"); // Wrong order
        buf.extend_from_slice(b"hello");

        assert!(matches!(
            TrojanUdpPacket::decode(&buf),
            DecodeResult::Invalid(_)
        ));
    }

    #[test]
    fn test_trojan_udp_packet_encode() {
        let addr = Address::IPv4([8, 8, 8, 8], 53);
        let payload = b"hello";
        let encoded = TrojanUdpPacket::encode(&addr, payload);

        // Verify structure: addr(7) + length(2) + crlf(2) + payload(5) = 16
        assert_eq!(encoded.len(), 16);
        assert_eq!(&encoded[0..7], &[1, 8, 8, 8, 8, 0x00, 0x35]);
        assert_eq!(&encoded[7..9], &[0x00, 0x05]); // length
        assert_eq!(&encoded[9..11], b"\r\n");
        assert_eq!(&encoded[11..16], b"hello");
    }

    #[test]
    fn test_trojan_udp_packet_encode_decode_roundtrip() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let payload = b"test payload data";

        let encoded = TrojanUdpPacket::encode(&addr, payload);

        match TrojanUdpPacket::decode(&encoded) {
            DecodeResult::Ok(packet, consumed) => {
                assert_eq!(consumed, encoded.len());
                assert_eq!(packet.addr, addr);
                assert_eq!(packet.payload.as_ref(), payload);
            }
            _ => panic!("Failed to decode"),
        }
    }

    #[test]
    fn test_trojan_udp_packet_empty_payload() {
        let addr = Address::IPv4([1, 2, 3, 4], 80);
        let payload: &[u8] = &[];

        let encoded = TrojanUdpPacket::encode(&addr, payload);

        match TrojanUdpPacket::decode(&encoded) {
            DecodeResult::Ok(packet, _) => {
                assert!(packet.payload.is_empty());
            }
            _ => panic!("Failed to decode"),
        }
    }

    #[test]
    fn test_trojan_udp_packet_large_payload() {
        let addr = Address::IPv4([1, 2, 3, 4], 80);
        let payload = vec![0xAB; 1000];

        let encoded = TrojanUdpPacket::encode(&addr, &payload);

        match TrojanUdpPacket::decode(&encoded) {
            DecodeResult::Ok(packet, _) => {
                assert_eq!(packet.payload.len(), 1000);
                assert!(packet.payload.iter().all(|&b| b == 0xAB));
            }
            _ => panic!("Failed to decode"),
        }
    }
}
