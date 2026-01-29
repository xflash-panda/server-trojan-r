use crate::address;
use crate::logger::log;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use anyhow::Result;
use bytes::{Bytes, BytesMut};

const UDP_TIMEOUT: u64 = 60; // UDP association timeout in seconds;
const BUF_SIZE: usize = 4 * 1024;
const UDP_CHANNEL_BUFFER_SIZE: usize = 64;
const TCP_WRITE_CHANNEL_BUFFER_SIZE: usize = 256;
const CLEANUP_TIMEOUT_SECS: u64 = 5;

// UDP Association info
#[derive(Debug, Clone)]
pub struct UdpAssociation {
    pub socket: Arc<UdpSocket>,
    last_activity: Arc<Mutex<Instant>>,
    created_at: Instant,
}

impl UdpAssociation {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            created_at: Instant::now(),
        }
    }
    
    #[inline]
    pub async fn update_activity(&self) {
        *self.last_activity.lock().await = Instant::now();
    }
    
    pub async fn is_inactive(&self, timeout_secs: u64) -> bool {
        let last_activity = *self.last_activity.lock().await;
        last_activity.elapsed().as_secs() > timeout_secs
    }
    
    #[inline]
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

// UDP Packet for Trojan UDP Associate
#[derive(Debug)]
pub struct UdpPacket {
    pub addr: address::Address,
    pub length: u16,
    pub payload: Bytes,
}

#[derive(Debug)]
pub enum DecodeResult {
    Ok(UdpPacket, usize),
    NeedMoreData,
    Invalid,
}

impl UdpPacket {
    pub fn decode(buf: &[u8]) -> DecodeResult {
        if buf.len() < 4 {
            return DecodeResult::NeedMoreData;
        }

        let mut cursor = 0;
        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => { // IPv4
                if buf.len() < cursor + 6 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::IPv4(ip, port)
            }
            3 => { // Domain
                if buf.len() <= cursor {
                    return DecodeResult::NeedMoreData;
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len + 2 {
                    return DecodeResult::NeedMoreData;
                }
                let domain = match std::str::from_utf8(&buf[cursor..cursor + domain_len]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return DecodeResult::Invalid,
                };
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::Domain(domain, port)
            }
            4 => { // IPv6
                if buf.len() < cursor + 18 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::IPv6(ip, port)
            }
            _ => return DecodeResult::Invalid,
        };

        // Read length
        if buf.len() < cursor + 2 {
            return DecodeResult::NeedMoreData;
        }
        let length = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;

        // Read CRLF
        if buf.len() < cursor + 2 {
            return DecodeResult::NeedMoreData;
        }
        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return DecodeResult::Invalid;
        }
        cursor += 2;

        if buf.len() < cursor + length as usize {
            return DecodeResult::NeedMoreData;
        }
        let payload = Bytes::copy_from_slice(&buf[cursor..cursor + length as usize]);
        cursor += length as usize;

        DecodeResult::Ok(UdpPacket {
            addr,
            length,
            payload,
        }, cursor)
    }

    pub fn encode(&self) -> Vec<u8> {
        let addr_size = match &self.addr {
            address::Address::IPv4(_, _) => 1 + 4 + 2, // type + ip + port
            address::Address::Domain(domain, _) => 1 + 1 + domain.len() + 2, // type + len + domain + port
            address::Address::IPv6(_, _) => 1 + 16 + 2, // type + ip + port
        };
        let total_size = addr_size + 2 + 2 + self.payload.len(); // addr + length + CRLF + payload
        
        let mut buf = Vec::with_capacity(total_size);

        match &self.addr {
            address::Address::IPv4(ip, port) => {
                buf.push(1); // IPv4
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            address::Address::Domain(domain, port) => {
                buf.push(3); // Domain
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            address::Address::IPv6(ip, port) => {
                buf.push(4); // IPv6
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.payload);

        buf
    }
}

// UDP清理任务，定期清理不活跃的UDP association
pub fn start_cleanup_task(
    associations: Arc<Mutex<HashMap<String, UdpAssociation>>>
) {
    tokio::spawn(async move {
        const CLEANUP_INTERVAL_SECS: u64 = UDP_TIMEOUT / 2;
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECS)
        );
        interval.tick().await;
        
        loop {
            interval.tick().await;
            
            let associations_to_check: Vec<(String, UdpAssociation)> = {
                let assocs = associations.lock().await;
                assocs.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            };
            
            let mut keys_to_remove = Vec::new();
            for (key, association) in associations_to_check {
                if association.is_inactive(UDP_TIMEOUT).await {
                    keys_to_remove.push(key);
                }
            }
            
            if !keys_to_remove.is_empty() {
                let mut assocs = associations.lock().await;
                let removed_count = keys_to_remove.len();
                for key in keys_to_remove {
                    assocs.remove(&key);
                }
                log::debug!(
                    removed = removed_count,
                    remaining = assocs.len(),
                    "Cleaned up inactive UDP associations"
                );
            }
        }
    });
}

// 处理 UDP Associate 请求
pub async fn handle_udp_associate<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    client_stream: S,
    _bind_addr: address::Address,
    peer_addr: String,
) -> Result<()> {
    log::info!(peer = %peer_addr, "Starting UDP associate");
    
    // 生成唯一的socket key
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let socket_key = format!("client_{}_{}", peer_addr, id);
    
    let udp_association = {
        let bind_socket_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 
            0
        );
        let socket = UdpSocket::bind(bind_socket_addr).await?;
        let association = UdpAssociation::new(socket);
        
        let mut associations = udp_associations.lock().await;
        associations.insert(socket_key.clone(), association.clone());
        association
    };

    let (mut client_read, client_write) = tokio::io::split(client_stream);
    
    let (udp_tx, mut udp_rx) = mpsc::channel::<(SocketAddr, Bytes)>(UDP_CHANNEL_BUFFER_SIZE);
    let (tcp_write_tx, mut tcp_write_rx) = mpsc::channel::<Vec<u8>>(TCP_WRITE_CHANNEL_BUFFER_SIZE);
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&udp_association.socket);
    let association_clone = udp_association.clone();
    
    let udp_recv_handle = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(BUF_SIZE);
        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    break;
                }
                result = {
                    buf.clear();
                    if buf.capacity() < BUF_SIZE {
                        buf.reserve(BUF_SIZE - buf.capacity());
                    }
                    buf.resize(BUF_SIZE, 0);
                    socket_clone.recv_from(&mut buf[..])
                } => {
                    match result {
                        Ok((len, from_addr)) => {
                            association_clone.update_activity().await;
                            
                            buf.truncate(len);
                            
                            let data = buf.split_to(len).freeze();
                            
                            match udp_tx.try_send((from_addr, data)) {
                                Ok(_) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    log::debug!("UDP channel full, dropping packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break;
                                }
                            }
                            
                            if buf.capacity() > BUF_SIZE * 2 {
                                buf = BytesMut::with_capacity(BUF_SIZE);
                            }
                        }
                        Err(e) => {
                            log::debug!("UDP socket recv error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });
    
    let peer_addr_for_write = peer_addr.clone();
    let tcp_write_handle = tokio::spawn(async move {
        let mut client_write = client_write;
        while let Some(encoded) = tcp_write_rx.recv().await {
            let mut written = 0;
            while written < encoded.len() {
                match client_write.write(&encoded[written..]).await {
                    Ok(0) => {
                        log::debug!(peer = %peer_addr_for_write, "TCP connection closed while writing UDP response, dropping UDP");
                        return;
                    }
                    Ok(n) => {
                        written += n;
                    }
                    Err(e) => {
                        log::debug!(peer = %peer_addr_for_write, error = %e, "Error writing UDP response to client, dropping UDP");
                        return;
                    }
                }
            }
        }
    });

    let result = async {
        let mut read_buf = vec![0u8; BUF_SIZE];
        let mut buffer = BytesMut::with_capacity(BUF_SIZE);
        'main_loop: loop {
            tokio::select! {
                read_result = client_read.read(&mut read_buf) => {
                    match read_result {
                        Ok(0) => {
                            break 'main_loop;
                        }
                        Ok(n) => {
                            buffer.extend_from_slice(&read_buf[..n]);
                            
                            loop {
                                match UdpPacket::decode(&buffer) {
                                    DecodeResult::Ok(udp_packet, consumed) => {
                                        let _ = buffer.split_to(consumed);
                                        
                                        udp_association.update_activity().await;
                                        
                                        match udp_packet.addr.to_socket_addr().await {
                                            Ok(remote_addr) => {
                                                if let Err(e) = udp_association.socket
                                                    .send_to(&udp_packet.payload, remote_addr).await {
                                                    log::debug!(peer = %peer_addr, error = %e, "Failed to send UDP packet");
                                                }
                                            }
                                            Err(e) => {
                                                log::debug!(peer = %peer_addr, error = %e, "Failed to resolve UDP target address");
                                            }
                                        }
                                    }
                                    DecodeResult::NeedMoreData => {
                                        break;
                                    }
                                    DecodeResult::Invalid => {
                                        log::debug!(peer = %peer_addr, "Invalid UDP packet, closing connection");
                                        break 'main_loop;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log::debug!(peer = %peer_addr, error = %e, "Error reading from client stream");
                            break 'main_loop;
                        }
                    }
                }
                
                packet = udp_rx.recv() => {
                    match packet {
                        Some((from_addr, data)) => {
                            let addr = match from_addr {
                                SocketAddr::V4(v4) => address::Address::IPv4(v4.ip().octets(), v4.port()),
                                SocketAddr::V6(v6) => address::Address::IPv6(v6.ip().octets(), v6.port()),
                            };
                            
                            let udp_packet = UdpPacket {
                                addr,
                                length: data.len() as u16,
                                payload: data,
                            };
                            
                            let encoded = udp_packet.encode();
                            match tcp_write_tx.try_send(encoded) {
                                Ok(_) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    log::debug!(peer = %peer_addr, "TCP write channel full, dropping packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break 'main_loop;
                                }
                            }
                        }
                        None => {
                            break 'main_loop;
                        }
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;

    drop(tcp_write_tx);
    
    let _ = cancel_tx.send(());
    
    match tokio::time::timeout(
        std::time::Duration::from_secs(CLEANUP_TIMEOUT_SECS),
        tcp_write_handle
    ).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            log::warn!(peer = %peer_addr, error = %e, "TCP write task ended with error");
        }
        Err(_) => {
            log::warn!(
                peer = %peer_addr,
                timeout_secs = CLEANUP_TIMEOUT_SECS,
                "TCP write task cleanup timeout"
            );
        }
    }
    
    match tokio::time::timeout(
        std::time::Duration::from_secs(CLEANUP_TIMEOUT_SECS),
        udp_recv_handle
    ).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            log::warn!(peer = %peer_addr, error = %e, "UDP receive task ended with error");
        }
        Err(_) => {
            log::warn!(
                peer = %peer_addr,
                timeout_secs = CLEANUP_TIMEOUT_SECS,
                "UDP receive task cleanup timeout"
            );
        }
    }
    
    {
        let mut associations = udp_associations.lock().await;
        associations.remove(&socket_key);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_udp_packet_encode_ipv4() {
        let packet = UdpPacket {
            addr: address::Address::IPv4([192, 168, 1, 1], 8080),
            length: 5,
            payload: Bytes::from_static(b"hello"),
        };

        let encoded = packet.encode();

        // Verify structure: type(1) + ip(4) + port(2) + length(2) + CRLF(2) + payload(5)
        assert_eq!(encoded.len(), 1 + 4 + 2 + 2 + 2 + 5);
        assert_eq!(encoded[0], 1); // IPv4 type
        assert_eq!(&encoded[1..5], &[192, 168, 1, 1]); // IP
        assert_eq!(u16::from_be_bytes([encoded[5], encoded[6]]), 8080); // Port
        assert_eq!(u16::from_be_bytes([encoded[7], encoded[8]]), 5); // Length
        assert_eq!(&encoded[9..11], b"\r\n"); // CRLF
        assert_eq!(&encoded[11..], b"hello"); // Payload
    }

    #[test]
    fn test_udp_packet_encode_ipv6() {
        let ip = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let packet = UdpPacket {
            addr: address::Address::IPv6(ip, 443),
            length: 4,
            payload: Bytes::from_static(b"test"),
        };

        let encoded = packet.encode();

        // Verify structure: type(1) + ip(16) + port(2) + length(2) + CRLF(2) + payload(4)
        assert_eq!(encoded.len(), 1 + 16 + 2 + 2 + 2 + 4);
        assert_eq!(encoded[0], 4); // IPv6 type
        assert_eq!(&encoded[1..17], &ip); // IP
    }

    #[test]
    fn test_udp_packet_encode_domain() {
        let packet = UdpPacket {
            addr: address::Address::Domain("example.com".to_string(), 80),
            length: 4,
            payload: Bytes::from_static(b"data"),
        };

        let encoded = packet.encode();

        // Verify structure: type(1) + len(1) + domain(11) + port(2) + length(2) + CRLF(2) + payload(4)
        assert_eq!(encoded.len(), 1 + 1 + 11 + 2 + 2 + 2 + 4);
        assert_eq!(encoded[0], 3); // Domain type
        assert_eq!(encoded[1], 11); // Domain length
        assert_eq!(&encoded[2..13], b"example.com"); // Domain
    }

    #[test]
    fn test_udp_packet_decode_ipv4() {
        let mut buf = Vec::new();
        buf.push(1); // IPv4
        buf.extend_from_slice(&[127, 0, 0, 1]); // IP
        buf.extend_from_slice(&8080u16.to_be_bytes()); // Port
        buf.extend_from_slice(&5u16.to_be_bytes()); // Length
        buf.extend_from_slice(b"\r\n"); // CRLF
        buf.extend_from_slice(b"hello"); // Payload

        match UdpPacket::decode(&buf) {
            DecodeResult::Ok(packet, consumed) => {
                assert_eq!(consumed, buf.len());
                assert_eq!(packet.length, 5);
                assert_eq!(packet.payload.as_ref(), b"hello");
                match packet.addr {
                    address::Address::IPv4(ip, port) => {
                        assert_eq!(ip, [127, 0, 0, 1]);
                        assert_eq!(port, 8080);
                    }
                    _ => panic!("Expected IPv4 address"),
                }
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_udp_packet_decode_ipv6() {
        let ip = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut buf = Vec::new();
        buf.push(4); // IPv6
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(b"test");

        match UdpPacket::decode(&buf) {
            DecodeResult::Ok(packet, _) => {
                match packet.addr {
                    address::Address::IPv6(decoded_ip, port) => {
                        assert_eq!(decoded_ip, ip);
                        assert_eq!(port, 443);
                    }
                    _ => panic!("Expected IPv6 address"),
                }
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_udp_packet_decode_domain() {
        let mut buf = Vec::new();
        buf.push(3); // Domain
        buf.push(11); // Domain length
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&80u16.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(b"data");

        match UdpPacket::decode(&buf) {
            DecodeResult::Ok(packet, _) => {
                match packet.addr {
                    address::Address::Domain(domain, port) => {
                        assert_eq!(domain, "example.com");
                        assert_eq!(port, 80);
                    }
                    _ => panic!("Expected Domain address"),
                }
            }
            _ => panic!("Expected successful decode"),
        }
    }

    #[test]
    fn test_udp_packet_decode_need_more_data_short() {
        let buf = [1, 127, 0]; // Too short
        match UdpPacket::decode(&buf) {
            DecodeResult::NeedMoreData => {}
            _ => panic!("Expected NeedMoreData"),
        }
    }

    #[test]
    fn test_udp_packet_decode_need_more_data_incomplete_payload() {
        let mut buf = Vec::new();
        buf.push(1);
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&8080u16.to_be_bytes());
        buf.extend_from_slice(&100u16.to_be_bytes()); // Claim 100 bytes payload
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(b"short"); // Only 5 bytes

        match UdpPacket::decode(&buf) {
            DecodeResult::NeedMoreData => {}
            _ => panic!("Expected NeedMoreData"),
        }
    }

    #[test]
    fn test_udp_packet_decode_invalid_type() {
        let buf = [99, 0, 0, 0, 0]; // Invalid address type
        match UdpPacket::decode(&buf) {
            DecodeResult::Invalid => {}
            _ => panic!("Expected Invalid"),
        }
    }

    #[test]
    fn test_udp_packet_decode_invalid_crlf() {
        let mut buf = Vec::new();
        buf.push(1);
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&8080u16.to_be_bytes());
        buf.extend_from_slice(&5u16.to_be_bytes());
        buf.extend_from_slice(b"\n\r"); // Wrong order
        buf.extend_from_slice(b"hello");

        match UdpPacket::decode(&buf) {
            DecodeResult::Invalid => {}
            _ => panic!("Expected Invalid due to wrong CRLF"),
        }
    }

    #[test]
    fn test_udp_packet_encode_decode_roundtrip() {
        let original = UdpPacket {
            addr: address::Address::Domain("test.example.org".to_string(), 12345),
            length: 11,
            payload: Bytes::from_static(b"hello world"),
        };

        let encoded = original.encode();
        match UdpPacket::decode(&encoded) {
            DecodeResult::Ok(decoded, consumed) => {
                assert_eq!(consumed, encoded.len());
                assert_eq!(decoded.length, original.length);
                assert_eq!(decoded.payload, original.payload);
                match (original.addr, decoded.addr) {
                    (address::Address::Domain(d1, p1), address::Address::Domain(d2, p2)) => {
                        assert_eq!(d1, d2);
                        assert_eq!(p1, p2);
                    }
                    _ => panic!("Address type mismatch"),
                }
            }
            _ => panic!("Roundtrip decode failed"),
        }
    }

    #[test]
    fn test_udp_packet_empty_payload() {
        let packet = UdpPacket {
            addr: address::Address::IPv4([10, 0, 0, 1], 53),
            length: 0,
            payload: Bytes::new(),
        };

        let encoded = packet.encode();
        match UdpPacket::decode(&encoded) {
            DecodeResult::Ok(decoded, _) => {
                assert_eq!(decoded.length, 0);
                assert!(decoded.payload.is_empty());
            }
            _ => panic!("Failed to decode empty payload packet"),
        }
    }

    #[tokio::test]
    async fn test_udp_association_new() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let association = UdpAssociation::new(socket);
        assert!(!association.is_inactive(60).await);
    }

    #[tokio::test]
    async fn test_udp_association_update_activity() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let association = UdpAssociation::new(socket);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        association.update_activity().await;
        assert!(!association.is_inactive(1).await);
    }

    #[test]
    fn test_udp_association_age() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let association = UdpAssociation::new(socket);
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            assert!(association.age().as_millis() >= 50);
        });
    }
}