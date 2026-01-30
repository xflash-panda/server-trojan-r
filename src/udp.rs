use crate::acl::{AclEngine, Protocol};
use crate::address::{self, Address};
use crate::logger::log;
use crate::stats::UserStats;

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

const UDP_TIMEOUT: u64 = 60; // UDP association timeout in seconds;
const BUF_SIZE: usize = 4 * 1024;
const UDP_CHANNEL_BUFFER_SIZE: usize = 64;
const TCP_WRITE_CHANNEL_BUFFER_SIZE: usize = 256;
const CLEANUP_TIMEOUT_SECS: u64 = 5;

// UDP Association info
#[derive(Debug, Clone)]
pub struct UdpAssociation {
    pub socket: Arc<UdpSocket>,
    /// Stores elapsed seconds from created_at for last activity
    last_activity_secs: Arc<AtomicU64>,
    created_at: Instant,
}

impl UdpAssociation {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            last_activity_secs: Arc::new(AtomicU64::new(0)),
            created_at: Instant::now(),
        }
    }

    /// Update the last activity timestamp (lock-free)
    #[inline]
    pub fn update_activity(&self) {
        self.last_activity_secs
            .store(self.created_at.elapsed().as_secs(), Ordering::Release);
    }

    /// Check if the association is inactive (lock-free)
    pub fn is_inactive(&self, timeout_secs: u64) -> bool {
        let last_activity_secs = self.last_activity_secs.load(Ordering::Acquire);
        let current_secs = self.created_at.elapsed().as_secs();
        current_secs.saturating_sub(last_activity_secs) > timeout_secs
    }

    #[inline]
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

/// UDP Packet for Trojan UDP Associate
///
/// Format: Address + Length(2) + CRLF(2) + Payload
#[derive(Debug)]
pub struct UdpPacket {
    pub addr: Address,
    pub payload: Bytes,
}

/// UDP packet decode result
#[derive(Debug)]
pub enum DecodeResult {
    Ok(UdpPacket, usize),
    NeedMoreData,
    Invalid(&'static str),
}

impl UdpPacket {
    /// Create a new UDP packet
    pub fn new(addr: Address, payload: Bytes) -> Self {
        Self { addr, payload }
    }

    /// Decode UDP packet from buffer
    ///
    /// Format: Address + Length(2 bytes) + CRLF + Payload
    pub fn decode(buf: &[u8]) -> DecodeResult {
        // Decode address first
        let (addr, mut cursor) = match Address::decode(buf) {
            address::DecodeResult::Ok(addr, consumed) => (addr, consumed),
            address::DecodeResult::NeedMoreData => return DecodeResult::NeedMoreData,
            address::DecodeResult::Invalid(msg) => return DecodeResult::Invalid(msg),
        };

        // Read length (2 bytes)
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
            return DecodeResult::Invalid("missing CRLF");
        }
        cursor += 2;

        // Read payload
        if buf.len() < cursor + length as usize {
            return DecodeResult::NeedMoreData;
        }
        let payload = Bytes::copy_from_slice(&buf[cursor..cursor + length as usize]);
        cursor += length as usize;

        DecodeResult::Ok(UdpPacket { addr, payload }, cursor)
    }

    /// Encode UDP packet to bytes (allocates new Vec)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_size());
        self.encode_into(&mut buf);
        buf
    }

    /// Encode UDP packet into existing buffer (zero allocation if buffer has capacity)
    #[inline]
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.clear();
        buf.reserve(self.encoded_size());

        // Encode address
        self.addr.encode(buf);

        // Encode length + CRLF + payload
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.payload);
    }

    /// Get the total encoded size in bytes
    #[inline]
    pub fn encoded_size(&self) -> usize {
        self.addr.encoded_size() + 2 + 2 + self.payload.len()
    }

    /// Get payload length
    #[inline]
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Check if payload is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Type alias for UDP associations map using DashMap for lock-free concurrent access
pub type UdpAssociations = Arc<DashMap<String, UdpAssociation>>;

/// Create a new UDP associations map
pub fn new_udp_associations() -> UdpAssociations {
    Arc::new(DashMap::new())
}

// UDP清理任务，定期清理不活跃的UDP association
pub fn start_cleanup_task(associations: UdpAssociations) {
    tokio::spawn(async move {
        const CLEANUP_INTERVAL_SECS: u64 = UDP_TIMEOUT / 2;
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
        interval.tick().await;

        loop {
            interval.tick().await;

            // DashMap allows lock-free iteration and removal
            // retain() is atomic per-entry, no global lock needed
            let initial_count = associations.len();
            associations.retain(|_, association| !association.is_inactive(UDP_TIMEOUT));
            let removed_count = initial_count - associations.len();

            if removed_count > 0 {
                log::debug!(
                    removed = removed_count,
                    remaining = associations.len(),
                    "Cleaned up inactive UDP associations"
                );
            }
        }
    });
}

/// UDP relay session manager
///
/// Handles bidirectional UDP relay between a TCP client stream and UDP socket
pub struct UdpRelaySession {
    association: UdpAssociation,
    socket_key: String,
    peer_addr: String,
    udp_associations: UdpAssociations,
    acl_engine: Option<Arc<AclEngine>>,
    user_stats: Arc<UserStats>,
}

impl UdpRelaySession {
    /// Create a new UDP relay session
    pub async fn new(
        udp_associations: UdpAssociations,
        peer_addr: String,
        acl_engine: Option<Arc<AclEngine>>,
        user_stats: Arc<UserStats>,
    ) -> Result<Self> {
        // Generate unique socket key
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let socket_key = format!("client_{}_{}", peer_addr, id);

        // Create and register UDP association
        let bind_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let socket = UdpSocket::bind(bind_addr).await?;
        let association = UdpAssociation::new(socket);

        // DashMap insert is lock-free
        udp_associations.insert(socket_key.clone(), association.clone());

        Ok(Self {
            association,
            socket_key,
            peer_addr,
            udp_associations,
            acl_engine,
            user_stats,
        })
    }

    /// Run the UDP relay session
    pub async fn run<S>(self, client_stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        log::info!(peer = %self.peer_addr, "Starting UDP associate");

        let (client_read, client_write) = tokio::io::split(client_stream);

        // Create channels
        let (udp_tx, udp_rx) = mpsc::channel::<(SocketAddr, Bytes)>(UDP_CHANNEL_BUFFER_SIZE);
        let (tcp_write_tx, tcp_write_rx) =
            mpsc::channel::<Vec<u8>>(TCP_WRITE_CHANNEL_BUFFER_SIZE);
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        // Spawn background tasks
        let udp_recv_handle =
            self.spawn_udp_receiver(cancel_rx, udp_tx);
        let tcp_write_handle =
            Self::spawn_tcp_writer(client_write, tcp_write_rx, self.peer_addr.clone());

        // Run main relay loop
        let result = self
            .run_relay_loop(client_read, udp_rx, tcp_write_tx)
            .await;

        // Cleanup
        self.cleanup(cancel_tx, tcp_write_handle, udp_recv_handle)
            .await;

        result
    }

    /// Spawn UDP receiver task
    fn spawn_udp_receiver(
        &self,
        mut cancel_rx: oneshot::Receiver<()>,
        udp_tx: mpsc::Sender<(SocketAddr, Bytes)>,
    ) -> tokio::task::JoinHandle<()> {
        let socket = Arc::clone(&self.association.socket);
        let association = self.association.clone();

        tokio::spawn(async move {
            let mut buf = BytesMut::with_capacity(BUF_SIZE);
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => break,
                    result = Self::recv_udp_packet(&socket, &mut buf) => {
                        match result {
                            Ok((len, from_addr)) => {
                                association.update_activity();
                                buf.truncate(len);
                                let data = buf.split_to(len).freeze();

                                if udp_tx.try_send((from_addr, data)).is_err() {
                                    // Channel full or closed
                                    if udp_tx.is_closed() {
                                        break;
                                    }
                                    log::debug!("UDP channel full, dropping packet");
                                }

                                // Shrink buffer if too large
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
        })
    }

    /// Helper to receive UDP packet
    async fn recv_udp_packet(
        socket: &UdpSocket,
        buf: &mut BytesMut,
    ) -> std::io::Result<(usize, SocketAddr)> {
        buf.clear();
        if buf.capacity() < BUF_SIZE {
            buf.reserve(BUF_SIZE - buf.capacity());
        }
        buf.resize(BUF_SIZE, 0);
        socket.recv_from(&mut buf[..]).await
    }

    /// Spawn TCP writer task
    fn spawn_tcp_writer<W>(
        mut client_write: W,
        mut tcp_write_rx: mpsc::Receiver<Vec<u8>>,
        peer_addr: String,
    ) -> tokio::task::JoinHandle<()>
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            while let Some(encoded) = tcp_write_rx.recv().await {
                if let Err(e) = Self::write_all(&mut client_write, &encoded).await {
                    log::debug!(peer = %peer_addr, error = %e, "Error writing UDP response");
                    return;
                }
            }
        })
    }

    /// Write all data to writer
    async fn write_all<W: AsyncWrite + Unpin>(
        writer: &mut W,
        data: &[u8],
    ) -> std::io::Result<()> {
        let mut written = 0;
        while written < data.len() {
            match writer.write(&data[written..]).await {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "connection closed",
                    ))
                }
                Ok(n) => written += n,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Run the main relay loop
    async fn run_relay_loop<R>(
        &self,
        mut client_read: R,
        mut udp_rx: mpsc::Receiver<(SocketAddr, Bytes)>,
        tcp_write_tx: mpsc::Sender<Vec<u8>>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin,
    {
        let mut read_buf = vec![0u8; BUF_SIZE];
        let mut buffer = BytesMut::with_capacity(BUF_SIZE);
        // Reusable encode buffer to avoid allocations per packet
        let mut encode_buf = Vec::with_capacity(BUF_SIZE);

        loop {
            tokio::select! {
                // Handle TCP -> UDP (client sending data)
                read_result = client_read.read(&mut read_buf) => {
                    match read_result {
                        Ok(0) => break,
                        Ok(n) => {
                            buffer.extend_from_slice(&read_buf[..n]);
                            if !self.process_tcp_packets(&mut buffer).await? {
                                break;
                            }
                        }
                        Err(e) => {
                            log::debug!(peer = %self.peer_addr, error = %e, "Error reading from client");
                            break;
                        }
                    }
                }

                // Handle UDP -> TCP (remote response)
                packet = udp_rx.recv() => {
                    match packet {
                        Some((from_addr, data)) => {
                            // Record download bytes (remote -> client)
                            self.user_stats.add_download(data.len() as u64);
                            if !Self::send_udp_response_reuse(&tcp_write_tx, from_addr, data, &self.peer_addr, &mut encode_buf) {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }

    /// Process TCP packets from buffer, returns false if should stop
    async fn process_tcp_packets(&self, buffer: &mut BytesMut) -> Result<bool> {
        loop {
            match UdpPacket::decode(buffer) {
                DecodeResult::Ok(udp_packet, consumed) => {
                    let _ = buffer.split_to(consumed);
                    self.association.update_activity();

                    // Get host and port for ACL matching
                    let (host, port) = match &udp_packet.addr {
                        Address::IPv4(ip, port) => {
                            (std::net::Ipv4Addr::from(*ip).to_string(), *port)
                        }
                        Address::IPv6(ip, port) => {
                            (std::net::Ipv6Addr::from(*ip).to_string(), *port)
                        }
                        Address::Domain(domain, port) => (domain.clone(), *port),
                    };

                    // Match against ACL rules for UDP
                    let outbound = if let Some(ref engine) = self.acl_engine {
                        engine.match_host(&host, port, Protocol::UDP)
                    } else {
                        None
                    };

                    // Check if connection should be rejected
                    if let Some(ref handler) = outbound {
                        if handler.is_reject() {
                            log::debug!(peer = %self.peer_addr, target = %udp_packet.addr.to_key(), "UDP packet rejected by ACL");
                            continue;
                        }

                        // Check if outbound supports UDP
                        if !handler.allows_udp() {
                            log::debug!(peer = %self.peer_addr, target = %udp_packet.addr.to_key(), "UDP not supported by outbound");
                            continue;
                        }
                    }

                    // For now, we use direct UDP for simplicity
                    // TODO: Implement full UDP proxying through SOCKS5 if needed
                    match udp_packet.addr.to_socket_addr().await {
                        Ok(remote_addr) => {
                            let payload_len = udp_packet.payload.len() as u64;
                            if let Err(e) = self
                                .association
                                .socket
                                .send_to(&udp_packet.payload, remote_addr)
                                .await
                            {
                                log::debug!(peer = %self.peer_addr, error = %e, "Failed to send UDP packet");
                            } else {
                                // Record upload bytes (client -> remote)
                                self.user_stats.add_upload(payload_len);
                            }
                        }
                        Err(e) => {
                            log::debug!(peer = %self.peer_addr, error = %e, "Failed to resolve UDP target");
                        }
                    }
                }
                DecodeResult::NeedMoreData => return Ok(true),
                DecodeResult::Invalid(msg) => {
                    log::debug!(peer = %self.peer_addr, error = msg, "Invalid UDP packet");
                    return Ok(false);
                }
            }
        }
    }

    /// Send UDP response back to TCP client (original version for compatibility)
    #[allow(dead_code)]
    fn send_udp_response(
        tcp_write_tx: &mpsc::Sender<Vec<u8>>,
        from_addr: SocketAddr,
        data: Bytes,
        peer_addr: &str,
    ) -> bool {
        let addr = match from_addr {
            SocketAddr::V4(v4) => Address::IPv4(v4.ip().octets(), v4.port()),
            SocketAddr::V6(v6) => Address::IPv6(v6.ip().octets(), v6.port()),
        };

        let udp_packet = UdpPacket::new(addr, data);
        let encoded = udp_packet.encode();

        match tcp_write_tx.try_send(encoded) {
            Ok(_) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::debug!(peer = %peer_addr, "TCP write channel full, dropping packet");
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Send UDP response back to TCP client with buffer reuse
    /// Reuses the encode buffer to avoid allocations per packet
    fn send_udp_response_reuse(
        tcp_write_tx: &mpsc::Sender<Vec<u8>>,
        from_addr: SocketAddr,
        data: Bytes,
        peer_addr: &str,
        encode_buf: &mut Vec<u8>,
    ) -> bool {
        let addr = match from_addr {
            SocketAddr::V4(v4) => Address::IPv4(v4.ip().octets(), v4.port()),
            SocketAddr::V6(v6) => Address::IPv6(v6.ip().octets(), v6.port()),
        };

        let udp_packet = UdpPacket::new(addr, data);
        // Reuse buffer - encode_into clears and fills
        udp_packet.encode_into(encode_buf);

        // We need to clone here because channel takes ownership
        // But at least we reuse the buffer for encoding
        match tcp_write_tx.try_send(encode_buf.clone()) {
            Ok(_) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::debug!(peer = %peer_addr, "TCP write channel full, dropping packet");
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Cleanup session resources
    async fn cleanup(
        self,
        cancel_tx: oneshot::Sender<()>,
        tcp_write_handle: tokio::task::JoinHandle<()>,
        udp_recv_handle: tokio::task::JoinHandle<()>,
    ) {
        // Signal cancellation
        let _ = cancel_tx.send(());

        // Helper to wait with timeout and abort if necessary
        async fn wait_with_abort(
            handle: tokio::task::JoinHandle<()>,
            timeout_secs: u64,
            task_name: &str,
            peer_addr: &str,
        ) {
            let timeout_duration = std::time::Duration::from_secs(timeout_secs);
            tokio::select! {
                _ = handle => {}
                _ = tokio::time::sleep(timeout_duration) => {
                    log::warn!(
                        peer = %peer_addr,
                        timeout_secs = timeout_secs,
                        "{} cleanup timeout, task will be aborted on drop",
                        task_name
                    );
                    // The handle is moved into select, so dropping it here aborts the task
                }
            }
        }

        // Wait for tasks with timeout
        wait_with_abort(
            tcp_write_handle,
            CLEANUP_TIMEOUT_SECS,
            "TCP write task",
            &self.peer_addr,
        )
        .await;

        wait_with_abort(
            udp_recv_handle,
            CLEANUP_TIMEOUT_SECS,
            "UDP receive task",
            &self.peer_addr,
        )
        .await;

        // Remove from associations (lock-free with DashMap)
        self.udp_associations.remove(&self.socket_key);
    }
}

/// Handle UDP Associate request (convenience function)
pub async fn handle_udp_associate<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    udp_associations: UdpAssociations,
    client_stream: S,
    _bind_addr: Address,
    peer_addr: String,
    acl_engine: Option<Arc<AclEngine>>,
    user_stats: Arc<UserStats>,
) -> Result<()> {
    let session = UdpRelaySession::new(udp_associations, peer_addr, acl_engine, user_stats).await?;
    session.run(client_stream).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_udp_packet_encode_ipv4() {
        let packet = UdpPacket::new(
            Address::IPv4([192, 168, 1, 1], 8080),
            Bytes::from_static(b"hello"),
        );

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
        let packet = UdpPacket::new(Address::IPv6(ip, 443), Bytes::from_static(b"test"));

        let encoded = packet.encode();

        // Verify structure: type(1) + ip(16) + port(2) + length(2) + CRLF(2) + payload(4)
        assert_eq!(encoded.len(), 1 + 16 + 2 + 2 + 2 + 4);
        assert_eq!(encoded[0], 4); // IPv6 type
        assert_eq!(&encoded[1..17], &ip); // IP
    }

    #[test]
    fn test_udp_packet_encode_domain() {
        let packet = UdpPacket::new(
            Address::Domain("example.com".to_string(), 80),
            Bytes::from_static(b"data"),
        );

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
                assert_eq!(packet.len(), 5);
                assert_eq!(packet.payload.as_ref(), b"hello");
                match packet.addr {
                    Address::IPv4(ip, port) => {
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
            DecodeResult::Ok(packet, _) => match packet.addr {
                Address::IPv6(decoded_ip, port) => {
                    assert_eq!(decoded_ip, ip);
                    assert_eq!(port, 443);
                }
                _ => panic!("Expected IPv6 address"),
            },
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
            DecodeResult::Ok(packet, _) => match packet.addr {
                Address::Domain(domain, port) => {
                    assert_eq!(domain, "example.com");
                    assert_eq!(port, 80);
                }
                _ => panic!("Expected Domain address"),
            },
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
            DecodeResult::Invalid(_) => {}
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
            DecodeResult::Invalid(_) => {}
            _ => panic!("Expected Invalid due to wrong CRLF"),
        }
    }

    #[test]
    fn test_udp_packet_encode_decode_roundtrip() {
        let original = UdpPacket::new(
            Address::Domain("test.example.org".to_string(), 12345),
            Bytes::from_static(b"hello world"),
        );

        let encoded = original.encode();
        match UdpPacket::decode(&encoded) {
            DecodeResult::Ok(decoded, consumed) => {
                assert_eq!(consumed, encoded.len());
                assert_eq!(decoded.len(), original.len());
                assert_eq!(decoded.payload, original.payload);
                assert_eq!(decoded.addr, original.addr);
            }
            _ => panic!("Roundtrip decode failed"),
        }
    }

    #[test]
    fn test_udp_packet_empty_payload() {
        let packet = UdpPacket::new(Address::IPv4([10, 0, 0, 1], 53), Bytes::new());

        let encoded = packet.encode();
        match UdpPacket::decode(&encoded) {
            DecodeResult::Ok(decoded, _) => {
                assert_eq!(decoded.len(), 0);
                assert!(decoded.is_empty());
            }
            _ => panic!("Failed to decode empty payload packet"),
        }
    }

    #[test]
    fn test_udp_packet_new() {
        let addr = Address::IPv4([192, 168, 1, 1], 8080);
        let payload = Bytes::from_static(b"test");
        let packet = UdpPacket::new(addr.clone(), payload.clone());

        assert_eq!(packet.addr, addr);
        assert_eq!(packet.payload, payload);
        assert_eq!(packet.len(), 4);
        assert!(!packet.is_empty());
    }

    // ========== encode_into buffer reuse tests ==========

    #[test]
    fn test_udp_packet_encode_into_basic() {
        let packet = UdpPacket::new(
            Address::IPv4([192, 168, 1, 1], 8080),
            Bytes::from_static(b"hello"),
        );

        let mut buf = Vec::new();
        packet.encode_into(&mut buf);

        // Should match encode() output
        assert_eq!(buf, packet.encode());
    }

    #[test]
    fn test_udp_packet_encode_into_reuse() {
        let packet1 = UdpPacket::new(
            Address::IPv4([10, 0, 0, 1], 1234),
            Bytes::from_static(b"first"),
        );
        let packet2 = UdpPacket::new(
            Address::IPv4([10, 0, 0, 2], 5678),
            Bytes::from_static(b"second packet with longer payload"),
        );

        let mut buf = Vec::new();

        // First encode
        packet1.encode_into(&mut buf);
        let encoded1 = buf.clone();

        // Second encode reuses same buffer
        packet2.encode_into(&mut buf);
        let encoded2 = buf.clone();

        // Verify both encodings are correct
        assert_eq!(encoded1, packet1.encode());
        assert_eq!(encoded2, packet2.encode());

        // Verify buffer was actually reused (capacity should be >= max size)
        assert!(buf.capacity() >= encoded2.len());
    }

    #[test]
    fn test_udp_packet_encode_into_clears_buffer() {
        let packet = UdpPacket::new(
            Address::IPv4([127, 0, 0, 1], 80),
            Bytes::from_static(b"test"),
        );

        // Pre-fill buffer with junk
        let mut buf = vec![0xFF; 100];
        packet.encode_into(&mut buf);

        // Should match fresh encode, not have old data
        assert_eq!(buf, packet.encode());
    }

    #[test]
    fn test_udp_packet_encoded_size() {
        // IPv4
        let packet_v4 = UdpPacket::new(
            Address::IPv4([192, 168, 1, 1], 8080),
            Bytes::from_static(b"hello"),
        );
        assert_eq!(packet_v4.encoded_size(), packet_v4.encode().len());

        // IPv6
        let packet_v6 = UdpPacket::new(
            Address::IPv6([0; 16], 443),
            Bytes::from_static(b"test"),
        );
        assert_eq!(packet_v6.encoded_size(), packet_v6.encode().len());

        // Domain
        let packet_domain = UdpPacket::new(
            Address::Domain("example.com".to_string(), 80),
            Bytes::from_static(b"data"),
        );
        assert_eq!(packet_domain.encoded_size(), packet_domain.encode().len());
    }

    #[test]
    fn test_udp_packet_encode_into_performance_pattern() {
        // Simulate typical usage pattern: many packets encoded into same buffer
        let mut buf = Vec::with_capacity(1024);
        let initial_cap = buf.capacity();

        for i in 0..100 {
            let packet = UdpPacket::new(
                Address::IPv4([192, 168, 1, i as u8], 8080),
                Bytes::from(format!("payload_{}", i)),
            );
            packet.encode_into(&mut buf);

            // Verify correct encoding each time
            assert_eq!(buf, packet.encode());
        }

        // Buffer should have grown only as needed, not per-packet
        // (capacity should be close to max packet size, not 100x)
        assert!(buf.capacity() <= initial_cap * 4);
    }

    #[tokio::test]
    async fn test_udp_association_new() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let association = UdpAssociation::new(socket);
        assert!(!association.is_inactive(60));
    }

    #[tokio::test]
    async fn test_udp_association_update_activity() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let association = UdpAssociation::new(socket);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        association.update_activity();
        assert!(!association.is_inactive(1));
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

    // ========== Concurrency tests ==========

    #[tokio::test]
    async fn test_udp_association_concurrent_update_activity() {
        // Test that concurrent updates don't cause issues
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let association = Arc::new(UdpAssociation::new(socket));

        let mut handles = vec![];
        for _ in 0..10 {
            let assoc = Arc::clone(&association);
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    assoc.update_activity();
                    tokio::task::yield_now().await;
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // After all updates, should still be active
        assert!(!association.is_inactive(60));
    }

    #[tokio::test]
    async fn test_udp_association_concurrent_read_write() {
        // Test concurrent reads and writes to activity tracker
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let association = Arc::new(UdpAssociation::new(socket));

        let assoc_writer = Arc::clone(&association);
        let assoc_reader = Arc::clone(&association);

        // Writer task
        let writer = tokio::spawn(async move {
            for _ in 0..1000 {
                assoc_writer.update_activity();
                tokio::task::yield_now().await;
            }
        });

        // Reader task
        let reader = tokio::spawn(async move {
            for _ in 0..1000 {
                let _ = assoc_reader.is_inactive(60);
                tokio::task::yield_now().await;
            }
        });

        writer.await.unwrap();
        reader.await.unwrap();
    }

    #[tokio::test]
    async fn test_udp_association_is_inactive_accuracy() {
        // Test that is_inactive correctly detects inactivity
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let association = UdpAssociation::new(socket);

        // Initially should not be inactive
        assert!(!association.is_inactive(0));

        // Wait 2 seconds and check
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(association.is_inactive(1)); // Should be inactive after 1 sec timeout

        // Update activity
        association.update_activity();
        assert!(!association.is_inactive(1)); // Should be active again
    }

    #[tokio::test]
    async fn test_udp_association_clone_shares_state() {
        // Test that cloned associations share the same activity state
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let association1 = UdpAssociation::new(socket);
        let association2 = association1.clone();

        // Update activity on one clone
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        association1.update_activity();

        // Both should see the same activity state
        assert!(!association1.is_inactive(1));
        assert!(!association2.is_inactive(1));
    }

    // ========== DashMap tests ==========

    #[tokio::test]
    async fn test_udp_associations_dashmap_concurrent_insert() {
        let associations = new_udp_associations();
        let mut handles = vec![];

        // Spawn multiple tasks to insert concurrently
        for i in 0..100 {
            let assocs = Arc::clone(&associations);
            handles.push(tokio::spawn(async move {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let association = UdpAssociation::new(socket);
                assocs.insert(format!("key_{}", i), association);
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(associations.len(), 100);
    }

    #[tokio::test]
    async fn test_udp_associations_dashmap_concurrent_read_write() {
        let associations = new_udp_associations();

        // Pre-populate
        for i in 0..50 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            associations.insert(format!("key_{}", i), UdpAssociation::new(socket));
        }

        let assocs_writer = Arc::clone(&associations);
        let assocs_reader = Arc::clone(&associations);

        // Writer task - insert new entries
        let writer = tokio::spawn(async move {
            for i in 50..100 {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                assocs_writer.insert(format!("key_{}", i), UdpAssociation::new(socket));
                tokio::task::yield_now().await;
            }
        });

        // Reader task - read existing entries
        let reader = tokio::spawn(async move {
            for i in 0..50 {
                let _ = assocs_reader.get(&format!("key_{}", i));
                tokio::task::yield_now().await;
            }
        });

        writer.await.unwrap();
        reader.await.unwrap();

        assert_eq!(associations.len(), 100);
    }

    #[tokio::test]
    async fn test_udp_associations_dashmap_retain() {
        let associations = new_udp_associations();

        // Insert entries with different activity states
        for i in 0..10 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let assoc = UdpAssociation::new(socket);
            // Mark even-numbered entries as active
            if i % 2 == 0 {
                assoc.update_activity();
            }
            associations.insert(format!("key_{}", i), assoc);
        }

        // Wait for odd entries to become inactive
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Update activity on even entries again
        for i in (0..10).step_by(2) {
            if let Some(assoc) = associations.get(&format!("key_{}", i)) {
                assoc.update_activity();
            }
        }

        // Retain only active entries (timeout = 1 second)
        associations.retain(|_, assoc| !assoc.is_inactive(1));

        // Should have 5 entries (even numbered)
        assert_eq!(associations.len(), 5);
        for i in (0..10).step_by(2) {
            assert!(associations.contains_key(&format!("key_{}", i)));
        }
    }

    #[tokio::test]
    async fn test_udp_associations_dashmap_concurrent_retain() {
        let associations = new_udp_associations();

        // Pre-populate
        for i in 0..100 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            associations.insert(format!("key_{}", i), UdpAssociation::new(socket));
        }

        let assocs_retain = Arc::clone(&associations);
        let assocs_insert = Arc::clone(&associations);

        // Retain task
        let retain_task = tokio::spawn(async move {
            for _ in 0..10 {
                assocs_retain.retain(|_, _| true); // Keep all
                tokio::task::yield_now().await;
            }
        });

        // Insert task
        let insert_task = tokio::spawn(async move {
            for i in 100..150 {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                assocs_insert.insert(format!("key_{}", i), UdpAssociation::new(socket));
                tokio::task::yield_now().await;
            }
        });

        retain_task.await.unwrap();
        insert_task.await.unwrap();

        // Should have all entries
        assert_eq!(associations.len(), 150);
    }

    #[tokio::test]
    async fn test_udp_associations_dashmap_remove() {
        let associations = new_udp_associations();

        // Insert entries
        for i in 0..10 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            associations.insert(format!("key_{}", i), UdpAssociation::new(socket));
        }

        assert_eq!(associations.len(), 10);

        // Remove some entries
        associations.remove("key_0");
        associations.remove("key_5");
        associations.remove("key_9");

        assert_eq!(associations.len(), 7);
        assert!(!associations.contains_key("key_0"));
        assert!(!associations.contains_key("key_5"));
        assert!(!associations.contains_key("key_9"));
        assert!(associations.contains_key("key_1"));
    }
}
