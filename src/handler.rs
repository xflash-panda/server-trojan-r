//! Connection handling logic
//!
//! This module contains the request processing and connection relay logic.

use crate::acl;
use crate::core::{
    copy_bidirectional_with_stats, hooks, Address, DecodeResult, Server, TrojanCmd, TrojanRequest,
    TrojanUdpPacket, UserId,
};
use crate::logger::log;
use crate::transport::TransportStream;

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::transport::ConnectionMeta;

/// Read and decode a complete Trojan request from the stream
///
/// This function handles partial reads by continuing to read until
/// a complete request is received or an error occurs.
pub async fn read_trojan_request(
    stream: &mut TransportStream,
    buf: &mut BytesMut,
    buffer_size: usize,
) -> Result<TrojanRequest> {
    let mut temp_buf = vec![0u8; buffer_size];

    loop {
        // Try to decode with current buffer (check completeness first to avoid clone)
        if buf.len() >= TrojanRequest::MIN_SIZE {
            match TrojanRequest::check_complete(buf) {
                Ok(_header_len) => {
                    // Buffer contains complete request, now decode it
                    match TrojanRequest::decode_zerocopy(buf) {
                        DecodeResult::Ok(req, _) => {
                            return Ok(req);
                        }
                        DecodeResult::Invalid(e) => {
                            return Err(anyhow!("Invalid request: {}", e));
                        }
                        DecodeResult::NeedMoreData => {
                            // Should not happen after check_complete succeeds
                            unreachable!("check_complete succeeded but decode failed");
                        }
                    }
                }
                Err(None) => {
                    // Need more data, continue reading
                }
                Err(Some(e)) => {
                    return Err(anyhow!("Invalid request: {}", e));
                }
            }
        }

        // Read more data
        let n = stream.read(&mut temp_buf).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(anyhow!("Connection closed before receiving request"));
            } else {
                return Err(anyhow!("Connection closed with incomplete request"));
            }
        }

        buf.extend_from_slice(&temp_buf[..n]);

        // Prevent buffer from growing too large (protection against malicious clients)
        if buf.len() > buffer_size * 2 {
            return Err(anyhow!("Request too large"));
        }
    }
}

/// Process a single connection
pub async fn process_connection(
    server: &Server,
    mut stream: TransportStream,
    meta: ConnectionMeta,
) -> Result<()> {
    // Read Trojan request with timeout and retry for incomplete data
    let buffer_size = server.conn_config.buffer_size;
    let mut buf = BytesMut::with_capacity(buffer_size);

    let request = tokio::time::timeout(
        server.conn_config.request_timeout,
        read_trojan_request(&mut stream, &mut buf, buffer_size),
    )
    .await
    .map_err(|_| anyhow!("Request read timeout"))??;

    let peer_addr = meta.peer_addr.to_string();

    // Authenticate user
    let user_id = match server.authenticator.authenticate(&request.password).await {
        Some(id) => id,
        None => {
            log::authentication(&peer_addr, false);
            log::debug!(
                peer = %peer_addr,
                transport = %meta.transport_type,
                "Invalid user credentials"
            );
            return Err(anyhow!("Invalid user credentials"));
        }
    };

    log::authentication(&peer_addr, true);
    log::debug!(peer = %peer_addr, user_id = user_id, "User authenticated");

    // Register connection for tracking and kick-off capability
    let (conn_id, cancel_token) = server.conn_manager.register(user_id, peer_addr.clone());
    log::debug!(peer = %peer_addr, user_id = user_id, conn_id = conn_id, "Connection registered");

    // Ensure connection is unregistered when done
    let _guard = scopeguard::guard((), |_| {
        server.conn_manager.unregister(conn_id);
        log::debug!(conn_id = conn_id, "Connection unregistered");
    });

    // Record proxy request
    server.stats.record_request(user_id);

    match request.cmd {
        TrojanCmd::Connect => {
            handle_connect(
                server,
                stream,
                request.addr,
                request.payload,
                peer_addr,
                user_id,
                cancel_token,
            )
            .await
        }
        TrojanCmd::UdpAssociate => {
            handle_udp_associate(
                server,
                stream,
                request.addr,
                request.payload,
                peer_addr,
                user_id,
                cancel_token,
            )
            .await
        }
    }
}

/// Handle TCP CONNECT command
async fn handle_connect(
    server: &Server,
    client_stream: TransportStream,
    target: Address,
    initial_payload: bytes::Bytes,
    peer_addr: String,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Route the connection (passing Address directly avoids string allocation)
    let outbound_type = server.router.route(&target).await;

    // Check if connection should be rejected
    if matches!(outbound_type, hooks::OutboundType::Reject) {
        log::debug!(peer = %peer_addr, target = %target, "Connection rejected by router");
        return Ok(());
    }

    log::debug!(peer = %peer_addr, target = %target, outbound = ?outbound_type, "Connecting to target");

    // Build connect context
    let ctx = ConnectContext {
        server,
        client_stream,
        target: &target,
        initial_payload,
        peer_addr: &peer_addr,
        user_id,
        cancel_token,
    };

    // Connect based on outbound type
    match outbound_type {
        hooks::OutboundType::Direct => handle_direct_connect(ctx).await,
        hooks::OutboundType::Proxy(handler) => handle_proxy_connect(ctx, handler).await,
        hooks::OutboundType::Reject => Ok(()), // Already handled above
    }
}

/// Context for handling outbound connections
struct ConnectContext<'a> {
    server: &'a Server,
    client_stream: TransportStream,
    target: &'a Address,
    initial_payload: bytes::Bytes,
    peer_addr: &'a str,
    user_id: UserId,
    cancel_token: CancellationToken,
}

impl<'a> ConnectContext<'a> {
    /// Relay data between client and remote with stats tracking
    async fn relay<S>(self, mut remote_stream: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Write initial payload if any
        if !self.initial_payload.is_empty() {
            self.server
                .stats
                .record_upload(self.user_id, self.initial_payload.len() as u64);
            remote_stream.write_all(&self.initial_payload).await?;
        }

        // Relay data with stats tracking and cancellation support
        let stats = Arc::clone(&self.server.stats);
        let relay_fut = copy_bidirectional_with_stats(
            self.client_stream,
            remote_stream,
            self.server.conn_config.idle_timeout_secs(),
            Some((self.user_id, stats)),
        );

        tokio::select! {
            result = relay_fut => {
                match result {
                    Ok(r) if r.completed => {
                        log::trace!(peer = %self.peer_addr, up = r.a_to_b, down = r.b_to_a, "Relay completed");
                    }
                    Ok(r) => {
                        log::debug!(peer = %self.peer_addr, up = r.a_to_b, down = r.b_to_a, "Connection timeout");
                    }
                    Err(e) => {
                        log::debug!(peer = %self.peer_addr, error = %e, "Relay error");
                    }
                }
            }
            _ = self.cancel_token.cancelled() => {
                log::debug!(peer = %self.peer_addr, "Connection kicked");
            }
        }

        Ok(())
    }
}

/// Handle direct connection
async fn handle_direct_connect(ctx: ConnectContext<'_>) -> Result<()> {
    // Resolve target address
    let remote_addr = ctx.target.to_socket_addr().await?;

    // Connect with timeout
    let remote_stream = match tokio::time::timeout(
        ctx.server.conn_config.connect_timeout,
        TcpStream::connect(remote_addr),
    )
    .await
    {
        Ok(Ok(stream)) => {
            if ctx.server.conn_config.tcp_nodelay {
                let _ = stream.set_nodelay(true);
            }
            stream
        }
        Ok(Err(e)) => {
            log::debug!(peer = %ctx.peer_addr, error = %e, "TCP connect failed");
            return Err(e.into());
        }
        Err(_) => {
            log::debug!(peer = %ctx.peer_addr, "TCP connect timeout");
            return Err(anyhow!("TCP connect timeout"));
        }
    };

    log::debug!(peer = %ctx.peer_addr, remote = %remote_addr, "Connected to remote (direct)");
    ctx.relay(remote_stream).await
}

/// Handle proxy connection via ACL engine outbound handler
async fn handle_proxy_connect(
    ctx: ConnectContext<'_>,
    handler: Arc<acl::OutboundHandler>,
) -> Result<()> {
    use acl::{Addr as AclAddr, AsyncOutbound};

    // Convert Address to ACL Addr
    let (host, port) = match ctx.target {
        Address::IPv4(ip, port) => (std::net::Ipv4Addr::from(*ip).to_string(), *port),
        Address::IPv6(ip, port) => (std::net::Ipv6Addr::from(*ip).to_string(), *port),
        Address::Domain(domain, port) => (domain.clone(), *port),
    };
    let mut acl_addr = AclAddr::new(&host, port);

    // Connect via proxy with timeout
    let remote_stream = match tokio::time::timeout(
        ctx.server.conn_config.connect_timeout,
        handler.dial_tcp(&mut acl_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            log::debug!(peer = %ctx.peer_addr, target = %ctx.target, error = %e, "Proxy connect failed");
            return Err(anyhow!("Proxy connect failed: {}", e));
        }
        Err(_) => {
            log::debug!(peer = %ctx.peer_addr, target = %ctx.target, "Proxy connect timeout");
            return Err(anyhow!("Proxy connect timeout"));
        }
    };

    log::debug!(peer = %ctx.peer_addr, target = %ctx.target, handler = ?handler, "Connected to remote (proxy)");
    ctx.relay(remote_stream).await
}

/// Maximum UDP read buffer size to prevent memory exhaustion
const UDP_MAX_READ_BUFFER_SIZE: usize = 256 * 1024; // 256KB

/// Handle UDP ASSOCIATE command
async fn handle_udp_associate(
    server: &Server,
    mut client_stream: TransportStream,
    _initial_target: Address,
    initial_payload: bytes::Bytes,
    peer_addr: String,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    use acl::{Addr as AclAddr, AsyncOutbound, AsyncUdpConn};

    // Buffer for reading UDP packets from TCP stream (with size limit)
    let mut read_buf = BytesMut::with_capacity(8 * 1024); // Start with 8KB
    if !initial_payload.is_empty() {
        read_buf.extend_from_slice(&initial_payload);
    }

    // UDP relay loop
    let mut temp_buf = vec![0u8; 65536];
    let mut udp_conn: Option<Box<dyn AsyncUdpConn>> = None;
    let mut current_handler: Option<Arc<acl::OutboundHandler>> = None;

    loop {
        tokio::select! {
            // Read from client TCP stream
            result = client_stream.read(&mut temp_buf) => {
                let n = match result {
                    Ok(0) => {
                        log::debug!(peer = %peer_addr, "UDP client disconnected");
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        log::debug!(peer = %peer_addr, error = %e, "UDP read error");
                        break;
                    }
                };

                // Check buffer size limit to prevent memory exhaustion
                if read_buf.len() + n > UDP_MAX_READ_BUFFER_SIZE {
                    log::warn!(
                        peer = %peer_addr,
                        buffer_size = read_buf.len(),
                        "UDP read buffer exceeded limit, closing connection"
                    );
                    break;
                }

                read_buf.extend_from_slice(&temp_buf[..n]);

                // Process all complete UDP packets in buffer
                while !read_buf.is_empty() {
                    match TrojanUdpPacket::decode(&read_buf) {
                        DecodeResult::Ok(packet, consumed) => {
                            let _ = read_buf.split_to(consumed);

                            // Route the packet
                            let outbound_type = server.router.route(&packet.addr).await;

                            match outbound_type {
                                hooks::OutboundType::Reject => {
                                    log::debug!(peer = %peer_addr, target = %packet.addr, "UDP packet rejected by router");
                                    continue;
                                }
                                hooks::OutboundType::Direct => {
                                    // For direct, we need to create a UDP connection if not exists
                                    if udp_conn.is_none() || current_handler.is_some() {
                                        // Explicitly drop old connection to release resources
                                        if let Some(old_conn) = udp_conn.take() {
                                            drop(old_conn);
                                        }
                                        current_handler = None;

                                        let direct = acl::Direct::new();
                                        let mut acl_addr = AclAddr::new(packet.addr.host(), packet.addr.port());
                                        match direct.dial_udp(&mut acl_addr).await {
                                            Ok(conn) => {
                                                udp_conn = Some(conn);
                                            }
                                            Err(e) => {
                                                log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "Failed to create direct UDP connection");
                                                continue;
                                            }
                                        }
                                    }
                                }
                                hooks::OutboundType::Proxy(handler) => {
                                    // Check if handler supports UDP
                                    if !handler.allows_udp() {
                                        log::debug!(peer = %peer_addr, target = %packet.addr, "UDP not allowed by outbound handler");
                                        continue;
                                    }

                                    // Create new UDP connection if handler changed or not exists
                                    let need_new_conn = match &current_handler {
                                        None => true,
                                        Some(h) => !Arc::ptr_eq(h, &handler),
                                    };

                                    if need_new_conn {
                                        // Explicitly drop old connection to release resources
                                        if let Some(old_conn) = udp_conn.take() {
                                            drop(old_conn);
                                        }

                                        let mut acl_addr = AclAddr::new(packet.addr.host(), packet.addr.port());
                                        match handler.dial_udp(&mut acl_addr).await {
                                            Ok(conn) => {
                                                udp_conn = Some(conn);
                                                current_handler = Some(handler);
                                            }
                                            Err(e) => {
                                                log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "Failed to create proxy UDP connection");
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }

                            // Send UDP packet
                            if let Some(ref conn) = udp_conn {
                                let acl_addr = AclAddr::new(packet.addr.host(), packet.addr.port());
                                match conn.write_to(&packet.payload, &acl_addr).await {
                                    Ok(n) => {
                                        server.stats.record_upload(user_id, n as u64);
                                        log::trace!(peer = %peer_addr, target = %packet.addr, bytes = n, "UDP packet sent");
                                    }
                                    Err(e) => {
                                        log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "UDP send error");
                                    }
                                }
                            }
                        }
                        DecodeResult::NeedMoreData => break,
                        DecodeResult::Invalid(msg) => {
                            log::debug!(peer = %peer_addr, error = %msg, "Invalid UDP packet");
                            read_buf.clear();
                            break;
                        }
                    }
                }
            }

            // Read from UDP connection (if exists)
            result = async {
                if let Some(ref conn) = udp_conn {
                    let mut buf = vec![0u8; 65536];
                    conn.read_from(&mut buf).await.map(|(n, addr)| (n, addr, buf))
                } else {
                    // No UDP connection, wait forever
                    std::future::pending::<acl_engine_r::Result<(usize, AclAddr, Vec<u8>)>>().await
                }
            } => {
                match result {
                    Ok((n, from_addr, buf)) => {
                        // Convert AclAddr back to Address
                        let addr = acl_addr_to_address(&from_addr);

                        // Encode and send back to client
                        let response = TrojanUdpPacket::encode(&addr, &buf[..n]);
                        if let Err(e) = client_stream.write_all(&response).await {
                            log::debug!(peer = %peer_addr, error = %e, "Failed to write UDP response");
                            break;
                        }
                        server.stats.record_download(user_id, n as u64);
                        log::trace!(peer = %peer_addr, from = %from_addr, bytes = n, "UDP packet received");
                    }
                    Err(e) => {
                        log::debug!(peer = %peer_addr, error = %e, "UDP recv error");
                    }
                }
            }

            // Handle cancellation
            _ = cancel_token.cancelled() => {
                log::debug!(peer = %peer_addr, "UDP connection kicked by admin");
                break;
            }
        }
    }

    Ok(())
}

/// Convert AclAddr to Address
fn acl_addr_to_address(addr: &acl::Addr) -> Address {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Try to parse as IP address first
    if let Ok(ipv4) = addr.host.parse::<Ipv4Addr>() {
        return Address::IPv4(ipv4.octets(), addr.port);
    }
    if let Ok(ipv6) = addr.host.parse::<Ipv6Addr>() {
        return Address::IPv6(ipv6.octets(), addr.port);
    }
    // Otherwise treat as domain
    Address::Domain(addr.host.clone(), addr.port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acl::Addr as AclAddr;

    #[test]
    fn test_acl_addr_to_address_ipv4() {
        let acl_addr = AclAddr::new("192.168.1.1", 8080);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::IPv4([192, 168, 1, 1], 8080)));
    }

    #[test]
    fn test_acl_addr_to_address_ipv6() {
        let acl_addr = AclAddr::new("::1", 443);
        let addr = acl_addr_to_address(&acl_addr);
        match addr {
            Address::IPv6(ip, port) => {
                assert_eq!(port, 443);
                assert_eq!(ip, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            }
            _ => panic!("Expected IPv6 address"),
        }
    }

    #[test]
    fn test_acl_addr_to_address_ipv6_full() {
        let acl_addr = AclAddr::new("2001:db8::1", 80);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::IPv6(_, 80)));
    }

    #[test]
    fn test_acl_addr_to_address_domain() {
        let acl_addr = AclAddr::new("example.com", 80);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::Domain(ref d, 80) if d == "example.com"));
    }

    #[test]
    fn test_acl_addr_to_address_domain_with_subdomain() {
        let acl_addr = AclAddr::new("sub.example.com", 443);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::Domain(ref d, 443) if d == "sub.example.com"));
    }
}
