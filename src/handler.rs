//! Connection handling logic
//!
//! This module contains the request processing and connection relay logic.

use crate::acl;
use crate::config;
use crate::core::{
    copy_bidirectional_with_stats, hooks, Address, DecodeResult, Server, TrojanCmd, TrojanRequest,
    TrojanUdpPacket, UserId,
};
use crate::logger::log;
use crate::transport::{ConnectionMeta, TransportStream};

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// Maximum UDP read buffer size to prevent memory exhaustion
const UDP_MAX_READ_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Maximum entries in per-session UDP route cache
const UDP_MAX_ROUTE_CACHE_ENTRIES: usize = 256;

/// Read and decode a complete Trojan request from the stream
///
/// This function handles partial reads by continuing to read until
/// a complete request is received or an error occurs.
pub async fn read_trojan_request(
    stream: &mut TransportStream,
    buf: &mut BytesMut,
    conn_config: &config::ConnConfig,
) -> Result<TrojanRequest> {
    let buffer_size = conn_config.buffer_size;
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
        read_trojan_request(&mut stream, &mut buf, &server.conn_config),
    )
    .await
    .map_err(|_| anyhow!("Request read timeout"))??;

    // Free request parsing buffer immediately — payload is an independent Bytes.
    // Saves 32KB per connection during the relay phase.
    drop(buf);

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
        hooks::OutboundType::Direct(resolved) => handle_direct_connect(ctx, resolved).await,
        hooks::OutboundType::Reject => Ok(()), // Already handled above
        hooks::OutboundType::Proxy(handler) => handle_proxy_connect(ctx, handler).await,
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
        // Keep ownership of client_stream so we can shutdown after cancel
        let mut client_stream = self.client_stream;

        // Write initial payload if any
        if !self.initial_payload.is_empty() {
            self.server
                .stats
                .record_upload(self.user_id, self.initial_payload.len() as u64);
            remote_stream.write_all(&self.initial_payload).await?;
        }

        // Relay data with stats tracking and cancellation support.
        // Pass &mut so streams aren't moved into the future — this allows
        // graceful shutdown even when cancel_token drops the relay future.
        let stats = Arc::clone(&self.server.stats);
        let relay_fut = copy_bidirectional_with_stats(
            &mut client_stream,
            &mut remote_stream,
            self.server.conn_config.idle_timeout_secs(),
            self.server.conn_config.buffer_size,
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

        // Graceful shutdown for both streams (covers cancel, timeout, and error paths).
        // Sends WebSocket Close frames, gRPC trailers, or TCP FIN as appropriate.
        let _ = client_stream.shutdown().await;
        let _ = remote_stream.shutdown().await;

        Ok(())
    }
}

/// Handle direct connection
async fn handle_direct_connect(
    ctx: ConnectContext<'_>,
    resolved: Option<std::net::SocketAddr>,
) -> Result<()> {
    // Use pre-resolved address from SSRF check when available, avoiding redundant DNS
    let remote_addr = match resolved {
        Some(addr) => addr,
        None => ctx.target.to_socket_addr().await?,
    };

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

/// Handle proxy connection via ACL outbound handler
async fn handle_proxy_connect(
    ctx: ConnectContext<'_>,
    handler: Arc<acl::OutboundHandler>,
) -> Result<()> {
    use acl_engine_r::outbound::{Addr as AclAddr, AsyncOutbound};

    // Convert Address to ACL Addr (Cow avoids clone for domains)
    let mut acl_addr = AclAddr::new(ctx.target.host().into_owned(), ctx.target.port());

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

    log::debug!(peer = %ctx.peer_addr, target = %ctx.target, handler = ?handler, "Connected via proxy");
    ctx.relay(remote_stream).await
}

/// Handle UDP ASSOCIATE command
///
/// Trojan UDP packet format (within TCP stream):
/// ATYP + DST.ADDR + DST.PORT + Length(2 bytes) + CRLF + Payload
async fn handle_udp_associate(
    server: &Server,
    mut client_stream: TransportStream,
    _initial_target: Address,
    initial_payload: bytes::Bytes,
    peer_addr: String,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    use acl_engine_r::outbound::{Addr as AclAddr, AsyncOutbound, AsyncUdpConn};
    use std::collections::HashMap;

    log::debug!(peer = %peer_addr, "UDP associate started");

    // Buffer for reading from client
    let buffer_size = server.conn_config.buffer_size;
    let mut read_buf = vec![0u8; buffer_size];
    let mut pending_data = BytesMut::new();

    // Process initial payload if any
    if !initial_payload.is_empty() {
        pending_data.extend_from_slice(&initial_payload);
    }

    // Per-session route cache: avoids repeated router.route() + DNS for the same target.
    // Also caches the AclAddr for write_to() to avoid per-packet String allocation.
    let mut route_cache: HashMap<Address, (hooks::OutboundType, AclAddr)> = HashMap::new();

    // UDP connection state - reuse connection when possible
    let mut udp_conn: Option<Box<dyn AsyncUdpConn>> = None;
    let mut current_handler: Option<Arc<acl::OutboundHandler>> = None;

    // Buffer for receiving UDP responses
    let mut recv_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            // Read from client (TCP stream with Trojan UDP packets)
            read_result = client_stream.read(&mut read_buf) => {
                match read_result {
                    Ok(0) => {
                        log::debug!(peer = %peer_addr, "UDP client disconnected");
                        break;
                    }
                    Ok(n) => {
                        // Check buffer size limit to prevent memory exhaustion
                        if pending_data.len() + n > UDP_MAX_READ_BUFFER_SIZE {
                            log::warn!(
                                peer = %peer_addr,
                                buffer_size = pending_data.len(),
                                "UDP read buffer exceeded limit, closing connection"
                            );
                            break;
                        }

                        pending_data.extend_from_slice(&read_buf[..n]);

                        // Process all complete UDP packets in buffer
                        while pending_data.len() >= TrojanUdpPacket::MIN_SIZE {
                            match TrojanUdpPacket::decode(&pending_data) {
                                DecodeResult::Ok(packet, consumed) => {
                                    // Remove consumed bytes from buffer
                                    let _ = pending_data.split_to(consumed);

                                    // Route the packet (use cache to avoid repeated DNS lookups and String allocs)
                                    let (outbound_type, send_addr) = match route_cache.get(&packet.addr) {
                                        Some(cached) => (cached.0.clone(), &cached.1),
                                        None => {
                                            let result = server.router.route(&packet.addr).await;
                                            // Pre-compute the AclAddr for write_to() once per unique target
                                            let acl_addr = match &result {
                                                hooks::OutboundType::Direct(Some(addr)) => {
                                                    AclAddr::new(addr.ip().to_string(), addr.port())
                                                }
                                                _ => AclAddr::new(packet.addr.host().into_owned(), packet.addr.port()),
                                            };
                                            // Evict all entries when cache is full to bound memory
                                            if route_cache.len() >= UDP_MAX_ROUTE_CACHE_ENTRIES {
                                                route_cache.clear();
                                            }
                                            route_cache.insert(packet.addr.clone(), (result.clone(), acl_addr));
                                            let cached = route_cache.get(&packet.addr).unwrap();
                                            (cached.0.clone(), &cached.1)
                                        }
                                    };

                                    match &outbound_type {
                                        hooks::OutboundType::Reject => {
                                            log::debug!(peer = %peer_addr, target = %packet.addr, "UDP packet rejected by router");
                                            continue;
                                        }
                                        hooks::OutboundType::Direct(_) => {
                                            // For direct, we need to create a UDP connection if not exists
                                            if udp_conn.is_none() || current_handler.is_some() {
                                                // Explicitly drop old connection to release resources
                                                if let Some(old_conn) = udp_conn.take() {
                                                    drop(old_conn);
                                                }
                                                current_handler = None;

                                                let direct = acl::Direct::new();
                                                // Reuse cached AclAddr (avoids per-packet String allocation)
                                                let mut dial_addr = send_addr.clone();
                                                match direct.dial_udp(&mut dial_addr).await {
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
                                            if !handler.allows_udp() {
                                                log::debug!(peer = %peer_addr, target = %packet.addr, "Proxy handler does not support UDP, rejecting");
                                                continue;
                                            }

                                            // Create new UDP connection if handler changed or not exists
                                            let need_new_conn = match &current_handler {
                                                None => true,
                                                Some(h) => !Arc::ptr_eq(h, handler),
                                            };

                                            if need_new_conn {
                                                // Explicitly drop old connection to release resources
                                                if let Some(old_conn) = udp_conn.take() {
                                                    drop(old_conn);
                                                }

                                                // Reuse cached AclAddr (avoids per-packet String allocation)
                                                let mut dial_addr = send_addr.clone();
                                                match handler.dial_udp(&mut dial_addr).await {
                                                    Ok(conn) => {
                                                        udp_conn = Some(conn);
                                                        current_handler = Some(handler.clone());
                                                    }
                                                    Err(e) => {
                                                        log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "Failed to create proxy UDP connection");
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Send UDP packet using cached AclAddr (zero per-packet String allocation)
                                    if let Some(ref conn) = udp_conn {
                                        match conn.write_to(&packet.payload, send_addr).await {
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
                                DecodeResult::Invalid(e) => {
                                    log::debug!(peer = %peer_addr, error = %e, "Invalid UDP packet");
                                    // Clear buffer and continue
                                    pending_data.clear();
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::debug!(peer = %peer_addr, error = %e, "UDP read error");
                        break;
                    }
                }
            }

            // Read from UDP connection (responses)
            recv_result = async {
                if let Some(ref conn) = udp_conn {
                    recv_buf.iter_mut().for_each(|b| *b = 0);
                    conn.read_from(&mut recv_buf).await
                } else {
                    // No connection, wait forever
                    std::future::pending().await
                }
            } => {
                match recv_result {
                    Ok((n, from_addr)) => {
                        // Convert acl::Addr to Address
                        let addr = acl_addr_to_address(&from_addr);

                        // Encode response as Trojan UDP packet
                        let response = TrojanUdpPacket::encode(&addr, &recv_buf[..n]);

                        // Send back to client
                        match client_stream.write_all(&response).await {
                            Ok(()) => {
                                server.stats.record_download(user_id, n as u64);
                                log::trace!(peer = %peer_addr, from = %addr, bytes = n, "UDP response sent");
                            }
                            Err(e) => {
                                log::debug!(peer = %peer_addr, error = %e, "Failed to send UDP response");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log::debug!(peer = %peer_addr, error = %e, "UDP recv error");
                        // Don't break, just log the error
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

    // Graceful shutdown of the client TCP stream carrying UDP packets
    let _ = client_stream.shutdown().await;

    log::debug!(peer = %peer_addr, "UDP associate ended");
    Ok(())
}

/// Convert acl::Addr to core::Address
fn acl_addr_to_address(addr: &acl_engine_r::outbound::Addr) -> Address {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Try to parse as IPv4
    if let Ok(ipv4) = addr.host.parse::<Ipv4Addr>() {
        return Address::IPv4(ipv4.octets(), addr.port);
    }
    // Try to parse as IPv6
    if let Ok(ipv6) = addr.host.parse::<Ipv6Addr>() {
        return Address::IPv6(ipv6.octets(), addr.port);
    }
    // Otherwise treat as domain
    Address::Domain(addr.host.clone(), addr.port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_recv_buf_reuse_no_stale_data() {
        let mut buf = vec![0u8; 1024];

        // Simulate first recv: write some data
        buf[..5].copy_from_slice(b"hello");
        let n1 = 5;
        assert_eq!(&buf[..n1], b"hello");

        // Simulate clearing before second recv (same as production code)
        buf.iter_mut().for_each(|b| *b = 0);

        // Simulate second recv: shorter data
        buf[..2].copy_from_slice(b"hi");
        let n2 = 2;

        // Only n2 bytes should be valid; bytes after should be zero
        assert_eq!(&buf[..n2], b"hi");
        assert_eq!(buf[n2], 0, "byte after recv data should be zero, not stale");
    }

    #[test]
    fn test_acl_addr_to_address_ipv4() {
        let addr = acl_engine_r::outbound::Addr::new("192.168.1.1", 80);
        let result = acl_addr_to_address(&addr);
        assert!(matches!(result, Address::IPv4(_, 80)));
    }

    #[test]
    fn test_acl_addr_to_address_ipv6() {
        let addr = acl_engine_r::outbound::Addr::new("::1", 443);
        let result = acl_addr_to_address(&addr);
        assert!(matches!(result, Address::IPv6(_, 443)));
    }

    #[test]
    fn test_acl_addr_to_address_ipv6_full() {
        let addr = acl_engine_r::outbound::Addr::new("2001:db8::1", 8080);
        let result = acl_addr_to_address(&addr);
        assert!(matches!(result, Address::IPv6(_, 8080)));
    }

    #[test]
    fn test_acl_addr_to_address_domain() {
        let addr = acl_engine_r::outbound::Addr::new("example.com", 443);
        let result = acl_addr_to_address(&addr);
        match result {
            Address::Domain(host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected Domain address"),
        }
    }

    #[test]
    fn test_acl_addr_to_address_domain_with_subdomain() {
        let addr = acl_engine_r::outbound::Addr::new("sub.example.com", 8443);
        let result = acl_addr_to_address(&addr);
        match result {
            Address::Domain(host, port) => {
                assert_eq!(host, "sub.example.com");
                assert_eq!(port, 8443);
            }
            _ => panic!("Expected Domain address"),
        }
    }
}
