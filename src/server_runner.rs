//! Server startup and accept loop
//!
//! This module handles server initialization, transport configuration,
//! and the main connection accept loop.

use crate::acl;
use crate::config;
use crate::core::{hooks, Server};
use crate::handler::process_connection;
use crate::logger::log;
use crate::transport::{ConnectionMeta, TransportStream, TransportType};

use anyhow::{anyhow, Result};
use socket2::{SockRef, TcpKeepalive};
use std::sync::Arc;

/// Build transport configuration from server config
pub fn build_transport_config(config: &config::ServerConfig) -> (TransportType, bool) {
    let transport_type = if config.enable_grpc {
        TransportType::Grpc
    } else if config.enable_ws {
        TransportType::WebSocket
    } else {
        TransportType::Tcp
    };

    let has_tls = config.cert.is_some() && config.key.is_some();

    (transport_type, has_tls)
}

/// Build outbound router from ACL configuration
pub async fn build_router(
    config: &config::ServerConfig,
    refresh_geodata: bool,
) -> Result<Arc<dyn hooks::OutboundRouter>> {
    use crate::acl::AclRouter;

    if let Some(ref acl_path) = config.acl_conf_file {
        if !acl_path.exists() {
            return Err(anyhow!("ACL config file not found: {}", acl_path.display()));
        }

        // Validate file extension
        let ext = acl_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
            return Err(anyhow!(
                "Invalid ACL config file format: expected .yaml or .yml"
            ));
        }

        let acl_config = acl::load_acl_config(acl_path).await?;
        let engine =
            acl::AclEngine::new(acl_config, Some(config.data_dir.as_path()), refresh_geodata)
                .await?;

        log::info!(
            acl_file = %acl_path.display(),
            rules = engine.rule_count(),
            block_private_ip = config.block_private_ip,
            refresh_geodata = refresh_geodata,
            "ACL router loaded"
        );

        Ok(Arc::new(AclRouter::with_block_private_ip(
            engine,
            config.block_private_ip,
        )) as Arc<dyn hooks::OutboundRouter>)
    } else {
        log::info!(
            block_private_ip = config.block_private_ip,
            "No ACL config, using direct connection for all traffic"
        );
        Ok(Arc::new(hooks::DirectRouter::with_block_private_ip(
            config.block_private_ip,
        )) as Arc<dyn hooks::OutboundRouter>)
    }
}

/// Network settings for transport layer
#[derive(Clone)]
pub struct NetworkSettings {
    /// gRPC service name (path becomes "/${service_name}/Tun")
    pub grpc_service_name: String,
    /// WebSocket path
    pub ws_path: String,
}

/// TCP keepalive interval — matches Go's net.ListenConfig default (15s).
/// Dead peers are detected in ~45s (3 probes × 15s).
const TCP_KEEPALIVE_SECS: u64 = 15;

/// Parse peer address string into SocketAddr, falling back to 0.0.0.0:0
fn parse_peer_addr(addr: &str) -> std::net::SocketAddr {
    addr.parse()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
}

/// Accept and handle a connection with proper transport wrapping
pub async fn accept_connection<S>(
    server: Arc<Server>,
    stream: S,
    peer_addr: String,
    transport_type: TransportType,
    network_settings: NetworkSettings,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use crate::transport::{GrpcConnection, WebSocketTransport};

    match transport_type {
        TransportType::Grpc => {
            let peer_addr_for_log = peer_addr.clone();
            log::debug!(peer = %peer_addr_for_log, "gRPC connection established, waiting for streams");
            let grpc_conn = GrpcConnection::with_config(
                stream,
                &network_settings.grpc_service_name,
                server.conn_config.buffer_size,
            )
            .await?;
            let result = grpc_conn
                .run(move |grpc_transport| {
                    let server = Arc::clone(&server);
                    let peer_addr = peer_addr.clone();
                    async move {
                        let stream: TransportStream = Box::pin(grpc_transport);
                        let meta = ConnectionMeta {
                            peer_addr: parse_peer_addr(&peer_addr),
                            transport_type: TransportType::Grpc,
                        };
                        process_connection(&server, stream, meta).await
                    }
                })
                .await;

            match &result {
                Ok(()) => {
                    log::debug!(peer = %peer_addr_for_log, "gRPC connection closed normally");
                }
                Err(e) => {
                    log::debug!(peer = %peer_addr_for_log, error = %e, "gRPC connection closed with error");
                }
            }
            result
        }
        TransportType::WebSocket => {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

            // Limit tungstenite internal buffers to prevent unbounded memory growth.
            // At 50k connections, tungstenite's defaults (write_buffer_size=128KB,
            // max_write_buffer_size=usize::MAX) would allow tens of GB total.
            // Our WebSocketTransport layer handles backpressure via Poll::Pending,
            // but tungstenite's own buffers must also be bounded.
            let buf_size = server.conn_config.buffer_size;
            let ws_config = WebSocketConfig::default()
                .write_buffer_size(buf_size) // matches relay buffer size
                .max_write_buffer_size(buf_size * 2) // 2x buffer_size (default usize::MAX!)
                .max_message_size(Some(buf_size * 4)) // 4x buffer_size = 128KB (default 64MB)
                .max_frame_size(Some(buf_size * 2)); // 2x buffer_size (default 16MB)

            // WebSocket handshake with path validation
            let ws_path = network_settings.ws_path.clone();
            let ws_stream = tokio_tungstenite::accept_hdr_async_with_config(
                stream,
                |req: &Request, response: Response| {
                    let path = req.uri().path();
                    // For "/" or empty path, accept any path (Xray behavior)
                    if !ws_path.is_empty() && ws_path != "/" && path != ws_path {
                        log::debug!(path = %path, expected = %ws_path, "WebSocket path mismatch");
                        let reject = http::Response::builder()
                            .status(http::StatusCode::NOT_FOUND)
                            .body(None)
                            .unwrap();
                        return Err(reject);
                    }
                    Ok(response)
                },
                Some(ws_config),
            )
            .await?;
            let ws_transport = WebSocketTransport::new(ws_stream);
            let stream: TransportStream = Box::pin(ws_transport);
            let meta = ConnectionMeta {
                peer_addr: parse_peer_addr(&peer_addr),
                transport_type: TransportType::WebSocket,
            };
            process_connection(&server, stream, meta).await
        }
        TransportType::Tcp => {
            let stream: TransportStream = Box::pin(stream);
            let meta = ConnectionMeta {
                peer_addr: parse_peer_addr(&peer_addr),
                transport_type: TransportType::Tcp,
            };
            process_connection(&server, stream, meta).await
        }
    }
}

/// Run the server accept loop
pub async fn run_server(server: Arc<Server>, config: &config::ServerConfig) -> Result<()> {
    use crate::transport::TlsTransportListener;
    use tokio::sync::Semaphore;

    let addr = format!("{}:{}", config.host, config.port);
    let (transport_type, has_tls) = build_transport_config(config);

    // Connection limiter: 0 = unlimited
    let conn_limiter = if server.conn_config.max_connections > 0 {
        Some(Arc::new(Semaphore::new(server.conn_config.max_connections)))
    } else {
        None
    };

    // Build TLS acceptor if needed
    let tls_acceptor = if has_tls {
        let tls_config = TlsTransportListener::load_tls_config(
            config.cert.as_ref().unwrap(),
            config.key.as_ref().unwrap(),
        )?;
        Some(tokio_rustls::TlsAcceptor::from(tls_config))
    } else {
        None
    };

    // Bind TCP listener with SO_REUSEADDR for fast restarts
    let socket_addr: std::net::SocketAddr = addr.parse()?;
    let socket = socket2::Socket::new(
        match socket_addr {
            std::net::SocketAddr::V4(_) => socket2::Domain::IPV4,
            std::net::SocketAddr::V6(_) => socket2::Domain::IPV6,
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    // Allow immediate rebind after restart (skip TIME_WAIT)
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket_addr.into())?;
    socket.listen(server.conn_config.tcp_backlog)?;

    let listener = tokio::net::TcpListener::from_std(socket.into())?;
    let local_addr = listener.local_addr()?;

    // Build network settings from config
    let network_settings = NetworkSettings {
        grpc_service_name: config.grpc_service_name.clone(),
        ws_path: config.ws_path.clone(),
    };

    log::info!(
        address = %local_addr,
        transport = %transport_type,
        tls = has_tls,
        max_connections = server.conn_config.max_connections,
        ws_path = %network_settings.ws_path,
        grpc_service = %network_settings.grpc_service_name,
        "Server started"
    );

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let peer_addr = addr.to_string();
                log::connection(&peer_addr, "new");

                // Acquire connection permit (backpressure when at limit)
                let _permit = if let Some(ref limiter) = conn_limiter {
                    match limiter.clone().acquire_owned().await {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            // Semaphore closed, shutting down
                            break;
                        }
                    }
                } else {
                    None
                };

                let server = Arc::clone(&server);
                let tls_acceptor = tls_acceptor.clone();
                let network_settings = network_settings.clone();

                tokio::spawn(async move {
                    // Hold permit for the lifetime of this connection
                    let _permit = _permit;
                    let result = async {
                        // Set TCP_NODELAY for lower latency
                        if server.conn_config.tcp_nodelay {
                            let _ = stream.set_nodelay(true);
                        }

                        // Enable TCP keepalive to detect dead peers (mobile disconnect, network change, etc.)
                        let keepalive = TcpKeepalive::new()
                            .with_time(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS))
                            .with_interval(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS));
                        let _ = SockRef::from(&stream).set_tcp_keepalive(&keepalive);

                        if let Some(tls_acceptor) = tls_acceptor {
                            // TLS handshake with timeout
                            match tokio::time::timeout(
                                server.conn_config.tls_handshake_timeout,
                                tls_acceptor.accept(stream),
                            )
                            .await
                            {
                                Ok(Ok(tls_stream)) => {
                                    log::debug!(peer = %peer_addr, "TLS handshake successful");
                                    accept_connection(server, tls_stream, peer_addr.clone(), transport_type, network_settings).await
                                }
                                Ok(Err(e)) => {
                                    log::debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                                    Err(anyhow!("TLS handshake failed: {}", e))
                                }
                                Err(_) => {
                                    log::debug!(peer = %peer_addr, "TLS handshake timeout");
                                    Err(anyhow!("TLS handshake timeout"))
                                }
                            }
                        } else {
                            accept_connection(server, stream, peer_addr.clone(), transport_type, network_settings).await
                        }
                    }
                    .await;

                    if let Err(e) = result {
                        log::debug!(peer = %peer_addr, error = %e, "Connection error");
                    }
                    log::connection(&peer_addr, "closed");
                });
            }
            Err(e) => {
                log::error!(error = %e, "Failed to accept connection");
                // Continue accepting unless it's a fatal error
                if e.kind() == std::io::ErrorKind::Other {
                    break;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn test_conn_limiter_backpressure() {
        // Simulate max_connections = 2
        let limiter = Arc::new(Semaphore::new(2));

        // Acquire 2 permits (simulates 2 active connections)
        let permit1 = limiter.clone().acquire_owned().await.unwrap();
        let permit2 = limiter.clone().acquire_owned().await.unwrap();
        assert_eq!(limiter.available_permits(), 0);

        // 3rd acquire should block — verify with try_acquire
        assert!(limiter.try_acquire().is_err());

        // Drop one permit (connection closes) -> slot freed
        drop(permit1);
        assert_eq!(limiter.available_permits(), 1);

        // Now a new connection can acquire
        let _permit3 = limiter.clone().acquire_owned().await.unwrap();
        assert_eq!(limiter.available_permits(), 0);

        drop(permit2);
        drop(_permit3);
        assert_eq!(limiter.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_conn_limiter_unlimited_when_none() {
        // max_connections = 0 -> conn_limiter is None -> no limit
        let max_connections: usize = 0;
        let conn_limiter: Option<Arc<Semaphore>> = if max_connections > 0 {
            Some(Arc::new(Semaphore::new(max_connections)))
        } else {
            None
        };

        assert!(conn_limiter.is_none());
    }

    #[tokio::test]
    async fn test_conn_limiter_permit_moved_into_task() {
        let limiter = Arc::new(Semaphore::new(1));
        let limiter_clone = limiter.clone();

        // Simulate: acquire in accept loop, move into spawned task
        let handle = tokio::spawn(async move {
            let _permit = limiter_clone.acquire_owned().await.unwrap();
            // Simulate connection work
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            // _permit dropped here when task ends
        });

        // Give the task time to acquire
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(limiter.available_permits(), 0);

        // Wait for task to finish
        handle.await.unwrap();
        assert_eq!(limiter.available_permits(), 1);
    }

    #[test]
    fn test_ws_config_buffer_limits() {
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        let buf_size: usize = 32 * 1024;
        let ws_config = WebSocketConfig::default()
            .write_buffer_size(buf_size)
            .max_write_buffer_size(buf_size * 2)
            .max_message_size(Some(buf_size * 4))
            .max_frame_size(Some(buf_size * 2));

        // Write buffer matches configured buffer_size
        assert_eq!(ws_config.write_buffer_size, buf_size);
        // Max write buffer is 2x buffer_size and bounded (not usize::MAX)
        assert_eq!(ws_config.max_write_buffer_size, buf_size * 2);
        assert!(ws_config.max_write_buffer_size < usize::MAX);

        // Message and frame sizes are bounded
        assert_eq!(ws_config.max_message_size, Some(buf_size * 4));
        assert_eq!(ws_config.max_frame_size, Some(buf_size * 2));
    }

    #[test]
    fn test_tcp_keepalive_interval() {
        use super::TCP_KEEPALIVE_SECS;
        // Match Go net.ListenConfig default: 15s keepalive
        assert_eq!(TCP_KEEPALIVE_SECS, 15);
        // 3 probes × 15s interval = ~45s detection time
        let detection_time = TCP_KEEPALIVE_SECS * 3;
        assert!(
            detection_time <= 60,
            "keepalive detection should be under 60s"
        );
    }

    #[test]
    fn test_ws_config_defaults_are_unbounded() {
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        // Verify that tungstenite defaults are indeed unbounded -
        // this is the root cause we're protecting against.
        let defaults = WebSocketConfig::default();
        assert_eq!(defaults.max_write_buffer_size, usize::MAX);
    }

    #[test]
    fn test_parse_peer_addr_valid_ipv4() {
        use super::parse_peer_addr;
        let addr = parse_peer_addr("127.0.0.1:8080");
        assert_eq!(addr.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_peer_addr_valid_ipv6() {
        use super::parse_peer_addr;
        let addr = parse_peer_addr("[::1]:443");
        assert_eq!(addr.ip(), std::net::Ipv6Addr::LOCALHOST);
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_parse_peer_addr_invalid_falls_back() {
        use super::parse_peer_addr;
        let addr = parse_peer_addr("not-an-address");
        assert_eq!(addr, std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    }

    #[test]
    fn test_parse_peer_addr_empty_falls_back() {
        use super::parse_peer_addr;
        let addr = parse_peer_addr("");
        assert_eq!(addr, std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    }

    #[test]
    fn test_parse_peer_addr_missing_port_falls_back() {
        use super::parse_peer_addr;
        let addr = parse_peer_addr("127.0.0.1");
        assert_eq!(addr, std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    }

    /// Verify WS path validation logic: non-empty, non-"/" path should reject mismatch
    #[test]
    fn test_ws_path_validation_logic() {
        // Simulates the condition used in accept_connection
        let check_path = |ws_path: &str, request_path: &str| -> bool {
            // Returns true if connection should be REJECTED
            !ws_path.is_empty() && ws_path != "/" && request_path != ws_path
        };

        // Configured path "/secret", request path matches → accept
        assert!(!check_path("/secret", "/secret"));

        // Configured path "/secret", request path differs → reject
        assert!(check_path("/secret", "/other"));
        assert!(check_path("/secret", "/"));
        assert!(check_path("/secret", ""));

        // Configured path is "/" → accept all (Xray behavior)
        assert!(!check_path("/", "/anything"));
        assert!(!check_path("/", "/"));

        // Configured path is empty → accept all (Xray behavior)
        assert!(!check_path("", "/anything"));
        assert!(!check_path("", ""));
    }
}
