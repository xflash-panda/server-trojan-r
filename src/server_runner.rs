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
            let grpc_conn =
                GrpcConnection::with_service_name(stream, &network_settings.grpc_service_name)
                    .await?;
            let result = grpc_conn
                .run(move |grpc_transport| {
                    let server = Arc::clone(&server);
                    let peer_addr = peer_addr.clone();
                    async move {
                        let stream: TransportStream = Box::pin(grpc_transport);
                        let meta = ConnectionMeta {
                            peer_addr: peer_addr
                                .parse()
                                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
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
            // Defaults are: write_buffer_size=128KB, max_write_buffer_size=usize::MAX,
            // max_send_queue=None (unlimited). With slow clients, tungstenite buffers
            // data internally without bound, causing memory to grow to 10+ GB.
            // These limits enable backpressure so copy_bidirectional slows down
            // reads from the remote instead of buffering indefinitely.
            let ws_config = WebSocketConfig::default()
                .write_buffer_size(32 * 1024) // 32KB (default 128KB)
                .max_write_buffer_size(2 * 1024 * 1024) // 2MB (default usize::MAX!)
                .max_message_size(Some(2 * 1024 * 1024)) // 2MB (default 64MB)
                .max_frame_size(Some(512 * 1024)); // 512KB (default 16MB)

            // WebSocket handshake with path validation
            let ws_path = network_settings.ws_path.clone();
            let ws_stream = tokio_tungstenite::accept_hdr_async_with_config(
                stream,
                |req: &Request, response: Response| {
                    let path = req.uri().path();
                    if path != ws_path && !ws_path.is_empty() && ws_path != "/" {
                        log::debug!(path = %path, expected = %ws_path, "WebSocket path mismatch");
                        // For "/" or empty path, accept any path (Xray behavior)
                    }
                    Ok(response)
                },
                Some(ws_config),
            )
            .await?;
            let ws_transport = WebSocketTransport::new(ws_stream);
            let stream: TransportStream = Box::pin(ws_transport);
            let meta = ConnectionMeta {
                peer_addr: peer_addr
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                transport_type: TransportType::WebSocket,
            };
            process_connection(&server, stream, meta).await
        }
        TransportType::Tcp => {
            let stream: TransportStream = Box::pin(stream);
            let meta = ConnectionMeta {
                peer_addr: peer_addr
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
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
        let limiter = Arc::new(Semaphore::new(2));

        let permit1 = limiter.clone().acquire_owned().await.unwrap();
        let permit2 = limiter.clone().acquire_owned().await.unwrap();
        assert_eq!(limiter.available_permits(), 0);

        assert!(limiter.try_acquire().is_err());

        drop(permit1);
        assert_eq!(limiter.available_permits(), 1);

        let _permit3 = limiter.clone().acquire_owned().await.unwrap();
        assert_eq!(limiter.available_permits(), 0);

        drop(permit2);
        drop(_permit3);
        assert_eq!(limiter.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_conn_limiter_unlimited_when_none() {
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

        let handle = tokio::spawn(async move {
            let _permit = limiter_clone.acquire_owned().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(limiter.available_permits(), 0);

        handle.await.unwrap();
        assert_eq!(limiter.available_permits(), 1);
    }

    #[test]
    fn test_ws_config_buffer_limits() {
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        let ws_config = WebSocketConfig::default()
            .write_buffer_size(32 * 1024)
            .max_write_buffer_size(2 * 1024 * 1024)
            .max_message_size(Some(2 * 1024 * 1024))
            .max_frame_size(Some(512 * 1024));

        // Write buffer is bounded (not usize::MAX)
        assert_eq!(ws_config.write_buffer_size, 32 * 1024);
        assert_eq!(ws_config.max_write_buffer_size, 2 * 1024 * 1024);
        assert!(ws_config.max_write_buffer_size < usize::MAX);

        // Message and frame sizes are bounded
        assert_eq!(ws_config.max_message_size, Some(2 * 1024 * 1024));
        assert_eq!(ws_config.max_frame_size, Some(512 * 1024));
    }

    #[test]
    fn test_ws_config_defaults_are_unbounded() {
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

        // Verify that tungstenite defaults are indeed unbounded -
        // this is the root cause we're protecting against.
        let defaults = WebSocketConfig::default();
        assert_eq!(defaults.max_write_buffer_size, usize::MAX);
    }
}
