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

            // WebSocket handshake with path validation
            let ws_path = network_settings.ws_path.clone();
            let ws_stream =
                tokio_tungstenite::accept_hdr_async(stream, |req: &Request, response: Response| {
                    let path = req.uri().path();
                    if path != ws_path && !ws_path.is_empty() && ws_path != "/" {
                        log::debug!(path = %path, expected = %ws_path, "WebSocket path mismatch");
                        // For "/" or empty path, accept any path (Xray behavior)
                    }
                    Ok(response)
                })
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

    let addr = format!("{}:{}", config.host, config.port);
    let (transport_type, has_tls) = build_transport_config(config);

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
        ws_path = %network_settings.ws_path,
        grpc_service = %network_settings.grpc_service_name,
        "Server started"
    );

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let peer_addr = addr.to_string();
                log::connection(&peer_addr, "new");

                let server = Arc::clone(&server);
                let tls_acceptor = tls_acceptor.clone();
                let network_settings = network_settings.clone();

                tokio::spawn(async move {
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
