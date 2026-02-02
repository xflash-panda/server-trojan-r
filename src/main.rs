//! Trojan proxy server with layered architecture
//!
//! Architecture:
//! - `core/`: Core proxy logic with hook traits for extensibility
//! - `transport/`: Transport layer abstraction (TCP, WebSocket, gRPC)
//! - `business/`: Business implementations (API, auth, stats)

mod acl;
mod business;
mod config;
mod core;
mod error;
mod logger;
mod transport;

// Use mimalloc as the global allocator for better performance
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use logger::log;

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::business::{
    ApiAuthenticator, ApiManager, ApiStatsCollector, BackgroundTasks, TaskConfig, UserManager,
};
use crate::core::{
    copy_bidirectional_with_stats, Address, ConnectionManager, DecodeResult, Server, TrojanCmd,
    TrojanRequest, UserId,
};
use crate::transport::{ConnectionMeta, TransportStream, TransportType};

/// Read and decode a complete Trojan request from the stream
///
/// This function handles partial reads by continuing to read until
/// a complete request is received or an error occurs.
async fn read_trojan_request(
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
async fn process_connection(
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
            // UDP support would be implemented here
            log::debug!(peer = %peer_addr, "UDP associate not implemented in new architecture");
            Err(anyhow!("UDP associate not implemented"))
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
    if matches!(outbound_type, core::hooks::OutboundType::Reject) {
        log::debug!(peer = %peer_addr, target = %target, "Connection rejected by router");
        return Ok(());
    }

    log::debug!(peer = %peer_addr, target = %target, outbound = ?outbound_type, "Connecting to target");

    // Connect based on outbound type
    match outbound_type {
        core::hooks::OutboundType::Direct => {
            handle_direct_connect(
                server,
                client_stream,
                &target,
                initial_payload,
                &peer_addr,
                user_id,
                cancel_token,
            )
            .await
        }
        core::hooks::OutboundType::Reject => {
            // Already handled above
            Ok(())
        }
    }
}

/// Handle direct connection
async fn handle_direct_connect(
    server: &Server,
    client_stream: TransportStream,
    target: &Address,
    initial_payload: bytes::Bytes,
    peer_addr: &str,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Resolve target address
    let remote_addr = target.to_socket_addr().await?;

    // Connect with timeout
    let mut remote_stream = match tokio::time::timeout(
        server.conn_config.connect_timeout,
        TcpStream::connect(remote_addr),
    )
    .await
    {
        Ok(Ok(stream)) => {
            if server.conn_config.tcp_nodelay {
                let _ = stream.set_nodelay(true);
            }
            stream
        }
        Ok(Err(e)) => {
            log::debug!(peer = %peer_addr, error = %e, "TCP connect failed");
            return Err(e.into());
        }
        Err(_) => {
            log::debug!(peer = %peer_addr, "TCP connect timeout");
            return Err(anyhow!("TCP connect timeout"));
        }
    };

    log::debug!(peer = %peer_addr, remote = %remote_addr, "Connected to remote (direct)");

    // Write initial payload if any
    if !initial_payload.is_empty() {
        server
            .stats
            .record_upload(user_id, initial_payload.len() as u64);
        remote_stream.write_all(&initial_payload).await?;
    }

    // Relay data with stats tracking and cancellation support
    let stats = Arc::clone(&server.stats);
    let relay_fut = copy_bidirectional_with_stats(
        client_stream,
        remote_stream,
        server.conn_config.idle_timeout_secs(),
        Some((user_id, stats)),
    );

    tokio::select! {
        result = relay_fut => {
            match result {
                Ok(r) if r.completed => {}
                Ok(_) => {
                    log::debug!(peer = %peer_addr, "Connection timeout due to inactivity");
                }
                Err(e) => {
                    log::debug!(peer = %peer_addr, error = %e, "Relay error");
                }
            }
        }
        _ = cancel_token.cancelled() => {
            log::debug!(peer = %peer_addr, "Connection kicked by admin");
        }
    }

    Ok(())
}

/// Build transport configuration
fn build_transport_config(config: &config::ServerConfig) -> (TransportType, bool) {
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
async fn build_router(
    config: &config::ServerConfig,
    refresh_geodata: bool,
) -> Result<Arc<dyn core::hooks::OutboundRouter>> {
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
        )) as Arc<dyn core::hooks::OutboundRouter>)
    } else {
        log::info!(
            block_private_ip = config.block_private_ip,
            "No ACL config, using direct connection for all traffic"
        );
        Ok(Arc::new(core::hooks::DirectRouter::with_block_private_ip(
            config.block_private_ip,
        )) as Arc<dyn core::hooks::OutboundRouter>)
    }
}

/// Network settings for transport layer
#[derive(Clone)]
struct NetworkSettings {
    /// gRPC service name (path becomes "/${service_name}/Tun")
    grpc_service_name: String,
    /// WebSocket path
    ws_path: String,
}

/// Accept and handle a connection with proper transport wrapping
async fn accept_connection<S>(
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
async fn run_server(server: Arc<Server>, config: &config::ServerConfig) -> Result<()> {
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

#[tokio::main]
async fn main() -> Result<()> {
    // Install ring as the default crypto provider for rustls
    // This must be done before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Parse CLI arguments
    let cli = config::CliArgs::parse_args();
    cli.validate()?;

    // Initialize logger
    logger::init_logger(&cli.log_mode);

    log::info!(
        api = %cli.api,
        node = cli.node,
        "Starting Trojan server with layered architecture"
    );

    // Create connection manager (shared between core and business layers)
    let conn_manager = ConnectionManager::new();

    // Create API manager
    let api_manager = Arc::new(ApiManager::new(&cli)?);

    // Create user manager
    let user_manager = Arc::new(UserManager::new(conn_manager.clone()));

    // Fetch configuration from remote panel (needed for port before registration)
    let remote_config = api_manager.fetch_config().await?;

    // Initialize node with port from config
    let register_id = api_manager.initialize(remote_config.server_port).await?;
    log::info!(register_id = %register_id, "Node initialized");

    // Fetch initial users
    let users = api_manager.fetch_users().await?;
    user_manager.init(&users).await;

    // Build server config
    let server_config = config::ServerConfig::from_remote(&remote_config, &cli, users)?;

    // Create authenticator using shared user map
    let authenticator = Arc::new(ApiAuthenticator::new(user_manager.get_users_arc()));

    // Create stats collector
    let stats_collector = Arc::new(ApiStatsCollector::new());

    // Build router from ACL config
    let router = build_router(&server_config, cli.refresh_geodata).await?;

    // Build connection config from CLI args
    let conn_config = config::ConnConfig::from_cli(&cli);

    // Build server using the builder pattern
    let server = Arc::new(
        Server::builder()
            .authenticator(authenticator)
            .stats(Arc::clone(&stats_collector) as Arc<dyn core::hooks::StatsCollector>)
            .router(router)
            .conn_manager(conn_manager)
            .conn_config(conn_config)
            .build(),
    );

    // Start background tasks
    let task_config = TaskConfig::new(
        cli.fetch_users_interval,
        cli.report_traffics_interval,
        cli.heartbeat_interval,
    );
    let background_tasks = BackgroundTasks::new(
        task_config,
        Arc::clone(&api_manager),
        Arc::clone(&user_manager),
        Arc::clone(&stats_collector),
    );
    background_tasks.start();

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    // Setup shutdown handler
    let api_for_shutdown = Arc::clone(&api_manager);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to setup SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM");

            tokio::select! {
                _ = sigint.recv() => {
                    log::info!("SIGINT received, shutting down...");
                }
                _ = sigterm.recv() => {
                    log::info!("SIGTERM received, shutting down...");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
            log::info!("Shutdown signal received...");
        }

        // Unregister node
        log::info!("Unregistering node...");
        if let Err(e) = api_for_shutdown.unregister().await {
            log::warn!(error = %e, "Failed to unregister node");
        } else {
            log::info!("Node unregistered successfully");
        }

        cancel_token_clone.cancel();
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });

    // Run server
    run_server(server, &server_config).await
}
