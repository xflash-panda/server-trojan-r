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
    TrojanRequest,
};
use crate::transport::{ConnectionMeta, TransportListener, TransportStream, TransportType};

const BUF_SIZE: usize = 32 * 1024;
const CONNECTION_TIMEOUT_SECS: u64 = 300;
const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Process a single connection
async fn process_connection(
    server: &Server,
    mut stream: TransportStream,
    meta: ConnectionMeta,
) -> Result<()> {
    // Read Trojan request
    let mut buf = BytesMut::with_capacity(BUF_SIZE);
    buf.resize(BUF_SIZE, 0);
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Err(anyhow!("Connection closed before receiving request"));
    }

    buf.truncate(n);

    // Decode request (zero-copy)
    let request = match TrojanRequest::decode_zerocopy(&mut buf) {
        DecodeResult::Ok(req, _) => req,
        DecodeResult::NeedMoreData => {
            return Err(anyhow!("Incomplete request"));
        }
        DecodeResult::Invalid(e) => {
            return Err(anyhow!("Invalid request: {}", e));
        }
    };

    let peer_addr = meta.peer_addr.to_string();

    // Authenticate user
    let user_id = match server.authenticator.authenticate(&request.password).await {
        Some(id) => id,
        None => {
            log::authentication(&peer_addr, false);
            log::warn!(
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
            log::warn!(peer = %peer_addr, "UDP associate not implemented in new architecture");
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
    user_id: u64,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Get host and port for routing
    let (host, port) = match &target {
        Address::IPv4(ip, port) => (std::net::Ipv4Addr::from(*ip).to_string(), *port),
        Address::IPv6(ip, port) => (std::net::Ipv6Addr::from(*ip).to_string(), *port),
        Address::Domain(domain, port) => (domain.clone(), *port),
    };

    // Route the connection
    let outbound_type = server.router.route(&host, port).await;

    // Check if connection should be rejected
    if matches!(outbound_type, core::hooks::OutboundType::Reject) {
        log::info!(peer = %peer_addr, target = %target, "Connection rejected by router");
        return Ok(());
    }

    log::info!(peer = %peer_addr, target = %target, outbound = ?outbound_type, "Connecting to target");

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
    user_id: u64,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Resolve target address
    let remote_addr = target.to_socket_addr().await?;

    // Connect with timeout
    let mut remote_stream = match tokio::time::timeout(
        tokio::time::Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        TcpStream::connect(remote_addr),
    )
    .await
    {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            stream
        }
        Ok(Err(e)) => {
            log::warn!(peer = %peer_addr, error = %e, "TCP connect failed");
            return Err(e.into());
        }
        Err(_) => {
            log::warn!(peer = %peer_addr, "TCP connect timeout");
            return Err(anyhow!("TCP connect timeout"));
        }
    };

    log::info!(peer = %peer_addr, remote = %remote_addr, "Connected to remote (direct)");

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
        CONNECTION_TIMEOUT_SECS,
        Some((user_id, stats)),
    );

    tokio::select! {
        result = relay_fut => {
            match result {
                Ok(r) if r.completed => {}
                Ok(_) => {
                    log::warn!(peer = %peer_addr, "Connection timeout due to inactivity");
                }
                Err(e) => {
                    log::debug!(peer = %peer_addr, error = %e, "Relay error");
                }
            }
        }
        _ = cancel_token.cancelled() => {
            log::info!(peer = %peer_addr, "Connection kicked by admin");
        }
    }

    Ok(())
}

/// Build transport listener based on configuration
async fn build_transport_listener(
    config: &config::ServerConfig,
) -> Result<Box<dyn TransportListener>> {
    use crate::transport::TcpTransportListener;

    let addr = format!("{}:{}", config.host, config.port);

    // Determine transport type
    let transport_type = if config.enable_grpc {
        TransportType::Grpc
    } else if config.enable_ws {
        TransportType::WebSocket
    } else {
        TransportType::Tcp
    };

    // For now, just use TCP listener
    // Full transport layer integration will be done in a future iteration
    let tcp_listener = TcpTransportListener::bind(&addr).await?;

    log::info!(
        address = %addr,
        transport = %transport_type,
        tls = config.cert.is_some(),
        "Transport listener created"
    );

    Ok(Box::new(tcp_listener))
}

/// Build outbound router from ACL configuration
async fn build_router(
    config: &config::ServerConfig,
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
        let engine = acl::AclEngine::new(acl_config, Some(config.data_dir.as_path())).await?;

        log::info!(
            acl_file = %acl_path.display(),
            rules = engine.rule_count(),
            "ACL router loaded"
        );

        Ok(Arc::new(AclRouter::new(engine)) as Arc<dyn core::hooks::OutboundRouter>)
    } else {
        log::info!("No ACL config, using direct connection for all traffic");
        Ok(Arc::new(core::hooks::DirectRouter) as Arc<dyn core::hooks::OutboundRouter>)
    }
}

/// Run the server accept loop
async fn run_server(
    server: Arc<Server>,
    listener: Box<dyn TransportListener>,
    transport_type: TransportType,
) -> Result<()> {
    let addr = listener.local_addr()?;
    log::info!(address = %addr, transport = %transport_type, "Server started");

    loop {
        match listener.accept().await {
            Ok((stream, meta)) => {
                let peer_addr = meta.peer_addr.to_string();
                log::connection(&peer_addr, "new");

                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    let result = process_connection(&server, stream, meta).await;
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

    // Initialize node
    let register_id = api_manager.initialize().await?;
    log::info!(register_id = %register_id, "Node initialized");

    // Fetch configuration from remote panel
    let remote_config = api_manager.fetch_config().await?;

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
    let router = build_router(&server_config).await?;

    // Determine transport type for logging
    let transport_type = if server_config.enable_grpc {
        TransportType::Grpc
    } else if server_config.enable_ws {
        TransportType::WebSocket
    } else {
        TransportType::Tcp
    };

    // Build server using the builder pattern
    let server = Arc::new(
        Server::builder()
            .authenticator(authenticator)
            .stats(Arc::clone(&stats_collector) as Arc<dyn core::hooks::StatsCollector>)
            .router(router)
            .conn_manager(conn_manager)
            .build(),
    );

    // Build transport listener
    let listener = build_transport_listener(&server_config).await?;

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
    run_server(server, listener, transport_type).await
}
