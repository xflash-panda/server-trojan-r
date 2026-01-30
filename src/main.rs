mod acl;
mod address;
mod api;
mod config;
mod error;
mod grpc;
mod logger;
mod relay;
mod stats;
mod tls;
mod udp;
mod utils;
mod ws;

// Use mimalloc as the global allocator for better performance
// (5-15% improvement in allocation-heavy workloads)
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use logger::log;

use acl::AsyncOutbound;
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const BUF_SIZE: usize = 32 * 1024;

const CONNECTION_TIMEOUT_SECS: u64 = 300;
const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Copy)]
pub enum TransportMode {
    Tcp,
    WebSocket,
    Grpc,
}

pub struct Server {
    pub listener: TcpListener,
    /// Shared users map (updated by UserManager)
    pub users: Arc<RwLock<HashMap<[u8; 56], i64>>>,
    pub transport_mode: TransportMode,
    pub enable_udp: bool,
    pub udp_associations: udp::UdpAssociations,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub acl_engine: Option<Arc<acl::AclEngine>>,
    /// Stats manager for tracking user traffic
    pub stats: stats::StatsManager,
    /// Connection manager for tracking active connections and kick-off capability
    pub connections: stats::ConnectionManager,
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Ok = 0,
    ErrRead = 1,
    ErrWrite = 2,
    ErrResolve = 3,
    MoreData = 4,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrojanCmd {
    Connect = 1,
    UdpAssociate = 3,
}

#[derive(Debug)]
pub struct TrojanRequest {
    pub password: [u8; 56],
    pub cmd: TrojanCmd,
    pub addr: address::Address,
    pub payload: Bytes,
}

impl TrojanRequest {
    /// Decode Trojan request from buffer (legacy version with copy)
    #[allow(dead_code)]
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 59 {
            return Err(anyhow!("Buffer too small"));
        }

        let mut cursor = 0;

        let mut password = [0u8; 56];
        password.copy_from_slice(&buf[cursor..cursor + 56]);
        cursor += 56;

        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after password"));
        }
        cursor += 2;

        let cmd = match buf[cursor] {
            1 => TrojanCmd::Connect,
            3 => TrojanCmd::UdpAssociate,
            _ => return Err(anyhow!("Invalid command")),
        };
        cursor += 1;

        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => {
                if buf.len() < cursor + 6 {
                    return Err(anyhow!("Buffer too small for IPv4"));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::IPv4(ip, port)
            }
            3 => {
                if buf.len() <= cursor {
                    return Err(anyhow!("Buffer too small for domain length"));
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len + 2 {
                    return Err(anyhow!("Buffer too small for domain"));
                }
                let domain = std::str::from_utf8(&buf[cursor..cursor + domain_len])
                    .map_err(|e| anyhow!("Invalid UTF-8 domain: {}", e))?
                    .to_string();
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::Domain(domain, port)
            }
            4 => {
                if buf.len() < cursor + 18 {
                    return Err(anyhow!("Buffer too small for IPv6"));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::IPv6(ip, port)
            }
            _ => return Err(anyhow!("Invalid address type")),
        };

        if buf.len() < cursor + 2 || buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after address"));
        }
        cursor += 2;

        let payload = Bytes::copy_from_slice(&buf[cursor..]);

        Ok((
            TrojanRequest {
                password,
                cmd,
                addr,
                payload,
            },
            cursor,
        ))
    }

    /// Decode Trojan request from BytesMut with zero-copy payload extraction
    ///
    /// This version avoids copying the payload data by using BytesMut::split_off()
    /// which shares the underlying allocation.
    pub fn decode_zerocopy(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 59 {
            return Err(anyhow!("Buffer too small"));
        }

        let mut cursor = 0;

        let mut password = [0u8; 56];
        password.copy_from_slice(&buf[cursor..cursor + 56]);
        cursor += 56;

        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after password"));
        }
        cursor += 2;

        let cmd = match buf[cursor] {
            1 => TrojanCmd::Connect,
            3 => TrojanCmd::UdpAssociate,
            _ => return Err(anyhow!("Invalid command")),
        };
        cursor += 1;

        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => {
                if buf.len() < cursor + 6 {
                    return Err(anyhow!("Buffer too small for IPv4"));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::IPv4(ip, port)
            }
            3 => {
                if buf.len() <= cursor {
                    return Err(anyhow!("Buffer too small for domain length"));
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len + 2 {
                    return Err(anyhow!("Buffer too small for domain"));
                }
                let domain = std::str::from_utf8(&buf[cursor..cursor + domain_len])
                    .map_err(|e| anyhow!("Invalid UTF-8 domain: {}", e))?
                    .to_string();
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::Domain(domain, port)
            }
            4 => {
                if buf.len() < cursor + 18 {
                    return Err(anyhow!("Buffer too small for IPv6"));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                address::Address::IPv6(ip, port)
            }
            _ => return Err(anyhow!("Invalid address type")),
        };

        if buf.len() < cursor + 2 || buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after address"));
        }
        cursor += 2;

        // Zero-copy: split_off returns a new BytesMut sharing the allocation
        // freeze() converts it to Bytes without copying
        let payload = buf.split_off(cursor).freeze();

        // Clear the header portion (we've consumed it)
        buf.clear();

        Ok(TrojanRequest {
            password,
            cmd,
            addr,
            payload,
        })
    }
}

async fn handle_connection<S>(server: Arc<Server>, stream: S, peer_addr: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 只需要一套 Trojan 协议处理逻辑
    process_trojan(server, stream, peer_addr).await
}

async fn process_trojan<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    server: Arc<Server>,
    mut stream: S,
    peer_addr: String,
) -> Result<()> {
    // 读取 Trojan 请求 - 使用 BytesMut 实现零拷贝
    let mut buf = BytesMut::with_capacity(BUF_SIZE);
    buf.resize(BUF_SIZE, 0);
    let n = stream.read(&mut buf).await?;

    if n == 0 {
        return Err(anyhow!("Connection closed before receiving request"));
    }

    // Truncate to actual read size
    buf.truncate(n);

    // Zero-copy decode
    let request = TrojanRequest::decode_zerocopy(&mut buf)?;

    // 验证用户 (通过 uuid 验证) - 需要获取读锁
    let user_id = {
        let users = server.users.read().await;
        match users.get(&request.password) {
            Some(&id) => id,
            None => {
                let transport = match server.transport_mode {
                    TransportMode::Tcp => "TCP",
                    TransportMode::WebSocket => "WS",
                    TransportMode::Grpc => "gRPC",
                };
                log::authentication(&peer_addr, false);
                log::warn!(peer = %peer_addr, transport = transport, "Invalid user credentials");
                return Err(anyhow!("Invalid user credentials"));
            }
        }
    };

    log::authentication(&peer_addr, true);
    log::debug!(peer = %peer_addr, user_id = user_id, "User authenticated");

    // Register connection for tracking and kick-off capability
    let (conn_id, cancel_token) = server
        .connections
        .register(user_id as u64, peer_addr.clone());
    log::debug!(peer = %peer_addr, user_id = user_id, conn_id = conn_id, "Connection registered");

    // Ensure connection is unregistered when done
    let _guard = scopeguard::guard((), |_| {
        server.connections.unregister(conn_id);
        log::debug!(conn_id = conn_id, "Connection unregistered");
    });

    // Record proxy request for this user
    server.stats.record_request(user_id as u64);

    // Get user stats for traffic tracking
    let user_stats = server.stats.get_or_create(user_id as u64);

    match request.cmd {
        TrojanCmd::Connect => {
            handle_connect(
                stream,
                request.addr,
                request.payload,
                peer_addr,
                server.acl_engine.clone(),
                user_stats,
                cancel_token,
            )
            .await
        }
        TrojanCmd::UdpAssociate => {
            if !server.enable_udp {
                log::warn!(peer = %peer_addr, "UDP associate request rejected: UDP support is disabled");
                return Err(anyhow!("UDP support is disabled"));
            }
            udp::handle_udp_associate(
                Arc::clone(&server.udp_associations),
                stream,
                request.addr,
                peer_addr,
                server.acl_engine.clone(),
                user_stats,
                cancel_token,
            )
            .await
        }
    }
}

// 统一的 CONNECT 处理

async fn handle_connect<S: AsyncRead + AsyncWrite + Unpin>(
    client_stream: S,
    target_addr: address::Address,
    initial_payload: Bytes,
    peer_addr: String,
    acl_engine: Option<Arc<acl::AclEngine>>,
    user_stats: Arc<stats::UserStats>,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Get host and port for ACL matching
    let (host, port) = match &target_addr {
        address::Address::IPv4(ip, port) => (std::net::Ipv4Addr::from(*ip).to_string(), *port),
        address::Address::IPv6(ip, port) => (std::net::Ipv6Addr::from(*ip).to_string(), *port),
        address::Address::Domain(domain, port) => (domain.clone(), *port),
    };

    // Match against ACL rules
    let outbound = if let Some(ref engine) = acl_engine {
        engine.match_host(&host, port, acl::Protocol::TCP)
    } else {
        None
    };

    // Check if connection should be rejected
    if let Some(ref handler) = outbound {
        if handler.is_reject() {
            log::info!(peer = %peer_addr, target = %target_addr.to_key(), "Connection rejected by ACL");
            return Ok(());
        }
    }

    log::info!(peer = %peer_addr, target = %target_addr.to_key(), outbound = ?outbound, "Connecting to target");

    // Use ACL outbound or direct connection
    if let Some(handler) = outbound {
        // Use acl-engine-r's async outbound
        let mut acl_addr = acl::Addr::new(&host, port);

        let mut tcp_conn: Box<dyn acl::AsyncTcpConn> = match tokio::time::timeout(
            tokio::time::Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
            handler.dial_tcp(&mut acl_addr),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                log::warn!(peer = %peer_addr, error = %e, "ACL outbound connect failed");
                return Err(anyhow!("ACL outbound connect failed: {}", e));
            }
            Err(_) => {
                log::warn!(peer = %peer_addr, timeout_secs = TCP_CONNECT_TIMEOUT_SECS, "ACL outbound connect timeout");
                return Err(anyhow!(
                    "ACL outbound connect timeout after {} seconds",
                    TCP_CONNECT_TIMEOUT_SECS
                ));
            }
        };

        log::info!(peer = %peer_addr, target = %target_addr.to_key(), "Connected via ACL outbound");

        // Write initial payload if any
        if !initial_payload.is_empty() {
            user_stats.add_upload(initial_payload.len() as u64);
            tcp_conn.write_all(&initial_payload).await?;
        }

        // Relay data with stats tracking and cancellation support
        let relay_fut = relay::copy_bidirectional_with_stats(
            client_stream,
            tcp_conn,
            CONNECTION_TIMEOUT_SECS,
            Some(user_stats),
        );

        tokio::select! {
            result = relay_fut => {
                match result {
                    Ok(r) if r.completed => {}
                    Ok(_) => {
                        log::warn!(peer = %peer_addr, "Connection timeout due to inactivity");
                    }
                    Err(e) => {
                        log::debug!(peer = %peer_addr, error = %e, "Copy bidirectional error");
                    }
                }
            }
            _ = cancel_token.cancelled() => {
                log::info!(peer = %peer_addr, "Connection kicked by admin");
            }
        }
    } else {
        // Direct connection (no ACL engine or no match)
        let remote_addr = target_addr.to_socket_addr().await?;
        let mut remote_stream = match tokio::time::timeout(
            tokio::time::Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
            TcpStream::connect(remote_addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                // Set TCP_NODELAY to disable Nagle's algorithm for lower latency
                let _ = stream.set_nodelay(true);
                stream
            }
            Ok(Err(e)) => {
                log::warn!(peer = %peer_addr, error = %e, "TCP connect failed");
                return Err(e.into());
            }
            Err(_) => {
                log::warn!(peer = %peer_addr, timeout_secs = TCP_CONNECT_TIMEOUT_SECS, "TCP connect timeout");
                return Err(anyhow!(
                    "TCP connect timeout after {} seconds",
                    TCP_CONNECT_TIMEOUT_SECS
                ));
            }
        };
        log::info!(peer = %peer_addr, remote = %remote_addr, "Connected to remote server (direct)");

        if !initial_payload.is_empty() {
            user_stats.add_upload(initial_payload.len() as u64);
            remote_stream.write_all(&initial_payload).await?;
        }

        // Relay data with stats tracking and cancellation support
        let relay_fut = relay::copy_bidirectional_with_stats(
            client_stream,
            remote_stream,
            CONNECTION_TIMEOUT_SECS,
            Some(user_stats),
        );

        tokio::select! {
            result = relay_fut => {
                match result {
                    Ok(r) if r.completed => {}
                    Ok(_) => {
                        log::warn!(peer = %peer_addr, "Connection timeout due to inactivity");
                    }
                    Err(e) => {
                        log::debug!(peer = %peer_addr, error = %e, "Copy bidirectional error");
                    }
                }
            }
            _ = cancel_token.cancelled() => {
                log::info!(peer = %peer_addr, "Connection kicked by admin");
            }
        }
    }

    Ok(())
}

// 连接检测与分发
pub async fn accept_connection<S>(server: Arc<Server>, stream: S, peer_addr: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match server.transport_mode {
        TransportMode::Grpc => {
            let peer_addr_for_log = peer_addr.clone();
            log::info!(peer = %peer_addr_for_log, "gRPC connection established, waiting for streams");
            let grpc_conn = grpc::GrpcH2cConnection::new(stream).await?;
            let result = grpc_conn
                .run(move |transport| {
                    let server = Arc::clone(&server);
                    let peer_addr = peer_addr.clone();
                    async move { handle_connection(server, transport, peer_addr).await }
                })
                .await;

            match &result {
                Ok(()) => {
                    log::info!(peer = %peer_addr_for_log, "gRPC connection closed normally");
                }
                Err(e) => {
                    log::warn!(peer = %peer_addr_for_log, error = %e, "gRPC connection closed with error");
                }
            }
            result
        }
        TransportMode::WebSocket => {
            let ws_stream = tokio_tungstenite::accept_async(stream).await?;
            let ws_transport = ws::WebSocketTransport::new(ws_stream);
            handle_connection(server, ws_transport, peer_addr).await
        }
        TransportMode::Tcp => handle_connection(server, stream, peer_addr).await,
    }
}

impl Server {
    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);
        let addr = server.listener.local_addr()?;
        let mode = match server.transport_mode {
            TransportMode::Tcp => "TCP",
            TransportMode::WebSocket => "WebSocket",
            TransportMode::Grpc => "gRPC",
        };
        let tls_enabled = server.tls_acceptor.is_some();

        log::info!(address = %addr, mode = mode, tls = tls_enabled, "Server started");

        // UDP清理任务
        udp::start_cleanup_task(Arc::clone(&server.udp_associations));

        loop {
            match server.listener.accept().await {
                Ok((stream, addr)) => {
                    // Set TCP_NODELAY on accepted connection for lower latency
                    let _ = stream.set_nodelay(true);
                    log::connection(&addr.to_string(), "new");
                    let server_clone = Arc::clone(&server);

                    tokio::spawn(async move {
                        let peer_addr = addr.to_string();
                        let result = async {
                            if let Some(ref tls_acceptor) = server_clone.tls_acceptor {
                                const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 30; // TLS握手超时30秒
                                match tokio::time::timeout(
                                    tokio::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                                    tls_acceptor.accept(stream)
                                ).await {
                                    Ok(Ok(tls_stream)) => {
                                        log::info!(peer = %peer_addr, "TLS handshake successful");
                                        accept_connection(server_clone, tls_stream, peer_addr.clone()).await
                                    }
                                    Ok(Err(e)) => {
                                        log::error!(peer = %peer_addr, error = %e, "TLS handshake failed");
                                        Err(anyhow!("TLS handshake failed: {}", e))
                                    }
                                    Err(_) => {
                                        log::warn!(peer = %peer_addr, timeout_secs = TLS_HANDSHAKE_TIMEOUT_SECS, "TLS handshake timeout");
                                        Err(anyhow!("TLS handshake timeout after {} seconds", TLS_HANDSHAKE_TIMEOUT_SECS))
                                    }
                                }
                            } else {
                                accept_connection(server_clone, stream, peer_addr.clone()).await
                            }
                        }.await;

                        if let Err(e) = result {
                            log::error!(peer = %peer_addr, error = %e, "Connection error");
                        } else {
                            log::connection(&peer_addr, "closed");
                        }
                    });
                }
                Err(e) => {
                    log::error!(error = %e, "Failed to accept connection");
                    break;
                }
            }
        }

        Ok(())
    }
}

pub async fn build_server(
    config: &config::ServerConfig,
    users: Arc<RwLock<HashMap<[u8; 56], i64>>>,
    stats: stats::StatsManager,
    connections: stats::ConnectionManager,
) -> Result<Server> {
    let addr: String = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;

    let user_count = users.read().await.len();
    log::info!(user_count = user_count, "Loaded users for authentication");

    let transport_mode = if config.enable_grpc {
        TransportMode::Grpc
    } else if config.enable_ws {
        TransportMode::WebSocket
    } else {
        TransportMode::Tcp
    };

    let tls_acceptor =
        tls::get_tls_acceptor(config.cert.clone(), config.key.clone(), transport_mode)?;

    // Load ACL engine if config file is provided
    let acl_engine = if let Some(ref acl_path) = config.acl_conf_file {
        if !acl_path.exists() {
            return Err(anyhow!("ACL config file not found: {}", acl_path.display()));
        }

        // Validate file extension
        let ext = acl_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
            return Err(anyhow!(
                "Invalid ACL config file format: expected .yaml or .yml extension, got .{} (file: {})",
                ext,
                acl_path.display()
            ));
        }

        let acl_config = acl::load_acl_config(acl_path).await?;
        let engine = acl::AclEngine::new(acl_config, Some(config.data_dir.as_path())).await?;
        log::info!(
            acl_file = %acl_path.display(),
            rules = engine.rule_count(),
            "ACL engine loaded"
        );
        Some(Arc::new(engine))
    } else {
        log::info!("No ACL config file provided, using direct connection for all traffic");
        None
    };

    Ok(Server {
        listener,
        users,
        transport_mode,
        enable_udp: config.enable_udp,
        udp_associations: udp::new_udp_associations(),
        tls_acceptor,
        acl_engine,
        stats,
        connections,
    })
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
        "Starting Trojan server with remote panel integration"
    );

    // Create stats and connection managers
    let stats = stats::StatsManager::new();
    let connections = stats::ConnectionManager::new();

    // Create API manager
    let api_manager = Arc::new(api::ApiManager::new(&cli)?);

    // Create user manager
    let user_manager = Arc::new(api::UserManager::new(connections.clone()));

    // Initialize node (register or verify existing registration)
    let register_id = api_manager.initialize().await?;
    log::info!(register_id = %register_id, "Node initialized");

    // Fetch configuration from remote panel
    let remote_config = api_manager.fetch_config().await?;

    // Fetch initial users
    let users = api_manager.fetch_users().await?;
    user_manager.init(&users).await;

    // Build server config from remote + CLI
    let server_config = config::ServerConfig::from_remote(&remote_config, &cli, users)?;

    // Build server with shared users reference
    let server = build_server(
        &server_config,
        user_manager.get_users_arc(),
        stats.clone(),
        connections.clone(),
    )
    .await?;

    // Start background tasks
    let background_tasks = api::BackgroundTasks::new(
        Arc::clone(&api_manager),
        Arc::clone(&user_manager),
        stats,
        cli.clone(),
    );
    let _background_handle = background_tasks.start();

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    // Setup shutdown handler for SIGINT (Ctrl+C) and SIGTERM
    let api_for_shutdown = Arc::clone(&api_manager);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint =
                signal(SignalKind::interrupt()).expect("Failed to setup SIGINT handler");
            let mut sigterm =
                signal(SignalKind::terminate()).expect("Failed to setup SIGTERM handler");

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

        // Signal cancellation
        cancel_token_clone.cancel();

        // Give a moment for cleanup, then exit
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });

    // Run server
    server.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trojan_request(password: &[u8; 56], cmd: u8, addr_type: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(password);
        buf.extend_from_slice(b"\r\n");
        buf.push(cmd);
        buf.push(addr_type);

        match addr_type {
            1 => {
                // IPv4
                buf.extend_from_slice(&[127, 0, 0, 1]);
                buf.extend_from_slice(&8080u16.to_be_bytes());
            }
            3 => {
                // Domain
                let domain = b"example.com";
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain);
                buf.extend_from_slice(&80u16.to_be_bytes());
            }
            4 => {
                // IPv6
                buf.extend_from_slice(&[0u8; 16]);
                buf.extend_from_slice(&443u16.to_be_bytes());
            }
            _ => {}
        }

        buf.extend_from_slice(b"\r\n");
        buf
    }

    #[test]
    fn test_trojan_request_decode_ipv4() {
        let password = [b'a'; 56];
        let mut request_bytes = make_trojan_request(&password, 1, 1);
        request_bytes.extend_from_slice(b"payload data");

        let (request, consumed) = TrojanRequest::decode(&request_bytes).unwrap();

        assert_eq!(request.password, password);
        assert_eq!(request.cmd, TrojanCmd::Connect);
        assert!(matches!(
            request.addr,
            address::Address::IPv4([127, 0, 0, 1], 8080)
        ));
        assert_eq!(request.payload.as_ref(), b"payload data");
        assert!(consumed > 0);
    }

    #[test]
    fn test_trojan_request_decode_domain() {
        let password = [b'b'; 56];
        let mut request_bytes = make_trojan_request(&password, 3, 3);
        request_bytes.extend_from_slice(b"hello");

        let (request, _) = TrojanRequest::decode(&request_bytes).unwrap();

        assert_eq!(request.cmd, TrojanCmd::UdpAssociate);
        assert!(matches!(request.addr, address::Address::Domain(ref d, 80) if d == "example.com"));
        assert_eq!(request.payload.as_ref(), b"hello");
    }

    #[test]
    fn test_trojan_request_decode_ipv6() {
        let password = [b'c'; 56];
        let mut request_bytes = make_trojan_request(&password, 1, 4);
        request_bytes.extend_from_slice(b"ipv6 payload");

        let (request, _) = TrojanRequest::decode(&request_bytes).unwrap();

        assert!(matches!(request.addr, address::Address::IPv6(_, 443)));
        assert_eq!(request.payload.as_ref(), b"ipv6 payload");
    }

    #[test]
    fn test_trojan_request_decode_zerocopy_ipv4() {
        let password = [b'a'; 56];
        let mut request_bytes = make_trojan_request(&password, 1, 1);
        request_bytes.extend_from_slice(b"payload data");

        let mut buf = BytesMut::from(&request_bytes[..]);
        let request = TrojanRequest::decode_zerocopy(&mut buf).unwrap();

        assert_eq!(request.password, password);
        assert_eq!(request.cmd, TrojanCmd::Connect);
        assert!(matches!(
            request.addr,
            address::Address::IPv4([127, 0, 0, 1], 8080)
        ));
        assert_eq!(request.payload.as_ref(), b"payload data");

        // Buffer should be cleared after zerocopy decode
        assert!(buf.is_empty());
    }

    #[test]
    fn test_trojan_request_decode_zerocopy_domain() {
        let password = [b'b'; 56];
        let mut request_bytes = make_trojan_request(&password, 3, 3);
        request_bytes.extend_from_slice(b"hello world!");

        let mut buf = BytesMut::from(&request_bytes[..]);
        let request = TrojanRequest::decode_zerocopy(&mut buf).unwrap();

        assert_eq!(request.cmd, TrojanCmd::UdpAssociate);
        assert!(matches!(request.addr, address::Address::Domain(ref d, 80) if d == "example.com"));
        assert_eq!(request.payload.as_ref(), b"hello world!");
    }

    #[test]
    fn test_trojan_request_decode_zerocopy_empty_payload() {
        let password = [b'd'; 56];
        let request_bytes = make_trojan_request(&password, 1, 1);

        let mut buf = BytesMut::from(&request_bytes[..]);
        let request = TrojanRequest::decode_zerocopy(&mut buf).unwrap();

        assert!(request.payload.is_empty());
    }

    #[test]
    fn test_trojan_request_decode_zerocopy_large_payload() {
        let password = [b'e'; 56];
        let mut request_bytes = make_trojan_request(&password, 1, 1);
        let large_payload = vec![0xAB; 10000];
        request_bytes.extend_from_slice(&large_payload);

        let mut buf = BytesMut::from(&request_bytes[..]);
        let request = TrojanRequest::decode_zerocopy(&mut buf).unwrap();

        assert_eq!(request.payload.len(), 10000);
        assert!(request.payload.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_trojan_request_decode_vs_zerocopy_equivalence() {
        let password = [b'f'; 56];
        let mut request_bytes = make_trojan_request(&password, 1, 1);
        request_bytes.extend_from_slice(b"test payload for equivalence check");

        // Decode with copy version
        let (request_copy, _) = TrojanRequest::decode(&request_bytes).unwrap();

        // Decode with zerocopy version
        let mut buf = BytesMut::from(&request_bytes[..]);
        let request_zerocopy = TrojanRequest::decode_zerocopy(&mut buf).unwrap();

        // Both should produce identical results
        assert_eq!(request_copy.password, request_zerocopy.password);
        assert_eq!(request_copy.cmd, request_zerocopy.cmd);
        assert_eq!(request_copy.addr, request_zerocopy.addr);
        assert_eq!(request_copy.payload, request_zerocopy.payload);
    }

    #[test]
    fn test_trojan_request_decode_buffer_too_small() {
        let buf = vec![0u8; 50]; // Less than minimum 59 bytes
        let result = TrojanRequest::decode(&buf);
        assert!(result.is_err());

        let mut buf_mut = BytesMut::from(&buf[..]);
        let result_zerocopy = TrojanRequest::decode_zerocopy(&mut buf_mut);
        assert!(result_zerocopy.is_err());
    }

    #[test]
    fn test_trojan_request_decode_invalid_crlf() {
        let mut buf = vec![b'a'; 56];
        buf.extend_from_slice(b"\n\r"); // Wrong order
        buf.push(1);
        buf.push(1);
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&8080u16.to_be_bytes());
        buf.extend_from_slice(b"\r\n");

        let result = TrojanRequest::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_trojan_request_decode_invalid_command() {
        let mut buf = vec![b'a'; 56];
        buf.extend_from_slice(b"\r\n");
        buf.push(99); // Invalid command
        buf.push(1);
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&8080u16.to_be_bytes());
        buf.extend_from_slice(b"\r\n");

        let result = TrojanRequest::decode(&buf);
        assert!(result.is_err());
    }
}
