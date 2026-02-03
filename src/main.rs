//! Trojan proxy server with layered architecture
//!
//! Architecture:
//! - `core/`: Core proxy logic with hook traits for extensibility
//! - `transport/`: Transport layer abstraction (TCP, WebSocket, gRPC)
//! - `business/`: Business implementations (API, auth, stats)
//! - `handler`: Connection processing logic
//! - `server_runner`: Server startup and accept loop

mod acl;
mod business;
mod config;
mod core;
mod error;
mod handler;
mod logger;
mod server_runner;
mod transport;

// Use mimalloc as the global allocator for better performance
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use logger::log;

use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::business::{
    ApiAuthenticator, ApiManager, ApiStatsCollector, BackgroundTasks, TaskConfig, UserManager,
};
use crate::core::{ConnectionManager, Server};

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
    let router = server_runner::build_router(&server_config, cli.refresh_geodata).await?;

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
    server_runner::run_server(server, &server_config).await
}
